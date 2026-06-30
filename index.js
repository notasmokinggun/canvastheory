/**
 * Canvas Theory — Cloud Functions
 * ─────────────────────────────────────────────────────────────────────────
 * This file replaces the client-only Razorpay flow in index.html.
 *
 * THE PROBLEM THIS FIXES:
 * The original site set `amount` in the browser before opening Razorpay
 * checkout. Anyone could edit that JS and pay ₹1 for a ₹2,499 jacket — there
 * was no server in the loop to say "no, this costs ₹2,499."
 *
 * THE FIX:
 * 1. Client calls createOrder() with product + specs (no amount).
 * 2. This function calculates the authoritative price server-side and asks
 *    Razorpay to create an Order for that exact amount.
 * 3. Client passes the returned order_id (not amount) into Razorpay
 *    checkout. Razorpay enforces server-to-server that the payment matches
 *    the order it created — the client literally cannot change the price.
 * 4. Razorpay calls our webhook (webhooks.js) when payment is captured.
 *    We verify the HMAC signature, then mark the order 'paid' in Firestore.
 *    Only this server-verified write is ever trusted.
 *
 * DEPLOY:
 *   firebase functions:secrets:set RAZORPAY_KEY_ID
 *   firebase functions:secrets:set RAZORPAY_KEY_SECRET
 *   firebase functions:secrets:set RAZORPAY_WEBHOOK_SECRET
 *   firebase deploy --only functions
 */

const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { onDocumentCreated } = require('firebase-functions/v2/firestore');
const { defineSecret } = require('firebase-functions/params');
const { setGlobalOptions } = require('firebase-functions/v2');
const admin = require('firebase-admin');
const Razorpay = require('razorpay');

admin.initializeApp();
const db = admin.firestore();

setGlobalOptions({ region: 'asia-south1', maxInstances: 10 });

const RAZORPAY_KEY_ID     = defineSecret('RAZORPAY_KEY_ID');
const RAZORPAY_KEY_SECRET = defineSecret('RAZORPAY_KEY_SECRET');

function getRazorpayClient() {
  return new Razorpay({
    key_id:     RAZORPAY_KEY_ID.value(),
    key_secret: RAZORPAY_KEY_SECRET.value(),
  });
}

// ─────────────────────────────────────────────────────────────────────────
// PRICE TABLE — single source of truth for what anything costs.
// The client never sends a price; it only sends what was selected, and
// this table decides what that costs. Keep this in sync with the chip
// values in index.html's order form (jacket-patches, tote-surface, etc).
// All amounts are in paise (₹1 = 100 paise) because that's what Razorpay
// expects.
// ─────────────────────────────────────────────────────────────────────────
const BASE_PRICE = {
  jacket: 249900, // ₹2,499
  tote:    89900, // ₹899
  guitar: 319900, // ₹3,199 — guitar project jackets, priced as a jacket variant
};

const JACKET_PATCH_COST = {
  'No patches':          0,
  'Floral embroidery':   15000, // +₹150
  'Band / graphic patch':12000, // +₹120
  'Custom text':         10000, // +₹100
  'Geometric pattern':   12000, // +₹120
  'Vintage badges':      18000, // +₹180
};

const JACKET_DISTRESS_COST = {
  'None (clean)': 0,
  'Light':        5000,  // +₹50
  'Medium':       8000,  // +₹80
  'Heavy':        12000, // +₹120
};

const TOTE_SURFACE_COST = {
  'Plain':              0,
  'Floral embroidery':  12000,
  'Custom text':        8000,
  'Geometric pattern':  10000,
};

const TOTE_SIZE_DELTA = {
  'Small (30×35 cm)':  0,
  'Medium (38×42 cm)': 10000, // +₹100
  'Large (45×50 cm)':  20000, // +₹200
};

/**
 * Calculates the authoritative order amount in paise from product + specs.
 * Never trust a price sent by the client — always recompute it here.
 */
function calculatePrice(product, specs) {
  if (!BASE_PRICE.hasOwnProperty(product)) {
    throw new HttpsError('invalid-argument', `Unknown product type: ${product}`);
  }

  let amount = BASE_PRICE[product];

  if (product === 'jacket' || product === 'guitar') {
    const patches = Array.isArray(specs.patches) ? specs.patches : [specs.patches].filter(Boolean);
    patches.forEach(p => { amount += JACKET_PATCH_COST[p] || 0; });
    amount += JACKET_DISTRESS_COST[specs.distress] || 0;
  }

  if (product === 'tote') {
    amount += TOTE_SURFACE_COST[specs.surface] || 0;
    amount += TOTE_SIZE_DELTA[specs.size] || 0;
  }

  return amount;
}

// ─────────────────────────────────────────────────────────────────────────
// createOrder — callable from the client via the Firebase SDK:
//   const createOrder = httpsCallable(functions, 'createOrder');
//   const { data } = await createOrder({ product: 'jacket', specs: {...} });
//   // data.order_id, data.amount, data.key_id  → pass into Razorpay checkout
// ─────────────────────────────────────────────────────────────────────────
exports.createOrder = onCall(
  { secrets: [RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET] },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError('unauthenticated', 'Sign in with Google before placing an order.');
    }

    const { product, specs, shipping } = request.data || {};

    if (!product || !specs || !shipping) {
      throw new HttpsError('invalid-argument', 'Missing product, specs, or shipping details.');
    }

    // Basic server-side validation — mirrors the client validateForm() checks
    // in index.html, but never trust the client alone.
    const requiredShippingFields = ['name', 'phone', 'address', 'pincode', 'state'];
    for (const field of requiredShippingFields) {
      if (!shipping[field] || String(shipping[field]).trim().length === 0) {
        throw new HttpsError('invalid-argument', `Missing shipping field: ${field}`);
      }
    }
    if (!/^[6-9]\d{9}$/.test(shipping.phone)) {
      throw new HttpsError('invalid-argument', 'Invalid Indian mobile number.');
    }
    if (!/^\d{6}$/.test(shipping.pincode)) {
      throw new HttpsError('invalid-argument', 'Invalid Indian pincode.');
    }

    const amount = calculatePrice(product, specs);

    const rzp = getRazorpayClient();
    const rzpOrder = await rzp.orders.create({
      amount,
      currency: 'INR',
      receipt: `ct_${request.auth.uid.slice(0, 8)}_${Date.now()}`,
      notes: {
        uid:     request.auth.uid,
        product,
      },
    });

    await db.collection('orders').doc(rzpOrder.id).set({
      order_id:         rzpOrder.id,
      user_uid:         request.auth.uid,
      user_email:       request.auth.token.email || null,
      product,
      specs,
      shipping_address: shipping,
      amount_paise:     amount,
      currency:         'INR',
      status:           'pending',
      progress_photos:  [],
      created_at:       admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      order_id: rzpOrder.id,
      amount,
      currency: 'INR',
      key_id:   RAZORPAY_KEY_ID.value(),
    };
  }
);

// ─────────────────────────────────────────────────────────────────────────
// getMyOrders — callable that returns the signed-in user's own orders.
// Firestore security rules already restrict reads to the owner, but this
// callable is convenient for a dashboard that wants sorted, paginated results
// without exposing raw Firestore queries to the client.
// ─────────────────────────────────────────────────────────────────────────
exports.getMyOrders = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError('unauthenticated', 'Sign in to view your orders.');
  }

  const snap = await db.collection('orders')
    .where('user_uid', '==', request.auth.uid)
    .orderBy('created_at', 'desc')
    .limit(50)
    .get();

  return {
    orders: snap.docs.map(doc => ({ id: doc.id, ...doc.data() })),
  };
});

// ─────────────────────────────────────────────────────────────────────────
// onUserOrderPaid — Firestore trigger that fires whenever an order document
// is created. Not used for payment verification (that's the webhook's job,
// since this trigger only sees what's already in Firestore) — this is for
// side effects like analytics logging once an order enters 'pending' state.
// ─────────────────────────────────────────────────────────────────────────
exports.onUserOrderPaid = onDocumentCreated('orders/{orderId}', async (event) => {
  const order = event.data?.data();
  if (!order) return;

  console.log(`New order created: ${event.params.orderId} — product=${order.product} amount=${order.amount_paise}`);

  // Optional: increment a denormalized counter for admin dashboards.
  await db.collection('stats').doc('orders').set(
    { total_pending: admin.firestore.FieldValue.increment(1) },
    { merge: true }
  );
});

// Re-export the webhook handler so `firebase deploy --only functions`
// picks it up from this single entry point.
exports.razorpayWebhook = require('./webhooks').razorpayWebhook;
