/**
 * Canvas Theory — Razorpay Webhook Handler
 * ─────────────────────────────────────────────────────────────────────────
 * Razorpay calls this endpoint directly (server-to-server) whenever a
 * payment event happens — captured, failed, refunded, etc. This is the
 * ONLY place an order is ever marked 'paid'. The client's Razorpay
 * `handler` callback in index.html should be treated as a UX nicety
 * (show a success message) — never as proof that money moved. A user
 * could close the tab right after paying and before the handler fires;
 * the webhook is what's guaranteed to arrive.
 *
 * SECURITY: every request is checked against an HMAC-SHA256 signature
 * computed with your webhook secret. Requests that don't match are
 * rejected outright — this is what stops someone from POSTing a fake
 * "payment.captured" event directly to your endpoint.
 *
 * SETUP:
 *   1. Razorpay Dashboard → Settings → Webhooks → Add New Webhook
 *   2. URL: https://asia-south1-<project-id>.cloudfunctions.net/razorpayWebhook
 *   3. Active events: payment.captured, payment.failed, refund.processed
 *   4. Copy the generated webhook secret and run:
 *      firebase functions:secrets:set RAZORPAY_WEBHOOK_SECRET
 */

const { onRequest } = require('firebase-functions/v2/https');
const { defineSecret } = require('firebase-functions/params');
const admin = require('firebase-admin');
const crypto = require('crypto');

const RAZORPAY_WEBHOOK_SECRET = defineSecret('RAZORPAY_WEBHOOK_SECRET');

function getDb() {
  // admin.initializeApp() already called in index.js, which requires
  // this file — calling it again here would throw, so just grab firestore.
  return admin.firestore();
}

function verifySignature(rawBody, signature, secret) {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody)
    .digest('hex');

  // Constant-time comparison to avoid timing attacks.
  const expectedBuf = Buffer.from(expected, 'hex');
  const signatureBuf = Buffer.from(signature || '', 'hex');
  if (expectedBuf.length !== signatureBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, signatureBuf);
}

exports.razorpayWebhook = onRequest(
  { secrets: [RAZORPAY_WEBHOOK_SECRET] },
  async (req, res) => {
    if (req.method !== 'POST') {
      res.status(405).send('Method not allowed');
      return;
    }

    const signature = req.headers['x-razorpay-signature'];
    // req.rawBody is provided by the Cloud Functions runtime — using the
    // raw, unparsed bytes is essential here. Signing the re-serialized
    // req.body can produce a different byte sequence (key order, spacing)
    // and silently fail verification.
    const rawBody = req.rawBody;

    if (!signature || !rawBody) {
      console.warn('Webhook rejected: missing signature or body');
      res.status(400).send('Missing signature');
      return;
    }

    const isValid = verifySignature(rawBody, signature, RAZORPAY_WEBHOOK_SECRET.value());
    if (!isValid) {
      console.warn('Webhook rejected: signature mismatch');
      res.status(400).send('Invalid signature');
      return;
    }

    const event = req.body;
    const db = getDb();

    try {
      switch (event.event) {
        case 'payment.captured': {
          const payment = event.payload.payment.entity;
          const orderId = payment.order_id;

          const orderRef = db.collection('orders').doc(orderId);
          const orderSnap = await orderRef.get();

          if (!orderSnap.exists) {
            console.error(`Webhook for unknown order: ${orderId}`);
            break;
          }

          // Defense in depth: re-confirm the captured amount matches what
          // we calculated server-side at createOrder() time. If these ever
          // disagree, something is wrong upstream — don't silently accept it.
          const expectedAmount = orderSnap.data().amount_paise;
          if (payment.amount !== expectedAmount) {
            console.error(`Amount mismatch on order ${orderId}: expected ${expectedAmount}, got ${payment.amount}`);
            await orderRef.update({ status: 'amount_mismatch_flagged' });
            break;
          }

          await orderRef.update({
            status:              'paid',
            razorpay_payment_id: payment.id,
            paid_at:             admin.firestore.FieldValue.serverTimestamp(),
          });

          // Award referral credit if this order used a referral code.
          const orderData = orderSnap.data();
          if (orderData.referral_code) {
            await applyReferralCredit(db, orderData.referral_code, orderId);
          }

          console.log(`Order ${orderId} marked paid (payment ${payment.id})`);
          break;
        }

        case 'payment.failed': {
          const payment = event.payload.payment.entity;
          const orderId = payment.order_id;
          await db.collection('orders').doc(orderId).update({
            status:        'failed',
            failure_reason: payment.error_description || 'unknown',
            failed_at:     admin.firestore.FieldValue.serverTimestamp(),
          }).catch(() => {
            // Order doc may not exist if createOrder partially failed — log and move on.
            console.warn(`Could not update failed order ${orderId}`);
          });
          break;
        }

        case 'refund.processed': {
          const refund = event.payload.refund.entity;
          const orderId = refund.notes?.order_id || null;
          if (orderId) {
            await db.collection('orders').doc(orderId).update({
              status:      'refunded',
              refund_id:   refund.id,
              refunded_at: admin.firestore.FieldValue.serverTimestamp(),
            });
          }
          break;
        }

        default:
          console.log(`Unhandled webhook event: ${event.event}`);
      }

      // Always 200 once signature is verified and we've processed (or
      // intentionally ignored) the event — Razorpay retries on non-2xx,
      // and we don't want retries for events we've already handled.
      res.status(200).send('OK');
    } catch (err) {
      console.error('Webhook processing error:', err);
      // 500 here DOES trigger a Razorpay retry, which is what we want for
      // a genuine processing failure (e.g. Firestore transient error).
      res.status(500).send('Internal error');
    }
  }
);

/**
 * Credits ₹200 (20000 paise) to the referring user when their referral
 * code is used on a successfully paid order. Called from the
 * payment.captured handler above.
 */
async function applyReferralCredit(db, referralCode, orderId) {
  const usersSnap = await db.collection('users')
    .where('referral_code', '==', referralCode)
    .limit(1)
    .get();

  if (usersSnap.empty) {
    console.warn(`Referral code not found: ${referralCode}`);
    return;
  }

  const referrerDoc = usersSnap.docs[0];
  await referrerDoc.ref.update({
    credits: admin.firestore.FieldValue.increment(20000), // ₹200 in paise
  });

  await db.collection('referral_credits').add({
    referrer_uid: referrerDoc.id,
    order_id:     orderId,
    amount_paise: 20000,
    created_at:   admin.firestore.FieldValue.serverTimestamp(),
  });

  console.log(`Referral credit applied to ${referrerDoc.id} for order ${orderId}`);
}
