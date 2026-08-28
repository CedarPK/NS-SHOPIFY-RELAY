// This file automatically becomes a live URL once deployed to Vercel:
//   https://<your-project-name>.vercel.app/api/shopify-refund
// That URL is what you paste into the Shopify webhook.

export const config = {
  api: {
    bodyParser: false // we need the raw, untouched body to verify Shopify's signature
  }
};

import crypto from 'crypto';
import OAuth from 'oauth-1.0a';
process.on('unhandledRejection', (err) => console.error('UNHANDLED REJECTION:', err));
process.on('uncaughtException', (err) => console.error('UNCAUGHT EXCEPTION:', err));
function getRawBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function verifyShopifyHmac(rawBody, hmacHeader, secret) {
  const digest = crypto.createHmac('sha256', secret).update(rawBody, 'utf8').digest('base64');
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader || ''));
  } catch {
    return false; // header missing or wrong length — definitely not valid
  }
}

// Newer Dev Dashboard apps don't hand you a static Admin API token —
// instead you exchange your Client ID + Client secret for a
// short-lived access token each time (the "client credentials grant").
// We fetch a fresh one on every request rather than trying to cache
// it across invocations, since serverless functions don't reliably
// persist memory between calls anyway.
async function getShopifyAccessToken() {
  const shop = process.env.SHOPIFY_SHOP_DOMAIN;

  const res = await fetch(`https://${shop}/admin/oauth/access_token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.SHOPIFY_CLIENT_ID,
      client_secret: process.env.SHOPIFY_CLIENT_SECRET,
      grant_type: 'client_credentials'
    })
  });

 if (!res.ok) {
    const errorBody = await res.text();
    throw new Error(`Shopify token request failed: ${res.status} ${res.statusText} — ${errorBody}`);
  }

  const data = await res.json();
  return data.access_token;
}

async function getShopifyOrderFinancialStatus(orderId) {
  const shop = process.env.SHOPIFY_SHOP_DOMAIN;
    console.log('CLIENT_ID present:', !!process.env.SHOPIFY_CLIENT_ID, 'length:', (process.env.SHOPIFY_CLIENT_ID || '').length);
  console.log('CLIENT_SECRET present:', !!process.env.SHOPIFY_CLIENT_SECRET, 'length:', (process.env.SHOPIFY_CLIENT_SECRET || '').length);
  const token = await getShopifyAccessToken();

  const res = await fetch(
    `https://${shop}/admin/api/2024-01/orders/${orderId}.json?fields=id,financial_status`,
    { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
  );

  if (!res.ok) {
    throw new Error(`Shopify order lookup failed: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();
  return data.order.financial_status; // "refunded", "partially_refunded", "paid", etc.
}

function buildNetsuiteAuthHeader(url) {
  const oauth = OAuth({
    consumer: {
      key: process.env.NETSUITE_CONSUMER_KEY,
      secret: process.env.NETSUITE_CONSUMER_SECRET
    },
    signature_method: 'HMAC-SHA256',
    hash_function(baseString, key) {
      return crypto.createHmac('sha256', key).update(baseString).digest('base64');
    }
  });

  const requestData = { url, method: 'POST' };
  const token = {
    key: process.env.NETSUITE_TOKEN_ID,
    secret: process.env.NETSUITE_TOKEN_SECRET
  };

  return oauth.toHeader(oauth.authorize(requestData, token));
}

export default async function handler(req, res) {
console.log('HANDLER STARTED', req.method, new Date().toISOString());
  try {
    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const rawBody = await getRawBody(req);
    const hmacHeader = req.headers['x-shopify-hmac-sha256'];

    const verified = verifyShopifyHmac(rawBody, hmacHeader, process.env.SHOPIFY_WEBHOOK_SECRET);
    if (!verified) {
      return res.status(401).json({ error: 'Invalid HMAC — request did not come from Shopify' });
    }

    const payload = JSON.parse(rawBody);
    const orderId = payload.order_id;

    let financialStatus;
    try {
      financialStatus = await getShopifyOrderFinancialStatus(orderId);
    } catch (e) {
      console.error('Shopify lookup failed', e);
      return res.status(502).json({ error: `Shopify lookup failed: ${e.message}` });
    }

    if (financialStatus !== 'refunded') {
      // Partial refund, or something else — do not close the order.
      return res.status(200).json({
        skipped: true,
        reason: `financial_status is "${financialStatus}", not a full refund`
      });
    }

    const netsuiteUrl = process.env.NETSUITE_RESTLET_URL;
    if (!netsuiteUrl) {
      console.error('NETSUITE_RESTLET_URL is not set');
      return res.status(500).json({ error: 'NETSUITE_RESTLET_URL environment variable is missing' });
    }

    const authHeader = buildNetsuiteAuthHeader(netsuiteUrl);

    let nsResponse;
    try {
      nsResponse = await fetch(netsuiteUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeader },
        body: JSON.stringify({ ...payload, financial_status: financialStatus })
      });
    } catch (e) {
      console.error('Could not reach NetSuite', e);
      return res.status(502).json({ error: `Could not reach NetSuite: ${e.message}` });
    }

    const rawResult = await nsResponse.text();
    let result;
    try {
      result = JSON.parse(rawResult);
    } catch {
      // NetSuite didn't return JSON — likely an HTML error page (bad URL,
      // expired token, deployment not released, etc). Surface the raw
      // text so it's visible in the logs instead of crashing.
      console.error('NetSuite returned non-JSON response', nsResponse.status, rawResult.slice(0, 500));
      return res.status(502).json({
        error: 'NetSuite returned a non-JSON response',
        netsuiteStatus: nsResponse.status,
        netsuiteBodyPreview: rawResult.slice(0, 500)
      });
    }

    return res.status(nsResponse.ok ? 200 : 502).json(result);

  } catch (e) {
    // Catch-all so a crash always produces a real, readable log entry
    // instead of a blank 502.
    console.error('Unhandled error in relay', e);
    return res.status(500).json({ error: e.message, stack: e.stack });
  }
}
