/*
 * Shrine License Validation Worker (Cloudflare)
 * This worker validates RSA signatures for the Shrine theme.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Only handle the specific endpoint
    if (url.pathname !== '/api/updates/check') {
      return new Response('Not Found', { status: 404 });
    }

    // Support both GET (query params) and POST (body)
    let shop, license;
    if (request.method === 'GET') {
      shop = url.searchParams.get('shop');
      license = url.searchParams.get('license');
    } else {
      try {
        const body = await request.json();
        shop = body.shop;
        license = body.license;
      } catch (e) {}
    }

    if (!shop || !license) {
      return new Response(JSON.stringify({ 
        status: 'inactive', 
        message: 'Missing shop or license.' 
      }), {
        headers: { 'Content-Type': 'application/json' },
        status: 400
      });
    }

    try {
      // 1. Get Public Key from Environment Variable (PEM Format)
      // Note: In Cloudflare Dashboard, add PUBLIC_KEY as a secret.
      const publicKeyPem = env.PUBLIC_KEY; 
      if (!publicKeyPem) {
         throw new Error('Public key not configured in environment.');
      }

      // 2. Import Key
      const key = await importPublicKey(publicKeyPem);

      // 3. Verify Signature
      const encoder = new TextEncoder();
      const data = encoder.encode(shop);
      const signature = base64ToArray(license);

      const isValid = await crypto.subtle.verify(
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        key,
        signature,
        data
      );

      if (isValid) {
        return new Response(JSON.stringify({
          status: 'active',
          message: 'Shrine Theme License: ACTIVE',
          details: { shop, authenticated: true }
        }), { headers: { 'Content-Type': 'application/json' } });
      } else {
        return new Response(JSON.stringify({
          status: 'inactive',
          message: 'License key is invalid for this domain.'
        }), { headers: { 'Content-Type': 'application/json' } });
      }

    } catch (err) {
      return new Response(JSON.stringify({
        status: 'error',
        message: 'Validation failed: ' + err.message
      }), {
        headers: { 'Content-Type': 'application/json' },
        status: 500
      });
    }
  }
};

async function importPublicKey(pem) {
  // Remove PEM headers/footers and newlines
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";
  const pemContents = pem.substring(
    pem.indexOf(pemHeader) + pemHeader.length,
    pem.indexOf(pemFooter)
  ).replace(/\s/g, '');

  const binaryDerString = atob(pemContents);
  const binaryDer = str2ab(binaryDerString);

  return await crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"]
  );
}

function base64ToArray(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}
