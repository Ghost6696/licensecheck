/*
 * Shrine License Validation Worker (Cloudflare)
 * This worker validates RSA signatures for the Shrine theme.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Handle CORS Preflight (OPTIONS)
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      "Access-Control-Max-Age": "86400",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders,
      });
    }

    // Only handle the specific endpoint
    if (url.pathname !== '/api/updates/check') {
      return new Response('Not Found', { status: 404 });
    }

    // 2. Robust Parameter Extraction
    let shop = url.searchParams.get('shop') || url.searchParams.get('domain');
    let license = url.searchParams.get('license') || url.searchParams.get('key');

    let body = {};
    if (request.method === "POST") {
      try {
        const contentType = request.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          body = await request.clone().json();
          shop = shop || body.shop || body.domain || body.url;
          license = license || body.license || body.key || body.license_key || body.shrine_license || body.data;
          
          // If still no license, scan all keys for a 180+ character string (likely the RSA license)
          if (!license) {
            for (const key in body) {
              if (typeof body[key] === 'string' && body[key].length > 180) {
                license = body[key];
                break;
              }
            }
          }
        } else {
          const formData = await request.clone().formData();
          shop = shop || formData.get('shop') || formData.get('domain');
          license = license || formData.get('license') || formData.get('key');
        }
      } catch (e) {}
    }

    // 3. Fallback for 'shop' from Referer
    if (!shop) {
      const referer = request.headers.get('referer');
      if (referer) {
        try { shop = new URL(referer).hostname; } catch (e) {}
      }
    }

    const jsonResponse = (data, status = 200) => {
      return new Response(JSON.stringify(data), {
        status: status,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      });
    };

    // 4. Validate Parameters
    // We return 200 'inactive' instead of 400 error to ensure the theme blocks access.
    if (!shop || !license) {
      return jsonResponse({ 
        "b": "body",
        "h": getBlockHtml(`Authentication failed. ${!shop ? 'Missing shop domain.' : ''} ${!license ? 'Missing license key.' : ''}`)
      }, 201);
    }

    try {
      const publicKeyPem = env.PUBLIC_KEY; 
      if (!publicKeyPem) {
         throw new Error('Public key not configured in environment.');
      }

      const key = await importPublicKey(publicKeyPem);
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
        return jsonResponse({
          status: 'active',
          message: 'Shrine Theme License: ACTIVE',
          details: { shop, authenticated: true }
        });
      } else {
        // Return 201 to trigger the theme's blocking injection logic
        return jsonResponse({
          "b": "body",
          "h": getBlockHtml("Token Invalid - The license key provided is not authorized for this domain.")
        }, 201);
      }

    } catch (err) {
      return jsonResponse({
        "b": "body",
        "h": getBlockHtml("Server Error - " + err.message)
      }, 201);
    }
  }
};

/**
 * Generates the premium blocking HTML message.
 */
function getBlockHtml(reason) {
  return `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Restricted | Shrine Theme</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
      :root {
        --primary: #000000;
        --accent: #ff3e3e;
        --bg: #0a0a0c;
        --card-bg: rgba(255, 255, 255, 0.03);
        --text-main: #ffffff;
        --text-muted: #94a3b8;
        --border: rgba(255, 255, 255, 0.08);
      }

      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }

      body {
        background-color: var(--bg);
        color: var(--text-main);
        font-family: 'Plus Jakarta Sans', sans-serif;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        overflow: hidden;
      }

      /* Animated Background */
      .bg-glow {
        position: fixed;
        width: 100vw;
        height: 100vh;
        z-index: -1;
        background: 
          radial-gradient(circle at 20% 20%, rgba(255, 62, 62, 0.05) 0%, transparent 40%),
          radial-gradient(circle at 80% 80%, rgba(255, 255, 255, 0.02) 0%, transparent 40%);
      }

      .container {
        position: relative;
        max-width: 520px;
        width: 90%;
        padding: 3.5rem;
        background: var(--card-bg);
        backdrop-filter: blur(24px);
        -webkit-backdrop-filter: blur(24px);
        border: 1px solid var(--border);
        border-radius: 40px;
        text-align: center;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        animation: reveal 1s cubic-bezier(0.16, 1, 0.3, 1);
      }

      @keyframes reveal {
        from { opacity: 0; transform: scale(0.95) translateY(20px); }
        to { opacity: 1; transform: scale(1) translateY(0); }
      }

      .logo {
        width: 140px;
        margin-bottom: 2.5rem;
        filter: brightness(0) invert(1);
        opacity: 0.9;
      }

      .badge {
        display: inline-flex;
        align-items: center;
        padding: 0.6rem 1.2rem;
        background: rgba(255, 62, 62, 0.1);
        color: #ff5f5f;
        font-size: 0.7rem;
        font-weight: 800;
        border-radius: 100px;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-bottom: 1.5rem;
        border: 1px solid rgba(255, 62, 62, 0.2);
      }

      h1 {
        font-size: 2.25rem;
        font-weight: 800;
        margin-bottom: 1rem;
        letter-spacing: -0.03em;
        background: linear-gradient(135deg, #ffffff 0%, #94a3b8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
      }

      p {
        font-size: 1.05rem;
        line-height: 1.6;
        color: var(--text-muted);
        margin-bottom: 2.5rem;
      }

      .reason-box {
        background: rgba(255, 255, 255, 0.02);
        border: 1px solid var(--border);
        border-radius: 20px;
        padding: 1.5rem;
        margin-bottom: 2.5rem;
        text-align: left;
      }

      .reason-label {
        font-size: 0.65rem;
        font-weight: 800;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.5rem;
      }

      .reason-content {
        font-size: 0.95rem;
        color: #cbd5e1;
        font-weight: 500;
        line-height: 1.5;
      }

      .actions {
        display: flex;
        flex-direction: column;
        gap: 1rem;
      }

      .btn {
        display: block;
        padding: 1.1rem;
        border-radius: 18px;
        text-decoration: none;
        font-weight: 700;
        font-size: 0.95rem;
        transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        cursor: pointer;
      }

      .btn-primary {
        background: #ffffff;
        color: #000000;
        box-shadow: 0 10px 20px -5px rgba(255, 255, 255, 0.1);
      }

      .btn-primary:hover {
        transform: translateY(-3px);
        box-shadow: 0 20px 30px -10px rgba(255, 255, 255, 0.2);
        background: #f8fafc;
      }

      @media (max-width: 480px) {
        .container { padding: 2.5rem 1.5rem; }
        h1 { font-size: 1.75rem; }
      }
    </style>
  </head>
  <body>
    <div class="bg-glow"></div>
    <div class="container">
      <img src="https://cdn.shrinetheme.com/Full_Logo_Transparent.png" alt="Shrine" class="logo">
      
      <div class="badge">Security Verification</div>
      
      <h1>Unauthorized Axis</h1>
      <p>This theme instance is currently restricted. A valid activation token is required to unlock premium features.</p>

      <div class="reason-box">
        <div class="reason-label">Restriction Details</div>
        <div class="reason-content">${reason}</div>
      </div>

      <div class="actions">
        <a href="https://github.com/Ghost6696/licensecheck" class="btn btn-primary">Contact Support</a>
      </div>
    </div>
  </body>
  </html>`;
}


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
