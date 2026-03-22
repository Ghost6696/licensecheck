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
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
      "Access-Control-Max-Age": "86400",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders,
      });
    }

    // Only handle the specific endpoint
    if (url.pathname === '/api/updates/check') {
      return await handleValidation(request, env, corsHeaders);
    }

    if (url.pathname.startsWith('/api/admin/')) {
      return await handleAdmin(request, env, corsHeaders);
    }

    return new Response('Not Found', { status: 404 });
  }
};

async function handleAdmin(request, env, corsHeaders) {
  const url = new URL(request.url);
  const auth = request.headers.get("Authorization");
  const adminPassword = env.ADMIN_PASSWORD || "shrine123"; // Default if not set

  // Simple basic auth check (Password in Authorization header)
  if (auth !== adminPassword && url.pathname !== '/api/admin/login') {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { 
      status: 401, 
      headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }

  // 1. Login Endpoint
  if (url.pathname === '/api/admin/login') {
    const { password } = await request.json();
    if (password === adminPassword) {
      return new Response(JSON.stringify({ success: true, token: adminPassword }), { 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }
    return new Response(JSON.stringify({ error: "Invalid password" }), { 
      status: 401, 
      headers: { ...corsHeaders, "Content-Type": "application/json" } 
    });
  }

  // 2. Licenses Endpoint (CRUD)
  if (url.pathname === '/api/admin/licenses') {
    // List all (KV doesn't support easy "list all" without pagination/prefixes, 
    // but for < 1000 keys we can use list())
    if (request.method === "GET") {
      const list = await env.LICENSES.list();
      const licenses = [];
      for (const key of list.keys) {
        const val = await env.LICENSES.get(key.name);
        licenses.push({ shop: key.name, ...JSON.parse(val) });
      }
      return new Response(JSON.stringify(licenses), { 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }

    // Add / Update / Alias
    if (request.method === "POST") {
      const data = await request.json(); // { shop, status, key, created, action, target }
      
      // Handle Alias Creation
      if (data.action === "add_alias") {
        if (!data.shop || !data.target) {
          return new Response(JSON.stringify({ error: "Missing shop or target for alias" }), { 
            status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } 
          });
        }
        await env.LICENSES.put(data.shop, JSON.stringify({ 
          type: "alias", 
          target: data.target,
          created: new Date().toISOString()
        }));
        return new Response(JSON.stringify({ success: true, message: "Alias added" }), { 
          headers: { ...corsHeaders, "Content-Type": "application/json" } 
        });
      }

      // Default: Add/Update Primary License
      const existingRaw = await env.LICENSES.get(data.shop);
      let existing = existingRaw ? JSON.parse(existingRaw) : {};

      const updated = {
        status: data.status || existing.status || "active",
        key: data.key || existing.key || "",
        created: data.created || existing.created || new Date().toISOString()
      };

      await env.LICENSES.put(data.shop, JSON.stringify(updated));
      return new Response(JSON.stringify({ success: true }), { 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }

    // Delete / Revoke
    if (request.method === "DELETE") {
      const { shop } = await request.json();
      await env.LICENSES.delete(shop);
      return new Response(JSON.stringify({ success: true }), { 
        headers: { ...corsHeaders, "Content-Type": "application/json" } 
      });
    }
  }

  return new Response('Not Found', { status: 404 });
}

async function handleValidation(request, env, corsHeaders) {
  const url = new URL(request.url);

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
    if (!shop || !license) {
      return jsonResponse({ 
        "b": "body",
        "h": getBlockHtml(`Authentication failed. ${!shop ? 'Missing shop domain.' : ''} ${!license ? 'Missing license key.' : ''}`)
      }, 201);
    }

    // 5. KV License Check (Strict Whitelist + Alias Support)
    if (env.LICENSES) {
      let stored = await env.LICENSES.get(shop);
      
      // 1. Check if this is an Alias (Pointer)
      if (stored) {
        const data = JSON.parse(stored);
        if (data.type === 'alias' && data.target) {
          // Resolve to the target primary domain
          console.log(`Resolving alias: ${shop} -> ${data.target}`);
          shop = data.target; 
          stored = await env.LICENSES.get(shop);
        }
      }

      // 2. If not found at all, it's an unregistered/deleted shop
      if (!stored) {
        return jsonResponse({
          "b": "body",
          "h": getBlockHtml("Unregistered Instance - This shop domain is not found in our license database. Please contact support.", "Unregistered")
        }, 201);
      }

      // 3. If found, check the status
      const licenseData = JSON.parse(stored);
      if (licenseData.status !== 'active') {
        const reason = licenseData.status === 'revoked' 
          ? "License Revoked - This theme instance has been deactivated by the developer." 
          : "License Inactive - This license is no longer valid.";
          
        return jsonResponse({
          "b": "body",
          "h": getBlockHtml(reason, "Deactivated")
        }, 201);
      }
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

/**
 * Generates the premium blocking HTML message.
 */
function getBlockHtml(reason, badgeText = "Security Verification") {
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
        --primary: #ffffff;
        --accent: #ff3e3e;
        --bg: #000000;
        --card-bg: #111111;
        --text-main: #ffffff;
        --text-muted: #a1a1aa;
        --border: #27272a;
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
        padding: 20px;
      }

      .container {
        max-width: 480px;
        width: 100%;
        padding: 4rem 3rem;
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 48px;
        text-align: center;
        box-shadow: 0 40px 100px -20px rgba(0, 0, 0, 0.8), 0 0 80px -40px var(--accent);
        display: flex;
        flex-direction: column;
        align-items: center;
        animation: reveal 1.2s cubic-bezier(0.16, 1, 0.3, 1);
      }

      @keyframes reveal {
        from { opacity: 0; transform: translateY(40px) scale(0.9); }
        to { opacity: 1; transform: translateY(0) scale(1); }
      }

      .logo-container {
        background: #ffffff;
        padding: 1.5rem;
        border-radius: 24px;
        display: inline-block;
        margin-bottom: 3rem;
        width: fit-content;
        margin-left: auto;
        margin-right: auto;
      }

      .logo {
        width: 120px;
        display: block;
      }

      .badge {
        display: inline-flex;
        align-items: center;
        padding: 0.75rem 1.5rem;
        background: rgba(255, 62, 62, 0.1);
        color: var(--accent);
        font-size: 0.75rem;
        font-weight: 800;
        border-radius: 100px;
        text-transform: uppercase;
        letter-spacing: 0.15em;
        margin-bottom: 2rem;
        border: 1px solid rgba(255, 62, 62, 0.2);
        width: fit-content;
        margin-left: auto;
        margin-right: auto;
      }

      h1 {
        font-size: 2.5rem;
        font-weight: 850;
        margin-bottom: 1.5rem;
        letter-spacing: -0.04em;
        line-height: 1.1;
        width: 100%;
      }

      p {
        font-size: 1.1rem;
        line-height: 1.6;
        color: var(--text-muted);
        margin-bottom: 3rem;
        width: 100%;
      }

      .reason-box {
        background: #18181b;
        border: 1px solid var(--border);
        border-radius: 24px;
        padding: 1.75rem;
        margin-bottom: 3rem;
        text-align: left;
        width: 100%;
      }


      .reason-content {
        font-size: 1rem;
        color: #e4e4e7;
        font-weight: 500;
        line-height: 1.5;
        font-family: monospace;
        word-break: break-all;
      }

      .actions {
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
        width: 100%;
      }

      .btn {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 0.75rem;
        padding: 1.25rem;
        border-radius: 20px;
        text-decoration: none;
        font-weight: 750;
        font-size: 1rem;
        transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        cursor: pointer;
        width: 100%;
      }

      .btn-primary {
        background: #ffffff;
        color: #000000;
        box-shadow: 0 10px 30px -10px rgba(255, 255, 255, 0.3);
      }

      .btn-primary:hover {
        transform: translateY(-4px);
        box-shadow: 0 25px 50px -15px rgba(255, 255, 255, 0.4);
        background: #f8fafc;
      }

      .btn-discord {
        background: #5865F2;
        color: #ffffff;
      }

      .btn-discord:hover {
        transform: translateY(-4px);
        box-shadow: 0 25px 50px -15px rgba(88, 101, 242, 0.4);
        background: #4752c4;
      }

      .discord-tag {
        font-size: 0.8rem;
        color: var(--text-muted);
        margin-top: 1.25rem;
        width: 100%;
      }

      .discord-tag strong {
        color: #ffffff;
        font-weight: 800;
      }

      @media (max-width: 480px) {
        .container { padding: 3rem 1.5rem; }
        h1 { font-size: 2rem; }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="logo-container">
        <img src="https://cdn.shrinetheme.com/Full_Logo_Transparent.png" alt="Shrine" class="logo">
      </div>
      
      <div class="badge">${badgeText}</div>
      
      <h1>Unauthorized Instance</h1>
      <p>This theme requires a valid license key. Premium features are locked until activation is verified.</p>

      <div class="reason-box">
        <div class="reason-content">${reason}</div>
      </div>

      <div class="actions">
        <a href="https://discord.com" class="btn btn-discord">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.946-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
          Support on Discord
        </a>
        <div class="discord-tag">Username: <strong>ghost968986</strong></div>
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
