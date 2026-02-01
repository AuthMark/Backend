//          Copyright © AuthMark 2026-Present under GNU GPLv3 LICENSE
// ==================== Cloudflare Worker – OAuth Handler ====================
//   GitHub ✅  |  Microsoft (needs Azure API permissions)  |  Google  |  Discord

export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    // ── debug endpoint ──────────────────────────────────────────────────────
    if (path === '/debug') {
      return new Response(JSON.stringify({
        workerUrl: url.origin,
        callbackUrls: {
          google    : `${url.origin}/callback/google`,
          github    : `${url.origin}/callback/github`,
          microsoft : `${url.origin}/callback/microsoft`,
          discord   : `${url.origin}/callback/discord`
        },
        environmentVariables: {
          GOOGLE_CLIENT_ID        : env.GOOGLE_CLIENT_ID        ? '✅ Set' : '❌ Missing',
          GOOGLE_CLIENT_SECRET    : env.GOOGLE_CLIENT_SECRET    ? '✅ Set' : '❌ Missing',
          GITHUB_CLIENT_ID        : env.GITHUB_CLIENT_ID        ? `✅ Set (${env.GITHUB_CLIENT_ID})` : '❌ Missing',
          GITHUB_CLIENT_SECRET    : env.GITHUB_CLIENT_SECRET    ? '✅ Set' : '❌ Missing',
          MICROSOFT_CLIENT_ID     : env.MICROSOFT_CLIENT_ID     ? `✅ Set (${env.MICROSOFT_CLIENT_ID})` : '❌ Missing',
          MICROSOFT_CLIENT_SECRET : env.MICROSOFT_CLIENT_SECRET ? '✅ Set' : '❌ Missing',
          DISCORD_CLIENT_ID       : env.DISCORD_CLIENT_ID       ? '✅ Set' : '❌ Missing',
          DISCORD_CLIENT_SECRET   : env.DISCORD_CLIENT_SECRET   ? '✅ Set' : '❌ Missing',
          ACCID_SECRET            : env.ACCID_SECRET            ? '✅ Set' : '❌ Missing'
        }
      }, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // ── route ───────────────────────────────────────────────────────────────
    if (path.startsWith('/login/'))    return handleLogin(url, env);
    if (path.startsWith('/callback/')) return handleCallback(url, request, env);

    return new Response(
`OAuth Worker – Active ✅
Usage : /login/{provider}?fwacc=YOUR_SITE
Debug : ${url.origin}/debug`, { status: 200 });
  }
};

// ─── LOGIN ──────────────────────────────────────────────────────────────────
async function handleLogin(url, env) {
  const provider = url.pathname.split('/')[2];
  const fwacc    = url.searchParams.get('fwacc');

  if (!fwacc) {
    return new Response('Missing fwacc parameter.', { status: 400 });
  }

  const configs = {
    google: {
      authUrl  : 'https://accounts.google.com/o/oauth2/v2/auth',
      clientId : env.GOOGLE_CLIENT_ID,
      scope    : 'openid email profile'
    },
    github: {
      authUrl  : 'https://github.com/login/oauth/authorize',
      clientId : env.GITHUB_CLIENT_ID,
      scope    : 'read:user user:email'
    },
    microsoft: {
      authUrl  : 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      clientId : env.MICROSOFT_CLIENT_ID,
      scope    : 'https://graph.microsoft.com/User.Read openid email profile offline_access'
    },
    discord: {
      authUrl  : 'https://discord.com/api/oauth2/authorize',
      clientId : env.DISCORD_CLIENT_ID,
      scope    : 'identify email'
    }
  };

  const config = configs[provider];
  if (!config)         return new Response(`Invalid provider: ${provider}`, { status: 400 });
  if (!config.clientId) return new Response(`Missing ${provider.toUpperCase()}_CLIENT_ID`, { status: 500 });

  // state carries everything CookieCheck needs on the way back
  const state = btoa(JSON.stringify({ fwacc, provider }));

  const callbackUrl = `${url.origin}/callback/${provider}`;
  const authUrl     = new URL(config.authUrl);
  authUrl.searchParams.set('client_id',     config.clientId);
  authUrl.searchParams.set('redirect_uri',  callbackUrl);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope',         config.scope);
  authUrl.searchParams.set('state',         state);

  console.log(`[LOGIN] ${provider} → callback: ${callbackUrl}`);
  return Response.redirect(authUrl.toString(), 302);
}

// ─── CALLBACK ───────────────────────────────────────────────────────────────
async function handleCallback(url, request, env) {
  const provider      = url.pathname.split('/')[2];
  const code          = url.searchParams.get('code');
  const error         = url.searchParams.get('error');
  const errorDesc     = url.searchParams.get('error_description');
  const stateParam    = url.searchParams.get('state');

  // ── provider returned an error ──
  if (error) {
    return new Response(
      `OAuth error from ${provider}: ${error}\n${errorDesc || ''}`, { status: 400 });
  }

  if (!code || !stateParam) {
    return new Response(`Missing ${!code ? 'code' : 'state'} from ${provider}`, { status: 400 });
  }

  // ── decode state ──
  let state;
  try { state = JSON.parse(atob(stateParam)); }
  catch (e) { return new Response('Invalid state parameter', { status: 400 }); }

  const { fwacc, provider: stateProvider } = state;
  console.log(`[CALLBACK] ${provider}, fwacc: ${fwacc}`);

  // ── exchange code → token ──
  const tokenData = await exchangeCodeForToken(provider, code, url.origin, env);

  if (!tokenData || !tokenData.access_token) {
    return new Response(
`=== TOKEN EXCHANGE FAILED ===
Provider : ${provider}
Response : ${JSON.stringify(tokenData, null, 2)}
Callback : ${url.origin}/callback/${provider}

Most likely cause: CLIENT_SECRET is wrong.
Regenerate it in your ${provider} OAuth app and update the Cloudflare variable.
`, { status: 500, headers: { 'Content-Type': 'text/plain' } });
  }

  console.log(`[CALLBACK] token received`);

  // ── fetch user info ──
  const userInfo = await getUserInfo(provider, tokenData.access_token);

  if (!userInfo || !userInfo.id) {
    return new Response(
`=== GET USER INFO FAILED ===
Provider : ${provider}
Response : ${JSON.stringify(userInfo, null, 2)}
Token    : received ✅

${provider === 'microsoft'
  ? 'Azure fix: API permissions → add User.Read (delegated) → Grant admin consent.'
  : provider === 'google'
    ? 'Google fix: publish the OAuth consent screen or add your email as a test user.'
    : 'Check scopes and app settings.'}
`, { status: 500, headers: { 'Content-Type': 'text/plain' } });
  }

  console.log(`[CALLBACK] user: ${userInfo.email || userInfo.id}`);

  // ── generate ACCID ──
  const accid = await generateAccid(userInfo.id, provider, env.ACCID_SECRET);

  // ── redirect back to CookieCheck with fwacc + provider + accid ──
  const cookieCheckSite = env.COOKIECHECK_SITE || 'https://authmark.github.io/CheckCookie/';
  const redirectUrl = new URL(cookieCheckSite);
  redirectUrl.searchParams.set('fwacc',    fwacc);       // where to go after
  redirectUrl.searchParams.set('provider', provider);    // ← was missing (bug 4)
  redirectUrl.searchParams.set('accid',    accid);       // the generated ID

  console.log(`[CALLBACK] ✅ redirecting to ${redirectUrl.toString()}`);
  return Response.redirect(redirectUrl.toString(), 302);
}

// ─── TOKEN EXCHANGE ─────────────────────────────────────────────────────────
async function exchangeCodeForToken(provider, code, origin, env) {
  const configs = {
    google    : { tokenUrl: 'https://oauth2.googleapis.com/token',                              clientId: env.GOOGLE_CLIENT_ID,    clientSecret: env.GOOGLE_CLIENT_SECRET },
    github    : { tokenUrl: 'https://github.com/login/oauth/access_token',                      clientId: env.GITHUB_CLIENT_ID,    clientSecret: env.GITHUB_CLIENT_SECRET },
    microsoft : { tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',       clientId: env.MICROSOFT_CLIENT_ID, clientSecret: env.MICROSOFT_CLIENT_SECRET },
    discord   : { tokenUrl: 'https://discord.com/api/oauth2/token',                             clientId: env.DISCORD_CLIENT_ID,   clientSecret: env.DISCORD_CLIENT_SECRET }
  };

  const config      = configs[provider];
  const callbackUrl = `${origin}/callback/${provider}`;

  try {
    const response = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept'      : 'application/json'
      },
      body: new URLSearchParams({
        client_id     : config.clientId,
        client_secret : config.clientSecret,
        code          : code,
        redirect_uri  : callbackUrl,
        grant_type    : 'authorization_code'
      }).toString()
    });

    const data = await response.json();
    if (!response.ok) console.error(`[TOKEN] ${provider} error:`, data);
    return data;
  } catch (e) {
    console.error(`[TOKEN] ${provider} exception:`, e);
    return { error: e.message };
  }
}

// ─── USER INFO ──────────────────────────────────────────────────────────────
async function getUserInfo(provider, accessToken) {
  const endpoints = {
    google    : 'https://www.googleapis.com/oauth2/v2/userinfo',
    github    : 'https://api.github.com/user',
    microsoft : 'https://graph.microsoft.com/oidc/userinfo',   // OIDC endpoint – fewer permissions needed
    discord   : 'https://discord.com/api/users/@me'
  };

  try {
    const response = await fetch(endpoints[provider], {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept'       : 'application/json'
      }
    });

    const data = await response.json();
    if (!response.ok) { console.error(`[USERINFO] ${provider} error:`, data); return data; }

    return {
      id    : data.id || data.sub,                          // Google/MS use 'sub', GitHub/Discord use 'id'
      email : data.email,
      name  : data.name || data.login || data.username
    };
  } catch (e) {
    console.error(`[USERINFO] ${provider} exception:`, e);
    return { error: e.message };
  }
}

// ─── ACCID ──────────────────────────────────────────────────────────────────
async function generateAccid(userId, provider, secret) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );

  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${provider}:${userId}`));

  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
