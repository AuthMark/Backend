// Cloudflare Worker - OAuth Handler (PRODUCTION-READY DEBUG VERSION)
// GitHub working ✅ | Now fixing Microsoft

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Debug endpoint
    if (path === '/debug') {
      return new Response(JSON.stringify({
        message: "Copy these EXACT URLs to your OAuth app settings",
        workerUrl: url.origin,
        callbackUrls: {
          google: `${url.origin}/callback/google`,
          github: `${url.origin}/callback/github`,
          microsoft: `${url.origin}/callback/microsoft`,
          discord: `${url.origin}/callback/discord`
        },
        environmentVariables: {
          GOOGLE_CLIENT_ID: env.GOOGLE_CLIENT_ID ? "✅ Set" : "❌ Missing",
          GOOGLE_CLIENT_SECRET: env.GOOGLE_CLIENT_SECRET ? "✅ Set" : "❌ Missing",
          GITHUB_CLIENT_ID: env.GITHUB_CLIENT_ID ? `✅ Set (${env.GITHUB_CLIENT_ID})` : "❌ Missing",
          GITHUB_CLIENT_SECRET: env.GITHUB_CLIENT_SECRET ? `✅ Set` : "❌ Missing",
          MICROSOFT_CLIENT_ID: env.MICROSOFT_CLIENT_ID ? `✅ Set (${env.MICROSOFT_CLIENT_ID})` : "❌ Missing",
          MICROSOFT_CLIENT_SECRET: env.MICROSOFT_CLIENT_SECRET ? "✅ Set" : "❌ Missing",
          DISCORD_CLIENT_ID: env.DISCORD_CLIENT_ID ? "✅ Set" : "❌ Missing",
          DISCORD_CLIENT_SECRET: env.DISCORD_CLIENT_SECRET ? "✅ Set" : "❌ Missing",
          ACCID_SECRET: env.ACCID_SECRET ? "✅ Set" : "❌ Missing"
        }
      }, null, 2), {
        headers: { 
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    // Route handlers
    if (path.startsWith('/login/')) {
      return handleLogin(url, env);
    } else if (path.startsWith('/callback/')) {
      return handleCallback(url, request, env);
    } else {
      return new Response(`
OAuth Worker - Active ✅

Usage: /login/{provider}?fwacc=YOUR_SITE

Available providers:
  ✅ google
  ✅ github  
  ✅ microsoft
  ✅ discord

Debug info: ${url.origin}/debug
      `, { status: 200 });
    }
  }
};

// Handle initial login request
async function handleLogin(url, env) {
  const provider = url.pathname.split('/')[2];
  const fwacc = url.searchParams.get('fwacc');
  
  console.log(`[LOGIN] Provider: ${provider}, Return URL: ${fwacc}`);
  
  if (!fwacc) {
    return new Response('Missing fwacc parameter. Usage: /login/{provider}?fwacc=YOUR_SITE', { 
      status: 400,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  const configs = {
    google: {
      authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      clientId: env.GOOGLE_CLIENT_ID,
      scope: 'openid email profile'
    },
    github: {
      authUrl: 'https://github.com/login/oauth/authorize',
      clientId: env.GITHUB_CLIENT_ID,
      scope: 'read:user user:email'
    },
    microsoft: {
      authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      clientId: env.MICROSOFT_CLIENT_ID,
      // Updated scope to explicitly request Graph API access
      scope: 'https://graph.microsoft.com/User.Read openid email profile offline_access'
    },
    discord: {
      authUrl: 'https://discord.com/api/oauth2/authorize',
      clientId: env.DISCORD_CLIENT_ID,
      scope: 'identify email'
    }
  };

  const config = configs[provider];
  if (!config) {
    return new Response(`Invalid provider: ${provider}. Valid options: google, github, microsoft, discord`, { 
      status: 400
    });
  }

  if (!config.clientId) {
    return new Response(`Missing CLIENT_ID for ${provider}. Please set ${provider.toUpperCase()}_CLIENT_ID in Worker environment variables.`, {
      status: 500
    });
  }

  const state = btoa(JSON.stringify({ fwacc, provider }));
  const callbackUrl = `${url.origin}/callback/${provider}`;
  const authUrl = new URL(config.authUrl);
  authUrl.searchParams.set('client_id', config.clientId);
  authUrl.searchParams.set('redirect_uri', callbackUrl);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', config.scope);
  authUrl.searchParams.set('state', state);

  console.log(`[LOGIN] Redirecting to OAuth provider. Callback URL: ${callbackUrl}`);

  return Response.redirect(authUrl.toString(), 302);
}

// Handle OAuth callback
async function handleCallback(url, request, env) {
  const provider = url.pathname.split('/')[2];
  const code = url.searchParams.get('code');
  const error = url.searchParams.get('error');
  const errorDescription = url.searchParams.get('error_description');
  const stateParam = url.searchParams.get('state');
  
  console.log(`[CALLBACK] Provider: ${provider}, Code: ${code ? 'received' : 'missing'}, Error: ${error || 'none'}`);

  // Check for OAuth errors
  if (error) {
    const errorMsg = `
===========================================
OAuth Error from ${provider}
===========================================

Error: ${error}
Description: ${errorDescription || 'No description provided'}

Common fixes:
- Make sure redirect URI matches exactly in ${provider} settings
- Verify CLIENT_ID is correct
- Check that required permissions/scopes are enabled

===========================================
    `.trim();
    console.error(`[CALLBACK] ${errorMsg}`);
    return new Response(errorMsg, { 
      status: 400,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
  
  if (!code || !stateParam) {
    const msg = `Missing ${!code ? 'code' : 'state'} parameter from ${provider}`;
    console.error(`[CALLBACK] ${msg}`);
    return new Response(msg, { status: 400 });
  }

  // Decode state
  let state;
  try {
    state = JSON.parse(atob(stateParam));
  } catch (e) {
    console.error(`[CALLBACK] Invalid state parameter:`, e);
    return new Response('Invalid state parameter', { status: 400 });
  }

  const { fwacc } = state;
  console.log(`[CALLBACK] Decoded state, return URL: ${fwacc}`);

  // Exchange code for access token
  console.log(`[CALLBACK] Exchanging code for token...`);
  const tokenData = await exchangeCodeForToken(provider, code, url.origin, env);
  
  if (!tokenData || !tokenData.access_token) {
    const detailedError = `
===========================================
DETAILED ERROR - Token Exchange Failed
===========================================

Provider: ${provider}
Step: Exchanging authorization code for access token

Token Response: ${JSON.stringify(tokenData, null, 2)}

Your Configuration:
- CLIENT_ID: ${provider === 'github' ? env.GITHUB_CLIENT_ID : provider === 'microsoft' ? env.MICROSOFT_CLIENT_ID : '(check /debug)'}
- CLIENT_SECRET: ${tokenData && tokenData.error === 'invalid_client' ? '❌ INCORRECT - Regenerate this!' : '(hidden)'}
- Callback URL: ${url.origin}/callback/${provider}

Common Causes:
1. CLIENT_SECRET is incorrect → Generate new one in ${provider} settings
2. CLIENT_ID doesn't match CLIENT_SECRET → Verify they're from same app
3. Callback URL mismatch → Check ${provider} OAuth settings

Next Steps:
${provider === 'microsoft' ? '1. Go to https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps' : 
  provider === 'github' ? '1. Go to https://github.com/settings/developers' : 
  provider === 'google' ? '1. Go to https://console.cloud.google.com/apis/credentials' :
  '1. Go to https://discord.com/developers/applications'}
2. Regenerate Client Secret
3. Update CLOUDFLARE Worker environment variable
4. Try again

===========================================
    `.trim();
    
    console.error(`[CALLBACK] ${detailedError}`);
    return new Response(detailedError, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  console.log(`[CALLBACK] Token received successfully`);

  // Get user info
  const userInfo = await getUserInfo(provider, tokenData.access_token);
  
  if (!userInfo || !userInfo.id) {
    const detailedError = `
===========================================
DETAILED ERROR - Get User Info Failed
===========================================

Provider: ${provider}
Step: Fetching user information using access token

User Info Response: ${JSON.stringify(userInfo, null, 2)}

Access Token: ${tokenData.access_token ? '✅ Received' : '❌ Missing'}

${provider === 'microsoft' ? `
MICROSOFT-SPECIFIC ISSUE:
This error usually means API permissions are not configured in Azure Portal.

REQUIRED FIX:
1. Go to: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps
2. Click on your app
3. Click "API permissions" in left sidebar
4. Click "+ Add a permission"
5. Select "Microsoft Graph" → "Delegated permissions"
6. Add these permissions:
   ✅ User.Read
   ✅ email
   ✅ openid
   ✅ profile
7. Click "Add permissions"
8. Click "Grant admin consent for [Your Org]" (IMPORTANT!)
9. Wait 2-5 minutes for changes to propagate
10. Try logging in again

Alternative Fix (if above doesn't work):
The app might need "ID tokens" enabled:
1. In Azure Portal → Your App → Authentication
2. Under "Implicit grant and hybrid flows"
3. Check ✅ "ID tokens"
4. Click Save
` : provider === 'google' ? `
GOOGLE-SPECIFIC ISSUE:
Common causes:
1. OAuth consent screen not configured
2. App is in testing mode and your account isn't added
3. Required scopes not enabled

Fix:
1. Go to: https://console.cloud.google.com/apis/credentials/consent
2. Make sure app is published or your account is in test users
3. Check that scopes include: email, profile, openid
` : provider === 'github' ? `
GITHUB-SPECIFIC ISSUE:
This is rare - token was received but user info failed.

Fix:
1. Check that scopes include: read:user user:email
2. Try regenerating Client Secret
3. Your GitHub account might have privacy settings blocking API access
` : `
DISCORD-SPECIFIC ISSUE:
Common causes:
1. Scopes don't include 'identify email'
2. Bot token used instead of OAuth token

Fix:
1. Verify scopes in Discord app settings
2. Make sure it's an OAuth app, not a bot
`}

Your OAuth Scopes:
- ${provider}: ${provider === 'github' ? 'read:user user:email' : 
                  provider === 'google' ? 'openid email profile' : 
                  provider === 'microsoft' ? 'https://graph.microsoft.com/User.Read openid email profile' : 
                  'identify email'}

===========================================
    `.trim();
    
    console.error(`[CALLBACK] ${detailedError}`);
    return new Response(detailedError, { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  console.log(`[CALLBACK] User info received: ${userInfo.email || userInfo.name || userInfo.id}`);

  // Generate ACCID
  const accid = await generateAccid(userInfo.id, provider, env.ACCID_SECRET);
  console.log(`[CALLBACK] Generated ACCID: ${accid.substring(0, 16)}...`);

  // Redirect to cookie checker
  const cookieCheckSite = env.COOKIECHECK_SITE || 'https://authmark.github.io/CheckCookie/';
  const redirectUrl = `${cookieCheckSite}?fwacc=${encodeURIComponent(fwacc)}&accid=${accid}`;
  
  console.log(`[CALLBACK] ✅ Success! Redirecting to: ${cookieCheckSite}`);
  return Response.redirect(redirectUrl, 302);
}

// Exchange authorization code for access token
async function exchangeCodeForToken(provider, code, origin, env) {
  const configs = {
    google: {
      tokenUrl: 'https://oauth2.googleapis.com/token',
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET
    },
    github: {
      tokenUrl: 'https://github.com/login/oauth/access_token',
      clientId: env.GITHUB_CLIENT_ID,
      clientSecret: env.GITHUB_CLIENT_SECRET
    },
    microsoft: {
      tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      clientId: env.MICROSOFT_CLIENT_ID,
      clientSecret: env.MICROSOFT_CLIENT_SECRET
    },
    discord: {
      tokenUrl: 'https://discord.com/api/oauth2/token',
      clientId: env.DISCORD_CLIENT_ID,
      clientSecret: env.DISCORD_CLIENT_SECRET
    }
  };

  const config = configs[provider];
  const callbackUrl = `${origin}/callback/${provider}`;

  console.log(`[TOKEN] Requesting token from ${provider}`);

  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code: code,
    redirect_uri: callbackUrl,
    grant_type: 'authorization_code'
  });

  try {
    const response = await fetch(config.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: body.toString()
    });

    const data = await response.json();
    
    console.log(`[TOKEN] Response status: ${response.status}`);
    
    if (!response.ok) {
      console.error(`[TOKEN] Error from ${provider}:`, data);
    }
    
    return data;
  } catch (e) {
    console.error(`[TOKEN] Exception for ${provider}:`, e);
    return { error: e.message };
  }
}

// Get user info from provider
async function getUserInfo(provider, accessToken) {
  const configs = {
    google: 'https://www.googleapis.com/oauth2/v2/userinfo',
    github: 'https://api.github.com/user',
    // Using the more reliable OpenID Connect userinfo endpoint for Microsoft
    microsoft: 'https://graph.microsoft.com/oidc/userinfo',
    discord: 'https://discord.com/api/users/@me'
  };

  const userInfoUrl = configs[provider];

  console.log(`[USERINFO] Fetching from ${provider}: ${userInfoUrl}`);

  try {
    const response = await fetch(userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });

    const data = await response.json();
    
    console.log(`[USERINFO] Response status: ${response.status}`);
    
    if (!response.ok) {
      console.error(`[USERINFO] Error from ${provider}:`, data);
      return data;
    }
    
    // Normalize user ID field across providers
    return {
      id: data.id || data.sub, // GitHub/Discord use 'id', Google/Microsoft use 'sub'
      email: data.email,
      name: data.name || data.login || data.username
    };
  } catch (e) {
    console.error(`[USERINFO] Exception for ${provider}:`, e);
    return { error: e.message };
  }
}

// Generate secure ACCID using HMAC-SHA256
async function generateAccid(userId, provider, secret) {
  const encoder = new TextEncoder();
  
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const data = encoder.encode(`${provider}:${userId}`);
  const signature = await crypto.subtle.sign('HMAC', key, data);

  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
