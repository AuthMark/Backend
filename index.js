// Cloudflare Worker - OAuth Handler (ULTRA DEBUG VERSION)
// This version shows DETAILED error messages to help diagnose issues
// Debug Branch

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Debug endpoint - shows all callback URLs
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
          GITHUB_CLIENT_SECRET: env.GITHUB_CLIENT_SECRET ? `✅ Set (starts with: ${env.GITHUB_CLIENT_SECRET.substring(0, 4)}...)` : "❌ Missing",
          MICROSOFT_CLIENT_ID: env.MICROSOFT_CLIENT_ID ? "✅ Set" : "❌ Missing",
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
        OAuth Worker - Active
        
        Usage: /login/{provider}?fwacc=YOUR_SITE
        
        Available providers: google, github, microsoft, discord
        
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
      scope: 'openid email profile'
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
    const errorMsg = `OAuth Error from ${provider}: ${error}${errorDescription ? ' - ' + errorDescription : ''}`;
    console.error(`[CALLBACK] ${errorMsg}`);
    return new Response(errorMsg, { status: 400 });
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
  
  // DETAILED ERROR RESPONSE
  if (!tokenData || !tokenData.access_token) {
    const detailedError = `
===========================================
DETAILED ERROR INFORMATION
===========================================

Provider: ${provider}
Step: Token Exchange Failed

Token Response: ${JSON.stringify(tokenData, null, 2)}

Common Causes:
1. CLIENT_SECRET is incorrect
2. CLIENT_ID doesn't match CLIENT_SECRET
3. Callback URL doesn't match exactly

Your Configuration:
- CLIENT_ID: ${provider === 'github' ? env.GITHUB_CLIENT_ID : 'Check /debug endpoint'}
- CLIENT_SECRET: ${provider === 'github' ? (env.GITHUB_CLIENT_SECRET ? 'Set (starts with: ' + env.GITHUB_CLIENT_SECRET.substring(0, 4) + '...)' : 'NOT SET') : 'Check /debug endpoint'}
- Callback URL: ${url.origin}/callback/${provider}

Next Steps:
1. Go to ${provider === 'github' ? 'https://github.com/settings/developers' : 'provider settings'}
2. Verify Client ID matches: ${provider === 'github' ? env.GITHUB_CLIENT_ID : '(check debug endpoint)'}
3. Generate NEW Client Secret and update in Cloudflare Worker
4. Make sure callback URL is EXACTLY: ${url.origin}/callback/${provider}

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
  
  // DETAILED ERROR RESPONSE FOR USER INFO
  if (!userInfo || !userInfo.id) {
    const detailedError = `
===========================================
DETAILED ERROR INFORMATION
===========================================

Provider: ${provider}
Step: Get User Info Failed

User Info Response: ${JSON.stringify(userInfo, null, 2)}

Access Token: ${tokenData.access_token ? 'Received' : 'Missing'}

Common Causes:
1. Access token is invalid or expired
2. OAuth scopes are incorrect
3. Provider API is down

Your OAuth Scopes:
- ${provider}: ${provider === 'github' ? 'read:user user:email' : provider === 'google' ? 'openid email profile' : provider === 'microsoft' ? 'openid email profile' : 'identify email'}

Next Steps:
1. Check that scopes are enabled in your OAuth app
2. Try regenerating the Client Secret
3. Test the access token manually

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
  
  console.log(`[CALLBACK] Success! Redirecting to: ${cookieCheckSite}`);
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
  console.log(`[TOKEN] Client ID: ${config.clientId}`);
  console.log(`[TOKEN] Callback URL: ${callbackUrl}`);

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
    console.log(`[TOKEN] Response data:`, JSON.stringify(data));
    
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
    microsoft: 'https://graph.microsoft.com/v1.0/me',
    discord: 'https://discord.com/api/users/@me'
  };

  const userInfoUrl = configs[provider];

  console.log(`[USERINFO] Fetching user info from ${provider}`);

  try {
    const response = await fetch(userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json',
        'User-Agent': 'Cloudflare-Worker-OAuth'
      }
    });

    const data = await response.json();
    
    console.log(`[USERINFO] Response status: ${response.status}`);
    console.log(`[USERINFO] Response data:`, JSON.stringify(data));
    
    if (!response.ok) {
      console.error(`[USERINFO] Error from ${provider}:`, data);
      return data; // Return the error so we can see it
    }
    
    // Normalize user ID field across providers
    return {
      id: data.id || data.sub,
      email: data.email,
      name: data.name || data.login || data.username,
      raw: data // Include raw response for debugging
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
