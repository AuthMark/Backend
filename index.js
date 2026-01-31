// Cloudflare Worker - OAuth Handler
// Supports Google, GitHub, Microsoft, Discord

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Route handlers
    if (path.startsWith('/login/')) {
      return handleLogin(url, env);
    } else if (path.startsWith('/callback/')) {
      return handleCallback(url, request, env);
    } else {
      return new Response('OAuth Worker - use /login/{provider}?fwacc=YOUR_SITE', { status: 200 });
    }
  }
};

// Handle initial login request
async function handleLogin(url, env) {
  const provider = url.pathname.split('/')[2]; // google, github, microsoft, discord
  const fwacc = url.searchParams.get('fwacc'); // The original website URL
  
  if (!fwacc) {
    return new Response('Missing fwacc parameter', { status: 400 });
  }

  // OAuth configurations
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
    return new Response('Invalid provider', { status: 400 });
  }

  // Store fwacc in state parameter (will be returned to us by OAuth provider)
  const state = btoa(JSON.stringify({ fwacc, provider }));
  
  // Build OAuth URL
  const callbackUrl = `${url.origin}/callback/${provider}`;
  const authUrl = new URL(config.authUrl);
  authUrl.searchParams.set('client_id', config.clientId);
  authUrl.searchParams.set('redirect_uri', callbackUrl);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', config.scope);
  authUrl.searchParams.set('state', state);

  return Response.redirect(authUrl.toString(), 302);
}

// Handle OAuth callback
async function handleCallback(url, request, env) {
  const provider = url.pathname.split('/')[2];
  const code = url.searchParams.get('code');
  const stateParam = url.searchParams.get('state');
  
  if (!code || !stateParam) {
    return new Response('Missing code or state', { status: 400 });
  }

  // Decode state to get fwacc and provider
  let state;
  try {
    state = JSON.parse(atob(stateParam));
  } catch (e) {
    return new Response('Invalid state parameter', { status: 400 });
  }

  const { fwacc } = state;

  // Exchange code for access token
  const tokenData = await exchangeCodeForToken(provider, code, url.origin, env);
  if (!tokenData) {
    return new Response('Failed to exchange code for token', { status: 500 });
  }

  // Get user info
  const userInfo = await getUserInfo(provider, tokenData.access_token);
  if (!userInfo) {
    return new Response('Failed to get user info', { status: 500 });
  }

  // Generate ACCID using HMAC-SHA256
  const accid = await generateAccid(userInfo.id, provider, env.ACCID_SECRET);

  // Get cookie check site URL (fallback to env variable if not in state)
  const cookieCheckSite = env.COOKIECHECK_SITE || 'https://your-cookie-checker.example.com';

  // Redirect to COOKIECHECK with both fwacc and accid
  const redirectUrl = `${cookieCheckSite}?fwacc=${encodeURIComponent(fwacc)}&accid=${accid}`;
  
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

    return await response.json();
  } catch (e) {
    console.error('Token exchange error:', e);
    return null;
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

  try {
    const response = await fetch(userInfoUrl, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
      }
    });

    const data = await response.json();
    
    // Normalize user ID field across providers
    return {
      id: data.id || data.sub, // GitHub/Discord use 'id', Google uses 'sub'
      email: data.email,
      name: data.name || data.login || data.username
    };
  } catch (e) {
    console.error('Get user info error:', e);
    return null;
  }
}

// Generate secure ACCID using HMAC-SHA256
async function generateAccid(userId, provider, secret) {
  const encoder = new TextEncoder();
  
  // Import the secret key
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // Create signature from provider:userId
  const data = encoder.encode(`${provider}:${userId}`);
  const signature = await crypto.subtle.sign('HMAC', key, data);

  // Convert to hex string
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
