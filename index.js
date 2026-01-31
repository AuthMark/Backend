export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (url.pathname.startsWith("/login/")) {
      const provider = url.pathname.split("/")[2];
      const fwacc = url.searchParams.get("fwacc");

      return Response.redirect(
        authURL(provider, fwacc, env),
        302
      );
    }

    if (url.pathname.startsWith("/callback/")) {
      const provider = url.pathname.split("/")[2];
      const fwacc = url.searchParams.get("fwacc");

      const user = await getUser(provider, url, env);
      const accid = await makeAccId(
        env.ACCID_SECRET,
        provider,
        user.id
      );

      return Response.redirect(
        `${fwacc}?accid=${accid}`,
        302
      );
    }

    return new Response("OK");
  }
};

async function makeAccId(secret, provider, id) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(`${provider}:${id}`)
  );
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")
    .slice(0,16);
}
