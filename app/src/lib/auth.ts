// The web page: the browser holds the Cloudflare Access login (a cookie on jarvis4.deyaochen.com), so
// requests are same-origin and carry nothing extra. The app's version is auth.native.ts.
//
// When the Access cookie expires, every request is answered with a 302 to the cloudflareaccess.com login
// page. fetch() cannot follow that cross-origin redirect, so the redirect is requested unfollowed
// (opaqueredirect) and recognised as "signed out": the page reloads itself, which walks through the
// Access login as a navigation.
export const base = () => "/";
export const fetchInit: RequestInit = { redirect: "manual", credentials: "same-origin" };
export async function authHeaders(): Promise<Record<string, string>> { return {}; }

let reloading = false;
function reloadForLogin(): boolean {
  if (reloading) return true;
  let last = 0;
  try { last = Number(sessionStorage.getItem("access-reload") || 0); } catch {}
  if (Date.now() - last < 60_000) return false; // just reloaded and bounced again: don't loop
  reloading = true;
  try { sessionStorage.setItem("access-reload", String(Date.now())); } catch {}
  setTimeout(() => location.reload(), 50);
  return true;
}
/** Is this response Access turning the request away? Throws the signed-out error if so. */
export async function checkRefused(r: Response): Promise<"ok" | "retry"> {
  if (r.type === "opaqueredirect" || r.status === 0) {
    throw new Error(reloadForLogin()
      ? "signed out of Cloudflare Access — reloading to sign in again"
      : "signed out of Cloudflare Access — reload the page to sign in again");
  }
  return "ok";
}

// the browser is signed in whenever the page loaded at all (Access gates the page itself)
export type AuthState = { phase: "loading" | "signedOut" | "signingIn" | "ready"; note: string | null };
const READY: AuthState = { phase: "ready", note: null };
export const useAuthState = () => READY;
export async function loadAuth() {}
export async function signIn(): Promise<boolean> { return true; }
