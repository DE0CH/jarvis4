// The page notices a new build of itself. The router names the build of the page it serves (GET api/build: its
// index.html's hash). An open tab asks now and then: the first answer is the build it was loaded from; a later,
// different one means the page on screen is old, and it loads itself again while nobody looks at it (in the
// background), never under the reader.

export type BuildLook = { loaded: string | null; stale: boolean; reload: boolean };

/** One look at the router's build: `loaded` the build this page came from (null before the first look), `seen` the
 *  router's answer ("" when it gave none), `hidden` whether the page is in the background. */
export function buildSeen(loaded: string | null, seen: string, hidden: boolean): BuildLook {
  if (!seen) return { loaded, stale: false, reload: false };
  if (loaded === null) return { loaded: seen, stale: false, reload: false };
  const stale = seen !== loaded;
  return { loaded, stale, reload: stale && hidden };
}
