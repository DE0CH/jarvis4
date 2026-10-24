// A form or reader is a PAGE: pushed on the stack over the list (the list stays mounted, so its
// scroll position is kept), closed with its Back button, the iPhone's swipe-back, the browser's Back,
// or Esc. `right` is the page's primary action (Start, Save…); Back is its Cancel.
//
// What a page shows can carry callbacks (a transcript's "Restore"), which a URL can't, so the
// payload is kept here under a key and the route only carries the key. A page whose payload is gone
// (the browser reloaded on it) goes back to the list.
import { useEffect, useRef, type ReactNode } from "react";
import { Platform, ScrollView, View } from "react-native";
import { router, useNavigation } from "expo-router";
import { KeyboardAwareScrollView } from "react-native-keyboard-controller";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useTheme } from "../theme";
import { Button, Flex, Heading } from "./kit";
import { isWeb, mouse } from "./overlays";

const payloads = new Map<string, unknown>();
let seq = 0;
export type PageKind = "new" | "terminal" | "transcript" | "grants" | "schedules" | "remote" | "task" | "task-edit" | "task-run" | "task-schedule" | "icloud-file" | "content" | "call" | "log" | "account";
export function openPage(kind: PageKind, payload: unknown = null) {
  const k = String(++seq) + "-" + Date.now().toString(36);
  payloads.set(k, payload);
  router.push({ pathname: ("/" + kind) as any, params: { k } });
}
export function payloadOf<T>(k: string | string[] | undefined): T | undefined {
  return payloads.get(String(k || "")) as T | undefined;
}
export function closePage() {
  if (router.canGoBack()) router.back(); else router.replace("/");
}
// a page's primary action (Start) leaves differently from Back: in the app the page slides off to
// the left, a "go ahead" motion, where Back slides it off to the right. The pop takes the animation
// the screen has when it starts, so the option is set first and the pop follows once it is applied.
// `instant`: the page closes while the shell's secure page still covers the app (the shell then slides its page
// away over the list), so it closes without a motion of its own
export function useDone() {
  const nav = useNavigation();
  return (instant = false) => {
    if (Platform.OS === "web" || !router.canGoBack()) { closePage(); return; }
    nav.setOptions({ animation: instant ? "none" : "slide_from_left" } as any);
    setTimeout(closePage, 50);
  };
}

// the top bar shared by the list and the pages: under the status bar, a hairline below
export function TopBar({ children, max = 820 }: { children: ReactNode; max?: number }) {
  const t = useTheme(), ins = useSafeAreaInsets();
  return (
    <View style={{ paddingTop: ins.top, backgroundColor: t.background, borderBottomWidth: 1, borderBottomColor: t.gray.a[5], zIndex: 5 }}>
      <Flex align="center" gap={3} style={{ width: "100%", maxWidth: max, alignSelf: "center", paddingHorizontal: 20, paddingVertical: 16 }}>{children}</Flex>
    </View>
  );
}

type PageProps = { title?: string; right?: ReactNode; onSubmit?: () => void; children: ReactNode; scrollRef?: any; onContentSizeChange?: () => void; onScroll?: (e: any) => void; id?: string };
export function Page({ title, right, onSubmit, children, scrollRef, onContentSizeChange, onScroll, id }: PageProps) {
  const t = useTheme(), ins = useSafeAreaInsets();
  const body = useRef<View>(null);
  // web: Esc closes (unless a dialog or menu is up); Enter in a one-line field / ⌘Enter in a text box submits
  const submit = useRef(onSubmit); submit.current = onSubmit;
  useEffect(() => {
    if (!isWeb) return;
    const key = (e: KeyboardEvent) => {
      const overlay = document.getElementById("dialog") || document.getElementById("menu");
      if (e.key === "Escape" && !e.defaultPrevented && !overlay) { closePage(); return; }
      if (e.key !== "Enter" || !submit.current || (e as any).isComposing || overlay) return;
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || (tag === "TEXTAREA" && (e.metaKey || e.ctrlKey))) { e.preventDefault(); submit.current(); }
    };
    // capture: react-native-web's TextInput stops its key events from bubbling
    window.addEventListener("keydown", key, true);
    return () => window.removeEventListener("keydown", key, true);
  }, []);
  // with a keyboard, start typing right away — but only into a field that is already on screen
  useEffect(() => {
    if (!isWeb || !mouse()) return;
    const f = (document.getElementById("page-body")?.querySelector("input:not([readonly]):not([disabled]),textarea:not([readonly]):not([disabled])") as HTMLElement | null);
    if (f && f.getBoundingClientRect().bottom < innerHeight) f.focus({ preventScroll: true });
  }, []);
  const Scroll: any = Platform.OS === "web" ? ScrollView : KeyboardAwareScrollView;
  return (
    <View {...({ dataSet: { page: "1" } } as any)} style={{ flex: 1, backgroundColor: t.background }} accessibilityLabel={title}>
      <TopBar max={720}>
        <Button id="page-back" variant="soft" color="gray" onPress={closePage}>← Back</Button>
        <Heading size={4} lines={1} style={{ flex: 1, minWidth: 0 }}>{title}</Heading>
        {right}
      </TopBar>
      <Scroll ref={scrollRef} bottomOffset={24} keyboardShouldPersistTaps="handled" onContentSizeChange={onContentSizeChange}
        onScroll={onScroll} scrollEventThrottle={onScroll ? 100 : undefined}
        contentContainerStyle={{ paddingBottom: 48 + ins.bottom }}>
        <View {...{ nativeID: "page-body" }} ref={body} testID={id} style={{ width: "100%", maxWidth: 720, alignSelf: "center", paddingHorizontal: 16, paddingTop: 8 }}>{children}</View>
      </Scroll>
    </View>
  );
}
