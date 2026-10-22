// The root: the list and its pages on a native stack (iOS push and swipe-back in the app; the browser's
// Back on the web), with the sidebar beside them on a wide screen and the overlays (dialog, menu, toasts)
// above everything. When Access refuses the app and its sign-in didn't complete, the sign-in screen
// shows instead (auth.native.ts).
import { useEffect } from "react";
import { Platform, Pressable, View } from "react-native";
import { Stack, router, usePathname } from "expo-router";
import { StatusBar } from "expo-status-bar";
import { SafeAreaProvider, useSafeAreaInsets } from "react-native-safe-area-context";
import { KeyboardProvider } from "react-native-keyboard-controller";
import { GestureHandlerRootView } from "react-native-gesture-handler";
import * as SystemUI from "expo-system-ui";
import "../lib/webInit";
import { useAuthState, loadAuth, signIn } from "../lib/auth";
import { markAppReady } from "../lib/shell";
import { useStore, setTab, start, TABS, useInboxCount, type Tab } from "../lib/store";
import { useTheme } from "../theme";
import { Button, CountBadge, Flex, Heading, P, Spinner, Text } from "../ui/kit";
import { OverlayHosts, useWide } from "../ui/overlays";

function Sidebar() {
  const t = useTheme(), ins = useSafeAreaInsets();
  const tab = useStore((s) => s.tab), path = usePathname();
  const onList = path === "/";
  const inbox = useInboxCount();
  const go = (k: Tab) => { setTab(k); if (!onList) router.dismissTo("/"); };
  return (
    <View nativeID="sidebar" accessibilityRole="menu" style={{ width: 220, paddingTop: 20 + ins.top, paddingHorizontal: 12, paddingLeft: 12 + ins.left, paddingBottom: 20, gap: 2, borderRightWidth: 1, borderRightColor: t.gray.a[5], backgroundColor: t.background }}>
      <View style={{ paddingHorizontal: 12, paddingTop: 4, paddingBottom: 16 }}><Heading size={4}>Jarvis 4</Heading></View>
      {TABS.map(([k, l]) => {
        const on = tab === k && onList;
        return (
          <Pressable key={k} {...({ dataSet: { tab: k } } as any)} accessibilityRole="menuitem" accessibilityState={{ selected: on }} onPress={() => go(k)}
            style={({ hovered }: any) => ({ paddingHorizontal: 12, paddingVertical: 8, borderRadius: 9, backgroundColor: on ? t.accent.a[3] : hovered ? t.gray.a[3] : "transparent" })}>
            <View style={{ flexDirection: "row", alignItems: "center" }}>
              <Text size={2} weight={on ? "medium" : "regular"} style={{ color: on ? t.accent.a[11] : t.gray[11] }}>{l}</Text>
              {k === "inbox" && <CountBadge n={inbox} id="sidebar-badge-inbox" />}
            </View>
          </Pressable>
        );
      })}
    </View>
  );
}

// the app when Cloudflare Access refused its token and the sign-in sheet was cancelled or failed: one
// button that opens the sign-in sheet again (the shell runs it)
function SignIn() {
  const t = useTheme(), a = useAuthState();
  return (
    <View style={{ flex: 1, backgroundColor: t.background, alignItems: "center", justifyContent: "center", padding: 24, gap: 16 }}>
      <Heading size={6}>Jarvis 4</Heading>
      {a.note ? <P size={2} color="gray" align="center" id="auth-note">{a.note}</P> : <P size={2} color="gray" align="center">Sign in with your Cloudflare login (Google or an email code).</P>}
      {a.phase === "signingIn" ? <Flex gap={2} align="center"><Spinner /><P size={2} color="gray">Signing in…</P></Flex>
        : <Button size={3} id="sign-in" onPress={() => signIn()}>Sign in</Button>}
    </View>
  );
}

function Signed() {
  const t = useTheme(), wide = useWide();
  useEffect(() => { start(); }, []);
  const stack = (
    <Stack screenOptions={{
      headerShown: false, contentStyle: { backgroundColor: t.background },
      animation: Platform.OS === "web" ? "none" : "default", fullScreenGestureEnabled: true,
    }} />
  );
  return (
    <View style={{ flex: 1, flexDirection: "row", backgroundColor: t.background }}>
      {wide && <Sidebar />}
      <View style={{ flex: 1 }}>{stack}</View>
    </View>
  );
}

export default function Root() {
  const t = useTheme(), a = useAuthState();
  // real content is on screen: the list with its first state (or the error saying why there is none), or sign-in
  const drawn = useStore((s) => s.state.loaded || !!s.state.loadError);
  useEffect(() => { if (a.phase !== "loading" && (a.phase !== "ready" || drawn)) requestAnimationFrame(() => markAppReady()); }, [a.phase, drawn]);
  useEffect(() => { loadAuth(); }, []);
  useEffect(() => { SystemUI.setBackgroundColorAsync(t.background).catch(() => {}); }, [t.background]);
  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <KeyboardProvider>
        <SafeAreaProvider>
          <StatusBar style={t.scheme === "dark" ? "light" : "dark"} />
          <View style={{ flex: 1, backgroundColor: t.background }}>
            {a.phase === "ready" || a.phase === "signingIn" ? <Signed /> : a.phase === "loading" ? null : <SignIn />}
            <OverlayHosts />
          </View>
        </SafeAreaProvider>
      </KeyboardProvider>
    </GestureHandlerRootView>
  );
}
