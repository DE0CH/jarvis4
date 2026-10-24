// The list: a top bar (the tab's name on a wide screen, where the tabs are the sidebar), the banners,
// the tabs (narrow screens), and the tab's view. Pages open on top of it (ui/page.tsx) and it stays
// mounted underneath, so its scroll position is kept. No pull-to-refresh: the ↻ button refreshes, and
// coming back to the foreground refreshes by itself.
import { ScrollView, View } from "react-native";
import { useSafeAreaInsets } from "react-native-safe-area-context";
import { useStore, setTab, refresh, TABS, useInboxCount, type Tab } from "../lib/store";
import { sessionTitle, usd } from "../lib/api";
import { useTheme } from "../theme";
import { BadgeList, Button, Callout, Heading, IconButton, P, Row, Rows, Spinner, Tabs } from "../ui/kit";
import { TopBar, openPage } from "../ui/page";
import { openNewSession } from "../lib/sessions";
import { useWide } from "../ui/overlays";
import { trustWarning } from "../lib/kernel";
import { Boundary } from "../ui/boundary";
import { Sessions } from "../views/Sessions";
import { Inbox } from "../views/Inbox";
import { Records } from "../views/Records";
import { Search } from "../views/Search";
import { Stores } from "../views/Stores";
import { Content } from "../views/Content";
import { Settings } from "../views/Settings";
import { Tasks } from "../views/Tasks";
import { TaskSchedules } from "../views/TaskSchedules";
import { Machines } from "../views/Machines";
import { Devices } from "../views/Devices";

function Banners() {
  const st = useStore((s) => s.state);
  const b = st.budget, trust = trustWarning(st), dead = st.sessions.filter((m) => m.authFailed);
  return (
    <View nativeID="banners">
      {!!st.loadError && <Callout color="red" mb={3}>{"Can't reach the router: " + st.loadError}</Callout>}
      {!!trust && <Callout color="amber" mb={3} id={st.kernel ? "banner-kernel" : "banner-core"}>{trust}</Callout>}
      {dead.length > 0 && <Callout color="red" mb={3} id="banner-creds">
        <P size={2} weight="bold" color="red">Claude login failed</P>
        <Rows><Row label="Sessions"><BadgeList color="red" items={dead.map(sessionTitle)} /></Row></Rows>
        <P size={1} color="red">If this stays: Settings → Claude account → Re-login.</P>
      </Callout>}
      {b?.capped || b?.warned ? <Callout color={b.capped ? "red" : "amber"} mb={3} id="banner-budget">
        <P size={2} weight="bold" color={b.capped ? "red" : "amber"}>{b.capped ? "Fly spend cap reached" : "Fly spend warning"}</P>
        <Rows><Row label="Spent">{usd(b.spentUsd)}</Row><Row label="Cap">{usd(b.capUsd)}</Row><Row label="Month">{b.month}</Row></Rows>
        <P size={1} color={b.capped ? "red" : "amber"}>{b.capped ? "Every running session was paused." : "At the cap, every running session is paused."}</P>
      </Callout> : null}
      {!!st.fly?.error && st.fly.error !== "FLY_READ_TOKEN not set" && <Callout color="red" mb={3}>{"Fly: " + st.fly.error}</Callout>}
    </View>
  );
}

export default function Dashboard() {
  const t = useTheme(), ins = useSafeAreaInsets(), wide = useWide();
  const tab = useStore((s) => s.tab);
  const refreshing = useStore((s) => s.refreshing);
  const inbox = useInboxCount();
  return (
    <View style={{ flex: 1, backgroundColor: t.background }}>
      <TopBar max={wide ? 1320 : 820}>
        <Heading size={4} lines={1} style={{ flex: 1, minWidth: 0 }}>{wide ? TABS.find(([k]) => k === tab)![1] : "Jarvis 4"}</Heading>
        <IconButton id="refreshBtn" variant="soft" color="gray" label="Refresh" onPress={() => refresh(true)}>{refreshing ? <Spinner /> : "↻"}</IconButton>
        {tab === "sessions" && <Button id="newBtn" onPress={openNewSession}>+ New session</Button>}
        {tab === "schedules" && <Button id="newScheduleBtn" onPress={() => openPage("task-schedule", {})}>+ New schedule</Button>}
      </TopBar>
      <ScrollView keyboardShouldPersistTaps="handled" contentContainerStyle={{ paddingBottom: 24 + ins.bottom }}>
        <View style={{ width: "100%", maxWidth: wide ? 1320 : 820, alignSelf: "center", paddingHorizontal: wide ? 32 : 16, paddingTop: 16 }}>
          <Banners />
          {!wide && <Tabs value={tab} onChange={(v) => setTab(v as Tab)} items={TABS} badges={{ inbox }} />}
          <View nativeID={"view-" + tab}>
            <Boundary what={"This tab"} reset={tab}>
            {tab === "sessions" && <Sessions />}
            {tab === "inbox" && <Inbox />}
            {tab === "search" && <Search />}
            {tab === "stores" && <Stores />}
            {tab === "content" && <Content />}
            {tab === "records" && <Records />}
            {tab === "tasks" && <Tasks />}
            {tab === "schedules" && <TaskSchedules />}
            {tab === "machines" && <Machines />}
            {tab === "devices" && <Devices />}
            {tab === "settings" && <Settings />}
            </Boundary>
          </View>
        </View>
      </ScrollView>
    </View>
  );
}
