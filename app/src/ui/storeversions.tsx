// A store's earlier versions (core/history.go, POST api/core/stores/versions): what made each one and its key names,
// never a value. The web page only proposes a restore (an Inbox request, rust/router/src/storerestore.rs); the iPhone app reviews
// the core's signed document of exactly what changes and signs it with Face ID.
import { useState } from "react";
import { View } from "react-native";
import { ago, storeVersions, type StoreVersion } from "../lib/api";
import { fileFromWeb } from "../lib/inbox";
import { useTheme } from "../theme";
import { Badge, Button, Flex, P, Spinner, mono } from "./kit";
import { RNText } from "./rntext";

const CAUSE: Record<string, string> = { recover: "Recover", created: "Created", write: "Key written", delete: "Key deleted", "deploy-key": "Deploy key", restore: "Restore" };

function Cause({ v }: { v: StoreVersion }) {
  const c = v.cause;
  return (
    <Flex gap={1} align="center" wrap>
      <Badge color={c.kind === "delete" ? "red" : c.kind === "restore" ? "blue" : "gray"}>{CAUSE[c.kind] || c.kind}</Badge>
      {c.key ? <Badge>{c.key}</Badge> : null}
      {c.writer?.by ? <Badge color="gray">{c.writer.by === "machine" ? "session" : c.writer.by}</Badge> : null}
      {c.from ? <Badge color="blue">{"from v" + c.from}</Badge> : null}
    </Flex>
  );
}

export function StoreVersions({ store }: { store: string }) {
  const t = useTheme();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [data, setData] = useState<{ current: string; versions: StoreVersion[] } | null>(null);
  const [asked, setAsked] = useState<number | null>(null);
  const id = "store-" + store + "-versions";
  const load = async () => {
    setOpen(true); setBusy(true); setErr(null);
    try { setData(await storeVersions(store)); } catch (e: any) { setErr(e?.message || String(e)); } finally { setBusy(false); }
  };
  if (!open) return <Flex mt={2}><Button id={id} size={1} variant="soft" color="gray" onPress={load}>Versions</Button></Flex>;
  return (
    <View style={{ marginTop: 8, gap: 6 }} {...{ dataSet: { versions: store } }}>
      <Flex gap={2} align="center">
        <P size={2} weight="medium" style={{ flex: 1 }}>Versions</P>
        {busy && <Spinner />}
        <Button id={id + "-close"} size={1} variant="ghost" color="gray" onPress={() => setOpen(false)}>Hide</Button>
      </Flex>
      {err && <P size={1} color="red" id={id + "-error"}>{err}</P>}
      {data && !data.versions.length && <P size={1} color="gray">None kept</P>}
      {data?.versions.map((v) => {
        const current = v.version === data.current;
        return (
          <View key={v.seq} {...{ dataSet: { version: String(v.seq) } }} style={{ borderTopWidth: 1, borderTopColor: t.gray.a[4], paddingTop: 6, gap: 4 }}>
            <Flex gap={2} align="center" wrap>
              <P size={2} weight="medium">{"v" + v.seq}</P>
              {current && <Badge color="green">Current</Badge>}
              <P size={1} color="gray">{ago(v.at)}</P>
              <Badge color="gray">{v.keys.length + (v.keys.length === 1 ? " key" : " keys")}</Badge>
            </Flex>
            <Cause v={v} />
            <RNText selectable numberOfLines={3} style={{ fontFamily: mono, fontSize: 12, lineHeight: 17, color: t.gray.a[11] }}>{v.keys.map((k) => k.name).join(" ") || "No keys"}</RNText>
            {!current && <Flex>
              <Button id={id + "-restore-" + v.seq} size={1} variant="soft" disabled={asked === v.seq}
                onPress={async () => { if (await fileFromWeb("restore", { store, seq: v.seq })) setAsked(v.seq); }}>
                {asked === v.seq ? "In the Inbox" : "Propose restore"}
              </Button>
            </Flex>}
          </View>
        );
      })}
    </View>
  );
}
