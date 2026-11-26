// What a secret store and each of its keys are for (GET api/stores, rust/router/src/storedocs.rs): the store's about text and
// one line per key with its explanation and, for a key a session wrote, which session. On the Stores page each text is
// editable in place (PUT api/stores/{store}/docs); the New session picker shows a compact read-only form.
import { useState } from "react";
import { View } from "react-native";
import { putStoreDocs, ago, type CoreStore, type StoreKey } from "../lib/api";
import { loadStores } from "../lib/store";
import { useTheme } from "../theme";
import { Badge, Button, Flex, P, Spinner, TextArea, mono } from "./kit";
import { RNText } from "./rntext";

const MAX = 2000; // the router's limit for one explanation (docMax)

// one text with an Edit button: Edit opens a text box in place, Save writes it, errors stay next to it
function EditableText({ id, value, empty, save, label }: { id: string; value: string; empty: string; save: (v: string) => Promise<void>; label: string }) {
  const t = useTheme();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(value);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const begin = () => { setDraft(value); setErr(null); setSaved(false); setOpen(true); };
  const submit = async () => {
    setSaving(true); setErr(null);
    try { await save(draft.trim()); setOpen(false); setSaved(true); setTimeout(() => setSaved(false), 2500); }
    catch (e: any) { setErr(e?.message || String(e)); }
    finally { setSaving(false); }
  };
  if (open) return (
    <View style={{ gap: 6, marginTop: 4 }}>
      <TextArea id={id + "-input"} rows={2} autoCapitalize="sentences" value={draft} onChangeText={setDraft} maxLength={MAX} placeholder={label} disabled={saving} />
      <Flex gap={2} align="center" wrap>
        <Button id={id + "-save"} size={1} disabled={saving || draft.trim() === value} onPress={submit}>{saving ? <><Spinner /><P size={1} color="gray">Saving…</P></> : "Save"}</Button>
        <Button id={id + "-cancel"} size={1} variant="soft" color="gray" disabled={saving} onPress={() => { setOpen(false); setErr(null); }}>Cancel</Button>
        {draft.trim() === "" && value !== "" && <P size={1} color="gray">Saving empty removes it.</P>}
      </Flex>
      {err && <P size={1} color="red" id={id + "-error"}>{"Could not save: " + err}</P>}
    </View>
  );
  return (
    <View style={{ flexDirection: "row", alignItems: "flex-start", gap: 8 }}>
      <RNText {...{ nativeID: id, testID: id }} selectable style={{ flex: 1, minWidth: 0, fontSize: 14, lineHeight: 20, color: value ? t.gray[12] : t.gray.a[10], fontStyle: value ? "normal" : "italic" }}>{value || empty}</RNText>
      {saved && <P size={1} color="green">Saved</P>}
      <Button id={id + "-edit"} size={1} variant="ghost" color="gray" label={"Edit " + label} onPress={begin}>Edit</Button>
    </View>
  );
}

// who wrote a key: a session's line shows as that session
function Writer({ k }: { k: StoreKey }) {
  if (k.writer?.by !== "machine") return null;
  const who = k.writer.sessionLabel || k.writer.session || k.writer.machine || "";
  if (!who) return null;
  return (
    <Flex gap={1} align="center" wrap>
      <P size={1} color="gray">Written by session</P>
      <Badge color="blue">{who}</Badge>
      {k.at ? <P size={1} color="gray">{ago(k.at)}</P> : null}
    </Flex>
  );
}

function KeyName({ name }: { name: string }) {
  const t = useTheme();
  return <RNText selectable style={{ fontFamily: mono, fontSize: 13, lineHeight: 20, color: t.gray[12], fontWeight: "600" }}>{name}</RNText>;
}

/** a store's about text and keys; `edit`: each text has an Edit button (the Stores page) */
export function StoreDocs({ store, edit }: { store: CoreStore; edit?: boolean }) {
  const t = useTheme();
  const save = async (docs: { about?: string; keys?: Record<string, string> }) => { await putStoreDocs(store.name, docs); loadStores(); };
  const keys = store.keyInfo;
  const sid = "store-" + store.name;
  return (
    <View style={{ gap: 8 }}>
      {edit
        ? <EditableText id={sid + "-about"} label="what this store is for" value={store.about || ""} empty="No description yet" save={(v) => save({ about: v })} />
        : store.about ? <P size={2}>{store.about}</P> : null}
      {!keys.length ? <P size={1} color="gray">No keys</P>
        : <View style={{ borderTopWidth: 1, borderTopColor: t.gray.a[4] }}>
          {keys.map((k) => (
            <View key={k.name} {...{ dataSet: { key: k.name } }} style={{ paddingVertical: edit ? 6 : 3, borderBottomWidth: 1, borderBottomColor: t.gray.a[4], gap: 2 }}>
              {edit ? <>
                <KeyName name={k.name} />
                <EditableText id={sid + "-key-" + k.name} label={"what " + k.name + " is for"} value={k.explanation || ""} empty="no explanation yet" save={(v) => save({ keys: { [k.name]: v } })} />
              </> : <RNText numberOfLines={2} style={{ fontSize: 13, lineHeight: 18 }}>
                <RNText style={{ fontFamily: mono, fontWeight: "600", color: t.gray[12] }}>{k.name}</RNText>
                <RNText style={{ color: k.explanation ? t.gray.a[11] : t.gray.a[9], fontStyle: k.explanation ? "normal" : "italic" }}>{"  " + (k.explanation || "no explanation yet")}</RNText>
              </RNText>}
              <Writer k={k} />
            </View>
          ))}
        </View>}
    </View>
  );
}
