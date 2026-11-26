// Content stores (GET api/content; rust/router/src/content.rs): named folders of files on the Storage Box, the file counterpart
// of the key stores. A session picked with one in New session pulls it into ~/content/<name>/ at every start and
// pushes its changes back with `content-sync push <name>`. Here: list, make, delete a store; its files on its own page.
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { askText, failed, toast, exclusive, pend, useStore } from "../lib/store";
import { Button, Card, Flex, Heading, Muted, P, Row, Rows, Spinner } from "../ui/kit";
import { Cards } from "../ui/cards";
import { openPage } from "../ui/page";

export type ContentStore = { name: string; files: number; bytes: number };
export const NAME_RE = /^[a-z0-9]([a-z0-9-]{0,40}[a-z0-9])?$/;
export const fmtBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1 << 20 ? `${(n / 1024).toFixed(1)} KB` : `${(n / (1 << 20)).toFixed(1)} MB`);

// shared with New session (the picker) and this tab
let cache: { at: number; items: ContentStore[] } | null = null;
export async function loadContentStores(fresh = false): Promise<ContentStore[]> {
  if (!fresh && cache && Date.now() - cache.at < 30000) return cache.items;
  const r = await api<{ stores: ContentStore[] }>("GET", "api/content" + (fresh ? "?fresh=1" : ""));
  cache = { at: Date.now(), items: r.stores || [] };
  return cache.items;
}

export function Content() {
  const [items, setItems] = useState<ContentStore[] | null>(null), [err, setErr] = useState<string | null>(null);
  const pending = useStore((s) => s.pending);
  async function load(fresh = false) {
    try { setItems(await loadContentStores(fresh)); setErr(null); } catch (e: any) { setErr(e.message); }
  }
  useEffect(() => { load(true); }, []);
  const create = () => exclusive("content-new", async () => {
    const name = await askText({ title: "New content store", action: "Make",
      input: { heading: "Name", label: "Lowercase letters, digits and dashes", placeholder: "e.g. notes", max: 42 } });
    if (name === null) return;
    if (!NAME_RE.test(name)) { toast("Use lowercase letters, digits and dashes (not at the ends).", "error"); return; }
    pend("content-new", "Making…");
    try { await api("POST", "api/content", { name }); toast("Made " + name + ".", "ok"); await load(true); }
    catch (e) { failed(e); }
    finally { pend("content-new", null); }
  });
  return (
    <>
      <Flex align="center" gap={2} mb={3}>
        <Muted style={{ flex: 1 }}>Folders of files a session gets in ~/content/&lt;name&gt;/.</Muted>
        <Button id="content-new" disabled={pending.has("content-new")} onPress={create}>+ New store</Button>
      </Flex>
      {items === null ? (err ? <P size={2} color="red">{err}</P> : <Flex gap={2} align="center"><Spinner /><Muted>Loading content stores…</Muted></Flex>)
        : !items.length ? <P size={3} color="gray" align="center" mt={8} mb={8}>No content stores.</P>
        : <Cards>
          {items.map((s) => (
            <Card key={s.name} data={{ content: s.name }}>
              <Heading size={3} mb={1}>{s.name}</Heading>
              <Rows><Row label="Files">{String(s.files)}</Row><Row label="Size">{fmtBytes(s.bytes)}</Row></Rows>
              <Flex gap={2} pt={3} style={{ marginTop: "auto" }}>
                <Button variant="soft" id={"content-open-" + s.name} onPress={() => openPage("content", { name: s.name, changed: () => load(true) })}>Files</Button>
              </Flex>
            </Card>
          ))}
        </Cards>}
      {!!err && items !== null && <P size={2} color="red" mt={2}>{err}</P>}
    </>
  );
}
