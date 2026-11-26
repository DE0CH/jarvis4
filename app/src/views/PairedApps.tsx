// Paired apps (GET api/devices; rust/router/src/devices.rs): Deyao's builds of the OpenClaw and Paseo apps, each paired once
// with its own Access service token. Remove deletes that token: the app then asks to pair again.
import { useEffect, useState } from "react";
import { api, ago } from "../lib/api";
import { ask, failed, exclusive } from "../lib/store";
import { Button, Card, Flex, Heading, Muted, P, Row, Rows, Text } from "../ui/kit";

type Device = { id: string; name: string; model: string; app: string; createdAt: string; lastSeenAt: string };
const APP: Record<string, string> = { openclaw: "OpenClaw", paseo: "Paseo" };

export function PairedAppsCard() {
  const [list, setList] = useState<Device[] | null>(null), [err, setErr] = useState<string | null>(null);
  async function load() {
    try { setList((await api<{ devices: Device[] }>("GET", "api/devices")).devices || []); setErr(null); } catch (e: any) { setErr(e.message); }
  }
  useEffect(() => { load(); }, []);
  const remove = (d: Device) => exclusive("device:" + d.id, async () => {
    if (!(await ask({ title: "Remove paired app?", rows: [{ label: "App", value: APP[d.app] || d.app }, { label: "Device", value: d.name }], action: "Remove", danger: true,
      detail: "Its access token is deleted; the app asks to pair again." }))) return;
    try { await api("DELETE", `api/devices/${d.id}`); await load(); } catch (e) { failed(e); }
  });
  return (
    <Card data={{ settings: "devices" }}>
      <Heading size={3} mb={1}>Paired apps</Heading>
      {list === null ? (err ? <P size={2} color="red">{err}</P> : <Muted>Loading…</Muted>)
        : !list.length ? <Muted>None. Pair from the OpenClaw or Paseo app (Settings → Jarvis).</Muted>
        : list.map((d) => (
          <Flex key={d.id} align="center" gap={2} pt={1} data={{ device: d.id }}>
            <Flex flex={1}><Rows>
              <Row label={APP[d.app] || d.app}><Text size={2}>{d.name + (d.model ? " · " + d.model : "")}</Text></Row>
              <Row label="Last seen">{ago(d.lastSeenAt)}</Row>
            </Rows></Flex>
            <Button size={1} variant="soft" color="red" onPress={() => remove(d)}>Remove</Button>
          </Flex>
        ))}
    </Card>
  );
}
