import { useEffect, useRef, useState } from "react";
import { View } from "react-native";
import { useStore, toast } from "../lib/store";
import { canCopy, copyText } from "../lib/clipboard";
import { useTheme } from "../theme";
import { Button, P, Quote, Spinner, type BtnVariant } from "./kit";
import type { ColorName } from "../theme";

// A button tied to a pending-action key: shows the in-flight label (disabled, spinner) while the
// action runs; `cool` renders it inert + faded (layout-shift guard, see useCoolAfterShift).
export function PButton({ pkey, onPress, label, cool, id, color, variant = "solid", size = 2 }: { pkey: string; onPress: () => void; label: string; cool?: boolean; id?: string; color?: ColorName; variant?: BtnVariant; size?: 1 | 2 | 3 }) {
  const p = useStore((s) => s.pending.get(pkey));
  if (p) return <Button size={size} color={color} variant={variant} disabled id={id}><Spinner /><BtnLabel size={size}>{p}</BtnLabel></Button>;
  return <Button size={size} color={color} variant={variant} disabled={cool} style={cool ? { opacity: 0.3 } : undefined} onPress={onPress} id={id}>{label}</Button>;
}
// a label next to a spinner inside a disabled button
export function BtnLabel({ children, size = 2 }: { children: string; size?: 1 | 2 | 3 }) {
  const t = useTheme();
  return <P size={size === 1 ? 1 : size === 3 ? 3 : 2} weight="medium" style={{ color: t.gray.a[8] }}>{children}</P>;
}
export function BusyButton({ label, color, variant = "solid", size = 2 }: { label: string; color?: ColorName; variant?: BtnVariant; size?: 1 | 2 | 3 }) {
  return <Button size={size} color={color} variant={variant} disabled><Spinner /><BtnLabel size={size}>{label}</BtnLabel></Button>;
}

// When a list's items change (e.g. one removed), the remaining destructive buttons move under
// the finger. Keep them inert + faded for 250ms after any composition change.
export function useCoolAfterShift(signature: string) {
  const last = useRef<string | null>(null);
  const [coolUntil, setCoolUntil] = useState(0);
  useEffect(() => {
    if (last.current !== null && last.current !== signature) { setCoolUntil(Date.now() + 250); const t = setTimeout(() => setCoolUntil(0), 270); last.current = signature; return () => clearTimeout(t); }
    last.current = signature;
  }, [signature]);
  return Date.now() < coolUntil;
}

// Flip a button into a pending state while an async action runs. The guard is a ref, not the
// state: a double tap (or Enter + tap) lands before the re-render that disables the button, and
// used to run the action twice. `guard` wraps the WHOLE handler (its question included).
export function useBusy(): [string | null, (label: string, fn: () => Promise<void>) => Promise<void>, (fn: () => Promise<void>) => Promise<void>] {
  const [busy, setBusy] = useState<string | null>(null);
  const on = useRef(false);
  const guard = async (fn: () => Promise<void>) => { if (on.current) return; on.current = true; try { await fn(); } finally { on.current = false; } };
  return [busy, async (label, fn) => { setBusy(label); try { await fn(); } finally { setBusy(null); } }, guard];
}

// Copy: a value to the clipboard (lib/clipboard: the browser's, or the shell's in the app), with a toast. Not
// shown where nothing can copy (an old browser): the value stays selectable text there.
export function CopyButton({ value, what, id, size = 1, label = "Copy" }: { value: string; what: string; id?: string; size?: 1 | 2 | 3; label?: string }) {
  const [done, setDone] = useState(false);
  useEffect(() => { if (!done) return; const t = setTimeout(() => setDone(false), 2000); return () => clearTimeout(t); }, [done]);
  if (!canCopy) return null;
  const run = () => copyText(value).then(() => { setDone(true); toast("Copied: " + what, "ok"); }, (e: any) => toast("Could not copy: " + (e?.message || e), "error"));
  return <Button size={size} variant="soft" color={done ? "green" : "gray"} id={id} onPress={run}>{done ? "Copied" : label}</Button>;
}

// what a conversation ended on (a paused or previous session's card), clamped to three lines
export function LastMessage({ last }: { last: { role: "user" | "assistant"; text: string } }) {
  return <Quote by={last.role === "user" ? "Last message (you)" : "Last message (Claude)"} lines={3}>{last.text}</Quote>;
}
// a Quote kept folded behind a Show button: for text of any length (a cron's prompt) that would otherwise grow the card
export function FoldedQuote({ by, children, id, color, mt = 2 }: { by: string; children: string; id: string; color?: ColorName; mt?: 1 | 2 | 3 }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      {open && <Quote by={by} color={color} mt={mt} id={id}>{children}</Quote>}
      <View style={{ flexDirection: "row", marginTop: open ? 4 : 8 }}>
        <Button size={1} variant="ghost" color={color || "gray"} id={id + "-toggle"} onPress={() => setOpen(!open)}>{open ? "Hide " + by.toLowerCase() : "Show " + by.toLowerCase()}</Button>
      </View>
    </>
  );
}
