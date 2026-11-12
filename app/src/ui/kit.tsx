// The component kit: Radix Themes' components as the web dashboard used them, rebuilt on React
// Native primitives so the same code draws the iPhone app and the web page. Only the props the
// dashboard actually uses exist. Nothing slides or fades (Deyao): things appear and disappear.
//
// Ids: `id` becomes the element id on the web (nativeID) and the accessibility identifier on iOS
// (testID), so the browser test and the XCUITest find the same controls. `data` becomes data-*
// attributes on the web (react-native-web's dataSet).
import { useState, type ReactNode } from "react";
import {
  ActivityIndicator, Platform, Pressable, ScrollView, View,
  type StyleProp, type TextInputProps, type TextStyle, type ViewStyle,
} from "react-native";
import { RNText, TextInput } from "./rntext";
import { Aligned } from "./align";
import { useTheme, space, radius, fontSize, lineHeight, headingLineHeight, letterSpacing, fonts, type ColorName, type Size } from "../theme";

type Sp = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
const sp = (n?: Sp) => (n ? space[n as keyof typeof space] : n === 0 ? 0 : undefined);
export const ids = (id?: string, data?: Record<string, string | number | undefined>) =>
  ({ ...(id ? { nativeID: id, testID: id } : {}), ...(data ? { dataSet: data } : {}) }) as any;
export const mono = Platform.OS === "web" ? fonts.monoWeb : fonts.mono;

// ---- text ----------------------------------------------------------------------------------
type TextColor = ColorName | "default";
export type TextProps = {
  children?: ReactNode; size?: 1 | 2 | 3 | 4 | 5 | 6; color?: TextColor; weight?: "regular" | "medium" | "bold";
  align?: "left" | "center" | "right"; mt?: Sp; mb?: Sp; mono?: boolean; lines?: number; upper?: boolean;
  style?: StyleProp<TextStyle>; id?: string; selectable?: boolean; onPress?: () => void; data?: Record<string, string>;
};
const W = { regular: "400", medium: "500", bold: "700" } as const;
export function Text({ children, size, color, weight, align, mt, mb, mono: m, lines, upper, style, id, selectable, onPress, data }: TextProps) {
  const t = useTheme();
  const s: TextStyle = {};
  if (size) { s.fontSize = fontSize[size]; s.lineHeight = lineHeight[size]; s.letterSpacing = letterSpacing[size] * fontSize[size]; }
  if (color && color !== "default") s.color = t.c[color].a[11];
  if (weight) s.fontWeight = W[weight];
  if (align) s.textAlign = align;
  if (mt !== undefined) s.marginTop = sp(mt);
  if (mb !== undefined) s.marginBottom = sp(mb);
  if (m) { s.fontFamily = mono; s.fontSize = (s.fontSize || 14) * 0.92; }
  if (upper) { s.textTransform = "uppercase"; s.letterSpacing = 0.04 * (s.fontSize || 12); }
  return <RNText {...ids(id, data)} numberOfLines={lines} selectable={selectable} onPress={onPress} style={[s, style]}>{children}</RNText>;
}
// the root of every text run: the theme's default colour and size 3 (nested Texts inherit)
export function Body({ children, style }: { children: ReactNode; style?: StyleProp<TextStyle> }) {
  const t = useTheme();
  return <RNText style={[{ color: t.gray[12], fontSize: 16, lineHeight: 24 }, style]}>{children}</RNText>;
}
// a block of text: always starts from the theme's colour (a bare RNText would be black in dark mode)
export function P(props: TextProps) {
  const t = useTheme();
  return <Text size={2} {...props} style={[{ color: t.gray[12] }, props.color && props.color !== "default" ? { color: t.c[props.color].a[11] } : null, props.style]} />;
}
export function Heading({ children, size = 3, mb, mt, lines, style, id }: { children: ReactNode; size?: Size; mb?: Sp; mt?: Sp; lines?: number; style?: StyleProp<TextStyle>; id?: string }) {
  const t = useTheme();
  return <RNText {...ids(id)} accessibilityRole="header" numberOfLines={lines}
    style={[{ color: t.gray[12], fontSize: fontSize[size], lineHeight: headingLineHeight[size], fontWeight: "700", letterSpacing: letterSpacing[size] * fontSize[size], marginBottom: sp(mb), marginTop: sp(mt) }, style]}>{children}</RNText>;
}
export const Muted = ({ children, mt, id, style, selectable }: { children: ReactNode; mt?: Sp; id?: string; style?: StyleProp<TextStyle>; selectable?: boolean }) => <P size={2} color="gray" mt={mt} id={id} style={style} selectable={selectable}>{children}</P>;
// section label inside forms and above groups
export const Lbl = ({ children, mt = 4 }: { children: ReactNode; mt?: Sp }) => <P size={1} weight="bold" color="gray" upper mt={mt} mb={2}>{children}</P>;
export function Code({ children }: { children: ReactNode }) {
  const t = useTheme();
  return <RNText style={{ fontFamily: mono, fontSize: 13, color: t.accent.a[11], backgroundColor: t.accent.a[3] }}>{children}</RNText>;
}

// ---- layout ----------------------------------------------------------------------------------
type FlexProps = {
  children?: ReactNode; dir?: "row" | "column"; gap?: Sp; align?: ViewStyle["alignItems"]; justify?: ViewStyle["justifyContent"];
  wrap?: boolean; mt?: Sp; mb?: Sp; pt?: Sp; p?: Sp; flex?: number; style?: StyleProp<ViewStyle>; id?: string; data?: Record<string, string>;
};
export function Flex({ children, dir = "row", gap, align, justify, wrap, mt, mb, pt, p, flex, style, id, data }: FlexProps) {
  return <View {...ids(id, data)} style={[{ flexDirection: dir, gap: sp(gap), alignItems: align, justifyContent: justify, flexWrap: wrap ? "wrap" : undefined, marginTop: sp(mt), marginBottom: sp(mb), paddingTop: sp(pt), padding: sp(p), flex }, style]}>{children}</View>;
}
export const Box = ({ children, mt, mb, style, id, data }: { children?: ReactNode; mt?: Sp; mb?: Sp; style?: StyleProp<ViewStyle>; id?: string; data?: Record<string, string> }) =>
  <View {...ids(id, data)} style={[{ marginTop: sp(mt), marginBottom: sp(mb) }, style]}>{children}</View>;

export function Card({ children, size = 2, mt, style, id, data, variant = "classic", dim }: { children: ReactNode; size?: 1 | 2; mt?: Sp; style?: StyleProp<ViewStyle>; id?: string; data?: Record<string, string>; variant?: "classic" | "surface"; dim?: boolean }) {
  const t = useTheme();
  return (
    <View {...ids(id, { card: variant, ...data })} style={[{ backgroundColor: variant === "surface" ? t.gray.a[2] : t.panel, borderRadius: radius[4], borderWidth: 1, borderColor: t.gray.a[6], padding: size === 1 ? 12 : 16, marginTop: sp(mt), opacity: dim ? 0.75 : 1 }, style]}>
      {children}
    </View>
  );
}

// ---- button ---------------------------------------------------------------------------------
export type BtnVariant = "solid" | "soft" | "surface" | "outline" | "ghost";
const BTN = { 1: { h: 24, px: 8, fs: 12, lh: 16, r: radius[1], gap: 4 }, 2: { h: 32, px: 12, fs: 14, lh: 20, r: radius[2], gap: 8 }, 3: { h: 40, px: 16, fs: 16, lh: 24, r: radius[3], gap: 12 } } as const;
export type ButtonProps = {
  children?: ReactNode; onPress?: () => void; size?: 1 | 2 | 3; variant?: BtnVariant; color?: ColorName; disabled?: boolean; loading?: boolean;
  id?: string; style?: StyleProp<ViewStyle>; label?: string; icon?: boolean; data?: Record<string, string>; keepFocus?: boolean;
  // web: a real link (<a href>, a new tab unless `self`) instead of onPress; the app keeps onPress
  href?: string; self?: boolean;
};
export function Button({ children, onPress, size = 2, variant = "solid", color = "blue", disabled, loading, id, style, label, icon, data, keepFocus, href, self }: ButtonProps) {
  const t = useTheme();
  const c = t.c[color], d = BTN[size], ghost = variant === "ghost";
  const off = disabled || loading;
  const look = (pressed: boolean): { bg: string; fg: string; border?: string } => {
    if (off) return { bg: ghost ? "transparent" : t.gray.a[3], fg: t.gray.a[8], border: variant === "surface" || variant === "outline" ? t.gray.a[6] : undefined };
    switch (variant) {
      case "solid": return { bg: pressed ? c[10] : c[9], fg: t.onSolid(color) };
      case "soft": return { bg: pressed ? c.a[5] : c.a[3], fg: c.a[11] };
      case "surface": return { bg: pressed ? c.a[4] : c.a[2], fg: c.a[11], border: c.a[7] };
      case "outline": return { bg: pressed ? c.a[3] : "transparent", fg: c.a[11], border: c.a[8] };
      default: return { bg: pressed ? c.a[4] : "transparent", fg: c.a[11] };
    }
  };
  return (
    <Pressable {...ids(id, data)} accessibilityRole="button" accessibilityLabel={label} accessibilityState={{ disabled: !!off }} disabled={off}
      {...(href && Platform.OS === "web" ? { href, hrefAttrs: self ? undefined : { target: "_blank", rel: "noopener" } } : { onPress })}
      // key chips on the terminal must not take the focus from its input (that would drop the keyboard)
      {...(keepFocus && Platform.OS === "web" ? { onPointerDown: (e: any) => e.preventDefault() } : {})}
      style={({ pressed }) => {
        const l = look(pressed);
        return [{
          height: ghost ? d.h - 4 : d.h, minWidth: icon ? d.h : undefined, width: icon ? d.h : undefined,
          paddingHorizontal: icon ? 0 : ghost ? d.px - 4 : d.px, borderRadius: d.r, backgroundColor: l.bg,
          borderWidth: l.border ? 1 : 0, borderColor: l.border, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: d.gap, alignSelf: "flex-start",
        }, Platform.OS === "web" ? ({ cursor: off ? "default" : "pointer", userSelect: "none" } as any) : null, style];
      }}>
      {({ pressed }) => {
        const l = look(pressed);
        return <>
          {loading && <Spinner color={l.fg} />}
          {typeof children === "string" || typeof children === "number" || Array.isArray(children)
            ? <RNText numberOfLines={1} style={{ color: l.fg, fontSize: icon ? 16 : d.fs, lineHeight: icon ? 24 : d.lh, fontWeight: ghost || icon ? "400" : "500" }}>{children}</RNText>
            : children}
        </>;
      }}
    </Pressable>
  );
}
export const IconButton = (p: ButtonProps) => <Button {...p} icon />;

export function Spinner({ color, size = 1 }: { color?: string; size?: 1 | 2 }) {
  const t = useTheme();
  return <ActivityIndicator size="small" color={color || t.gray.a[11]} style={{ transform: [{ scale: size === 1 ? 0.6 : 0.8 }], width: size === 1 ? 12 : 16, height: size === 1 ? 12 : 16 }} />;
}

// ---- badge / callout / progress ---------------------------------------------------------------
export function Badge({ children, color = "gray", upper, spin }: { children: ReactNode; color?: ColorName; upper?: boolean; spin?: boolean }) {
  const t = useTheme(), c = t.c[color];
  return (
    <View {...ids(undefined, { pill: color })} style={{ flexDirection: "row", alignItems: "center", gap: 4, height: 20, paddingHorizontal: 6, borderRadius: radius[1], backgroundColor: c.a[3], alignSelf: "flex-start", flexShrink: 1, minWidth: 0, maxWidth: "100%" }}>
      {spin && <Spinner color={c.a[11]} />}
      {/* a badge never grows past its container: a long text ends in … inside it, never over a neighbour (2026-10-20) */}
      <RNText numberOfLines={1} style={{ flexShrink: 1, minWidth: 0, color: c.a[11], fontSize: 12, lineHeight: 16, fontWeight: "500", textTransform: upper ? "uppercase" : undefined, letterSpacing: upper ? 0.36 : 0.03 }}>{children}</RNText>
    </View>
  );
}
export function Callout({ children, color = "gray", variant = "soft", mt, mb, id, data }: { children: ReactNode; color?: ColorName; variant?: "soft" | "surface"; mt?: Sp; mb?: Sp; id?: string; data?: Record<string, string> }) {
  const t = useTheme(), c = t.c[color];
  return (
    <View {...ids(id, data)} style={{ backgroundColor: variant === "soft" ? c.a[3] : c.a[2], borderWidth: variant === "surface" ? 1 : 0, borderColor: c.a[6], borderRadius: radius[3], padding: 12, gap: 4, marginTop: sp(mt), marginBottom: sp(mb) }}>
      {typeof children === "string" ? <CalloutText color={color}>{children}</CalloutText> : children}
    </View>
  );
}
export function CalloutText({ children, color = "gray" }: { children: ReactNode; color?: ColorName }) {
  const t = useTheme();
  return <RNText style={{ color: t.c[color].a[11], fontSize: 14, lineHeight: 20 }}>{children}</RNText>;
}
export function Progress({ value, color = "blue", size = 2, mt }: { value: number; color?: ColorName; size?: 1 | 2; mt?: Sp }) {
  const t = useTheme();
  return (
    <View style={{ height: size === 1 ? 4 : 6, borderRadius: 999, backgroundColor: t.gray.a[3], overflow: "hidden", marginTop: sp(mt) }}>
      <View style={{ width: `${Math.max(0, Math.min(100, value))}%`, height: "100%", backgroundColor: t.c[color][9] }} />
    </View>
  );
}

// ---- inputs ---------------------------------------------------------------------------------
type FieldProps = Omit<TextInputProps, "style" | "onChange"> & { size?: 2 | 3; id?: string; mono?: boolean; style?: StyleProp<TextStyle>; rows?: number; disabled?: boolean; data?: Record<string, string> };
function useField() {
  const [focus, setFocus] = useState(false);
  return { focus, onFocus: () => setFocus(true), onBlur: () => setFocus(false) };
}
// Text is 16 px everywhere (iOS Safari zooms into any smaller field).
export function TextField({ size = 2, id, mono: m, style, disabled, data, onFocus, onBlur, ...rest }: FieldProps) {
  const t = useTheme(), f = useField();
  return (
    <TextInput {...ids(id, data)} {...rest} editable={!disabled && rest.editable !== false}
      onFocus={(e) => { f.onFocus(); onFocus?.(e); }} onBlur={(e) => { f.onBlur(); onBlur?.(e); }}
      placeholderTextColor={t.gray.a[10]}
      style={[{
        height: size === 3 ? 40 : 32, borderRadius: size === 3 ? radius[3] : radius[2], borderWidth: 1, borderColor: f.focus ? t.focus : t.gray.a[7],
        backgroundColor: disabled ? t.gray.a[3] : t.surface, color: disabled ? t.gray.a[10] : t.gray[12], paddingHorizontal: size === 3 ? 12 : 8, fontSize: 16,
        fontFamily: m ? mono : undefined, minWidth: 0,
      }, Platform.OS === "web" ? ({ outlineStyle: "none" } as any) : null, style]} />
  );
}
export function TextArea({ id, rows = 3, mono: m, style, disabled, onFocus, onBlur, ...rest }: FieldProps) {
  const t = useTheme(), f = useField();
  return (
    <TextInput {...ids(id)} {...rest} multiline editable={!disabled} textAlignVertical="top"
      onFocus={(e) => { f.onFocus(); onFocus?.(e); }} onBlur={(e) => { f.onBlur(); onBlur?.(e); }}
      placeholderTextColor={t.gray.a[10]}
      style={[{
        minHeight: rows * 22 + 14, borderRadius: radius[2], borderWidth: 1, borderColor: f.focus ? t.focus : t.gray.a[7], backgroundColor: t.surface,
        color: t.gray[12], paddingHorizontal: 8, paddingTop: 6, paddingBottom: 6, fontSize: 16, lineHeight: 22, fontFamily: m ? mono : undefined,
      }, Platform.OS === "web" ? ({ outlineStyle: "none" } as any) : null, style]} />
  );
}

// ---- choice controls --------------------------------------------------------------------------
// a card per option; the chosen one gets the accent border (RadioCards / CheckboxCards)
function ChoiceCard({ on, onPress, children, check, id, data, disabled }: { on: boolean; onPress: () => void; children: ReactNode; check?: boolean; id?: string; data?: Record<string, string>; disabled?: boolean }) {
  const t = useTheme();
  return (
    <Pressable {...ids(id, { ...data, state: on ? "checked" : "unchecked" })} accessibilityRole={check ? "checkbox" : "radio"} accessibilityState={check ? { checked: on, disabled: !!disabled } : { selected: on, disabled: !!disabled }} onPress={onPress} disabled={disabled}
      style={({ pressed }) => [{ opacity: disabled ? 0.5 : 1,
        flexDirection: "row", alignItems: "center", gap: 8, borderRadius: radius[3], backgroundColor: pressed ? t.gray.a[2] : t.surface,
        borderWidth: !check && on ? 2 : 1, borderColor: !check && on ? t.accent[9] : t.gray.a[6],
        paddingVertical: !check && on ? 9 : 10, paddingHorizontal: !check && on ? 11 : 12,
      }, Platform.OS === "web" ? ({ cursor: disabled ? "default" : "pointer" } as any) : null]}>
      <View style={{ flex: 1, minWidth: 0 }}>{children}</View>
      {check && <View style={{ width: 16, height: 16, borderRadius: 4, backgroundColor: on ? t.accent[9] : t.surface, borderWidth: on ? 0 : 1, borderColor: t.gray.a[7], alignItems: "center", justifyContent: "center" }}>
        {on && <RNText style={{ color: "#fff", fontSize: 11, lineHeight: 14, fontWeight: "700" }}>✓</RNText>}
      </View>}
    </Pressable>
  );
}
export type Choice = { value: string; title: ReactNode; sub?: ReactNode; disabled?: boolean };
export function ChoiceText({ title, sub }: { title: ReactNode; sub?: ReactNode }) {
  return <><P size={2} weight="medium">{title}</P>{sub ? (typeof sub === "string" || typeof sub === "number" ? <P size={1} color="gray">{sub}</P> : <View style={{ marginTop: 4 }}>{sub}</View>) : null}</>;
}
export function RadioCards({ value, onChange, options, id }: { value: string; onChange: (v: string) => void; options: Choice[]; id?: string }) {
  // each option is `<id>-<value>` too (the UI tests tap them)
  return <View {...ids(id)} style={{ gap: 8 }}>{options.map((o) => <ChoiceCard key={o.value} id={id ? id + "-" + o.value : undefined} data={{ value: o.value }} on={o.value === value} disabled={o.disabled} onPress={() => onChange(o.value)}><ChoiceText title={o.title} sub={o.sub} /></ChoiceCard>)}</View>;
}
export function CheckboxCards({ value, onChange, options, id }: { value: string[]; onChange: (v: string[]) => void; options: Choice[]; id?: string }) {
  const flip = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  return <View {...ids(id)} style={{ gap: 8 }}>{options.map((o) => <ChoiceCard key={o.value} check data={{ value: o.value }} on={value.includes(o.value)} onPress={() => flip(o.value)}><ChoiceText title={o.title} sub={o.sub} /></ChoiceCard>)}</View>;
}
export function Switch({ on, onChange, label, id }: { on: boolean; onChange: (v: boolean) => void; label?: string; id?: string }) {
  const t = useTheme();
  return (
    <Pressable {...ids(id)} accessibilityRole="switch" accessibilityState={{ checked: on }} onPress={() => onChange(!on)} style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
      <View style={{ width: 28, height: 16, borderRadius: 999, backgroundColor: on ? t.accent[9] : t.gray.a[3], borderWidth: on ? 0 : 1, borderColor: t.gray.a[5], justifyContent: "center", paddingHorizontal: 1 }}>
        <View style={{ width: 14, height: 14, borderRadius: 7, backgroundColor: "#fff", alignSelf: on ? "flex-end" : "flex-start", shadowColor: "#000", shadowOpacity: 0.15, shadowRadius: 2, shadowOffset: { width: 0, height: 1 } }} />
      </View>
      {label ? <P size={1} color="gray">{label}</P> : null}
    </Pressable>
  );
}
export function Segmented({ value, onChange, items, style, id }: { value: string; onChange: (v: string) => void; items: [string, string][]; style?: StyleProp<ViewStyle>; id?: string }) {
  const t = useTheme();
  return (
    <View style={[{ flexDirection: "row", height: 24, borderRadius: radius[2], backgroundColor: t.gray.a[3], padding: 0, width: "100%", maxWidth: 420 }, style]}>
      {items.map(([v, l]) => {
        const on = v === value;
        return (
          <Pressable key={v} {...ids(id ? id + "-" + v : undefined, { value: v })} accessibilityRole="tab" accessibilityState={{ selected: on }} onPress={() => onChange(v)}
            style={{ flex: 1, alignItems: "center", justifyContent: "center", borderRadius: radius[2], backgroundColor: on ? (t.scheme === "dark" ? t.gray.a[4] : t.panel) : "transparent", borderWidth: on ? 1 : 0, borderColor: t.gray.a[5] }}>
            <RNText style={{ fontSize: 12, lineHeight: 16, color: on ? t.gray[12] : t.gray.a[11], fontWeight: on ? "500" : "400" }}>{l}</RNText>
          </Pressable>
        );
      })}
    </View>
  );
}
// the Radix underline tab list, horizontally scrollable on a narrow screen
/** a count on a tab (the Inbox): a small solid pill after its name, nothing at 0 */
// ---- compact choices (New session; Deyao, 2026-11-12) -------------------------------------------
// A setting is one row showing what is chosen; a press opens it in place (one open at a time), so a form with many
// settings fits a screen. Inside, options are small tiles in a grid instead of a full-width card each.
export function Grid({ children, min = 200, max = 3, id, mt }: { children: ReactNode; min?: number; max?: number; id?: string; mt?: Sp }) {
  const [w, setW] = useState(0);
  const cols = w ? Math.max(1, Math.min(max, Math.floor((w + 6) / (min + 6)))) : 1;
  const cw = cols > 1 ? Math.floor(((w - 6 * (cols - 1)) / cols) * 100) / 100 : undefined;
  const items = (Array.isArray(children) ? children.flat() : [children]).filter(Boolean) as any[];
  return (
    <View {...ids(id)} onLayout={(e) => setW(e.nativeEvent.layout.width)} style={{ flexDirection: cols > 1 ? "row" : "column", flexWrap: cols > 1 ? "wrap" : undefined, gap: 6, marginTop: sp(mt) }}>
      {items.map((c, i) => <View key={c?.key ?? i} style={{ width: cw }}>{c}</View>)}
    </View>
  );
}
function Tile({ on, onPress, title, sub, right, check, id, data }: { on: boolean; onPress: () => void; title: ReactNode; sub?: ReactNode; right?: ReactNode; check?: boolean; id?: string; data?: Record<string, string> }) {
  const t = useTheme();
  const ring = !check && on;
  return (
    <Pressable {...ids(id, { ...data, state: on ? "checked" : "unchecked" })} accessibilityRole={check ? "checkbox" : "radio"} accessibilityState={check ? { checked: on } : { selected: on }} onPress={onPress}
      style={({ pressed }) => [{ flexDirection: "row", alignItems: "center", gap: 8, minHeight: sub ? 44 : 36, borderRadius: radius[2],
        backgroundColor: check && on ? t.accent.a[3] : pressed ? t.gray.a[2] : t.surface, borderWidth: ring ? 2 : 1, borderColor: on ? t.accent[9] : t.gray.a[6],
        paddingVertical: ring ? 4 : 5, paddingHorizontal: ring ? 9 : 10 }, Platform.OS === "web" ? ({ cursor: "pointer" } as any) : null]}>
      {check && <View style={{ width: 16, height: 16, borderRadius: 4, backgroundColor: on ? t.accent[9] : t.surface, borderWidth: on ? 0 : 1, borderColor: t.gray.a[7], alignItems: "center", justifyContent: "center" }}>
        {on && <RNText style={{ color: "#fff", fontSize: 11, lineHeight: 14, fontWeight: "700" }}>✓</RNText>}
      </View>}
      <View style={{ flex: 1, minWidth: 0 }}>
        <RNText numberOfLines={1} style={{ color: t.gray[12], fontSize: 14, lineHeight: 20, fontWeight: on || !check ? "500" : "400" }}>{title}</RNText>
        {sub ? <RNText numberOfLines={1} style={{ color: t.gray.a[11], fontSize: 12, lineHeight: 16 }}>{sub}</RNText> : null}
      </View>
      {right ? <View style={{ flexDirection: "row", gap: 4, flexShrink: 0 }}>{right}</View> : null}
    </Pressable>
  );
}
export type TileChoice = { value: string; title: ReactNode; sub?: ReactNode; right?: ReactNode };
/** pick one: `<id>-<value>` each, like RadioCards */
export function RadioTiles({ value, onChange, options, id, min, max }: { value: string; onChange: (v: string) => void; options: TileChoice[]; id?: string; min?: number; max?: number }) {
  return <Grid id={id} min={min} max={max}>{options.map((o) => <Tile key={o.value} id={id ? id + "-" + o.value : undefined} data={{ value: o.value }} on={o.value === value} onPress={() => onChange(o.value)} title={o.title} sub={o.sub} right={o.right} />)}</Grid>;
}
/** pick any */
export function CheckTiles({ value, onChange, options, id, min, max, mt }: { value: string[]; onChange: (v: string[]) => void; options: TileChoice[]; id?: string; min?: number; max?: number; mt?: Sp }) {
  const flip = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  return <Grid id={id} min={min} max={max} mt={mt}>{options.map((o) => <Tile key={o.value} check id={id ? id + "-" + o.value : undefined} data={{ value: o.value }} on={value.includes(o.value)} onPress={() => flip(o.value)} title={o.title} sub={o.sub} right={o.right} />)}</Grid>;
}
function Chevron({ open }: { open: boolean }) {
  const t = useTheme();
  return <RNText style={{ color: t.gray.a[9], fontSize: 18, lineHeight: 20, width: 12, textAlign: "center", transform: [{ rotate: open ? "90deg" : "0deg" }] }}>›</RNText>;
}
export function Settings({ children, mt = 4, id }: { children: ReactNode; mt?: Sp; id?: string }) {
  const t = useTheme();
  return <View {...ids(id)} style={{ marginTop: sp(mt), borderWidth: 1, borderColor: t.gray.a[6], borderRadius: radius[3], overflow: "hidden" }}>{children}</View>;
}
/** one row of Settings: `summary` is what is chosen now; `children` are the choices, shown while open */
export function Setting({ id, label, summary, open, onToggle, first, children }: { id?: string; label: string; summary: ReactNode; open: boolean; onToggle: () => void; first?: boolean; children: ReactNode }) {
  const t = useTheme();
  const plain = typeof summary === "string";
  return (
    <View style={{ borderTopWidth: first ? 0 : 1, borderTopColor: t.gray.a[5], backgroundColor: open ? t.gray.a[2] : undefined }}>
      <Pressable {...ids(id, { open: open ? "true" : "false" })} accessibilityRole="button" accessibilityState={{ expanded: open }} onPress={onToggle}
        style={({ pressed }) => [{ flexDirection: "row", alignItems: "center", gap: 12, minHeight: 44, paddingVertical: 8, paddingHorizontal: 12, backgroundColor: pressed ? t.gray.a[2] : undefined }, Platform.OS === "web" ? ({ cursor: "pointer" } as any) : null]}>
        <RNText style={{ width: 80, flexShrink: 0, color: t.gray.a[11], fontSize: 13, lineHeight: 20 }}>{label}</RNText>
        {plain ? <RNText numberOfLines={1} style={{ flex: 1, minWidth: 0, color: t.gray[12], fontSize: 14, lineHeight: 20 }}>{summary}</RNText>
          : <View style={{ flex: 1, minWidth: 0, flexDirection: "row", flexWrap: "wrap", alignItems: "center", gap: 4 }}>{summary}</View>}
        <Chevron open={open} />
      </Pressable>
      {open && <View {...ids(id ? id + "-pane" : undefined)} style={{ paddingHorizontal: 12, paddingBottom: 12 }}>{children}</View>}
    </View>
  );
}
/** a text button that shows or hides what follows it */
export function FoldLine({ open, onToggle, children, id }: { open: boolean; onToggle: () => void; children: string; id?: string }) {
  const t = useTheme();
  return (
    <Pressable {...ids(id)} accessibilityRole="button" accessibilityState={{ expanded: open }} onPress={onToggle} style={[{ flexDirection: "row", alignItems: "center", gap: 6, minHeight: 36, alignSelf: "flex-start" }, Platform.OS === "web" ? ({ cursor: "pointer" } as any) : null]}>
      <Chevron open={open} /><RNText style={{ color: t.accent.a[11], fontSize: 14, lineHeight: 20 }}>{children}</RNText>
    </Pressable>
  );
}
export function CountBadge({ n, id }: { n: number; id?: string }) {
  const t = useTheme();
  if (!n) return null;
  return (
    <View {...ids(id)} accessibilityLabel={`${n} waiting`} style={{ minWidth: 18, height: 18, borderRadius: 9, paddingHorizontal: 5, backgroundColor: t.c.red[9], alignItems: "center", justifyContent: "center", marginLeft: 6 }}>
      <RNText style={{ fontSize: 11, lineHeight: 14, fontWeight: "600", color: "#ffffff" }}>{n > 99 ? "99+" : String(n)}</RNText>
    </View>
  );
}
export function Tabs({ value, onChange, items, badges = {} }: { value: string; onChange: (v: string) => void; items: [string, string][]; badges?: Record<string, number> }) {
  const t = useTheme();
  return (
    <View nativeID="tablist" testID="tablist" style={{ marginHorizontal: -16, marginBottom: 12 }}>
      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={{ paddingHorizontal: 16 }}
        style={{ borderBottomWidth: 1, borderBottomColor: t.gray.a[5] }}>
        {items.map(([k, l]) => {
          const on = k === value;
          return (
            <Pressable key={k} {...ids("tab-" + k, { tab: k })} accessibilityRole="tab" accessibilityState={{ selected: on }} accessibilityLabel={l} onPress={() => onChange(k)}
              style={{ height: 40, justifyContent: "center", paddingHorizontal: 8 }}>
              {({ pressed }) => <>
                <View style={{ paddingHorizontal: 8, paddingVertical: 4, borderRadius: radius[2], backgroundColor: pressed ? t.gray.a[3] : "transparent", flexDirection: "row", alignItems: "center" }}>
                  <RNText style={{ fontSize: 14, lineHeight: 20, color: on ? t.gray[12] : t.gray.a[11], fontWeight: on ? "500" : "400" }}>{l}</RNText>
                  <CountBadge n={badges[k] || 0} id={"tab-badge-" + k} />
                </View>
                {on && <View style={{ position: "absolute", left: 0, right: 0, bottom: 0, height: 2, backgroundColor: t.accent[9] }} />}
              </>}
            </Pressable>
          );
        })}
      </ScrollView>
    </View>
  );
}

// status pill (a small uppercase badge)
export function Pill({ kind, children, spin }: { kind: "ok" | "dim" | "wait" | "bad" | "info"; children: ReactNode; spin?: boolean }) {
  const color = ({ ok: "green", dim: "gray", wait: "amber", bad: "red", info: "blue" } as const)[kind];
  return <Badge color={color} upper spin={spin}>{children}</Badge>;
}

// ---- facts as UI (Deyao, 2026-10-12: no prose pieced together by code) ------------------------
// A fact is a labelled row (label left, value right; the value wraps), a list of them is Rows, a
// status is a Badge/Pill. Text an LLM (or a person) wrote is a Quote labelled with its author.
export function Rows({ children, mt, mb, id, data }: { children: ReactNode; mt?: Sp; mb?: Sp; id?: string; data?: Record<string, string> }) {
  return <View {...ids(id, data)} style={{ marginTop: sp(mt), marginBottom: sp(mb), gap: 2 }}>{children}</View>;
}
export function Row({ label, children, id, mono: m, color, lines, selectable, data, part }: { label: string; children?: ReactNode; id?: string; mono?: boolean; color?: ColorName; lines?: number; selectable?: boolean; data?: Record<string, string>; part?: string }) {
  const t = useTheme();
  const plain = typeof children === "string" || typeof children === "number";
  // in a grid of cards, the same row lines up across the cards of one grid row (align.tsx); `part` names the row when
  // its label isn't unique in the card (a log line's time, a waiter's Purpose next to the holder's)
  return (
    <Aligned part={part || "row:" + label}><View {...ids(id, { row: label, ...data })} style={{ flexDirection: "row", alignItems: "flex-start", gap: 12, minHeight: 20 }}>
      <RNText style={{ width: 104, flexShrink: 0, color: t.gray.a[11], fontSize: 13, lineHeight: 20 }}>{label}</RNText>
      {plain
        ? <RNText numberOfLines={lines} selectable={selectable} style={{ flex: 1, minWidth: 0, color: color ? t.c[color].a[11] : t.gray[12], fontSize: m ? 12.5 : 14, lineHeight: 20, fontFamily: m ? mono : undefined }}>{children}</RNText>
        : <View style={{ flex: 1, minWidth: 0, flexDirection: "row", flexWrap: "wrap", alignItems: "center", gap: 4 }}>{children}</View>}
    </View></Aligned>
  );
}
/** a short list as badges (stores, fields); `none` when empty */
export function BadgeList({ items, none = "None", color = "gray" }: { items: string[]; none?: string; color?: ColorName }) {
  const t = useTheme();
  if (!items.length) return <RNText style={{ color: t.gray.a[11], fontSize: 14, lineHeight: 20 }}>{none}</RNText>;
  return <>{items.map((x) => <Badge key={x} color={color}>{x}</Badge>)}</>;
}
/** prose someone else wrote (an LLM's reason, a prompt), shown as theirs: a labelled, quoted block */
export function Quote({ by, children, id, lines, mt = 2, color = "gray" }: { by: string; children: ReactNode; id?: string; lines?: number; mt?: Sp; color?: ColorName }) {
  const t = useTheme();
  return (
    <View style={{ borderLeftWidth: 2, borderLeftColor: t.c[color].a[6], paddingLeft: 8, marginTop: sp(mt) }}>
      <RNText style={{ color: t.c[color].a[11], fontSize: 12, lineHeight: 16 }}>{by}</RNText>
      <RNText {...ids(id)} numberOfLines={lines} selectable style={{ color: t.gray[12], fontSize: 14, lineHeight: 20 }}>{children}</RNText>
    </View>
  );
}
