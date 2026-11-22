import { Accordion, NumberInput, PasswordInput, Select, Stack, Switch, Textarea, TextInput } from '@mantine/core';
import { useState, type ReactNode } from 'react';
import type { CatalogEntry, CatalogField, CheckConfig } from '../../api';
import { useLang, useT } from '../../i18n';
import { checkText } from '../checkText';

const L = {
  ru: {
    keyword: 'Ключевое слово', keyword_hint: 'Проверка упадёт, если этого текста нет в ответе', keyword_invert: 'Наоборот: падать, если текст есть',
    advanced: 'Тонкая настройка',
  },
  en: {
    keyword: 'Keyword', keyword_hint: 'The check fails when this text is not in the response', keyword_invert: 'Reverse: fail when the text is there',
    advanced: 'Fine tuning',
  },
};

/** Types whose settings live in their own struct; every other catalog type keeps them flat in params. */
export const STRUCT_TYPES = ['http', 'dns', 'tcp', 'tls'];
export const OWN_KEYS = ['xray', 'mtproto', 'http', 'tcp', 'tls', 'dns', 'params'] as const;

export const catalogKey = (e: CatalogEntry) => e.preset || e.type;

/** Drop empty strings/arrays/objects so the hub applies its defaults. */
export function clean<T>(v: T): T {
  if (Array.isArray(v)) return v.filter((x) => x !== '' && x != null).map(clean) as T;
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      const c = clean(x);
      if (c === '' || c == null || (Array.isArray(c) && c.length === 0) || (typeof c === 'object' && !Array.isArray(c) && Object.keys(c as object).length === 0)) continue;
      out[k] = c;
    }
    return out as T;
  }
  return v;
}

/** withType switches a check to a catalog entry, starting its settings from the entry's defaults. */
export function withType(x: CheckConfig, e: CatalogEntry): CheckConfig {
  const next: CheckConfig = { ...x, type: e.type };
  if (e.type === 'xray') next.xray ??= { link: '' };
  else if (e.type === 'mtproto') next.mtproto ??= { link: '' };
  else if (STRUCT_TYPES.includes(e.type)) (next as unknown as Record<string, unknown>)[e.type] ??= {};
  else {
    const params: Record<string, string> = {};
    for (const f of e.fields ?? []) if (f.default) params[f.name] = f.default;
    next.params = params;
  }
  return next;
}

/** ownSettings keeps only the settings of the check's own type: what other types left behind is not sent. */
export function ownSettings(d: CheckConfig): CheckConfig {
  const body: CheckConfig = { ...d };
  for (const k of OWN_KEYS) {
    const own = d.type === k || (k === 'params' && !STRUCT_TYPES.includes(d.type) && d.type !== 'xray' && d.type !== 'mtproto');
    if (!own) delete body[k];
  }
  return body;
}

// Headers are one "Name: value" per line in the form and a map in the API.
const headersToText = (h?: Record<string, string>) => Object.entries(h ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n');
function textToHeaders(s: string) {
  const out: Record<string, string> = {};
  for (const line of s.split('\n')) {
    const i = line.indexOf(':');
    if (i > 0) out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

/**
 * CheckFields renders a catalog type's settings: the main fields, the shared
 * keyword for text-returning types, `children`, then the advanced fields
 * folded away. The check form and Tools both use it.
 */
export function CheckFields({ d, info, onChange, children }: { d: CheckConfig; info?: CatalogEntry; onChange: (patch: Partial<CheckConfig>) => void; children?: ReactNode }) {
  const t = useT(L);
  const { lang } = useLang();
  const words = checkText[lang] as Record<string, string>;
  const [headers, setHeaders] = useState(headersToText(d.http?.headers));

  // A field's value lives in the type's own struct for http, dns, tcp, tls, and in params for the rest.
  const structured = info ? STRUCT_TYPES.includes(info.type) : false;
  const bag = (): Record<string, unknown> => (structured ? ((d as unknown as Record<string, Record<string, unknown>>)[d.type] ?? {}) : d.params ?? {});
  const fieldValue = (name: string): string => {
    const v = bag()[name];
    if (name === 'accepted_status' && Array.isArray(v)) return v.join(', ');
    return v == null ? '' : String(v);
  };
  const setField = (f: CatalogField, raw: string | boolean) => {
    if (structured) {
      let v: unknown = raw;
      if (f.name === 'accepted_status') v = String(raw).split(/[,\s]+/).filter(Boolean);
      else if (f.kind === 'number') v = raw === '' ? undefined : Number(raw);
      onChange({ [d.type]: { ...bag(), [f.name]: v } } as Partial<CheckConfig>);
    } else {
      const v = typeof raw === 'boolean' ? (raw ? 'true' : '') : String(raw);
      onChange({ params: { ...(d.params ?? {}), [f.name]: v } });
    }
  };
  const visible = (f: CatalogField) => {
    if (!f.show_if) return true;
    const [k, want] = f.show_if.split('=');
    return (fieldValue(k) || info?.fields?.find((x) => x.name === k)?.default || '') === want;
  };

  const renderField = (f: CatalogField) => {
    if (!visible(f) || (f.name === 'token' && d.type === 'push')) return null;
    const common = { label: words[`f_${f.name}`] ?? f.name, description: words[`h_${f.name}`], required: f.required };
    const mono = { input: { fontFamily: 'var(--mantine-font-family-monospace)', fontSize: 12 } };
    if (f.name === 'headers' && d.type === 'http') {
      return <Textarea key={f.name} {...common} autosize minRows={2} maxRows={8} styles={mono} placeholder="Authorization: Bearer …" value={headers} onChange={(e) => { const v = e.currentTarget.value; setHeaders(v); onChange({ http: { ...d.http!, headers: textToHeaders(v) } }); }} />;
    }
    switch (f.kind) {
      case 'password':
        return <PasswordInput key={f.name} {...common} autoComplete="new-password" value={fieldValue(f.name)} onChange={(e) => setField(f, e.currentTarget.value)} />;
      case 'number':
        return <NumberInput key={f.name} {...common} placeholder={f.default} hideControls value={fieldValue(f.name)} onChange={(v) => setField(f, String(v))} />;
      case 'bool':
        return <Switch key={f.name} label={common.label} description={common.description} checked={fieldValue(f.name) === 'true'} onChange={(e) => setField(f, e.currentTarget.checked)} />;
      case 'select':
        return <Select key={f.name} {...common} allowDeselect={!f.required} clearable={!f.required} placeholder={f.default} data={(f.options ?? []).map((o) => ({ value: o, label: words[`o_${o}`] ?? o }))} value={fieldValue(f.name) || f.default || null} onChange={(v) => setField(f, v ?? '')} />;
      case 'textarea':
        return <Textarea key={f.name} {...common} autosize minRows={3} maxRows={14} styles={mono} value={fieldValue(f.name)} onChange={(e) => setField(f, e.currentTarget.value)} />;
    }
    return <TextInput key={f.name} {...common} value={fieldValue(f.name)} onChange={(e) => setField(f, e.currentTarget.value)} />;
  };

  const fields = info?.fields ?? [];
  const main = fields.filter((f) => !f.advanced);
  const extra = fields.filter((f) => f.advanced);
  // http has its own keyword fields; other text-returning types share the spec-level ones.
  const sharedKeyword = !!info?.keyword && info.type !== 'http';

  return (
    <>
      {main.map(renderField)}
      {sharedKeyword && (
        <Stack gap="xs">
          <TextInput label={t('keyword')} description={t('keyword_hint')} value={d.keyword ?? ''} onChange={(e) => onChange({ keyword: e.currentTarget.value })} />
          {!!d.keyword && <Switch label={t('keyword_invert')} checked={!!d.keyword_invert} onChange={(e) => onChange({ keyword_invert: e.currentTarget.checked })} />}
        </Stack>
      )}
      {children}
      {extra.some(visible) && (
        <Accordion variant="contained" radius="md">
          <Accordion.Item value="adv">
            <Accordion.Control>{t('advanced')}</Accordion.Control>
            <Accordion.Panel><Stack gap="sm">{extra.map(renderField)}</Stack></Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      )}
    </>
  );
}
