import {
  Alert, Anchor, Badge, Box, Button, Card, Drawer, Group, ScrollArea, Skeleton, Stack, Table, Text, Tooltip,
} from '@mantine/core';
import { IconAlertTriangle, IconBan, IconLockOpen, IconShieldCheck, IconShieldLock, IconUserCheck } from '@tabler/icons-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { api, queryClient, useAbuse, useAbuseUser, type AbuseEvent, type AbuseRow } from '../api';
import { confirmThen } from '../components/guards';
import { Empty, Section } from '../components/Cards';
import { clickableRow, notifyError, notifyOk, PageHeader, QueryError } from '../components/Misc';
import { Dot } from '../components/Status';
import { ago, clock, since } from '../format';
import { useCommon, useLang, useT } from '../i18n';
import { status } from '../theme';

const L = {
  ru: {
    title: 'Антифрод', subtitle: 'Клиенты, которые сидят с намного большего числа адресов, чем позволяет лимит устройств',
    mode_off: 'Выключен', mode_notify: 'Уведомления', mode_ban: 'Уведомления и блокировка', settings: 'Настройки',
    off_hint: 'Антифрод выключен. Включить: Настройки → Remnawave → Антифрод.',
    cover: 'Ноды ответили {0} из {1} · опрос {2}', cover_wait: 'Ещё не опрашивал', users: 'пользователей в панели: {0}',
    client: 'Клиент', limit: 'Лимит', now: 'Сейчас', day: 'За 24 ч', nodes: 'Ноды', state: 'Состояние', last: 'Последнее событие',
    s_banned: 'заблокирован', s_ban: 'выше порога блокировки {0}', s_notify: 'выше порога {0}', s_ok: 'в норме',
    a_notify: 'уведомление', a_would_ban: 'был бы заблокирован', a_ban: 'заблокирован', a_ban_failed: 'не удалось заблокировать', a_enable: 'разблокирован вручную',
    empty: 'Подозрительных клиентов нет', empty_hint: 'Здесь появятся клиенты выше порога и все, по кому были события за неделю.',
    addresses: 'Адреса', prefix: 'Адрес', first: 'Впервые', seen: 'Последний раз', history: 'История', no_addr: 'Адресов за срок хранения нет',
    allow: 'В белый список', allow_title: 'Добавить в белый список?', allow_body: 'Пользователь {0} больше не будет проверяться: ни уведомлений, ни блокировки. Убрать можно в настройках антифрода.', allow_ok: 'Добавлен в белый список',
    enable: 'Разблокировать', enable_title: 'Разблокировать в панели?', enable_body: 'Подписка пользователя {0} снова включится в Remnawave, отсчёт антифрода начнётся заново.', enable_ok: 'Подписка включена',
    tg: 'Telegram',
  },
  en: {
    title: 'Antifraud', subtitle: 'Subscribers connecting from far more addresses than their device limit allows',
    mode_off: 'Off', mode_notify: 'Notify', mode_ban: 'Notify and ban', settings: 'Settings',
    off_hint: 'The antifraud is off. Turn it on in Settings → Remnawave → Antifraud.',
    cover: 'Nodes answered: {0} of {1} · polled {2}', cover_wait: 'Not polled yet', users: 'users in the panel: {0}',
    client: 'Subscriber', limit: 'Limit', now: 'Now', day: '24 h', nodes: 'Nodes', state: 'State', last: 'Last event',
    s_banned: 'banned', s_ban: 'over the ban threshold {0}', s_notify: 'over the threshold {0}', s_ok: 'normal',
    a_notify: 'notice', a_would_ban: 'would be banned', a_ban: 'banned', a_ban_failed: 'ban failed', a_enable: 'unbanned by hand',
    empty: 'No suspicious subscribers', empty_hint: 'Subscribers over a threshold show here, and everyone with an event this week.',
    addresses: 'Addresses', prefix: 'Address', first: 'First seen', seen: 'Last seen', history: 'History', no_addr: 'No addresses within the retention',
    allow: 'Allowlist', allow_title: 'Add to the allowlist?', allow_body: 'User {0} will no longer be judged: no messages, no bans. Remove it in the antifraud settings.', allow_ok: 'Added to the allowlist',
    enable: 'Unban', enable_title: 'Unban in the panel?', enable_body: 'The subscription of user {0} is turned back on in Remnawave and its count starts over.', enable_ok: 'Subscription enabled',
    tg: 'Telegram',
  },
};

function useEventText() {
  const t = useT(L);
  return (e: AbuseEvent) => (e.action === 'ban' && e.error ? t('a_ban_failed') : t(`a_${e.action}` as 'a_notify'));
}

function who(r: { user: { id: number; username?: string } }) {
  return r.user.username ? `${r.user.username} · ${r.user.id}` : String(r.user.id);
}

function StateCell({ row }: { row: AbuseRow }) {
  const t = useT(L);
  const { lang } = useLang();
  if (row.ban_failed) return <Badge color="orange" variant="light" tt="none" leftSection={<IconAlertTriangle size={12} />}>{t('a_ban_failed')}</Badge>;
  if (row.banned_at) return <Badge color="red" variant="light" tt="none" leftSection={<IconBan size={12} />}>{t('s_banned')}</Badge>;
  if (row.level === 'ban') return <Badge color="red" variant="outline" tt="none">{t('s_ban', row.since ? since(row.since, lang) : '')}</Badge>;
  if (row.level === 'notify') return <Badge color="orange" variant="outline" tt="none">{t('s_notify', row.since ? since(row.since, lang) : '')}</Badge>;
  return <Text size="sm" c="dimmed">{t('s_ok')}</Text>;
}

function UserDrawer({ id, onClose }: { id: number | null; onClose: () => void }) {
  const t = useT(L);
  const c = useCommon();
  const q = useAbuseUser(id);
  const evText = useEventText();
  const [busy, setBusy] = useState('');
  const d = q.data;
  const act = (kind: 'allow' | 'enable') => {
    if (id == null) return;
    confirmThen({
      title: t(`${kind}_title`), body: t(`${kind}_body`, d?.user.username || id), confirm: t(kind), cancel: c('cancel'),
      onConfirm: async () => {
        setBusy(kind);
        try {
          await api('POST', `/api/v1/abuse/${id}/${kind}`);
          notifyOk(t(`${kind}_ok`));
          await queryClient.invalidateQueries({ queryKey: ['abuse'] });
          if (kind === 'allow') await queryClient.invalidateQueries({ queryKey: ['settings'] });
        } catch (e) {
          notifyError(e);
        } finally {
          setBusy('');
        }
      },
    });
  };
  const banned = (!!d?.state.banned_at && !d?.state.ban_failed) || d?.user.status === 'DISABLED';
  return (
    <Drawer opened={id != null} onClose={onClose} position="right" size="lg" title={d ? <Text fw={700}>{who(d)}</Text> : null}>
      {q.isLoading || !d ? <Skeleton h={200} /> : (
        <Stack gap="lg">
          <Group gap="sm">
            {d.user.telegram_id ? <Badge variant="light">{t('tg')} {d.user.telegram_id}</Badge> : null}
            <Badge variant="light" color="gray">{t('limit')}: {d.user.limit}</Badge>
            {d.user.status && <Badge variant="light" color={d.user.status === 'ACTIVE' ? 'teal' : 'red'}>{d.user.status}</Badge>}
          </Group>
          <Group gap="sm">
            <Button variant="light" leftSection={<IconUserCheck size={16} />} loading={busy === 'allow'} onClick={() => act('allow')}>{t('allow')}</Button>
            {banned && <Button variant="light" color="teal" leftSection={<IconLockOpen size={16} />} loading={busy === 'enable'} onClick={() => act('enable')}>{t('enable')}</Button>}
          </Group>
          <Section title={t('addresses')}>
            {d.addresses.length === 0 ? <Text size="sm" c="dimmed">{t('no_addr')}</Text> : (
              <ScrollArea type="auto">
                <Table striped miw={480}>
                  <Table.Thead><Table.Tr><Table.Th>{t('prefix')}</Table.Th><Table.Th>{t('nodes')}</Table.Th><Table.Th>{t('first')}</Table.Th><Table.Th>{t('seen')}</Table.Th></Table.Tr></Table.Thead>
                  <Table.Tbody>
                    {d.addresses.map((a) => (
                      <Table.Tr key={a.prefix}>
                        <Table.Td><Text size="sm" ff="monospace">{a.prefix}</Text></Table.Td>
                        <Table.Td><Text size="sm">{a.nodes.join(', ')}</Text></Table.Td>
                        <Table.Td><Text size="sm">{clock(a.first, true)}</Text></Table.Td>
                        <Table.Td><Text size="sm">{clock(a.last, true)}</Text></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            )}
          </Section>
          <Section title={t('history')}>
            <Stack gap={6}>
              {d.events.map((e, i) => (
                <Group key={i} gap={8} wrap="nowrap" align="flex-start">
                  <Text size="sm" c="dimmed" miw={120}>{clock(e.at, true)}</Text>
                  <Box>
                    <Text size="sm" fw={600}>{evText(e)}</Text>
                    <Text size="xs" c="dimmed">{t('limit')} {e.limit} · {t('now')} {e.now} · {t('day')} {e.day}{e.nodes.length ? ` · ${e.nodes.join(', ')}` : ''}</Text>
                    {e.error && <Text size="xs" c="red">{e.error}</Text>}
                  </Box>
                </Group>
              ))}
            </Stack>
          </Section>
        </Stack>
      )}
    </Drawer>
  );
}

export default function Abuse() {
  const t = useT(L);
  const { lang } = useLang();
  const q = useAbuse();
  const evText = useEventText();
  const [open, setOpen] = useState<number | null>(null);
  if (q.isError) return (<><PageHeader title={t('title')} /><QueryError error={q.error} onRetry={() => q.refetch()} /></>);
  const v = q.data;
  const cov = v?.coverage;
  const modeColor = cov?.mode === 'ban' ? 'red' : cov?.mode === 'off' ? 'gray' : 'orange';
  return (
    <>
      <PageHeader
        title={t('title')} subtitle={t('subtitle')}
        right={cov && (
          <Group gap="sm">
            <Badge size="lg" variant="light" color={modeColor} leftSection={<IconShieldLock size={14} />}>{t(`mode_${cov.mode || 'notify'}` as 'mode_off')}</Badge>
            <Anchor component={Link} to="/settings/remnawave" size="sm">{t('settings')}</Anchor>
          </Group>
        )}
      />
      {!v ? <Skeleton h={240} radius="lg" /> : (
        <Stack gap="lg">
          {cov?.mode === 'off' && <Alert color="gray" variant="light">{t('off_hint')}</Alert>}
          {cov?.mode !== 'off' && (
            <Group gap={8} wrap="nowrap" align="flex-start">
              <Dot color={!cov?.at ? status.unknown : cov.answered === 0 ? status.down : cov.answered < cov.nodes ? status.partial : status.ok} />
              <Text size="sm" style={{ marginTop: -4 }}>
                {cov?.at ? t('cover', cov.answered, cov.nodes, ago(cov.at, lang)) : t('cover_wait')}
                {cov?.users ? ` · ${t('users', cov.users)}` : ''}
              </Text>
              {cov?.error && <Tooltip label={cov.error} multiline maw={420}><IconAlertTriangle size={16} color="var(--mantine-color-orange-6)" /></Tooltip>}
            </Group>
          )}
          {v.rows.length === 0 ? (
            <Empty icon={IconShieldCheck} title={t('empty')}><Text size="sm" c="dimmed">{t('empty_hint')}</Text></Empty>
          ) : (
            <Card padding={0}>
              <ScrollArea type="auto">
                <Table highlightOnHover miw={820} verticalSpacing="sm">
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t('client')}</Table.Th><Table.Th ta="right">{t('limit')}</Table.Th><Table.Th ta="right">{t('now')}</Table.Th>
                      <Table.Th ta="right">{t('day')}</Table.Th><Table.Th>{t('nodes')}</Table.Th><Table.Th>{t('state')}</Table.Th><Table.Th>{t('last')}</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {v.rows.map((r) => (
                      <Table.Tr key={r.user.id} {...clickableRow(() => setOpen(r.user.id))}>
                        <Table.Td>
                          <Text size="sm" fw={600}>{r.user.username || r.user.id}</Text>
                          <Text size="xs" c="dimmed" ff="monospace">{r.user.id}{r.user.telegram_id ? ` · tg ${r.user.telegram_id}` : ''}</Text>
                        </Table.Td>
                        <Table.Td ta="right"><Text size="sm" className="uf-num">{r.limit}</Text></Table.Td>
                        <Table.Td ta="right"><Text size="sm" fw={700} className="uf-num">{r.now || '—'}</Text></Table.Td>
                        <Table.Td ta="right"><Text size="sm" className="uf-num">{r.day || '—'}</Text></Table.Td>
                        <Table.Td><Text size="sm" lineClamp={1}>{(r.nodes ?? []).join(', ') || '—'}</Text></Table.Td>
                        <Table.Td><StateCell row={r} /></Table.Td>
                        <Table.Td>
                          {r.last_event ? (
                            <Box>
                              <Text size="sm" c={r.last_event.error ? 'red' : undefined}>{evText(r.last_event)}</Text>
                              <Text size="xs" c="dimmed">{ago(r.last_event.at, lang)}</Text>
                            </Box>
                          ) : <Text size="sm" c="dimmed">—</Text>}
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Card>
          )}
        </Stack>
      )}
      <UserDrawer id={open} onClose={() => setOpen(null)} />
    </>
  );
}
