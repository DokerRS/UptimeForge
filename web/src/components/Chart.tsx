import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as echarts from 'echarts/core';
import { BarChart, LineChart } from 'echarts/charts';
import {
  DataZoomComponent, GridComponent, LegendComponent, MarkAreaComponent, MarkLineComponent, ToolboxComponent, TooltipComponent,
} from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import type { EChartsCoreOption } from 'echarts/core';
import { CHART_STYLES, usePrefs, type ChartStyle } from '../prefs';
import { chartPalette, findTheme } from '../themes';

echarts.use([
  LineChart, BarChart, GridComponent, TooltipComponent, LegendComponent, MarkAreaComponent, MarkLineComponent, ToolboxComponent,
  DataZoomComponent, CanvasRenderer,
]);

export type Pal = ReturnType<typeof chartPalette>;

export function usePalette(): Pal {
  const { prefs } = usePrefs();
  return useMemo(() => chartPalette(findTheme(prefs.theme)), [prefs.theme]);
}

/** useChartStyle is the user's chart style; anything unknown falls back to zabbix. */
export function useChartStyle(): ChartStyle {
  const { prefs } = usePrefs();
  return prefs.chart && CHART_STYLES.includes(prefs.chart) ? prefs.chart : 'zabbix';
}

/**
 * Chart renders an ECharts option and keeps it sized to its container.
 * Charts sharing a group move one crosshair together; with onZoom, dragging
 * across the plot selects a time window, and onReset runs on a double click.
 */
export function Chart({ option, height = 240, group, onZoom, onReset }: {
  option: EChartsCoreOption; height?: number; group?: string; onZoom?: (from: number, to: number) => void; onReset?: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);
  const zoom = useRef(onZoom);
  zoom.current = onZoom;
  const reset = useRef(onReset);
  reset.current = onReset;

  useEffect(() => {
    if (!ref.current) return;
    const c = echarts.init(ref.current, undefined, { renderer: 'canvas' });
    chart.current = c;
    if (group) {
      c.group = group;
      echarts.connect(group);
    }
    c.on('datazoom', (e: unknown) => {
      // A box selection reports either values or percents of the axis,
      // depending on the path it took; turn both into times.
      type Z = { startValue?: number; endValue?: number; start?: number; end?: number };
      const ev = e as Z & { batch?: Z[] };
      const opt = c.getOption() as { dataZoom?: Z[]; xAxis?: { min?: number; max?: number }[] };
      const z: Z = { ...opt.dataZoom?.[0], ...(ev.batch?.[0] ?? ev) };
      let from = z.startValue, to = z.endValue;
      const ax = opt.xAxis?.[0];
      if ((from == null || to == null) && z.start != null && z.end != null && ax?.min != null && ax?.max != null) {
        from = ax.min + ((ax.max - ax.min) * z.start) / 100;
        to = ax.min + ((ax.max - ax.min) * z.end) / 100;
      }
      if (from != null && to != null && to - from >= 60_000) zoom.current?.(from, to);
    });
    // Linked charts share the crosshair; only the one under the mouse shows its tooltip.
    const el = ref.current;
    const show = (on: boolean) => () => c.setOption({ tooltip: { showContent: on } });
    const enter = show(true), leave = show(false);
    const dbl = () => reset.current?.();
    el.addEventListener('mouseenter', enter);
    el.addEventListener('mouseleave', leave);
    el.addEventListener('dblclick', dbl);
    const ro = new ResizeObserver(() => c.resize());
    ro.observe(ref.current);
    return () => {
      el.removeEventListener('mouseenter', enter);
      el.removeEventListener('mouseleave', leave);
      el.removeEventListener('dblclick', dbl);
      ro.disconnect();
      c.dispose();
      chart.current = null;
    };
  }, [group]);

  useEffect(() => {
    const c = chart.current;
    if (!c) return;
    c.setOption(option, { notMerge: true, lazyUpdate: false });
    if (group) c.setOption({ tooltip: { showContent: ref.current?.matches(':hover') ?? false } });
    if (onZoom) c.dispatchAction({ type: 'takeGlobalCursor', key: 'dataZoomSelect', dataZoomSelectActive: true });
  }, [option, onZoom]);

  return <div ref={ref} style={{ width: '100%', height, cursor: onZoom ? 'crosshair' : undefined }} />;
}

export interface LineSeries {
  name: string;
  color: string;
  data: [number, number | null][];
  /** Peaks of each bucket: they feed the legend's max where averages hide spikes. */
  peak?: [number, number | null][];
  /** Optional min/max band drawn as a faint ribbon behind the line. */
  band?: [number, number | null, number | null][];
  area?: boolean;
  dashed?: boolean;
  /** Series sharing a stack name are drawn on top of each other. */
  stack?: string;
  /** Barely there: a hint of fill, no line. For the remainder of a stack, like CPU idle. */
  faint?: boolean;
  /** The chart's main series, filled under its line: incoming traffic, load 1m. */
  fill?: boolean;
  /** A secondary line drawn thinner, so the main series stays readable. */
  thin?: boolean;
  /** The outgoing half of an in/out pair: drawn below zero in the mirror style. */
  mirror?: boolean;
}

interface TimeOpts {
  series: LineSeries[];
  pal: Pal;
  format: (v: number) => string;
  axisFormat?: (v: number) => string;
  min?: number;
  max?: number | ((v: { max: number }) => number);
  interval?: number;
  from?: number;
  to?: number;
  marks?: { from: number; to: number; color: string; label: string }[];
  /** Horizontal references such as core count or total memory. */
  lines?: { value: number; label: string }[];
  stack?: boolean;
  /** Our own legend table replaces the built-in one. */
  legend?: boolean;
  zoom?: boolean;
  style?: ChartStyle;
  /**
   * When there are more points than pixels, each pixel draws the average (or
   * the max, for peaks) of its points: a week of 1-minute buckets is otherwise
   * a solid comb. Unset draws every point.
   */
  sampling?: 'average' | 'max';
  /** The UI language, for weekday names on the time axis. */
  lang?: string;
}

/** Windows this short (the live minute, a tight zoom) label time to the second. */
const SECONDS_SPAN = 10 * 60_000;
/** Windows longer than this name the weekday next to each date. */
const WEEKDAY_SPAN = 2 * 86400_000;

/**
 * timeLabel names a tick on the time axis by the calendar: a tick at local
 * midnight shows its date (bold, through the "d" rich style), any other tick
 * its time. So a zoom across three days reads "12.11 06:00 12:00 18:00 13.11",
 * never the same date four times.
 */
export function timeLabel(ms: number, spanMs: number, lang = 'en') {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  if (spanMs <= SECONDS_SPAN) return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  if (d.getHours() === 0 && d.getMinutes() === 0) {
    const date = `${p(d.getDate())}.${p(d.getMonth() + 1)}`;
    if (spanMs <= WEEKDAY_SPAN) return `{d|${date}}`;
    const wd = d.toLocaleDateString(lang, { weekday: 'short' }).replace('.', '');
    return `{d|${wd.charAt(0).toUpperCase()}${wd.slice(1)} ${date}}`;
  }
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** midnights lists every local midnight strictly inside the window: the day boundaries. */
export function midnights(from: number, to: number): number[] {
  const out: number[] = [];
  const d = new Date(from);
  d.setHours(24, 0, 0, 0);
  for (; d.getTime() < to && out.length < 400; d.setDate(d.getDate() + 1)) out.push(d.getTime());
  return out;
}

/**
 * gapped breaks the line where data is missing: ECharts joins any two
 * neighbouring points, which would draw an agent that was offline for an
 * hour as a smooth line through the outage.
 */
export function gapped(data: [number, number | null][]): [number, number | null][] {
  if (data.length < 3) return data;
  const steps = data.slice(1).map(([t], i) => t - data[i][0]).sort((a, b) => a - b);
  const step = steps[Math.floor(steps.length / 2)];
  if (!step) return data;
  const out: [number, number | null][] = [data[0]];
  for (let i = 1; i < data.length; i++) {
    if (data[i][0] - data[i - 1][0] > step * 2.5) out.push([data[i - 1][0] + step, null]);
    out.push(data[i]);
  }
  return out;
}

function escapeHTML(s: string) {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
}

function tipTime(ms: number, spanMs: number) {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getDate())}.${p(d.getMonth() + 1)} ${p(d.getHours())}:${p(d.getMinutes())}${spanMs <= SECONDS_SPAN ? `:${p(d.getSeconds())}` : ''}`;
}

/**
 * timeOption builds the house style for time series: 2px lines, one y-axis,
 * crosshair tooltip, day boundaries, and a legend only when there is more than
 * one series. The style decides the rest: zabbix (default) draws straight
 * segments over a full grid with the main series filled; smooth curves the
 * lines over a 10% wash; mirror is zabbix with mirror series below zero.
 */
export function timeOption(o: TimeOpts): EChartsCoreOption {
  const { pal } = o;
  const style = o.style ?? 'zabbix';
  const grid = style !== 'smooth';
  const from = o.from ?? Date.now() - 86400_000, to = o.to ?? Date.now();
  const span = to - from;
  const multi = o.series.length > 1;
  const showLegend = multi && o.legend !== false;
  // Mirror flips the outgoing half of a pair below zero; values everywhere
  // else (tooltip, axis) read as magnitudes, so the sign is only geometry.
  const flipped = (s: LineSeries) => style === 'mirror' && !!s.mirror;
  const anyFlipped = o.series.some(flipped);
  const mag = (f: (v: number) => string) => (anyFlipped ? (v: number) => f(Math.abs(v)) : f);
  const fmt = mag(o.format), axisFmt = mag(o.axisFormat ?? o.format);
  // Day boundaries on windows long enough to hold one, marked on the first series.
  const days = span > 2 * 3600_000 ? midnights(from, to) : [];
  const vlines = days.map((t) => ({ xAxis: t, label: { show: false }, lineStyle: { color: pal.axis, type: 'solid', width: 1, opacity: 0.7 } }));
  const hlines: object[] = (o.lines ?? []).map((l) => ({ yAxis: l.value, name: l.label }));
  if (anyFlipped) hlines.push({ yAxis: 0, label: { show: false }, lineStyle: { color: pal.axis, type: 'solid', width: 1 } });
  // As in Zabbix the main series is a solid shape and the other half of its
  // pair a line over it (mirror fills both, they no longer overlap); of two
  // shapes the bigger goes behind, or it would hide the smaller.
  const solid = (s: LineSeries) => grid && !s.thin && !s.faint && !(s.stack || o.stack) && !!(s.fill || s.area || !multi || flipped(s));
  const mean = (s: LineSeries) => {
    let sum = 0, n = 0;
    for (const [, v] of s.data) if (v != null && isFinite(v)) { sum += v; n++; }
    return n ? sum / n : 0;
  };
  const drawn = grid
    ? [...o.series.filter(solid).sort((a, b) => mean(b) - mean(a)), ...o.series.filter((s) => !solid(s))]
    : o.series;
  // Every other day shaded on long windows, as in Zabbix: the week reads by days.
  const bands = grid && span > 36 * 3600_000
    ? [from, ...days, to].slice(0, -1).map((t, i, a) => [t, a[i + 1] ?? to] as const).filter((_, i) => i % 2 === 1)
    : [];
  const areas = [
    ...bands.map(([a, b]) => [{ xAxis: a, itemStyle: { color: pal.grid, opacity: 0.45 } }, { xAxis: b }]),
    ...(o.marks ?? []).map((m) => [{ xAxis: m.from, itemStyle: { color: m.color, opacity: 0.12 } }, { xAxis: m.to }]),
  ];
  const series: unknown[] = [];
  for (const s of drawn) {
    if (s.band) {
      // Ribbon: invisible lower edge + stacked difference, both silent.
      series.push(
        { type: 'line', name: `${s.name}__lo`, stack: `band-${s.name}`, symbol: 'none', silent: true, lineStyle: { opacity: 0 },
          data: s.band.map(([t, lo]) => [t, lo]), tooltip: { show: false }, z: 1 },
        { type: 'line', name: `${s.name}__hi`, stack: `band-${s.name}`, symbol: 'none', silent: true, lineStyle: { opacity: 0 },
          areaStyle: { color: s.color, opacity: 0.12 }, data: s.band.map(([t, lo, hi]) => [t, hi != null && lo != null ? hi - lo : null]),
          tooltip: { show: false }, z: 1 },
      );
    }
    const stacked = !!(s.stack || o.stack);
    const flip = flipped(s);
    const data = flip ? gapped(s.data).map(([t, v]): [number, number | null] => [t, v == null ? null : -v]) : gapped(s.data);
    // Fill: a stack always; solid in the grid styles; smooth keeps a light
    // wash under the main series, an explicit area or a lone series.
    const area = s.faint ? { color: s.color, opacity: 0.05 }
      : stacked ? { color: s.color, opacity: grid ? 0.7 : 0.45 }
      : solid(s) ? { color: s.color, opacity: 0.7 }
      : !grid && (s.fill || (s.area ?? !multi)) ? { color: s.color, opacity: 0.1 }
      : undefined;
    const first = s === drawn[0];
    series.push({
      type: 'line',
      name: s.name,
      data,
      showSymbol: false,
      symbolSize: 7,
      connectNulls: false,
      sampling: o.sampling,
      smooth: stacked || grid ? false : 0.15,
      stack: s.stack ?? (o.stack ? 'total' : undefined),
      lineStyle: { width: s.faint ? 0 : stacked ? 1.5 : s.thin ? 1.25 : 2, color: s.color, type: s.dashed ? 'dashed' : 'solid', cap: 'round', join: 'round' },
      itemStyle: { color: s.color, borderColor: pal.surface, borderWidth: 2 },
      areaStyle: area,
      // Fills do not fade on hover: a pair is read together.
      emphasis: { focus: multi && !grid ? 'series' : 'none', lineStyle: { width: s.thin ? 1.25 : 2 } },
      markArea: areas.length && first ? { silent: true, z: 0, data: areas } : undefined,
      markLine: (hlines.length || vlines.length) && first
        ? {
            silent: true, symbol: 'none', animation: false,
            lineStyle: { color: pal.muted, type: [4, 4], width: 1 },
            label: { position: 'insideEndTop', color: pal.muted, fontSize: 10, formatter: (p: { name: string }) => p.name },
            data: [...vlines, ...hlines],
          }
        : undefined,
      // Fills sit under the plain lines they are compared with.
      z: area && !stacked ? 1 : 2,
    });
  }
  const gridLine = { color: pal.grid, width: 1, type: grid ? [3, 3] : 'solid' };
  return {
    animation: false,
    grid: { left: 8, right: 16, top: showLegend ? 36 : 14, bottom: 4, containLabel: true },
    legend: showLegend
      ? {
          top: 0, left: 0, icon: 'roundRect', itemWidth: 12, itemHeight: 4, itemGap: 16,
          textStyle: { color: pal.textSecondary, fontFamily: 'inherit', fontSize: 12 },
          data: o.series.map((s) => s.name),
        }
      : undefined,
    toolbox: o.zoom
      ? { show: true, itemSize: 0, right: -100, feature: { dataZoom: { yAxisIndex: 'none', brushStyle: { color: 'rgba(57,135,229,0.12)', borderColor: 'rgba(57,135,229,0.6)', borderWidth: 1 } } } }
      : undefined,
    tooltip: {
      trigger: 'axis',
      confine: true,
      backgroundColor: pal.surface,
      borderColor: pal.grid,
      borderWidth: 1,
      padding: [8, 12],
      textStyle: { color: pal.text, fontSize: 12 },
      axisPointer: { type: 'line', lineStyle: { color: pal.axis, width: 1 } },
      formatter: (params: { seriesName: string; value: [number, number | null]; color: string }[]) => {
        const rows = params.filter((p) => !p.seriesName.includes('__') && p.value[1] != null);
        if (!params.length) return '';
        const head = `<div style="color:${pal.muted};margin-bottom:6px">${tipTime(params[0].value[0], span)}</div>`;
        const v = (p: { value: [number, number | null] }) => Math.abs(p.value[1] ?? 0);
        const ordered = o.stack || o.series.some((s) => s.stack) ? rows.reverse() : rows.sort((a, b) => v(b) - v(a));
        return head + ordered
          .map((p) =>
            `<div style="display:flex;align-items:center;gap:14px;justify-content:space-between;min-width:170px">` +
            `<span><span style="display:inline-block;width:10px;height:3px;border-radius:2px;background:${p.color};margin-right:8px;vertical-align:middle"></span>${escapeHTML(p.seriesName)}</span>` +
            `<b style="font-family:var(--mantine-font-family-monospace)">${fmt(p.value[1]!)}</b></div>`)
          .join('');
      },
    },
    xAxis: {
      type: 'time',
      min: o.from,
      max: o.to,
      // The time axis stays at the bottom even when a mirror pair goes below zero.
      axisLine: { onZero: false, lineStyle: { color: pal.axis } },
      axisTick: { show: grid, lineStyle: { color: pal.axis } },
      splitLine: { show: grid, lineStyle: gridLine },
      axisLabel: {
        color: pal.muted, fontSize: 11, hideOverlap: true, formatter: (t: number) => timeLabel(t, span, o.lang),
        rich: { d: { color: pal.textSecondary, fontWeight: 650, fontSize: 11 } },
      },
    },
    yAxis: {
      type: 'value',
      // A mirrored pair needs room below zero; any other floor stays.
      min: anyFlipped && o.min === 0 ? undefined : o.min,
      max: o.max,
      interval: o.interval,
      splitNumber: grid ? 5 : 4,
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: { lineStyle: gridLine },
      axisLabel: { color: pal.muted, fontSize: 11, formatter: axisFmt },
    },
    series,
  };
}

/** Stats of one series over the shown window, for the legend table. */
export interface Stats { last: number | null; min: number | null; avg: number | null; max: number | null }

export function seriesStats(s: LineSeries): Stats {
  let last: number | null = null, min = Infinity, max = -Infinity, sum = 0, n = 0;
  for (const [, v] of s.data) {
    if (v == null || !isFinite(v)) continue;
    last = v;
    min = Math.min(min, v);
    max = Math.max(max, v);
    sum += v;
    n++;
  }
  for (const [, v] of s.peak ?? []) if (v != null && isFinite(v)) max = Math.max(max, v);
  if (!n) return { last: null, min: null, avg: null, max: null };
  return { last, min, avg: sum / n, max };
}

export const RANGES = ['1h', '6h', '24h', '7d', '30d'];
/** The live range: a server's last minute, streamed point by point instead of read from storage. */
export const LIVE_RANGE = '1m';

/**
 * useWindow is the time window of a page's charts: a named range, or a
 * window picked by dragging across a chart. q goes straight into the API.
 */
/** useWindow is a chart time window: a preset range, or a zoom (also given at start, e.g. from a pulse bar). */
export function useWindow(initial = '24h', initialZoom: { from: number; to: number } | null = null) {
  const [range, setRangeState] = useState(initial);
  const [zoom, setZoom] = useState<{ from: number; to: number } | null>(initialZoom);
  const setRange = useCallback((r: string) => {
    setRangeState(r);
    setZoom(null);
  }, []);
  const onZoom = useCallback((from: number, to: number) => setZoom({ from: Math.floor(from / 1000), to: Math.ceil(to / 1000) }), []);
  const reset = useCallback(() => setZoom(null), []);
  const q = useMemo(() => (zoom ? `from=${zoom.from}&to=${zoom.to}` : `range=${range}`), [zoom, range]);
  return { range, setRange, zoom, onZoom, reset, q };
}
