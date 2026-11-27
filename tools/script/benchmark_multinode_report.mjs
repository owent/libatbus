#!/usr/bin/env node
// Copyright 2026 atframework
//
// Summarize a benchmark_multinode_matrix.sh run: tables, CSV and charts.
//
// usage: node benchmark_multinode_report.mjs <results_root> <matrix.log> --out <report_dir>
//        [--baseline <single_pair_results>] [--include-invalid] [--no-render]
//        node benchmark_multinode_report.mjs --from-csv <multi_summary.csv> --out <report_dir>
//        [--charts-only] [--no-render]
//
// <results_root> holds one directory per run, named by the runner
//   n<N>__<crypto>__<comp>-<level>__<size>/recv.json
// and <matrix.log> is the runner's output (one status line per run: sender reports,
// memory floor, registration time). Both are needed for the validity check.
//
// Outputs (into --out):
//   multi_summary.csv      one row per run with every recorded figure
//   tables.md              QPS and throughput tables per node count
//   facts.json             key figures of the run (validity, baseline, resources)
//   charts/multinode-throughput-baseline.{echarts.json,svg}
//   charts/multinode-qps-baseline.{echarts.json,svg}
//   charts/multinode-throughput-combos-n1000.{echarts.json,svg}
//   charts/multinode-qps-combos-n1000.{echarts.json,svg}
//   charts/node-count-effect.{echarts.json,svg}
//
// A run is rated from the receiver's report. The receiver samples about once a second
// and every sample carries the real time it covers; samples that end within the first
// 2 seconds are dropped, the samples that reached 80% of the peak rate form the plateau,
// and QPS / throughput are the duration-weighted medians over it. A run counts as valid
// only when the receiver reported, every sender reported and sent something, the plateau
// is at least 3 seconds long and the runner did not have to stop it for low memory.
// Invalid runs stay out of the tables and charts and are listed; --include-invalid puts
// them back for a first look at an incomplete run.
//
// --baseline takes the single-pair results of benchmark_node_stream_matrix.sh; facts.json
// then lists them next to the same reports rated with the plateau rule.
//
// echarts is resolved from ECHARTS_NODE_MODULES (a node_modules directory) or from the
// node_modules next to this script's project.

import { readFileSync, readdirSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const argv = process.argv.slice(2);
const USAGE =
  'usage: node benchmark_multinode_report.mjs <results_root> <matrix.log> --out <report_dir> [--baseline <dir>] [--include-invalid] [--no-render]\n' +
  '   or: node benchmark_multinode_report.mjs --from-csv <multi_summary.csv> --out <report_dir> [--charts-only] [--no-render]';
const optionValue = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
};
const out = optionValue('--out');
const baselineRoot = optionValue('--baseline');
const fromCsv = optionValue('--from-csv');
const INCLUDE_INVALID = argv.includes('--include-invalid');
const chartsOnly = argv.includes('--charts-only');
const wantRender = !argv.includes('--no-render');
const FLAGS = new Set(['--include-invalid', '--no-render', '--charts-only']);
const positional = [];
for (let i = 0; i < argv.length; ++i) {
  if (argv[i].startsWith('--')) { if (!FLAGS.has(argv[i])) ++i; continue; }
  positional.push(resolve(argv[i]));
}
const [root, matrixLog] = positional;
if (!out || (!fromCsv && (!root || !matrixLog))) {
  console.error(USAGE);
  process.exit(1);
}
const chartsOutDir = chartsOnly ? resolve(out) : join(out, 'charts');
mkdirSync(chartsOutDir, { recursive: true });

const NODE_COUNTS = [2, 10, 100, 1000];
const SIZES = [200, 256, 1024, 8192, 32768, 307200];
const SIZE_LABELS = ['200B', '256B', '1KB', '8KB', '32KB', '300KB'];
const WARMUP_SEC = 2;      // receiver samples that end within this time are not rated
const MIN_PLATEAU_SEC = 3; // a run needs at least this much rated plateau time

const COMBOS = [
  { key: 'none__none-default', crypto: 'none', comp: 'none', level: 'default', label: '无加密无压缩' },
  { key: 'none__lz4-fast', crypto: 'none', comp: 'lz4', level: 'fast', label: 'lz4@fast' },
  { key: 'none__lz4-default', crypto: 'none', comp: 'lz4', level: 'default', label: 'lz4@default' },
  { key: 'none__zstd-default', crypto: 'none', comp: 'zstd', level: 'default', label: 'zstd@default' },
  { key: 'none__zstd-high-ratio', crypto: 'none', comp: 'zstd', level: 'high-ratio', label: 'zstd@high-ratio' },
  { key: 'aes-128-gcm__none-default', crypto: 'aes-128-gcm', comp: 'none', level: 'default', label: 'aes-128-gcm' },
  { key: 'aes-256-gcm__none-default', crypto: 'aes-256-gcm', comp: 'none', level: 'default', label: 'aes-256-gcm' },
  { key: 'chacha20-poly1305-ietf__none-default', crypto: 'chacha20-poly1305-ietf', comp: 'none', level: 'default', label: 'chacha20-poly1305-ietf' },
  { key: 'aes-128-gcm__lz4-fast', crypto: 'aes-128-gcm', comp: 'lz4', level: 'fast', label: 'lz4@fast + aes-128-gcm' },
  { key: 'aes-256-gcm__lz4-fast', crypto: 'aes-256-gcm', comp: 'lz4', level: 'fast', label: 'lz4@fast + aes-256-gcm' },
  { key: 'chacha20-poly1305-ietf__lz4-fast', crypto: 'chacha20-poly1305-ietf', comp: 'lz4', level: 'fast', label: 'lz4@fast + chacha20-poly1305-ietf' },
  { key: 'aes-128-gcm__lz4-default', crypto: 'aes-128-gcm', comp: 'lz4', level: 'default', label: 'lz4@default + aes-128-gcm' },
  { key: 'aes-256-gcm__lz4-default', crypto: 'aes-256-gcm', comp: 'lz4', level: 'default', label: 'lz4@default + aes-256-gcm' },
  { key: 'chacha20-poly1305-ietf__lz4-default', crypto: 'chacha20-poly1305-ietf', comp: 'lz4', level: 'default', label: 'lz4@default + chacha20-poly1305-ietf' },
  { key: 'aes-128-gcm__zstd-default', crypto: 'aes-128-gcm', comp: 'zstd', level: 'default', label: 'zstd@default + aes-128-gcm' },
  { key: 'aes-256-gcm__zstd-default', crypto: 'aes-256-gcm', comp: 'zstd', level: 'default', label: 'zstd@default + aes-256-gcm' },
  { key: 'chacha20-poly1305-ietf__zstd-default', crypto: 'chacha20-poly1305-ietf', comp: 'zstd', level: 'default', label: 'zstd@default + chacha20-poly1305-ietf' },
  { key: 'aes-128-gcm__zstd-high-ratio', crypto: 'aes-128-gcm', comp: 'zstd', level: 'high-ratio', label: 'zstd@high-ratio + aes-128-gcm' },
  { key: 'aes-256-gcm__zstd-high-ratio', crypto: 'aes-256-gcm', comp: 'zstd', level: 'high-ratio', label: 'zstd@high-ratio + aes-256-gcm' },
  { key: 'chacha20-poly1305-ietf__zstd-high-ratio', crypto: 'chacha20-poly1305-ietf', comp: 'zstd', level: 'high-ratio', label: 'zstd@high-ratio + chacha20-poly1305-ietf' },
];

// Middle of a set of samples weighted by their duration; the plain median when every
// weight is 1.
function weightedMedian(pairs) {
  const sorted = [...pairs].sort((a, b) => a.value - b.value);
  const total = sorted.reduce((a, p) => a + p.weight, 0);
  if (total <= 0 || sorted.length === 0) return null;
  let acc = 0;
  for (let i = 0; i < sorted.length; i++) {
    acc += sorted[i].weight;
    if (2 * acc >= total) {
      if (2 * acc === total && i + 1 < sorted.length) return (sorted[i].value + sorted[i + 1].value) / 2;
      return sorted[i].value;
    }
  }
  return sorted[sorted.length - 1].value;
}

// Steady-state ("plateau") figures of one run, seen from the receiver.
//
// The receiver's stat timer only fires when its event loop gets to run, and with many
// connections one poll() can keep the loop busy for seconds. Every sample therefore
// carries the real time it covers ("interval"; reports of older builds have none and
// are read as 1 s), and its rate is msgs / interval.
//
// Samples that end within the warm-up window are dropped. The samples that reached
// >= 80% of the peak rate form the plateau; QPS and throughput are the duration-weighted
// medians over it. A plain average over the whole run is lower (about 5-10% with one
// sender, because of the partial last sample; more with many, because of the connection
// ramp-up).
function receiverStats(dir) {
  try {
    const j = JSON.parse(readFileSync(join(dir, 'recv.json'), 'utf8'));
    const samples = j.samples ?? [];
    let end = 0;
    const rated = [];
    let maxInterval = 0;
    for (const s of samples) {
      const iv = Number(s.interval) > 0 ? Number(s.interval) : 1;
      maxInterval = Math.max(maxInterval, iv);
      end += iv;
      if (end <= WARMUP_SEC + 0.1 || iv < 0.2) continue;
      rated.push({ msgs: Number(s.msgs) || 0, bytes: Number(s.bytes) || 0, cpu: Number(s.cpu_percent) || 0, iv });
    }
    if (rated.length === 0) return null;
    const peak = Math.max(0, ...rated.map((s) => s.msgs / s.iv));
    if (peak <= 0) return null;
    const plateau = rated.filter((s) => s.msgs / s.iv >= 0.8 * peak);
    const plateauSecs = plateau.reduce((a, s) => a + s.iv, 0);
    const qps = weightedMedian(plateau.map((s) => ({ value: s.msgs / s.iv, weight: s.iv })));
    const mbps = weightedMedian(plateau.map((s) => ({ value: s.bytes / s.iv / 1048576, weight: s.iv })));
    const recvMsgs = Number(j.totals?.msgs) || 0;
    const elapsedSec = Number(j.totals?.elapsed_sec) || 0;
    return {
      qps,
      mbps,
      plateauSecs,
      recvCpu: plateauSecs > 0 ? plateau.reduce((a, s) => a + s.cpu * s.iv, 0) / plateauSecs : 0,
      recvRssKb: Math.max(0, ...samples.map((s) => Number(s.rss_kb) || 0), Number(j.peak_rss_kb) || 0),
      recvMsgs,
      avgQps: elapsedSec > 0 ? recvMsgs / elapsedSec : 0,  // whole-run average, for reference
      maxInterval,
      samples: samples.length,
    };
  } catch {
    return null;
  }
}

// Sender-side facts and the verdict of the runner, from its log.
function parseMatrixLog(path) {
  const map = new Map();
  if (!path || !existsSync(path)) return map;
  const re = /^\[(\d+)\/(\d+)\] (\w+) (\S+) qps=(\S+) plateau_secs=(\d+) recv=(\S+) sent=(\S+) senders=(\d+)\/(\d+) idle_senders=(\d+)(?: backpressure=(\d+) send_rss_kb=(\d+)-(\d+) send_buffer=(\d+) gate_wait_sec=(\d+))? min_avail_mb=(\d+)/;
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = re.exec(line);
    if (!m) continue;
    map.set(m[4], {
      index: Number(m[1]),
      status: m[3],
      runnerQps: m[5] === 'NA' ? null : Number(m[5]),
      recvMsgs: m[7] === 'NA' ? null : Number(m[7]),
      sentMsgs: Number(m[8]),
      senders: Number(m[9]),
      expectedSenders: Number(m[10]),
      idleSenders: Number(m[11]),
      backpressure: Number(m[12] ?? 0),
      sendRssMinKb: Number(m[13] ?? 0),
      sendRssMaxKb: Number(m[14] ?? 0),
      sendBuffer: Number(m[15] ?? 0),
      gateWait: Number(m[16] ?? 0),
      minAvailMb: Number(m[17]),
    });
  }
  return map;
}

const data = new Map(); // n -> Map(comboKey -> Map(size -> run))
const invalid = [];
if (fromCsv) {
  const lines = readFileSync(resolve(fromCsv), 'utf8').trim().split(/\r?\n/);
  const headers = lines[0].split(',');
  for (const line of lines.slice(1)) {
    const parts = line.split(',');
    const row = {};
    headers.forEach((h, i) => (row[h] = parts[i] ?? ''));
    const n = Number(row.nodes);
    const s = Number(row.payload_size);
    const comboKey = `${row.crypto}__${row.compression}-${row.level}`;
    const valid = row.valid === 'yes';
    const run = {
      name: `n${n}__${comboKey}__${s}`,
      qps: Number(row.qps),
      mbps: Number(row.mbps),
      plateauSecs: Number(row.plateau_sec),
      recvCpu: Number(row.receiver_cpu_percent),
      recvRssKb: Number(row.receiver_peak_rss_kb),
      recvMsgs: Number(row.receiver_msgs),
      avgQps: Number(row.receiver_whole_run_avg_qps),
      maxInterval: Number(row.receiver_max_sample_interval_sec),
      log: {
        senders: Number(row.senders),
        idleSenders: Number(row.idle_senders),
        sentMsgs: Number(row.sent_msgs),
        backpressure: Number(row.sender_backpressure),
        sendRssMinKb: Number(row.sender_peak_rss_min_kb),
        sendRssMaxKb: Number(row.sender_peak_rss_max_kb),
        sendBuffer: Number(row.sender_send_buffer_bytes),
        gateWait: Number(row.register_wait_sec),
        minAvailMb: Number(row.min_mem_available_mb),
      },
      reasons: row.note ? row.note.split('; ') : [],
      valid,
    };
    if (!valid) invalid.push(run);
    if (!data.has(n)) data.set(n, new Map());
    const byCombo = data.get(n);
    if (!byCombo.has(comboKey)) byCombo.set(comboKey, new Map());
    byCombo.get(comboKey).set(s, run);
  }
} else {
  const logInfo = parseMatrixLog(matrixLog);
  for (const n of NODE_COUNTS) {
    const byCombo = new Map();
    for (const c of COMBOS) {
      const bySize = new Map();
      for (const s of SIZES) {
        const name = `n${n}__${c.key}__${s}`;
        const st = receiverStats(join(root, name));
        if (!st) continue;
        const info = logInfo.get(name) ?? null;
        const reasons = [];
        if (st.plateauSecs < MIN_PLATEAU_SEC) reasons.push(`plateau ${st.plateauSecs.toFixed(1)}s`);
        if (info) {
          if (info.senders !== n - 1) reasons.push(`senders ${info.senders}/${n - 1}`);
          if (info.idleSenders > 0) reasons.push(`idle ${info.idleSenders}`);
          if (info.status !== 'OK') reasons.push(`runner ${info.status}`);
        }
        const run = { ...st, name, log: info, reasons, valid: reasons.length === 0 };
        if (!run.valid) invalid.push(run);
        bySize.set(s, run);
      }
      if (bySize.size) byCombo.set(c.key, bySize);
    }
    data.set(n, byCombo);
  }
}

const get = (n, comboKey, size) => data.get(n)?.get(comboKey)?.get(size) ?? null;
const qpsOf = (run) => (run && (run.valid || INCLUDE_INVALID) ? Math.round(run.qps) : null); // --include-invalid: first look at an incomplete run
const mbpsOf = (run) => (run && (run.valid || INCLUDE_INVALID) ? Number(run.mbps.toFixed(1)) : null);

// ---------- charts ----------
// One figure: the receiver's aggregate rate of every combination and packet size against the
// number of interconnected nodes, as a ratio to that series' own 2-node run. QPS and
// throughput have the same ratio, so one figure covers both metrics; the absolute values are
// in the tables. The 120 lines (20 combinations x 6 packet sizes) are told apart by three cues:
//   colour = packet size (the node-count effect depends on it first)
//   marker = compression
//   stroke = crypto
// chartSizes carries the canvas of the figure for the SVG renderer.
const SIZE_COLORS = ['#4e79a7', '#59a14f', '#f28e2b', '#e15759', '#b07aa1', '#2a9d8f'];
const COMP_KEYS = ['none-default', 'lz4-fast', 'lz4-default', 'zstd-default', 'zstd-high-ratio'];
const COMP_LABELS = { 'none-default': '无压缩', 'lz4-fast': 'lz4@fast', 'lz4-default': 'lz4@default', 'zstd-default': 'zstd@default', 'zstd-high-ratio': 'zstd@high-ratio' };
const COMP_MARKERS = { 'none-default': 'circle', 'lz4-fast': 'triangle', 'lz4-default': 'emptyTriangle', 'zstd-default': 'rect', 'zstd-high-ratio': 'emptyRect' };
const CRYPTO_STROKES = { none: 'solid', 'aes-128-gcm': [7, 4], 'aes-256-gcm': [1.5, 3], 'chacha20-poly1305-ietf': [9, 3, 2, 3] };
const compKeyOf = (combo) => `${combo.comp}-${combo.level}`;
const seriesName = (combo, i) => `${combo.label} · ${SIZE_LABELS[i]}`;

const chartSizes = {};
const generatedOptions = new Map();
function saveChart(name, opt, width = 960, height = 540, writeJson = !chartsOnly) {
  chartSizes[name] = [width, height];
  generatedOptions.set(name, opt);
  if (writeJson) {
    writeFileSync(join(chartsOutDir, name), JSON.stringify(opt, null, 2));
  }
}

const BASELINE = COMBOS[0];
// ratio (in percent) of a run to the 2-node run of the same combination and packet size
const ratioTo2 = (combo, size, n) => {
  const two = get(2, combo.key, size);
  const run = get(n, combo.key, size);
  return two && run && two.valid && run.valid && two.qps > 0 ? Math.round((run.qps / two.qps) * 1000) / 10 : null;
};
const ratios = [];
const effectSeries = COMBOS.slice(1).concat([BASELINE]).flatMap((combo) =>
  SIZES.map((size, i) => {
    const data = NODE_COUNTS.map((n) => ratioTo2(combo, size, n));
    ratios.push(...data.filter((v) => v != null));
    const baseline = combo === BASELINE;
    return {
      name: seriesName(combo, i),
      type: 'line',
      symbol: COMP_MARKERS[compKeyOf(combo)],
      symbolSize: baseline ? 7 : 5,
      lineStyle: { width: baseline ? 2.6 : 1.6, color: SIZE_COLORS[i], type: CRYPTO_STROKES[combo.crypto], opacity: baseline ? 1 : 0.75 },
      itemStyle: { color: SIZE_COLORS[i], opacity: baseline ? 1 : 0.85 },
      data,
      markLine: baseline && i === 0 ? {
        silent: true,
        symbol: 'none',
        lineStyle: { color: '#999999', type: 'dashed' },
        label: { formatter: '2 节点 = 100%', position: 'insideEndTop', color: '#666666' },
        data: [{ yAxis: 100 }],
      } : undefined,
    };
  })
);

// The legend is a key of three rows; its samples are series without data, so that every
// cue is shown on its own.
const KEY_COLOR = '#555555';
const keySeries = (name, stroke, marker, color) => ({
  name,
  type: 'line',
  data: [],
  symbol: marker,
  symbolSize: 8,
  lineStyle: { width: 2.4, color, type: stroke },
  itemStyle: { color },
});
const KEY_ROWS = [
  { caption: '包长（颜色）', items: SIZES.map((s, i) => keySeries(SIZE_LABELS[i], 'solid', 'circle', SIZE_COLORS[i])) },
  { caption: '压缩（标记）', items: COMP_KEYS.map((k) => keySeries(COMP_LABELS[k], 'solid', COMP_MARKERS[k], KEY_COLOR)) },
  { caption: '加密（线型）', items: [['none', '无加密'], ['aes-128-gcm', 'aes-128-gcm'], ['aes-256-gcm', 'aes-256-gcm'], ['chacha20-poly1305-ietf', 'chacha20-poly1305-ietf']].map(([crypto, text]) => keySeries(text, CRYPTO_STROKES[crypto], 'circle', KEY_COLOR)) },
];
// ticks of the ratio axis: the 1-2-5 steps from the first one at or below the smallest
// ratio up to the first one at or above the largest, so that the axis covers every series
const TICKS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 120, 150, 200, 300, 400, 500, 1000];
const ratioMin = Math.min(...ratios);
const ratioMax = Math.max(...ratios);
const ticks = ratios.length
  ? TICKS.filter((t) => t >= Math.max(...TICKS.filter((x) => x <= ratioMin), TICKS[0]) && t <= Math.min(...TICKS.filter((x) => x >= ratioMax), TICKS[TICKS.length - 1]))
  : [50, 100, 200];
const LEGEND_TOP = 40;
const LEGEND_ROW = 22;
saveChart('node-count-effect.echarts.json', {
  backgroundColor: '#fff',
  title: { text: '聚合 QPS 相对 2 节点的比值 vs 互联节点数（接收端；吞吐量的比值相同）', left: 'center', top: 10, textStyle: { fontSize: 15 } },
  legend: KEY_ROWS.map((row, r) => ({
    left: 140,
    top: LEGEND_TOP + r * LEGEND_ROW,
    itemWidth: 38,
    itemHeight: 14,
    itemGap: 18,
    textStyle: { fontSize: 12, color: '#333' },
    data: row.items.map((s) => s.name),
  })),
  graphic: KEY_ROWS.map((row, r) => ({
    type: 'text',
    left: 24,
    top: LEGEND_TOP + r * LEGEND_ROW + 1,
    style: { text: row.caption, fill: '#333', font: 'bold 13px sans-serif' },
  })),
  grid: { left: 16, right: 28, top: LEGEND_TOP + KEY_ROWS.length * LEGEND_ROW + 24, bottom: 14, containLabel: true },
  xAxis: {
    type: 'category',
    data: NODE_COUNTS.map(String), axisLabel: { fontSize: 12, interval: 0, margin: 10 }, axisTick: { alignWithLabel: true },
  },
  yAxis: {
    type: 'log', percent: true, name: '相对 2 节点', min: ticks[0], max: ticks[ticks.length - 1],
    axisLabel: { fontSize: 12, customValues: ticks }, splitLine: { lineStyle: { color: '#e6e6e6' } },
  },
  series: [...effectSeries, ...KEY_ROWS.flatMap((row) => row.items)],
}, 960, 640);

// Absolute aggregate throughput & QPS of the plaintext baseline across node counts
const buildBaselineSeries = (pick) =>
  SIZES.map((s, i) => ({
    name: SIZE_LABELS[i],
    type: 'line',
    symbol: 'circle',
    symbolSize: 8,
    lineStyle: { width: 3, color: SIZE_COLORS[i] },
    itemStyle: { color: SIZE_COLORS[i] },
    data: NODE_COUNTS.map((n) => pick(get(n, BASELINE.key, s))),
  }));

saveChart(
  'multinode-throughput-baseline.echarts.json',
  {
    backgroundColor: '#fff',
    title: { text: '聚合吞吐量 payload MB/s vs 互联节点数（接收端，无加密无压缩）', left: 'center', top: 10, textStyle: { fontSize: 15 } },
    legend: { top: 38 },
    tooltip: { trigger: 'axis', confine: true },
    grid: { left: 16, right: 28, top: 82, bottom: 14, containLabel: true },
    xAxis: {
      type: 'category',
      data: NODE_COUNTS.map((n) => `${n} 节点`),
      axisLabel: { fontSize: 12, interval: 0, margin: 10 },
      axisTick: { alignWithLabel: true },
    },
    yAxis: { type: 'value', name: 'MB/s', splitLine: { lineStyle: { color: '#e6e6e6' } } },
    series: buildBaselineSeries(mbpsOf),
  },
  960,
  540
);

saveChart(
  'multinode-qps-baseline.echarts.json',
  {
    backgroundColor: '#fff',
    title: { text: '聚合 QPS msg/s（对数轴） vs 互联节点数（接收端，无加密无压缩）', left: 'center', top: 10, textStyle: { fontSize: 15 } },
    legend: { top: 38 },
    tooltip: { trigger: 'axis', confine: true },
    grid: { left: 16, right: 28, top: 82, bottom: 14, containLabel: true },
    xAxis: {
      type: 'category',
      data: NODE_COUNTS.map((n) => `${n} 节点`),
      axisLabel: { fontSize: 12, interval: 0, margin: 10 },
      axisTick: { alignWithLabel: true },
    },
    yAxis: { type: 'log', name: 'msg/s', min: 1000, splitLine: { lineStyle: { color: '#e6e6e6' } } },
    series: buildBaselineSeries(qpsOf),
  },
  960,
  540
);

// All 20 crypto x compression combos at 1000 nodes (throughput + QPS), matching the
// single-pair combo chart color/stroke/marker convention for direct visual comparison.
const MULTI_COMP_COLORS = {
  'none-default': '#5470c6',
  'lz4-fast': '#91cc75',
  'lz4-default': '#3ba272',
  'zstd-default': '#fc8452',
  'zstd-high-ratio': '#ee6666',
};
const MULTI_CRYPTO_STYLE = {
  none: { stroke: 'solid', marker: 'circle' },
  'aes-128-gcm': { stroke: [7, 4], marker: 'triangle' },
  'aes-256-gcm': { stroke: [7, 4], marker: 'diamond' },
  'chacha20-poly1305-ietf': { stroke: [9, 3, 2, 3], marker: 'emptyTriangle' },
};
const MULTI_CRYPTOS = ['none', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305-ietf'];
const comboLegendName = (compKey, crypto) => `${COMP_LABELS[compKey]} · ${crypto}`;

if (data.get(1000)?.size) {
  const buildNodeComboChart = (n, title, yAxis, pick) => {
    const top = 40;
    const rowHeight = 22;
    const ordered = COMBOS.slice(1).concat([BASELINE]);
    const series = ordered.map((c) => {
      const ck = compKeyOf(c);
      const st = MULTI_CRYPTO_STYLE[c.crypto];
      const color = MULTI_COMP_COLORS[ck];
      return {
        name: comboLegendName(ck, c.crypto),
        type: 'line',
        symbol: st.marker,
        symbolSize: 8,
        lineStyle: { width: 2.4, color, type: st.stroke },
        itemStyle: { color },
        data: SIZES.map((s) => pick(get(n, c.key, s))),
      };
    });
    return {
      backgroundColor: '#fff',
      title: { text: title, left: 'center', top: 10, textStyle: { fontSize: 15 } },
      tooltip: { trigger: 'axis', confine: true },
      legend: COMP_KEYS.map((ck, r) => ({
        left: 150,
        top: top + r * rowHeight,
        itemWidth: 38,
        itemHeight: 14,
        itemGap: 18,
        textStyle: { fontSize: 12, color: '#333' },
        data: MULTI_CRYPTOS.map((crypto) => comboLegendName(ck, crypto)),
        stripPrefix: ' · ',
      })),
      graphic: COMP_KEYS.map((ck, r) => ({
        type: 'text',
        left: 24,
        top: top + r * rowHeight + 1,
        style: { text: COMP_LABELS[ck], fill: MULTI_COMP_COLORS[ck], font: 'bold 13px sans-serif' },
      })),
      grid: { left: 16, right: 28, top: top + COMP_KEYS.length * rowHeight + 24, bottom: 14, containLabel: true },
      xAxis: { type: 'category', data: SIZE_LABELS, axisLabel: { interval: 0 } },
      yAxis,
      series,
    };
  };

  saveChart(
    'multinode-throughput-combos-n1000.echarts.json',
    buildNodeComboChart(
      1000,
      '聚合吞吐量 payload MB/s - 1000 节点全部加密 × 压缩组合（接收端）',
      { type: 'value', name: 'MB/s', splitLine: { lineStyle: { color: '#e6e6e6' } } },
      mbpsOf
    ),
    960,
    640
  );
  saveChart(
    'multinode-qps-combos-n1000.echarts.json',
    buildNodeComboChart(
      1000,
      '聚合 QPS msg/s（对数轴） - 1000 节点全部加密 × 压缩组合（接收端）',
      { type: 'log', name: 'msg/s', min: 1000, splitLine: { lineStyle: { color: '#e6e6e6' } } },
      qpsOf
    ),
    960,
    640
  );
}


// ---------- Markdown tables ----------
function fmtQps(v) {
  if (v == null) return '-';
  if (v >= 1e6) return `${(v / 1e6).toFixed(2)}M`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
  return `${Math.round(v)}`;
}
function fmtMb(v) {
  if (v == null) return '-';
  return v >= 1024 ? `${(v / 1024).toFixed(2)}GB/s` : `${v.toFixed(0)}MB/s`;
}
const comboCells = (n, metric, combo) => SIZES.map((s) => (metric === 'qps' ? fmtQps(qpsOf(get(n, combo.key, s))) : fmtMb(mbpsOf(get(n, combo.key, s))))).join(' | ');

let md = '';
for (const n of NODE_COUNTS) {
  if (!data.get(n) || data.get(n).size === 0) {
    md += `\n#### ${n} 节点互联\n\n(无数据)\n`;
    continue;
  }
  for (const [metric, title] of [['qps', '聚合 QPS（接收端，msg/s）'], ['mbps', '聚合吞吐量（接收端，payload）']]) {
    md += `\n#### ${n} 节点互联 - ${title}\n\n`;
    md += `| 加密 | 压缩 | ${SIZE_LABELS.join(' | ')} |\n`;
    md += `|---|---|${SIZE_LABELS.map(() => '---:').join('|')}|\n`;
    for (const c of COMBOS) {
      if (!data.get(n).get(c.key)) continue;
      md += `| ${c.crypto} | ${c.comp === 'none' ? '无' : `${c.comp}@${c.level}`} | ${comboCells(n, metric, c)} |\n`;
    }
  }
}
if (!chartsOnly) {
writeFileSync(join(out, 'tables.md'), md);
}

// ---------- summary CSV ----------
const cols = ['nodes', 'crypto', 'compression', 'level', 'payload_size', 'qps', 'mbps', 'plateau_sec', 'receiver_cpu_percent',
  'receiver_peak_rss_kb', 'receiver_msgs', 'receiver_whole_run_avg_qps', 'receiver_max_sample_interval_sec', 'senders', 'idle_senders',
  'sent_msgs', 'sender_backpressure', 'sender_peak_rss_min_kb', 'sender_peak_rss_max_kb', 'sender_send_buffer_bytes', 'register_wait_sec',
  'min_mem_available_mb', 'valid', 'note'];
const csv = [cols.join(',')];
for (const n of NODE_COUNTS) {
  for (const c of COMBOS) {
    for (const s of SIZES) {
      const r = get(n, c.key, s);
      if (!r) continue;
      const info = r.log ?? {};
      const row = [n, c.crypto, c.comp, c.level, s, Math.round(r.qps), r.mbps.toFixed(1), r.plateauSecs.toFixed(2), r.recvCpu.toFixed(1),
        r.recvRssKb, r.recvMsgs, Math.round(r.avgQps), r.maxInterval.toFixed(2), info.senders ?? '', info.idleSenders ?? '',
        info.sentMsgs ?? '', info.backpressure ?? '', info.sendRssMinKb ?? '', info.sendRssMaxKb ?? '', info.sendBuffer ?? '', info.gateWait ?? '',
        info.minAvailMb ?? '', r.valid ? 'yes' : 'no', r.reasons.join('; ').replace(/,/g, ';')];
      csv.push(row.join(','));
    }
  }
}
if (!chartsOnly) {
writeFileSync(join(out, 'multi_summary.csv'), csv.join('\n'));
}

// ---------- key numbers for the analysis text ----------
const allRuns = [...data.values()].flatMap((byCombo) => [...byCombo.values()].flatMap((bySize) => [...bySize.values()]));
const validRuns = allRuns.filter((r) => r.valid);
const runsOf = (n) => validRuns.filter((r) => r.name.startsWith(`n${n}__`));
const availValues = allRuns.map((r) => r.log?.minAvailMb).filter((v) => Number.isFinite(v));
const r1 = (v) => Number(v.toFixed(1));

const facts = { invalid: invalid.map((r) => ({ name: r.name, reasons: r.reasons })) };
facts.runs = allRuns.length;
facts.validRuns = validRuns.length;
facts.baseline = Object.fromEntries(NODE_COUNTS.map((n) => [n, Object.fromEntries(SIZES.map((s) => {
  const r = get(n, 'none__none-default', s);
  return [s, r ? {
    qps: Math.round(r.qps), mbps: r1(r.mbps), cpu: r1(r.recvCpu), rssMb: r1(r.recvRssKb / 1024),
    plateauSecs: r1(r.plateauSecs), maxInterval: r1(r.maxInterval), avgQps: Math.round(r.avgQps), valid: r.valid,
    sentMsgs: r.log?.sentMsgs ?? null, recvMsgs: r.recvMsgs, backpressure: r.log?.backpressure ?? null,
    sendRssMinMb: r.log ? r1(r.log.sendRssMinKb / 1024) : null, sendRssMaxMb: r.log ? r1(r.log.sendRssMaxKb / 1024) : null,
    sendBuffer: r.log?.sendBuffer ?? null, gateWait: r.log?.gateWait ?? null, minAvailMb: r.log?.minAvailMb ?? null,
  } : null];
}))]));
// every combo, per node count
facts.combo = Object.fromEntries(NODE_COUNTS.map((n) => [n, Object.fromEntries(COMBOS.map((c) => [c.key, Object.fromEntries(SIZES.map((s) => {
  const r = get(n, c.key, s);
  return [s, r ? { qps: Math.round(r.qps), mbps: r1(r.mbps), cpu: r1(r.recvCpu), valid: r.valid } : null];
}))]))]));
facts.perNodeCount = Object.fromEntries(NODE_COUNTS.map((n) => {
  const rs = runsOf(n);
  const av = rs.map((r) => r.log?.minAvailMb).filter(Number.isFinite);
  const gw = rs.map((r) => r.log?.gateWait).filter(Number.isFinite);
  const sb = [...new Set(rs.map((r) => r.log?.sendBuffer).filter(Number.isFinite))];
  const base = rs.filter((r) => r.name.includes('__none__none-default__'));
  // the receiver's stat timer only fires between event-loop iterations: a sample interval
  // far above one second means one poll() kept the loop busy that long
  const intervals = rs.map((r) => r.maxInterval).filter(Number.isFinite);
  return [n, {
    runs: rs.length,
    invalid: allRuns.filter((r) => !r.valid && r.name.startsWith(`n${n}__`)).length,
    senders: rs[0]?.log?.senders ?? null,
    sendBufferBytes: sb,
    registerWaitMaxSec: gw.length ? Math.max(...gw) : null,
    registerWaitMinSec: gw.length ? Math.min(...gw) : null,
    minAvailMb: av.length ? Math.min(...av) : null,
    receiverCpuMin: base.length ? r1(Math.min(...base.map((r) => r.recvCpu))) : null,
    receiverCpuMax: base.length ? r1(Math.max(...base.map((r) => r.recvCpu))) : null,
    receiverRssMaxMb: rs.length ? r1(Math.max(...rs.map((r) => r.recvRssKb)) / 1024) : null,
    longLoopRuns: rs.filter((r) => r.maxInterval > 1.5).length,
    maxSampleInterval: intervals.length ? r1(Math.max(...intervals)) : null,
  }];
}));
facts.minAvailMb = availValues.length ? Math.min(...availValues) : null;
facts.maxRecvRssMb = r1(Math.max(...allRuns.map((r) => r.recvRssKb)) / 1024);
// The single-pair results given with --baseline, rated two ways from their raw reports:
// windowMean is the mean of the per-second samples with the first 2 and the last 1 dropped,
// plateau the result of the plateau rule used here.
if (baselineRoot && existsSync(baselineRoot)) {
  facts.singlePair = {};
  for (const c of COMBOS) {
    for (const s of [200, 1024, 8192, 307200]) {
      const f = join(baselineRoot, `${c.key}__${s}`, 'recv.json');
      const st = existsSync(f) ? receiverStats(dirname(f)) : null;
      if (!st) continue;
      const samples = JSON.parse(readFileSync(f, 'utf8')).samples ?? [];
      const window = samples.slice(2, samples.length - 1);
      (facts.singlePair[c.key] ??= {})[s] = {
        windowMean: window.length ? Math.round(window.reduce((a, x) => a + (Number(x.msgs) || 0), 0) / window.length) : null,
        plateau: Math.round(st.qps),
      };
    }
  }
}
if (!chartsOnly) {
writeFileSync(join(out, 'facts.json'), JSON.stringify(facts, null, 2));
}

console.log(`runs: ${facts.runs}, valid: ${facts.validRuns}, invalid: ${invalid.length}`);
if (!INCLUDE_INVALID) for (const r of invalid) console.log(`  INVALID ${r.name}: ${r.reasons.join(', ')}`);
console.log('baseline QPS by node count:');
for (const n of NODE_COUNTS) {
  console.log(`  n=${n}: ${SIZES.map((s) => `${SIZE_LABELS[SIZES.indexOf(s)]}=${facts.baseline[n][s]?.qps ?? '-'}`).join('  ')}`);
}
console.log(`min MemAvailable: ${facts.minAvailMb}MB, max receiver RSS: ${facts.maxRecvRssMb}MB`);

// ---------------------------------------------------------------------------
// Static SVGs. animation:false is required: an SSR SVG otherwise embeds an enter
// animation that never plays where the image is shown as a picture, which leaves every
// line clipped away. A JSON option cannot carry a formatter function, so the labels of a
// log axis are attached here: 3.5M / 200K, or percent for an axis marked "percent".
function renderCharts() {
  let echarts = null;
  const here = dirname(fileURLToPath(import.meta.url));
  for (const nm of [process.env.ECHARTS_NODE_MODULES, join(here, '..', '..', 'node_modules')].filter(Boolean)) {
    try {
      echarts = createRequire(join(nm, '_r.js'))('echarts');
      break;
    } catch {
      // try the next location
    }
  }
  if (!echarts) {
    console.log('echarts not found (set ECHARTS_NODE_MODULES): SVG charts skipped');
    return;
  }
  const compact = (v) => (v >= 1e6 ? `${Number((v / 1e6).toPrecision(3))}M` : v >= 1e3 ? `${Number((v / 1e3).toPrecision(3))}K` : `${v}`);
  let failed = 0;
  for (const [f, rawOption] of generatedOptions.entries()) {
    const option = JSON.parse(JSON.stringify(rawOption));
    if (option.legend) {
      const wrapLegend = (l) => {
        if (!l || !l.stripPrefix) return l;
        const { stripPrefix, ...rest } = l;
        return {
          ...rest,
          formatter: (name) => {
            const idx = name.indexOf(stripPrefix);
            return idx >= 0 ? name.slice(idx + stripPrefix.length) : name;
          },
        };
      };
      option.legend = Array.isArray(option.legend) ? option.legend.map(wrapLegend) : wrapLegend(option.legend);
    }
    for (const axis of ['xAxis', 'yAxis']) {
      option[axis] = [].concat(option[axis] ?? []).map((a) => {
        if (a.type !== 'log') return a;
        const { percent, ...rest } = a;
        return { ...rest, axisLabel: { ...rest.axisLabel, formatter: percent ? (v) => `${v}%` : compact } };
      });
    }
    const [width, height] = chartSizes[f] ?? [960, 540];
    const chart = echarts.init(null, null, { renderer: 'svg', ssr: true, width, height });
    try {
      chart.setOption({ ...option, animation: false });
      const svgName = f.replace('.echarts.json', '.svg');
      writeFileSync(join(chartsOutDir, svgName), chart.renderToSVGString());
      console.log(`chart: ${svgName}`);
    } catch (e) {
      ++failed;
      console.log(`SVG failed for ${f}: ${e.message}`);
    }
    chart.dispose();
  }
  if (failed) process.exitCode = 1;
}
if (wantRender) renderCharts();
