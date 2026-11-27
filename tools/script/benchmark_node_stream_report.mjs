#!/usr/bin/env node
// Copyright 2026 atframework
//
// Summarize benchmark_node_stream_matrix results and render charts.
//
// usage: node benchmark_node_stream_report.mjs <result_dir|summary.csv>... --out <report_dir>
//        [--html] [--bundle <echarts.min.js>] [--charts-only] [--label <platform>=<text>]
//
// Each <result_dir> contains one sub-directory per combo, named
//   <crypto>__<compression>-<level>__<size>
// with recv.json / send.json produced by benchmark_node_stream_send/recv.
// Alternatively, archived summary.<platform>.csv files can be passed directly to
// regenerate SVG charts without raw JSON runs.
// The directory name (or <platform> in summary.<platform>.csv) is used as the platform label.
//
// QPS, throughput and CPU of a combo are taken over the steady samples of the run: the
// samples after the warm-up that are neither idle nor partial, see steady().
//
// Outputs (into --out):
//   summary.<platform>.csv       per-combo metrics (receiver-side QPS/throughput, CPU, RSS)
//   summary.<platform>.md        the same data as a markdown table
//   charts/*.svg                 static SVG charts rendered by echarts SSR (throughput + QPS pairs)
//   benchmark_charts.html        interactive self-contained charts (when --html and echarts.min.js is bundled)

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, resolve, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const outIndex = argv.indexOf('--out');
if (argv.length < 2 || outIndex < 0) {
  console.error(
    'usage: node benchmark_node_stream_report.mjs <result_dir|summary.csv>... --out <report_dir> [--html] [--bundle <echarts.min.js>] [--charts-only] [--label <platform>=<text>]'
  );
  process.exit(1);
}
const outDir = resolve(argv[outIndex + 1]);
const bundleIndex = argv.indexOf('--bundle');
const bundleFile = bundleIndex >= 0 ? argv[bundleIndex + 1] : null;
const wantHtml = argv.includes('--html');
const chartsOnly = argv.includes('--charts-only');
const customLabels = new Map();
const resultInputs = [];
for (let i = 0; i < argv.length; ++i) {
  if (i === outIndex || i === outIndex + 1) continue;
  if (bundleIndex >= 0 && (i === bundleIndex || i === bundleIndex + 1)) continue;
  if (argv[i] === '--label') {
    const spec = argv[++i] ?? '';
    const eq = spec.indexOf('=');
    if (eq > 0) customLabels.set(spec.slice(0, eq), spec.slice(eq + 1));
    continue;
  }
  if (argv[i].startsWith('--')) continue;
  resultInputs.push(resolve(argv[i]));
}
if (resultInputs.length === 0) {
  console.error('no result directory or summary CSV given');
  process.exit(1);
}
const labelOf = (platform) => customLabels.get(platform) ?? platform;

// ---------------------------------------------------------------------------
// Parsing

// Steady-state statistics of a run.
// A sample covers "interval" seconds (1 s in reports of older builds). Samples that end
// within the warm-up window are dropped, and so are idle and partial ones (far below the
// peak rate, e.g. the fraction of a second before the receiver exits). QPS and throughput
// are the medians over the remaining samples, weighted by sample length; CPU is their
// weighted mean. A plain mean over a fixed window comes out about 7% low (it contains that
// partial last sample), and a mean reports a value from neither regime when a 15-second
// run switches between the two loopback throughput states.
// benchmark_multinode_report.mjs keeps only the samples that reached 80% of the peak rate:
// its windows also cover the wait before the senders start, and its runs stayed in one
// state (the plateau filled nearly the whole window).
const WARMUP_SEC = 2;
const MIN_RATE_FRACTION = 0.2;

function weightedMedian(values) {
  const sorted = [...values].sort((a, b) => a.value - b.value);
  const total = sorted.reduce((a, v) => a + v.weight, 0);
  if (total <= 0) return 0;
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

// -> { samples, seconds, qps, bytesPerSec, cpuPercent } of the steady samples, or null
function steady(samples) {
  let end = 0;
  const full = [];
  for (const s of samples) {
    const interval = Number(s.interval) > 0 ? Number(s.interval) : 1;
    end += interval;
    if (end <= WARMUP_SEC + 0.1 || interval < 0.2) continue;
    full.push({ rate: (Number(s.msgs) || 0) / interval, bytesPerSec: (Number(s.bytes) || 0) / interval, cpu: Number(s.cpu_percent) || 0, interval });
  }
  if (full.length === 0) return null;
  const peak = Math.max(0, ...full.map((s) => s.rate));
  const kept = peak > 0 ? full.filter((s) => s.rate >= MIN_RATE_FRACTION * peak) : [];
  if (kept.length === 0) return null;
  const seconds = kept.reduce((a, s) => a + s.interval, 0);
  return {
    samples: kept,
    seconds,
    qps: weightedMedian(kept.map((s) => ({ value: s.rate, weight: s.interval }))),
    bytesPerSec: weightedMedian(kept.map((s) => ({ value: s.bytesPerSec, weight: s.interval }))),
    cpuPercent: kept.reduce((a, s) => a + s.cpu * s.interval, 0) / seconds,
  };
}

// CPU of the whole run. The sender's per-second samples are unusable when its event loop
// is blocked for most of the run (large messages on the shm channel).
function wholeRunCpuPercent(report) {
  const elapsed = Number(report?.totals?.elapsed_sec) || 0;
  const cpu = Number(report?.cpu?.total_sec) || 0;
  return elapsed > 0 ? (cpu / elapsed) * 100 : 0;
}

const PAYLOAD_SIZES = [200, 1024, 8192, 65536, 307200];
const CRYPTO_ORDER = ['none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20', 'chacha20-poly1305-ietf'];
// compression presets: <algo>-<level>, matching the directory name scheme
// note: zstd level "balanced" maps to the zstd default level (3), reported as "zstd default"
const COMPRESS_SETS = [
  { key: 'none-default', algo: 'none', level: 'default', label: '无压缩' },
  { key: 'lz4-fast', algo: 'lz4', level: 'fast', label: 'lz4@fast' },
  { key: 'lz4-default', algo: 'lz4', level: 'default', label: 'lz4@default' },
  { key: 'zstd-default', algo: 'zstd', level: 'default', label: 'zstd@default' },
  { key: 'zstd-high-ratio', algo: 'zstd', level: 'high-ratio', label: 'zstd@high-ratio' },
];
// combined crypto+compression groups (AEAD-safe cryptos only)
const COMBINED_CRYPTOS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305-ietf'];

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    return null;
  }
}

function parseComboDir(name) {
  // <crypto>__<compression>-<level>__<size>
  const m = /^(.+)__(.+)-([^_]+)__(\d+)$/.exec(name);
  if (!m) return null;
  return { crypto: m[1], compression: `${m[2]}-${m[3]}`, size: Number(m[4]) };
}

function summarizePlatform(dir) {
  const platform = dir.split(/[\\/]/).filter(Boolean).pop();
  const combos = new Map();
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const parsed = parseComboDir(entry.name);
    if (!parsed) continue;
    const recv = readJson(join(dir, entry.name, 'recv.json'));
    const send = readJson(join(dir, entry.name, 'send.json'));
    if (!recv || !send) {
      console.warn(`[skip] ${platform}/${entry.name}: missing recv.json/send.json`);
      continue;
    }
    const recvSteady = steady(recv.samples ?? []);
    if (!recvSteady) {
      console.warn(`[skip] ${platform}/${entry.name}: no steady samples in recv.json`);
      continue;
    }
    const sendSteady = steady(send.samples ?? []);
    const dashIdx = parsed.compression.indexOf('-');
    const combo = {
      platform,
      crypto: parsed.crypto,
      compression: parsed.compression,
      level: dashIdx >= 0 ? parsed.compression.slice(dashIdx + 1) : 'default',
      compressionAlgo: dashIdx >= 0 ? parsed.compression.slice(0, dashIdx) : parsed.compression,
      size: parsed.size,
      qps: recvSteady.qps,
      throughputBytesPerSec: recvSteady.bytesPerSec,
      recvCpuPercent: recvSteady.cpuPercent,
      sendCpuPercent: sendSteady ? sendSteady.cpuPercent : wholeRunCpuPercent(send),
      steadySec: recvSteady.seconds,
      recvPeakRssKb: Math.max(...recv.samples.map((s) => s.rss_kb)),
      sendPeakRssKb: Math.max(...send.samples.map((s) => s.rss_kb)),
      seqGaps: recv.totals?.seq_gaps ?? 0,
      errors: (recv.totals?.errors ?? 0) + (send.totals?.errors ?? 0),
      negotiatedCrypto: recv.negotiated?.crypto ?? 'unknown',
      negotiatedCompression: recv.negotiated?.compression ?? 'unknown',
      compressionRatio: send.compression?.ratio ?? null,
      // per-second rates of the steady samples (for interactive charts)
      recvQpsSeries: recvSteady.samples.map((s) => Math.round(s.rate)),
      sendQpsSeries: sendSteady ? sendSteady.samples.map((s) => Math.round(s.rate)) : [],
    };
    combos.set(entry.name, combo);
  }
  return { platform, dir, combos: [...combos.values()] };
}

function summarizeCsv(csvPath) {
  const base = basename(csvPath);
  const m = /^summary\.(.+)\.csv$/i.exec(base);
  const platform = m ? m[1] : base.replace(/\.csv$/i, '');
  const lines = readFileSync(csvPath, 'utf8').trim().split(/\r?\n/);
  if (lines.length < 2) return { platform, dir: csvPath, combos: [] };
  const headers = lines[0].split(',');
  const combos = lines.slice(1).map((line) => {
    const parts = line.split(',');
    const row = {};
    headers.forEach((h, i) => (row[h] = parts[i] ?? ''));
    const level = row.level || 'default';
    const compressionAlgo = row.compression || 'none';
    return {
      platform,
      crypto: row.crypto,
      compression: `${compressionAlgo}-${level}`,
      level,
      compressionAlgo,
      size: Number(row.payload_size),
      qps: Number(row.qps),
      throughputBytesPerSec: Number(row.throughput_Bps),
      recvCpuPercent: Number(row.recv_cpu_percent),
      sendCpuPercent: Number(row.send_cpu_percent),
      steadySec: Number(row.steady_sec),
      recvPeakRssKb: Number(row.recv_peak_rss_kb),
      sendPeakRssKb: Number(row.send_peak_rss_kb),
      seqGaps: Number(row.seq_gaps || 0),
      errors: Number(row.errors || 0),
      negotiatedCrypto: row.negotiated_crypto || 'unknown',
      negotiatedCompression: row.negotiated_compression || 'unknown',
      compressionRatio: row.compression_ratio === '' ? null : Number(row.compression_ratio),
      recvQpsSeries: [],
      sendQpsSeries: [],
    };
  });
  return { platform, dir: csvPath, combos };
}

function summarizeInput(inputPath) {
  if (statSync(inputPath).isFile() && inputPath.toLowerCase().endsWith('.csv')) {
    return summarizeCsv(inputPath);
  }
  return summarizePlatform(inputPath);
}

const platforms = resultInputs.map(summarizeInput).filter((p) => p.combos.length > 0);
if (platforms.length === 0) {
  console.error('no usable results found');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// CSV / markdown output

function fmtQps(v) {
  if (v >= 1e6) return `${(v / 1e6).toFixed(2)}M`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`;
  return `${Math.round(v)}`;
}

function fmtBytes(v) {
  if (v >= 1024 ** 3) return `${(v / 1024 ** 3).toFixed(2)}GB/s`;
  if (v >= 1024 ** 2) return `${(v / 1024 ** 2).toFixed(1)}MB/s`;
  if (v >= 1024) return `${(v / 1024).toFixed(1)}KB/s`;
  return `${Math.round(v)}B/s`;
}

function fmtSize(v) {
  return v >= 1024 ? `${v / 1024 >= 1024 ? `${(v / 1024 / 1024).toFixed(0)}MB` : `${v / 1024}KB`}` : `${v}B`;
}

function comboOf(platformData, crypto, compressionAlgo, level, size) {
  const compression = `${compressionAlgo}-${level ?? 'default'}`;
  return platformData.combos.find((c) => c.crypto === crypto && c.compression === compression && c.size === size);
}

mkdirSync(outDir, { recursive: true });
const chartsDir = chartsOnly ? outDir : join(outDir, 'charts');
mkdirSync(chartsDir, { recursive: true });

if (!chartsOnly) {
for (const p of platforms) {
  const csvLines = [
    'crypto,compression,level,payload_size,qps,throughput_Bps,recv_cpu_percent,send_cpu_percent,recv_peak_rss_kb,send_peak_rss_kb,compression_ratio,seq_gaps,errors,negotiated_crypto,negotiated_compression,steady_sec',
  ];
  const mdLines = [
    `### ${p.platform}`,
    '',
    '加密 | 压缩 | 包长 | QPS(msg/s) | 吞吐量(payload) | CPU 收/发 (%) | 峰值内存 收/发 (MB) | 实测压缩率',
    '---|---|---:|---:|---:|---|---|---:',
  ];
  for (const c of [...p.combos].sort((a, b) => a.size - b.size)) {
    csvLines.push(
      [
        c.crypto,
        c.compressionAlgo,
        c.level,
        c.size,
        Math.round(c.qps),
        Math.round(c.throughputBytesPerSec),
        c.recvCpuPercent.toFixed(1),
        c.sendCpuPercent.toFixed(1),
        c.recvPeakRssKb,
        c.sendPeakRssKb,
        c.compressionRatio === null ? '' : c.compressionRatio.toFixed(4),
        c.seqGaps,
        c.errors,
        c.negotiatedCrypto,
        c.negotiatedCompression,
        c.steadySec.toFixed(1),
      ].join(',')
    );
    mdLines.push(
      [
        c.crypto,
        `${c.compressionAlgo}@${c.level}`,
        fmtSize(c.size),
        fmtQps(c.qps),
        fmtBytes(c.throughputBytesPerSec),
        `${c.recvCpuPercent.toFixed(0)}%/${c.sendCpuPercent.toFixed(0)}%`,
        `${(c.recvPeakRssKb / 1024).toFixed(1)}/${(c.sendPeakRssKb / 1024).toFixed(1)}`,
        c.compressionRatio === null ? '-' : `${(c.compressionRatio * 100).toFixed(1)}%`,
      ].join(' | ')
    );
  }
  writeFileSync(join(outDir, `summary.${p.platform}.csv`), csvLines.join('\n') + '\n');
  writeFileSync(join(outDir, `summary.${p.platform}.md`), mdLines.join('\n') + '\n');
}
}

// ---------------------------------------------------------------------------
// Charts (echarts SSR -> SVG)

let echarts = null;
try {
  // Resolve echarts either from an explicitly provided node_modules directory
  // (ECHARTS_NODE_MODULES) or from normal module resolution.
  const { createRequire } = await import('node:module');
  const baseDir = process.env.ECHARTS_NODE_MODULES;
  const req = baseDir ? createRequire(join(baseDir, '_resolver.js')) : createRequire(import.meta.url);
  echarts = req('echarts');
} catch {
  try {
    echarts = (await import('echarts')).default ?? (await import('echarts'));
  } catch {
    console.warn('echarts not installed; skipping SVG charts (npm install echarts)');
  }
}

const PALETTE = ['#5470c6', '#91cc75', '#fac858', '#ee6666', '#73c0de', '#3ba272'];

// All crypto x compression combinations of one platform share a single figure, throughput
// and QPS apart. Three cues tell the 22 lines apart:
//   colour = compression (the lines stratify by compression first)
//   stroke = crypto family (solid none, dashed AES-GCM, dotted chacha20, dash-dot chacha20-poly1305-ietf)
//   marker = the single algorithm (the three AES key lengths share one stroke)
const COMP_COLORS = {
  'none-default': '#5470c6',
  'lz4-fast': '#91cc75',
  'lz4-default': '#3ba272',
  'zstd-default': '#fc8452',
  'zstd-high-ratio': '#ee6666',
};
const CRYPTO_STYLE = {
  none: { stroke: 'solid', marker: 'circle' },
  'aes-128-gcm': { stroke: [7, 4], marker: 'triangle' },
  'aes-192-gcm': { stroke: [7, 4], marker: 'rect' },
  'aes-256-gcm': { stroke: [7, 4], marker: 'diamond' },
  chacha20: { stroke: [1.5, 3], marker: 'emptyCircle' },
  'chacha20-poly1305-ietf': { stroke: [9, 3, 2, 3], marker: 'emptyTriangle' },
};
// crypto without compression only exists for the six crypto presets
const COMBO_ROWS = COMPRESS_SETS.map((comp) => ({
  comp,
  cryptos: comp.algo === 'none' ? CRYPTO_ORDER : ['none', ...COMBINED_CRYPTOS],
}));
const comboName = (comp, crypto) => `${comp.label} · ${crypto}`;

function baseOption(title) {
  return {
    backgroundColor: '#ffffff',
    title: { text: title, left: 'center', top: 10, textStyle: { fontSize: 15 } },
    legend: { top: 36 },
    tooltip: { trigger: 'axis', confine: true },
    // containLabel keeps tick labels inside the canvas; axis names are folded
    // into the title to avoid clipped text at the canvas edges.
    grid: { left: 16, right: 28, top: 78, bottom: 14, containLabel: true },
  };
}

function lineBaseOption(title, seriesCount) {
  const opt = baseOption(title);
  opt.legend.top = 36;
  opt.legend.type = seriesCount > 8 ? 'scroll' : 'plain';
  opt.tooltip.trigger = 'axis';
  return opt;
}

function renderSvg(option, height = 540) {
  if (!echarts) return null;
  const chart = echarts.init(null, null, { renderer: 'svg', ssr: true, width: 960, height });
  // animation:false is required for SSR: echarts emits enter-animation keyframes
  // (a clip-path rect expanding from 0 width) into the SVG <style>; GitHub renders
  // SVGs via <img> where animations never play, leaving lines clipped to zero width.
  chart.setOption({ ...option, animation: false });
  const svg = chart.renderToSVGString();
  chart.dispose();
  return svg;
}

function saveChart(name, option, height) {
  const svg = renderSvg(option, height);
  if (!svg) return;
  writeFileSync(join(chartsDir, `${name}.svg`), svg);
  console.log(`chart: charts/${name}.svg`);
}

const SIZE_TICKS = PAYLOAD_SIZES.map((s) => fmtSize(s));

function valueLogAxis(name = 'msg/s') {
  return {
    type: 'log',
    name,
    // the lowest decade that still holds the smallest value
    min: ({ min }) => Math.pow(10, Math.floor(Math.log10(Math.max(min, 1)))),
    axisLabel: {
      formatter: (v) => (v >= 1e9 ? `${v / 1e9}G` : v >= 1e6 ? `${v / 1e6}M` : v >= 1e3 ? `${v / 1e3}K` : `${v}`),
    },
  };
}

function comboSeries(p, pick) {
  const combos = COMBO_ROWS.flatMap((row) => row.cryptos.map((crypto) => ({ comp: row.comp, crypto })));
  // the plaintext reference is drawn last, so that it stays visible under the others
  combos.push(combos.shift());
  return combos.map(({ comp, crypto }) => {
    const style = CRYPTO_STYLE[crypto];
    const color = COMP_COLORS[comp.key];
    return {
      name: comboName(comp, crypto),
      type: 'line',
      symbol: style.marker,
      symbolSize: 8,
      lineStyle: { width: 2.4, color, type: style.stroke },
      itemStyle: { color },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, crypto, comp.algo, comp.level, size);
        return c ? pick(c) : '-';
      }),
    };
  });
}

// The legend is a table: one row per compression (its colour in the row label), one cell per
// crypto. The line samples are drawn from the series themselves.
function comboChartHead(title) {
  const top = 40;
  const rowHeight = 22;
  return {
    ...baseOption(title),
    legend: COMBO_ROWS.map((row, r) => ({
      left: 150,
      top: top + r * rowHeight,
      itemWidth: 38,
      itemHeight: 14,
      itemGap: 18,
      textStyle: { fontSize: 12, color: '#333' },
      data: row.cryptos.map((crypto) => comboName(row.comp, crypto)),
      formatter: (name) => name.slice(name.indexOf(' · ') + 3),
    })),
    graphic: COMBO_ROWS.map((row, r) => ({
      type: 'text',
      left: 24,
      top: top + r * rowHeight + 1,
      style: { text: row.comp.label, fill: COMP_COLORS[row.comp.key], font: 'bold 13px sans-serif' },
    })),
    grid: { left: 16, right: 28, top: top + COMBO_ROWS.length * rowHeight + 24, bottom: 14, containLabel: true },
    xAxis: { type: 'category', data: SIZE_TICKS, axisLabel: { interval: 0 } },
  };
}

// Throughput & QPS of every crypto x compression combination against payload size
// (for primary TCP platforms; _shm and _mimalloc variants are compared in dedicated charts)
const comboPlatforms = platforms.filter((p) => !p.platform.includes('_'));
for (const p of comboPlatforms) {
  saveChart(
    `line-throughput-combos-${p.platform}`,
    {
      ...comboChartHead(`吞吐量曲线 payload MB/s - 全部加密 × 压缩组合 - ${labelOf(p.platform)}`),
      yAxis: { type: 'value', name: 'MB/s' },
      series: comboSeries(p, (c) => Number((c.throughputBytesPerSec / 1024 ** 2).toFixed(1))),
    },
    640
  );
  saveChart(
    `line-qps-combos-${p.platform}`,
    {
      ...comboChartHead(`QPS 曲线 msg/s（对数轴） - 全部加密 × 压缩组合 - ${labelOf(p.platform)}`),
      yAxis: valueLogAxis(),
      series: comboSeries(p, (c) => Math.round(c.qps)),
    },
    640
  );
}

// Line charts: cross-platform TCP baseline (none/none), throughput + QPS.
// Includes plain TCP platforms plus any `<platform>_mimalloc` allocator variant (dashed)
// so readers can compare both default allocators and allocator-aligned runs in one view.
const overviewPlatforms = platforms.filter((p) => !p.platform.endsWith('_shm'));
if (overviewPlatforms.length >= 2) {
  const overviewPalette = ['#5470c6', '#3ba272', '#91cc75', '#ee6666', '#73c0de', '#fac858'];
  const buildOverviewSeries = (pick) =>
    overviewPlatforms.map((p, i) => {
      const isVariant = p.platform.includes('_');
      const color = overviewPalette[i % overviewPalette.length];
      return {
        name: labelOf(p.platform),
        type: 'line',
        symbol: isVariant ? 'diamond' : 'circle',
        symbolSize: 8,
        lineStyle: { width: 3, color, type: isVariant ? 'dashed' : 'solid' },
        itemStyle: { color },
        data: PAYLOAD_SIZES.map((size) => {
          const c = comboOf(p, 'none', 'none', 'default', size);
          return c ? pick(c) : '-';
        }),
      };
    });

  saveChart('line-throughput-platforms', {
    ...lineBaseOption('吞吐量曲线 payload MB/s - 跨平台 TCP 基线对比（无加密无压缩）', overviewPlatforms.length),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: { type: 'value', name: 'MB/s' },
    series: buildOverviewSeries((c) => Number((c.throughputBytesPerSec / 1024 ** 2).toFixed(1))),
  });

  saveChart('line-qps-platforms', {
    ...lineBaseOption('QPS 曲线 msg/s（对数轴） - 跨平台 TCP 基线对比（无加密无压缩）', overviewPlatforms.length),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: valueLogAxis(),
    series: buildOverviewSeries((c) => Math.round(c.qps)),
  });
}

// Line charts: allocator comparison (`<platform>` default vs `<platform>_mimalloc`),
// throughput + QPS across four representative workloads (plain, aes-128-gcm, lz4, zstd).
const allocatorPairs = platforms
  .filter((p) => !p.platform.includes('_'))
  .map((p) => ({ base: p, mimalloc: platforms.find((q) => q.platform === `${p.platform}_mimalloc`) }))
  .filter((pair) => pair.mimalloc);

const ALLOCATOR_PROFILES = [
  { crypto: 'none', algo: 'none', level: 'default', label: '无加密无压缩', color: '#5470c6' },
  { crypto: 'aes-128-gcm', algo: 'none', level: 'default', label: 'aes-128-gcm', color: '#ee6666' },
  { crypto: 'none', algo: 'lz4', level: 'default', label: 'lz4@default', color: '#3ba272' },
  { crypto: 'none', algo: 'zstd', level: 'default', label: 'zstd@default', color: '#fc8452' },
];

for (const { base, mimalloc } of allocatorPairs) {
  const suffix = allocatorPairs.length === 1 ? '' : `-${base.platform}`;
  const buildAllocatorChart = (title, yAxis, pick) => {
    const top = 40;
    const rowHeight = 24;
    const rows = [
      { caption: 'mimalloc（实线）', dashed: false, platform: mimalloc, tag: 'mimalloc' },
      { caption: 'glibc 默认（虚线）', dashed: true, platform: base, tag: 'glibc' },
    ];
    const series = rows.flatMap((row) =>
      ALLOCATOR_PROFILES.map((prof) => ({
        name: `${prof.label} · ${row.tag}`,
        type: 'line',
        symbol: row.dashed ? 'emptyCircle' : 'circle',
        symbolSize: 8,
        lineStyle: { width: 2.8, color: prof.color, type: row.dashed ? [7, 4] : 'solid' },
        itemStyle: { color: prof.color },
        data: PAYLOAD_SIZES.map((size) => {
          const c = comboOf(row.platform, prof.crypto, prof.algo, prof.level, size);
          return c ? pick(c) : '-';
        }),
      }))
    );
    return {
      ...baseOption(title),
      legend: rows.map((row, r) => ({
        left: 168,
        top: top + r * rowHeight,
        itemWidth: 38,
        itemHeight: 14,
        itemGap: 20,
        textStyle: { fontSize: 12, color: '#333' },
        data: ALLOCATOR_PROFILES.map((prof) => `${prof.label} · ${row.tag}`),
        formatter: (name) => name.slice(0, name.indexOf(' · ')),
      })),
      graphic: rows.map((row, r) => ({
        type: 'text',
        left: 24,
        top: top + r * rowHeight + 1,
        style: { text: row.caption, fill: '#333', font: 'bold 13px sans-serif' },
      })),
      grid: { left: 16, right: 28, top: top + rows.length * rowHeight + 28, bottom: 14, containLabel: true },
      xAxis: { type: 'category', data: SIZE_TICKS, axisLabel: { interval: 0 } },
      yAxis,
      series,
    };
  };

  saveChart(
    `line-throughput-allocator${suffix}`,
    buildAllocatorChart(
      '吞吐量曲线 payload MB/s - 内存分配器对比（WSL2：mimalloc 实线 vs glibc 虚线）',
      { type: 'value', name: 'MB/s' },
      (c) => Number((c.throughputBytesPerSec / 1024 ** 2).toFixed(1))
    ),
    560
  );
  saveChart(
    `line-qps-allocator${suffix}`,
    buildAllocatorChart(
      'QPS 曲线 msg/s（对数轴） - 内存分配器对比（WSL2：mimalloc 实线 vs glibc 虚线）',
      valueLogAxis(),
      (c) => Math.round(c.qps)
    ),
    560
  );
}

// Line charts: the shm channel against the TCP channel of each platform (none/none, shm
// dashed), throughput + QPS. A platform takes part when both its TCP and `<platform>_shm`
// datasets are given.
const shmPairs = platforms
  .filter((p) => !p.platform.includes('_'))
  .map((p) => ({ tcp: p, shm: platforms.find((q) => q.platform === `${p.platform}_shm`) }))
  .filter((pair) => pair.shm);

function channelLine(name, p, color, dashed, pick) {
  return {
    name,
    type: 'line',
    symbol: dashed ? 'emptyCircle' : 'circle',
    symbolSize: 8,
    lineStyle: { width: 3, color, type: dashed ? 'dashed' : 'solid' },
    itemStyle: { color },
    data: PAYLOAD_SIZES.map((size) => {
      const c = comboOf(p, 'none', 'none', 'default', size);
      return c ? pick(c) : '-';
    }),
  };
}

if (shmPairs.length >= 1) {
  const shmColors = ['#5470c6', '#3ba272', '#ee6666', '#fac858'];
  const buildShmSeries = (pick) =>
    shmPairs.flatMap(({ tcp, shm }, i) => {
      const color = shmColors[i % shmColors.length];
      const baseLabel = labelOf(tcp.platform).replace(/\s*\([^)]*\)$/, '');
      return [
        channelLine(`${baseLabel} TCP`, tcp, color, false, pick),
        channelLine(`${baseLabel} shm`, shm, color, true, pick),
      ];
    });

  saveChart('line-throughput-shm-platforms', {
    ...lineBaseOption('吞吐量曲线 payload MB/s - 各平台 TCP 与共享内存（无加密无压缩，shm 为虚线）', shmPairs.length * 2),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: { type: 'value', name: 'MB/s' },
    series: buildShmSeries((c) => Number((c.throughputBytesPerSec / 1024 ** 2).toFixed(1))),
  });

  saveChart('line-qps-shm-platforms', {
    ...lineBaseOption('QPS 曲线 msg/s（对数轴） - 各平台 TCP 与共享内存（无加密无压缩，shm 为虚线）', shmPairs.length * 2),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: valueLogAxis(),
    series: buildShmSeries((c) => Math.round(c.qps)),
  });
}

// Interactive HTML (self-contained)

if (wantHtml) {
  let echartsJs = '';
  if (bundleFile && existsSync(bundleFile)) {
    echartsJs = readFileSync(bundleFile, 'utf8');
  } else {
    try {
      // fileURLToPath keeps this working on Windows where URL.pathname yields "/C:/..."
      echartsJs = readFileSync(
        join(dirname(fileURLToPath(import.meta.url)), '../../node_modules/echarts/dist/echarts.min.js'),
        'utf8'
      );
    } catch {
      console.warn('local echarts bundle not found; falling back to the jsdelivr CDN in the generated HTML');
      // fall back to CDN
      echartsJs = '';
    }
  }
  const data = platforms.map((p) => ({
    platform: p.platform,
    combos: p.combos.map((c) => ({
      crypto: c.crypto,
      compression: c.compression,
      size: c.size,
      qps: Math.round(c.qps),
      throughputBytesPerSec: Math.round(c.throughputBytesPerSec),
      recvCpuPercent: Number(c.recvCpuPercent.toFixed(1)),
      sendCpuPercent: Number(c.sendCpuPercent.toFixed(1)),
      recvPeakRssKb: c.recvPeakRssKb,
      sendPeakRssKb: c.sendPeakRssKb,
      compressionRatio: c.compressionRatio,
      recvQpsSeries: c.recvQpsSeries,
    })),
  }));
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>libatbus node stream benchmark</title>
${echartsJs ? `<script>${echartsJs}</script>` : `<script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>`}
<style>body{font-family:system-ui,sans-serif;margin:20px;background:#ffffff;color:#333}#opts{margin-bottom:12px}#main{width:960px;height:540px}</style>
</head>
<body>
<div id="opts"></div>
<div id="main"></div>
<script>
const DATA = ${JSON.stringify(data)};
// interactive explorer: pick platform / crypto / compression and switch metrics
const metrics = {
  qps: { name: 'QPS (msg/s)', key: 'qps' },
  throughput: { name: '吞吐量 (payload B/s)', key: 'throughputBytesPerSec' },
  recvCpu: { name: '收端 CPU%', key: 'recvCpuPercent' },
  sendCpu: { name: '发端 CPU%', key: 'sendCpuPercent' },
};
const sizes = ${JSON.stringify(PAYLOAD_SIZES)};
const platformSel = document.createElement('select');
const cryptoSel = document.createElement('select');
const compSel = document.createElement('select');
const metricSel = document.createElement('select');
for (const [el, values, label] of [
  [platformSel, DATA.map((d) => d.platform), '平台'],
  [cryptoSel, ${JSON.stringify(CRYPTO_ORDER)}, '加密'],
  [compSel, ${JSON.stringify(COMPRESS_SETS.map((c) => c.key))}, '压缩'],
  [metricSel, Object.keys(metrics), '指标'],
]) {
  for (const v of values) { const o = document.createElement('option'); o.textContent = v; el.appendChild(o); }
  el.id = label;
  document.getElementById('opts').append(label + ' ', el, ' ');
}
metricSel.value = 'qps';
const chart = echarts.init(document.getElementById('main'));
function render() {
  const key = metrics[metricSel.value].key;
  const size = sizes;
  const series = DATA.map((p) => {
    const bySize = {};
    for (const c of p.combos) {
      if (c.crypto === cryptoSel.value && c.compression === compSel.value) bySize[c.size] = c[key];
    }
    return {
      name: p.platform, type: 'bar',
      data: size.map((s) => bySize[s] ?? null),
    };
  });
  chart.setOption({
    title: { text: metrics[metricSel.value].name },
    tooltip: { trigger: 'axis' },
    legend: {},
    xAxis: { type: 'category', data: size.map((s) => s >= 1024 ? s / 1024 + 'KB' : s + 'B') },
    yAxis: {
      type: metrics[metricSel.value].key === 'qps' ? 'log' : 'value',
      name: metrics[metricSel.value].name,
      min: 1,
    },
    series,
  }, true);
}
for (const el of [platformSel, cryptoSel, compSel, metricSel]) el.onchange = render;
render();
</script>
</body>
</html>`;
  writeFileSync(join(outDir, 'benchmark_charts.html'), html);
  console.log('report: benchmark_charts.html');
}

console.log(`report written to ${outDir}`);
