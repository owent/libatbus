#!/usr/bin/env node
// Copyright 2026 atframework
//
// Summarize benchmark_node_stream_matrix results and render charts.
//
// usage: node benchmark_node_stream_report.mjs <result_dir> [<result_dir2> ...] --out <report_dir> [--html]
//
// Each <result_dir> contains one sub-directory per combo, named
//   <crypto>__<compression>-<level>__<size>
// with recv.json / send.json produced by benchmark_node_stream_send/recv.
// The directory name is used as the platform label (e.g. wsl / windows).
//
// Outputs (into --out):
//   summary.<platform>.csv       per-combo metrics (receiver-side QPS/throughput, CPU, RSS)
//   summary.<platform>.md        the same data as a markdown table
//   charts/*.svg                 static SVG charts rendered by echarts SSR
//   benchmark_charts.html        interactive self-contained charts (when --html and echarts.min.js is bundled)

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2);
const outIndex = argv.indexOf('--out');
if (argv.length < 2 || outIndex < 0) {
  console.error(
    'usage: node benchmark_node_stream_report.mjs <result_dir>... --out <report_dir> [--html] [--bundle <echarts.min.js>]'
  );
  process.exit(1);
}
const outDir = resolve(argv[outIndex + 1]);
const bundleIndex = argv.indexOf('--bundle');
const bundleFile = bundleIndex >= 0 ? argv[bundleIndex + 1] : null;
const wantHtml = argv.includes('--html');
const resultDirs = [];
for (let i = 0; i < argv.length; ++i) {
  if (i === outIndex || i === outIndex + 1) continue;
  if (bundleIndex >= 0 && (i === bundleIndex || i === bundleIndex + 1)) continue;
  if (argv[i].startsWith('--')) continue;
  resultDirs.push(resolve(argv[i]));
}
if (resultDirs.length === 0) {
  console.error('no result directory given');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Parsing

// Steady-window trimming: drop the first 2 samples (handshake + warmup) and the
// last 1 sample (drain tail) before averaging.
const TRIM_HEAD = 2;
const TRIM_TAIL = 1;

const PAYLOAD_SIZES = [200, 1024, 8192, 65536, 307200];
const CRYPTO_ORDER = ['none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20', 'chacha20-poly1305-ietf'];
// compression presets: <algo>-<level>, matching the directory name scheme
// note: zstd level "balanced" maps to the zstd default level (3), reported as "zstd default"
const COMPRESS_SETS = [
  { key: 'none-default', algo: 'none', level: 'default', label: '无压缩' },
  { key: 'lz4-fast', algo: 'lz4', level: 'fast', label: 'lz4 fast' },
  { key: 'lz4-default', algo: 'lz4', level: 'default', label: 'lz4 default' },
  { key: 'zstd-default', algo: 'zstd', level: 'default', label: 'zstd default' },
  { key: 'zstd-high-ratio', algo: 'zstd', level: 'high-ratio', label: 'zstd high-ratio' },
];
// combined crypto+compression groups (AEAD-safe cryptos only)
const COMBINED_CRYPTOS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305-ietf'];
const COMBINED_SETS = [];
for (const comp of COMPRESS_SETS.filter((c) => c.algo !== 'none')) {
  for (const crypto of COMBINED_CRYPTOS) {
    COMBINED_SETS.push({ crypto, compKey: comp.key, label: `${crypto} + ${comp.label}` });
  }
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    return null;
  }
}

function average(list) {
  if (list.length === 0) return 0;
  return list.reduce((a, b) => a + b, 0) / list.length;
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
    const window = recv.samples.slice(TRIM_HEAD, recv.samples.length - TRIM_TAIL);
    const sendWindow = send.samples.slice(TRIM_HEAD, send.samples.length - TRIM_TAIL);
    if (window.length === 0) {
      console.warn(`[skip] ${platform}/${entry.name}: empty steady window`);
      continue;
    }
    const payloadBytes = window.reduce((a, s) => a + s.bytes, 0);
    const payloadMsgs = window.reduce((a, s) => a + s.msgs, 0);
    const wallSec = window.length; // 1-second samples
    const dashIdx = parsed.compression.indexOf('-');
    const combo = {
      platform,
      crypto: parsed.crypto,
      compression: parsed.compression,
      level: dashIdx >= 0 ? parsed.compression.slice(dashIdx + 1) : 'default',
      compressionAlgo: dashIdx >= 0 ? parsed.compression.slice(0, dashIdx) : parsed.compression,
      size: parsed.size,
      qps: payloadMsgs / wallSec,
      throughputBytesPerSec: payloadBytes / wallSec,
      recvCpuPercent: average(window.map((s) => s.cpu_percent)),
      sendCpuPercent: average(sendWindow.map((s) => s.cpu_percent)),
      recvPeakRssKb: Math.max(...recv.samples.map((s) => s.rss_kb)),
      sendPeakRssKb: Math.max(...send.samples.map((s) => s.rss_kb)),
      seqGaps: recv.totals?.seq_gaps ?? 0,
      errors: (recv.totals?.errors ?? 0) + (send.totals?.errors ?? 0),
      negotiatedCrypto: recv.negotiated?.crypto ?? 'unknown',
      negotiatedCompression: recv.negotiated?.compression ?? 'unknown',
      compressionRatio: send.compression?.ratio ?? null,
      // per-second raw samples (for interactive charts)
      recvQpsSeries: window.map((s) => s.msgs),
      sendQpsSeries: sendWindow.map((s) => s.msgs),
    };
    combos.set(entry.name, combo);
  }
  return { platform, dir, combos: [...combos.values()] };
}

const platforms = resultDirs.map(summarizePlatform).filter((p) => p.combos.length > 0);
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
const chartsDir = join(outDir, 'charts');
mkdirSync(chartsDir, { recursive: true });

for (const p of platforms) {
  const csvLines = [
    'crypto,compression,level,payload_size,qps,throughput_Bps,recv_cpu_percent,send_cpu_percent,recv_peak_rss_kb,send_peak_rss_kb,compression_ratio,seq_gaps,errors,negotiated_crypto,negotiated_compression',
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
const LINE_PALETTE = [
  '#5470c6', '#91cc75', '#fac858', '#ee6666', '#73c0de', '#3ba272',
  '#fc8452', '#9a60b4', '#ea7ccc', '#5ab1ef', '#c6e910', '#d48265',
];
const CRYPTO_COLORS = Object.fromEntries(CRYPTO_ORDER.map((name, i) => [name, PALETTE[i % PALETTE.length]]));
const COMP_COLORS = {
  'none-default': '#5470c6',
  'lz4-fast': '#91cc75',
  'lz4-default': '#8fd9a8',
  'zstd-default': '#fac858',
  'zstd-high-ratio': '#ee6666',
};

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

function renderSvg(option) {
  if (!echarts) return null;
  const chart = echarts.init(null, null, { renderer: 'svg', ssr: true, width: 960, height: 540 });
  // animation:false is required for SSR: echarts emits enter-animation keyframes
  // (a clip-path rect expanding from 0 width) into the SVG <style>; GitHub renders
  // SVGs via <img> where animations never play, leaving lines clipped to zero width.
  chart.setOption({ ...option, animation: false });
  const svg = chart.renderToSVGString();
  chart.dispose();
  return svg;
}

function saveChart(name, option) {
  const svg = renderSvg(option);
  if (!svg) return;
  writeFileSync(join(chartsDir, `${name}.svg`), svg);
  console.log(`chart: charts/${name}.svg`);
}

function sizeAxis() {
  return {
    type: 'category',
    data: PAYLOAD_SIZES.map((s) => fmtSize(s)),
    axisLabel: { interval: 0 },
  };
}

function valueLogAxis() {
  return {
    type: 'log',
    min: 1,
    axisLabel: {
      formatter: (v) => {
        if (v >= 1e9) return `${v / 1e9}G`;
        if (v >= 1e6) return `${v / 1e6}M`;
        if (v >= 1e3) return `${v / 1e3}K`;
        return `${v}`;
      },
    },
  };
}

// Chart 1: QPS by payload size, one series per crypto algorithm (compression = none)
for (const p of platforms) {
  saveChart(`qps-crypto-${p.platform}`, {
    ...baseOption(`QPS (msg/s, 对数轴) - 加密算法对比（无压缩） - ${p.platform}`),
    xAxis: sizeAxis(),
    yAxis: valueLogAxis(),
    series: CRYPTO_ORDER.map((crypto) => ({
      name: crypto,
      type: 'bar',
      barGap: '10%',
      itemStyle: { color: CRYPTO_COLORS[crypto] },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, crypto, 'none', null, size);
        return c ? Math.round(c.qps) : '-';
      }),
    })),
  });
}

// Chart 2: throughput by payload size, one series per compression (crypto = none)
for (const p of platforms) {
  saveChart(`throughput-compression-${p.platform}`, {
    ...baseOption(`吞吐量 payload MB/s - 压缩算法对比（无加密） - ${p.platform}`),
    xAxis: sizeAxis(),
    yAxis: {
      type: 'value',
      axisLabel: { formatter: (v) => `${(v / 1024 ** 2).toFixed(0)}` },
    },
    series: COMPRESS_SETS.map((comp) => ({
      name: comp.label,
      type: 'bar',
      itemStyle: { color: COMP_COLORS[comp.key] },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, 'none', comp.algo, comp.level, size);
        return c ? Math.round(c.throughputBytesPerSec) : '-';
      }),
    })),
  });
}

// Chart 3: CPU efficiency (payload MB/s per total CPU percent, crypto dimension, compression none)
for (const p of platforms) {
  saveChart(`cpu-efficiency-${p.platform}`, {
    ...baseOption(`每核效率 payload MB/s / 总CPU% - 加密对比（无压缩） - ${p.platform}`),
    xAxis: sizeAxis(),
    yAxis: { type: 'value' },
    series: CRYPTO_ORDER.map((crypto) => ({
      name: crypto,
      type: 'bar',
      itemStyle: { color: CRYPTO_COLORS[crypto] },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, crypto, 'none', null, size);
        if (!c) return '-';
        const totalCpu = c.recvCpuPercent + c.sendCpuPercent;
        return totalCpu > 0 ? Number(((c.throughputBytesPerSec / 1024 ** 2 / totalCpu) * 100).toFixed(2)) : '-';
      }),
    })),
  });
}

// Chart 4: platform throughput comparison (no crypto, no compression)
if (platforms.length >= 2) {
  const [a, b] = platforms;
  saveChart('wsl-vs-windows', {
    ...baseOption(`平台吞吐量对比 payload MB/s（无加密无压缩）: ${platforms.map((p) => p.platform).join(' / ')}`),
    xAxis: sizeAxis(),
    yAxis: { type: 'value' },
    series: platforms.map((p, i) => ({
      name: p.platform,
      type: 'bar',
      itemStyle: { color: PALETTE[i] },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, 'none', 'none', 'default', size);
        return c ? Math.round(c.throughputBytesPerSec) : '-';
      }),
    })),
  });
  // and the crypto QPS ratio
  saveChart('wsl-vs-windows-qps-ratio', {
    ...baseOption(`QPS 比值 ${b.platform}=100%（无压缩）: ${a.platform} / ${b.platform}`),
    xAxis: sizeAxis(),
    yAxis: { type: 'value' },
    series: CRYPTO_ORDER.map((crypto, i) => ({
      name: crypto,
      type: 'bar',
      itemStyle: { color: PALETTE[i % PALETTE.length] },
      data: PAYLOAD_SIZES.map((size) => {
        const wa = comboOf(a, crypto, 'none', 'default', size);
        const wb = comboOf(b, crypto, 'none', 'default', size);
        return wa && wb && wb.qps > 0 ? Number(((wa.qps / wb.qps) * 100).toFixed(1)) : '-';
      }),
    })),
  });
}

// ---------------------------------------------------------------------------
// Line charts: per-config performance across payload sizes

function throughputLineSeries(p, combos) {
  return combos.map((spec, i) => {
    const color = spec.color ?? LINE_PALETTE[i % LINE_PALETTE.length];
    return {
      name: spec.label,
      type: 'line',
      symbol: 'circle',
      symbolSize: 7,
      lineStyle: { width: 2.5, color },
      itemStyle: { color },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, spec.crypto ?? 'none', spec.algo ?? 'none', spec.level ?? 'default', size);
        return c ? Number((c.throughputBytesPerSec / 1024 ** 2).toFixed(1)) : '-';
      }),
    };
  });
}

function qpsLineSeries(p, combos) {
  return combos.map((spec, i) => {
    const color = spec.color ?? LINE_PALETTE[i % LINE_PALETTE.length];
    return {
      name: spec.label,
      type: 'line',
      symbol: 'circle',
      symbolSize: 7,
      lineStyle: { width: 2.5, color },
      itemStyle: { color },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, spec.crypto ?? 'none', spec.algo ?? 'none', spec.level ?? 'default', size);
        return c ? Math.round(c.qps) : '-';
      }),
    };
  });
}

const SIZE_TICKS = PAYLOAD_SIZES.map((s) => fmtSize(s));

for (const p of platforms) {
  // Line chart 1: throughput lines, compression presets (crypto = none)
  saveChart(`line-throughput-compression-${p.platform}`, {
    ...lineBaseOption(`吞吐量曲线 payload MB/s - 压缩配置对比（无加密） - ${p.platform}`, COMPRESS_SETS.length),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: { type: 'value', name: 'MB/s' },
    series: throughputLineSeries(
      p,
      COMPRESS_SETS.map((c) => ({ label: c.label, algo: c.algo, level: c.level, color: COMP_COLORS[c.key] }))
    ),
  });

  // Line chart 2: throughput lines, crypto presets (compression = none)
  saveChart(`line-throughput-crypto-${p.platform}`, {
    ...lineBaseOption(`吞吐量曲线 payload MB/s - 加密算法对比（无压缩） - ${p.platform}`, CRYPTO_ORDER.length),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: { type: 'value', name: 'MB/s' },
    series: throughputLineSeries(
      p,
      CRYPTO_ORDER.map((c) => ({ label: c, crypto: c, algo: 'none', level: 'default', color: CRYPTO_COLORS[c] }))
    ),
  });

  // Line chart 3: QPS lines, crypto presets (compression = none)
  saveChart(`line-qps-crypto-${p.platform}`, {
    ...lineBaseOption(`QPS 曲线 msg/s - 加密算法对比（无压缩） - ${p.platform}`, CRYPTO_ORDER.length),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: { type: 'log', name: 'QPS', min: 1 },
    series: qpsLineSeries(
      p,
      CRYPTO_ORDER.map((c) => ({ label: c, crypto: c, algo: 'none', level: 'default', color: CRYPTO_COLORS[c] }))
    ),
  });

  // Line chart 4/5: combined crypto+compression groups, one chart per compression
  // preset (3 crypto lines + the no-crypto reference; a single 12-line chart's
  // legend overflows the canvas)
  for (const comp of COMPRESS_SETS.filter((c) => c.algo !== 'none')) {
    saveChart(`line-throughput-combined-${comp.key}-${p.platform}`, {
      ...lineBaseOption(
        `吞吐量曲线 payload MB/s - ${comp.label} + 加密 - ${p.platform}`,
        COMBINED_CRYPTOS.length + 1
      ),
      xAxis: { type: 'category', data: SIZE_TICKS },
      yAxis: { type: 'value', name: 'MB/s' },
      series: throughputLineSeries(p, [
        { label: '无加密（同压缩）', algo: comp.algo, level: comp.level, color: COMP_COLORS[comp.key] },
        ...COMBINED_CRYPTOS.map((crypto) => ({
          label: `+ ${crypto}`,
          crypto,
          algo: comp.algo,
          level: comp.level,
        })),
      ]),
    });
  }
}

// Line chart: cross-platform throughput (none/none) for every platform present
if (platforms.length >= 2) {
  saveChart('line-throughput-platforms', {
    ...lineBaseOption(`吞吐量曲线 payload MB/s - 平台对比（无加密无压缩）`, platforms.length),
    xAxis: { type: 'category', data: SIZE_TICKS },
    yAxis: { type: 'value', name: 'MB/s' },
    series: platforms.map((p, i) => ({
      name: p.platform,
      type: 'line',
      symbol: 'circle',
      symbolSize: 8,
      lineStyle: { width: 3, color: PALETTE[i % PALETTE.length] },
      itemStyle: { color: PALETTE[i % PALETTE.length] },
      data: PAYLOAD_SIZES.map((size) => {
        const c = comboOf(p, 'none', 'none', 'default', size);
        return c ? Number((c.throughputBytesPerSec / 1024 ** 2).toFixed(1)) : '-';
      }),
    })),
  });
}

// ---------------------------------------------------------------------------
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
