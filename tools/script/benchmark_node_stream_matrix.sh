#!/usr/bin/env bash
# Copyright 2026 atframework
#
# Run the node-level TCP stream benchmark matrix against
# benchmark_node_stream_send/recv and collect JSON results.
#
# usage: benchmark_node_stream_matrix.sh <bin_dir> <result_dir> [duration_sec] [listen_addr]
#   bin_dir     directory containing benchmark_node_stream_send / benchmark_node_stream_recv
#   result_dir  output directory (one sub-directory per combo)
#   duration_sec  send duration of each run (default 15)
#   listen_addr   receiver listen address; the sender listens on port+1 automatically
#
# Environment:
#   PRELOAD_LIB  optional shared library (e.g. mimalloc) prepended via LD_PRELOAD
#                to both processes.
#
# Combo layout (per size):
#   1. crypto dimension: 6 crypto algorithms with compression=none
#   2. compression dimension: 5 compression presets with crypto=none
#   3. combined dimension: 4 compression presets x 3 AEAD-safe crypto algorithms
# The receiver is started in the background; the sender floods until the duration
# elapses and both processes write JSON reports into the combo directory.

set -u

BIN_DIR="${1:-.}"
RESULT_DIR="${2:-./benchmark_results}"
DURATION="${3:-15}"
ADDR="${4:-ipv4://127.0.0.1:16500}"
# Optional 5th arg: shm://key. When set, the receiver also listens on it so the
# peer's connect-back upgrades the data channel to shared memory.
SHM_ADDR="${5:-}"

SEND_BIN="${BIN_DIR}/benchmark_node_stream_send"
RECV_BIN="${BIN_DIR}/benchmark_node_stream_recv"
if [[ ! -x "${SEND_BIN}" ]]; then
  if [[ -f "${SEND_BIN}.exe" ]]; then
    SEND_BIN="${SEND_BIN}.exe"
    RECV_BIN="${RECV_BIN}.exe"
  else
    echo "benchmark_node_stream_send not found in ${BIN_DIR}" >&2
    exit 1
  fi
fi

# The sender also listens (port+1) so the peer's connect-back builds the designed
# ctrl/data connection pair instead of a degenerate self loop.
SEND_LISTEN_ADDR="${ADDR%:*}:$(( ${ADDR##*:} + 1 ))"

CRYPTOS=(none aes-128-gcm aes-192-gcm aes-256-gcm chacha20 chacha20-poly1305-ietf)
COMPRESSIONS=("lz4 fast" "lz4 default" "zstd default" "zstd high-ratio")
COMBINED_CRYPTOS=(aes-128-gcm aes-256-gcm chacha20-poly1305-ietf)
SIZES=(200 1024 8192 65536 307200)

mkdir -p "${RESULT_DIR}"

# Build the explicit combo list to avoid duplicating the none/none baseline:
# entries are "crypto|comp|level"
COMBOS=()
for CRYPTO in "${CRYPTOS[@]}"; do
  COMBOS+=("${CRYPTO}|none|default")
done
for COMP_SPEC in "${COMPRESSIONS[@]}"; do
  COMP=$(echo "${COMP_SPEC}" | cut -d' ' -f1)
  LEVEL=$(echo "${COMP_SPEC}" | cut -d' ' -f2)
  COMBOS+=("none|${COMP}|${LEVEL}")
done
for COMP_SPEC in "${COMPRESSIONS[@]}"; do
  COMP=$(echo "${COMP_SPEC}" | cut -d' ' -f1)
  LEVEL=$(echo "${COMP_SPEC}" | cut -d' ' -f2)
  for CRYPTO in "${COMBINED_CRYPTOS[@]}"; do
    COMBOS+=("${CRYPTO}|${COMP}|${LEVEL}")
  done
done

TOTAL=$(( ${#COMBOS[@]} * ${#SIZES[@]} ))
INDEX=0
FAILED=0

run_pair() {
  local NAME="$1" CRYPTO="$2" COMP="$3" LEVEL="$4" SIZE="$5"
  local OUT_DIR="${RESULT_DIR}/${NAME}"
  mkdir -p "${OUT_DIR}"

  local PRELOAD_PREFIX=()
  if [[ -n "${PRELOAD_LIB:-}" ]]; then
    PRELOAD_PREFIX=(env "LD_PRELOAD=${PRELOAD_LIB}")
  fi

  local EXTRA_LISTEN_ARGS=()
  if [[ -n "${SHM_ADDR}" ]]; then
    EXTRA_LISTEN_ARGS=(--extra-listen="${SHM_ADDR}")
  fi

  "${PRELOAD_PREFIX[@]}" "${RECV_BIN}" "${ADDR}" 200000001 \
    --crypto="${CRYPTO}" --compression="${COMP}" --level="${LEVEL}" --payload-size="${SIZE}" \
    "${EXTRA_LISTEN_ARGS[@]}" \
    --json="${OUT_DIR}/recv.json" >"${OUT_DIR}/recv.stderr.log" 2>&1 &
  local RECV_PID=$!

  # give the listener a moment to bind
  sleep 1

  "${PRELOAD_PREFIX[@]}" "${SEND_BIN}" "${ADDR}" 200000002 200000001 "${SIZE}" "${DURATION}" \
    --crypto="${CRYPTO}" --compression="${COMP}" --level="${LEVEL}" \
    --listen="${SEND_LISTEN_ADDR}" \
    --json="${OUT_DIR}/send.json" >>"${OUT_DIR}/send.stderr.log" 2>&1

  # receiver exits when the sender disconnects; do not hang forever
  for _ in $(seq 1 30); do
    kill -0 "${RECV_PID}" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "${RECV_PID}" 2>/dev/null; then
    echo "receiver did not exit in time, killing: ${NAME}" >&2
    kill "${RECV_PID}" 2>/dev/null
    FAILED=$((FAILED + 1))
  fi
  wait "${RECV_PID}" 2>/dev/null

  if [[ -f "${OUT_DIR}/recv.json" && -f "${OUT_DIR}/send.json" ]]; then
    echo "    done: ${OUT_DIR}"
  else
    echo "    MISSING RESULT: ${OUT_DIR}" >&2
    FAILED=$((FAILED + 1))
  fi
}

for SIZE in "${SIZES[@]}"; do
  for COMBO in "${COMBOS[@]}"; do
    IFS='|' read -r CRYPTO COMP LEVEL <<<"${COMBO}"
    INDEX=$((INDEX + 1))
    NAME="${CRYPTO}__${COMP}-${LEVEL}__${SIZE}"
    echo "=== [${INDEX}/${TOTAL}] ${NAME} ==="
    run_pair "${NAME}" "${CRYPTO}" "${COMP}" "${LEVEL}" "${SIZE}"
  done
done

echo "=== matrix finished, ${FAILED} failed runs, results in ${RESULT_DIR} ==="
exit 0
