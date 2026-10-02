#!/usr/bin/env bash
# Run the LLM ladder (A + B + C + D) against the local jev OpenCode server.
#
#   scripts/run_llm_jev.sh small                      # ~1 h, 12 samples, 1 dataset
#   scripts/run_llm_jev.sh all                        # full ladder, every dataset
#   scripts/run_llm_jev.sh all --limit 20             # same coverage, ~9 h
#   scripts/run_llm_jev.sh all --datasets vulnllm_r_python,python_bench
#   scripts/run_llm_jev.sh small --dry-run            # print commands, run nothing
#
# Speeds come from your own jev run: leg B ~6 s/sample, leg C 2971 s for 20
# samples (~149 s/sample) at --concurrency 4, leg D assumed >= C. Expect
# ~5 min per sample end to end, so plan overnight.
#
# Options
#   --limit N          override the per-dataset sample count (all stages)
#   --concurrency N    parallel LLM calls, legs B and C/D (default 4)
#   --llm-timeout S    per-request timeout seconds (default 600)
#   --datasets a,b,c   only these manifests (all mode; any --list name)
#   --stop-on-error    abort at the first failing stage (default: keep going
#                      and report every failure at the end)
#   --dry-run          show the commands, execute nothing
#
# Environment
#   JEV_BASE_URL       default http://127.0.0.1:4096  (OpenCode server)
#   JEV_MODEL          default jev-1.13-free
set -uo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-small}"
if [ $# -gt 0 ]; then shift; fi

if [ "$MODE" = "-h" ] || [ "$MODE" = "--help" ] || [ "$MODE" = "help" ]; then
    sed -n '2,27p' "$0"
    exit 0
fi

JEV_BASE_URL="${JEV_BASE_URL:-http://127.0.0.1:4096}"
JEV_MODEL="${JEV_MODEL:-jev-1.13-free}"
CONCURRENCY=4
LLM_TIMEOUT_S=600
LIMIT_OVERRIDE=""
DATASETS_OVERRIDE=""
DRY_RUN=0
STOP_ON_ERROR=0

while [ $# -gt 0 ]; do
    case "$1" in
        --limit)        LIMIT_OVERRIDE="$2"; shift 2 ;;
        --concurrency)  CONCURRENCY="$2"; shift 2 ;;
        --llm-timeout)  LLM_TIMEOUT_S="$2"; shift 2 ;;
        --datasets)     DATASETS_OVERRIDE="$2"; shift 2 ;;
        --stop-on-error) STOP_ON_ERROR=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      sed -n "2,27p" "$0"; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

# The runner and every child process read these; env_config.py does not
# overwrite variables already exported, so they win over .env.
export LLM_BASE_URL="$JEV_BASE_URL"
export LLM_MODEL_ID="$JEV_MODEL"
export LLM_MODEL="$JEV_MODEL"
export LLM_PROVIDER_ID="${LLM_PROVIDER_ID:-opencode}"
export LLM_THINKING_PRINT="${LLM_THINKING_PRINT:-off}"

# dataset -> default sample cap for the full run
default_limit_for() {
    case "$1" in
        python_bench)     echo 48 ;;   # whole manifest
        proposal_min10)   echo 52 ;;   # whole manifest
        vulnllm_r_python) echo 30 ;;
        vulnllm_r_c|vulnllm_r_c_dataflow|vulnllm_r_repo_c|primevul|bigvul) echo 40 ;;
        *) echo 30 ;;
    esac
}

if [ "$MODE" = "small" ]; then
    STAGES="vulnllm_r_c_dataflow"
    [ -n "$LIMIT_OVERRIDE" ] || LIMIT_OVERRIDE=12
elif [ "$MODE" = "all" ]; then
    STAGES="vulnllm_r_c_dataflow,vulnllm_r_c,vulnllm_r_python,python_bench,proposal_min10,primevul,bigvul"
    [ -n "$DATASETS_OVERRIDE" ] && STAGES="$DATASETS_OVERRIDE"
else
    echo "usage: $0 small|all [--limit N] [--concurrency N] [--llm-timeout S]" \
         "[--datasets a,b] [--stop-on-error] [--dry-run]" >&2
    exit 2
fi

echo "model     $JEV_MODEL"
echo "endpoint  $JEV_BASE_URL"
echo "budget    max_tokens=${LLM_MAX_TOKENS:-8192} cap=${LLM_MAX_TOKENS_CAP:-32768}" \
     "temperature=${LLM_TEMPERATURE:-0.2} effort=${LLM_REASONING_EFFORT:-provider default}"
echo "legs      A (subset static), B (LLM only), C (static+LLM), D (full)"

# ---------------------------------------------------------------- preflight
if ! python3 - "$JEV_BASE_URL" <<'PY'
import sys, urllib.request
base = sys.argv[1].rstrip("/")
try:
    with urllib.request.urlopen(base + "/provider", timeout=8) as resp:
        resp.read()
    print(f"server    {base} answered HTTP {resp.status} (opencode)")
    sys.exit(0)
except Exception as exc:  # noqa: BLE001
    print(f"server    {base} unreachable: {type(exc).__name__}: {exc}")
    sys.exit(1)
PY
then
    if [ "$DRY_RUN" = 1 ]; then
        echo "server    WARNING: down; --dry-run continues anyway"
    else
        echo "" >&2
        echo "Start the jev OpenCode server first, or point JEV_BASE_URL at it:" >&2
        echo "  JEV_BASE_URL=http://127.0.0.1:4096 $0 $MODE" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------- estimates
# Measured on this machine: B 6 s/sample, C 149 s/sample (2971 s / 20).
# D carries the structural packet, so it is priced at >= C.
B_RATE=6; C_RATE=149; D_RATE=160
PER_SAMPLE=$((B_RATE + C_RATE + D_RATE))

echo ""
printf "%-22s %8s %10s %14s\n" "stage (dataset)" "samples" "tag" "est. wall"
total=0
for ds in ${STAGES//,/ }; do
    n="${LIMIT_OVERRIDE:-$(default_limit_for "$ds")}"
    est=$(( n * PER_SAMPLE ))
    total=$(( total + est ))
    printf "%-22s %8s %10s %14s\n" "$ds" "$n" "jev_${MODE}_${ds}_${n}" \
        "$(awk -v s="$est" 'BEGIN{printf "%.1f h", s/3600}')"
done
printf "%-22s %8s %10s %14s\n" "TOTAL" "" "" \
    "$(awk -v s="$total" 'BEGIN{printf "%.1f h", s/3600}')"
echo ""
echo "Log files: results/logs/jev_<stage>.log  (each stage also streams here)"

if [ "$DRY_RUN" = 1 ]; then
    echo ""
    echo "===== DRY RUN (nothing executed) ====="
fi

# ---------------------------------------------------------------- run
mkdir -p results/logs
FAILED=""
for ds in ${STAGES//,/ }; do
    n="${LIMIT_OVERRIDE:-$(default_limit_for "$ds")}"
    tag="jev_${MODE}_${ds}_${n}"
    cmd=(python scripts/run_benchmarks.py --suite llm
         --llm-source "$ds" --llm-limit "$n"
         --concurrency "$CONCURRENCY" --llm-timeout "$LLM_TIMEOUT_S"
         --tag "$tag" --model "$JEV_MODEL")
    echo ""
    echo "=== stage $tag: ${cmd[*]}"
    if [ "$DRY_RUN" = 1 ]; then
        "${cmd[@]}" --dry-run
        continue
    fi
    if ! "${cmd[@]}" 2>&1 | tee "results/logs/${tag}.log"; then
        FAILED="$FAILED $tag"
        echo "stage $tag FAILED (see results/logs/${tag}.log)"
        [ "$STOP_ON_ERROR" = 1 ] && break
    fi
done

echo ""
if [ "$DRY_RUN" = 1 ]; then
    echo "===== END DRY RUN ====="
    exit 0
fi
if [ -n "$FAILED" ]; then
    echo "failed stages:$FAILED"
    echo "Re-run just those with: scripts/run_llm_jev.sh $MODE --datasets <name>"
    exit 1
fi
echo "All stages finished. Paste every '===== RESULT =====' block back for analysis."
