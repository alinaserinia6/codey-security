#!/usr/bin/env bash
# Run the LLM ladder (A + B + C + D) against a local OpenCode server, on one
# dataset or on every one of them.
#
#   scripts/run_llm.sh small                      # ~1 h, 12 samples, 1 dataset
#   scripts/run_llm.sh all                        # full ladder, every dataset
#   scripts/run_llm.sh all --limit 20             # same coverage, shorter run
#   scripts/run_llm.sh all --model mimo-v2.6-flash-free
#   scripts/run_llm.sh all --datasets vulnllm_r_python,python_bench
#   scripts/run_llm.sh small --dry-run            # print commands, run nothing
#
# Rough rates, measured on this machine with a reasoning model at
# --concurrency 4: leg B ~6 s/sample, leg C ~149 s/sample, leg D a little
# slower than C. Expect ~5 min per sample end to end, so plan overnight for
# `all`; a faster model cuts into that linearly, a slower one adds to it.
#
# Options
#   --limit N          override the per-dataset sample count (all stages)
#   --concurrency N    parallel LLM calls, legs B and C/D (default 4)
#   --llm-timeout S    per-request timeout seconds (default 600)
#   --datasets a,b,c   only these manifests (all mode; any --list name)
#   --model M          model id (default: $LLM_MODEL, else the .env value)
#   --endpoint URL     OpenCode server URL (default: $LLM_BASE_URL, else .env)
#   --stop-on-error    abort at the first failing stage (default: keep going
#                      and report every failure at the end)
#   --dry-run          show the commands, execute nothing
#
# Environment (a flag wins over this, and this wins over .env, because
# env_config.py never overwrites a variable that is already exported)
#   LLM_BASE_URL       OpenCode server URL (default http://127.0.0.1:4096)
#   LLM_MODEL          model id on that server (default: .env value)
set -uo pipefail
cd "$(dirname "$0")/.."

show_help() { sed -n '2,/^set -uo/p' "$0" | sed '$d; s/^# \{0,1\}//'; }

MODE="${1:-small}"
if [ $# -gt 0 ]; then shift; fi

case "$MODE" in
    -h|--help|help) show_help; exit 0 ;;
esac

CONCURRENCY=4
LLM_TIMEOUT_S=600
LIMIT_OVERRIDE=""
DATASETS_OVERRIDE=""
MODEL_OPT=""
ENDPOINT_OPT=""
DRY_RUN=0
STOP_ON_ERROR=0

while [ $# -gt 0 ]; do
    case "$1" in
        --limit)         LIMIT_OVERRIDE="$2"; shift 2 ;;
        --concurrency)   CONCURRENCY="$2"; shift 2 ;;
        --llm-timeout)   LLM_TIMEOUT_S="$2"; shift 2 ;;
        --datasets)      DATASETS_OVERRIDE="$2"; shift 2 ;;
        --model)         MODEL_OPT="$2"; shift 2 ;;
        --endpoint)      ENDPOINT_OPT="$2"; shift 2 ;;
        --stop-on-error) STOP_ON_ERROR=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       show_help; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

# The project default: read an uncommented KEY=value out of .env. Exported
# variables and flags are applied on top, in that order.
env_file_value() {
    [ -f .env ] || return 0
    sed -n "s/^[[:space:]]*${1}[[:space:]]*=[[:space:]]*//p" .env \
        | head -n 1 | sed 's/[[:space:]]#.*$//; s/[[:space:]]*$//'
}

LLM_BASE_URL="${ENDPOINT_OPT:-${LLM_BASE_URL:-$(env_file_value LLM_BASE_URL)}}"
LLM_BASE_URL="${LLM_BASE_URL:-http://127.0.0.1:4096}"
LLM_MODEL="${MODEL_OPT:-${LLM_MODEL:-$(env_file_value LLM_MODEL_ID)}}"
if [ -z "$LLM_MODEL" ]; then LLM_MODEL="$(env_file_value LLM_MODEL)"; fi

export LLM_BASE_URL
export LLM_PROVIDER_ID="${LLM_PROVIDER_ID:-opencode}"
export LLM_THINKING_PRINT="${LLM_THINKING_PRINT:-off}"
# An empty export would mask .env, so only publish a model we actually have.
if [ -n "$LLM_MODEL" ]; then
    export LLM_MODEL_ID="$LLM_MODEL"
    export LLM_MODEL
fi

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

# Filesystem-safe model id, so two models never share a tag (and so never
# share the result files a tag names).
model_slug() { printf '%s' "${1:-model}" | tr -c 'A-Za-z0-9._-' '_'; }
SLUG="$(model_slug "${LLM_MODEL:-model}")"

if [ "$MODE" = "small" ]; then
    STAGES="vulnllm_r_c_dataflow"
    [ -n "$LIMIT_OVERRIDE" ] || LIMIT_OVERRIDE=12
elif [ "$MODE" = "all" ]; then
    STAGES="vulnllm_r_c_dataflow,vulnllm_r_c,vulnllm_r_python,python_bench,proposal_min10,primevul,bigvul"
    [ -n "$DATASETS_OVERRIDE" ] && STAGES="$DATASETS_OVERRIDE"
else
    echo "usage: $0 small|all [options]   (see --help)" >&2
    exit 2
fi

echo "model     ${LLM_MODEL:-<from .env>}"
echo "endpoint  $LLM_BASE_URL"
echo "budget    max_tokens=${LLM_MAX_TOKENS:-8192} cap=${LLM_MAX_TOKENS_CAP:-32768}" \
     "temperature=${LLM_TEMPERATURE:-0.2} effort=${LLM_REASONING_EFFORT:-provider default}"
echo "legs      A (subset static), B (LLM only), C (static+LLM), D (full)"

# ---------------------------------------------------------------- preflight
if ! python3 - "$LLM_BASE_URL" <<'PY'
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
        echo "Start an OpenCode server first, or point --endpoint at one:" >&2
        echo "  lingling serve --port 4096 --hostname 127.0.0.1" >&2
        echo "  $0 $MODE --endpoint http://127.0.0.1:4096" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------- estimates
# Measured on this machine: B 6 s/sample, C 149 s/sample (2971 s / 20).
# D carries the structural packet, so it is priced at >= C.
B_RATE=6; C_RATE=149; D_RATE=160
PER_SAMPLE=$((B_RATE + C_RATE + D_RATE))

echo ""
printf "%-22s %8s %56s %14s\n" "stage (dataset)" "samples" "tag" "est. wall"
total=0
for ds in ${STAGES//,/ }; do
    n="${LIMIT_OVERRIDE:-$(default_limit_for "$ds")}"
    est=$(( n * PER_SAMPLE ))
    total=$(( total + est ))
    printf "%-22s %8s %56s %14s\n" "$ds" "$n" "${SLUG}_${MODE}_${ds}_${n}" \
        "$(awk -v s="$est" 'BEGIN{printf "%.1f h", s/3600}')"
done
printf "%-22s %8s %56s %14s\n" "TOTAL" "" "" \
    "$(awk -v s="$total" 'BEGIN{printf "%.1f h", s/3600}')"
echo ""
echo "Log files: results/logs/<tag>.log  (each stage also streams here)"

if [ "$DRY_RUN" = 1 ]; then
    echo ""
    echo "===== DRY RUN (nothing executed) ====="
fi

# ---------------------------------------------------------------- run
mkdir -p results/logs
FAILED=""
for ds in ${STAGES//,/ }; do
    n="${LIMIT_OVERRIDE:-$(default_limit_for "$ds")}"
    tag="${SLUG}_${MODE}_${ds}_${n}"
    cmd=(python scripts/run_benchmarks.py --suite llm
         --llm-source "$ds" --llm-limit "$n"
         --concurrency "$CONCURRENCY" --llm-timeout "$LLM_TIMEOUT_S"
         --tag "$tag")
    if [ -n "$LLM_MODEL" ]; then cmd+=(--model "$LLM_MODEL"); fi
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
    echo "Re-run just those with: scripts/run_llm.sh $MODE --datasets <name>"
    exit 1
fi
echo "All stages finished. Paste every '===== RESULT =====' block back for analysis."
