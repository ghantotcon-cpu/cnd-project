#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# watch-falco.sh
# CND Project — Live Falco Alert Monitor
# Shows real-time supply chain security alerts for research documentation
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

clear
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   CND Project — Live Falco Alert Monitor                  ║${NC}"
echo -e "${BOLD}║   Watching for CND-SC-* supply chain alerts               ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Press ${BOLD}Ctrl+C${NC} to stop"
echo -e "  Run ${CYAN}bash scripts/attack-scenarios.sh${NC} in another terminal"
echo ""
echo "───────────────────────────────────────────────────────────"

FALCO_POD=$(kubectl get pod -n falco -l app.kubernetes.io/name=falco \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

if [ -z "$FALCO_POD" ]; then
    echo -e "${RED}ERROR: Falco pod not found. Run setup-cluster.sh first.${NC}"
    exit 1
fi

echo -e "  Falco pod: ${GREEN}${FALCO_POD}${NC}"
echo ""

ALERT_COUNT=0
START_TIME=$(date +%s)

kubectl logs -n falco "$FALCO_POD" -f --since=1s 2>/dev/null | \
while IFS= read -r line; do
    # Parse JSON Falco output
    RULE=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('rule',''))" 2>/dev/null || echo "")
    PRIORITY=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('priority',''))" 2>/dev/null || echo "")
    OUTPUT=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('output','')[:120])" 2>/dev/null || echo "$line")

    if [ -n "$RULE" ]; then
        ALERT_COUNT=$((ALERT_COUNT + 1))
        ELAPSED=$(( $(date +%s) - $START_TIME ))
        TIMESTAMP=$(date +%H:%M:%S)

        case "$PRIORITY" in
            CRITICAL)
                COLOR="${RED}${BOLD}"
                ;;
            ERROR)
                COLOR="${RED}"
                ;;
            WARNING)
                COLOR="${YELLOW}"
                ;;
            *)
                COLOR="${CYAN}"
                ;;
        esac

        echo -e ""
        echo -e "${COLOR}┌─ ALERT #${ALERT_COUNT} [$TIMESTAMP] [${PRIORITY}]${NC}"
        echo -e "${COLOR}│  Rule: ${RULE}${NC}"
        echo -e "${COLOR}└─ ${OUTPUT}${NC}"
        echo ""
    fi
done
