#!/usr/bin/env bash
# AI-Generated Code - 2026-11-25 - Auto
# This is AI generated code
#
# Reproduces the live-verified ASTF v2.0.2 defects against the local mock API.
# Requires Java 21+, Python 3.10+, and curl. Everything binds to 127.0.0.1.
set -euo pipefail

cd "$(dirname "$0")"
ASTF_VERSION="v2.0.2"
JAR="astf-${ASTF_VERSION}.jar"
PORT="${MOCK_PORT:-47811}"
TARGET="http://127.0.0.1:${PORT}"
mkdir -p out

if [[ ! -f "$JAR" ]]; then
  curl -fsSLO "https://github.com/OWASP/www-project-api-security-testing-framework/releases/download/${ASTF_VERSION}/${JAR}"
fi

start_mock() {
  rm -f requests.log
  MOCK_PORT="$PORT" STATEFUL="$1" python3 mock_api.py &
  MOCK_PID=$!
  sleep 1
}

stop_mock() {
  kill "$MOCK_PID" 2>/dev/null || true
  wait "$MOCK_PID" 2>/dev/null || true
}
trap stop_mock EXIT

summarize() {
  python3 - "$1" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
findings = report.get("findings", report)
print(f"  {len(findings)} findings")
for f in findings:
    print(f"  {f['severity']:8} {f['testCaseId']:16} {f['title']}  [{f['endpoint']}]")
PY
}

echo "== Scan 1: full catalog against stateless mock (D2, D3, D4, D5, D6)"
start_mock 0
java -jar "$JAR" -u "$TARGET" --endpoints-file endpoints.txt --no-discovery \
  --token alice-token --secondary-token bob-token --threads 2 \
  -f JSON -o out/scan1.json >out/scan1.log 2>&1 || true  # ASTF exits non-zero when it reports findings
summarize out/scan1.json
echo "  open-redirect probes sent: $(grep -c 'evil-attacker' requests.log || true)"
echo "  debug/doc probes sent:     $(grep -cE 'actuator|openapi' requests.log || true)"
echo "  methods sent to PATCH-only /notes by secondary identity:"
grep '/api/v1/notes' requests.log | grep '"user": "bob"' | sed 's/^/    /' || true
cp requests.log out/scan1-requests.log
stop_mock

echo
echo "== Scan 2: BOLA only, stateful DELETE that anyone may call (D1)"
start_mock 1
java -jar "$JAR" -u "$TARGET" --endpoints-file endpoints-delete.txt --no-discovery \
  --token alice-token --secondary-token bob-token --test-cases ASTF-API1-2023 \
  -f JSON -o out/scan2.json >out/scan2.log 2>&1 || true
summarize out/scan2.json
echo "  DELETE requests sent:"
python3 -c "
import json
for line in open('requests.log'):
    d = json.loads(line)
    print(f\"    {d['m']} {d['p']} as {d['user']}\")
"
cp requests.log out/scan2-requests.log
