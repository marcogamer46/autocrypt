#!/usr/bin/env bash
# Run every tests/test_*.py standalone; record pass/fail. Sequential (avoid
# CPU contention that made slow solvers blow their timeouts).
cd "$(dirname "$0")"
PY=".venv/Scripts/python.exe"
[ -f "$PY" ] || PY=python3
# Tests must not append to the default failures.jsonl in the repo root.
export AUTOCRYPT_NO_FAILURES_LOG=1
PASS=0; FAIL=0; ERR=0
: > tests_results.log
for f in tests/test_*.py; do
  name="${f##*/}"
  out=$("$PY" "$f" 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then
    PASS=$((PASS+1))
    printf "PASS  %s\n" "$name" | tee -a tests_results.log
  else
    FAIL=$((FAIL+1))
    printf "FAIL  %s (exit %s)\n" "$name" "$rc" | tee -a tests_results.log
    printf '%s\n' "$out" | tail -6 | sed 's/^/        /' >> tests_results.log
  fi
done
echo "----------------------------------------" >> tests_results.log
echo "TOTAL_passed=$PASS failed=$FAIL" | tee -a tests_results.log
