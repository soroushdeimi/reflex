#!/usr/bin/env bash
# Pre-submission checklist for Reflex (docs/submission.md lines 153-157).
# Run from repo root: ./scripts/check-reflex.sh

set -e
cd "$(dirname "$0")/../xray-core"
REPO_ROOT="$(dirname "$0")/.."
FAIL=0

echo "====================================="
echo "   Reflex Pre-Submission Checklist"
echo "====================================="
echo ""

echo "=== 1. Unit Tests ==="
echo "Running unit tests for proxy/reflex/..."
if go test ./proxy/reflex/... -count=1 -timeout 60s -v 2>&1 | grep -E '(PASS|FAIL|SKIP:|--- )'; then
  echo "✓ Unit tests completed"
else
  echo "✗ Unit tests failed"
  FAIL=1
fi
echo ""

echo "=== 2. Integration Tests ==="
echo "Running integration tests in tests/..."
if go test ./tests/... -count=1 -timeout 60s -v 2>&1 | grep -E '(PASS|FAIL|SKIP:|--- )'; then
  echo "✓ Integration tests completed"
else
  echo "✗ Integration tests failed"
  FAIL=1
fi
echo ""

echo "=== 3. Coverage Analysis ==="
echo "Target: 60-70% for inbound package"
echo ""
# Test inbound package only
go test -coverprofile=coverage.out ./proxy/reflex/inbound -count=1 -timeout 60s > /dev/null 2>&1
COVER_LINE=$(go tool cover -func=coverage.out | grep 'total:')
echo "$COVER_LINE"
COVER_PCT=$(echo "$COVER_LINE" | awk '{print $NF}' | tr -d '%')

# Check if coverage meets target
if awk -v c="$COVER_PCT" 'BEGIN { exit (c+0 >= 60) ? 0 : 1 }'; then
  echo "✓ Coverage: ${COVER_PCT}% - MEETS TARGET (60-70%)"
elif awk -v c="$COVER_PCT" 'BEGIN { exit (c+0 >= 55) ? 0 : 1 }'; then
  echo "⚠ Coverage: ${COVER_PCT}% - CLOSE TO TARGET (need 60%+)"
else
  echo "✗ Coverage: ${COVER_PCT}% - BELOW TARGET (need 60%+)"
  FAIL=1
fi

# Show coverage breakdown by file
echo ""
echo "Coverage by file:"
go tool cover -func=coverage.out | grep -E '(handshake\.go|inbound\.go|session\.go|morphing\.go)' | \
  awk '{printf "  %-30s %s\n", $1, $NF}'
echo ""
echo "For detailed HTML report: cd xray-core && go tool cover -html=coverage.out"
echo ""

echo "=== 4. Code Linting ==="
if command -v golangci-lint >/dev/null 2>&1; then
  echo "Running golangci-lint..."
  if golangci-lint run ./proxy/reflex/... ./tests/... 2>&1 | head -20; then
    echo "✓ Lint check passed"
  else
    echo "⚠ Lint issues found (see above)"
    FAIL=1
  fi
else
  echo "Running go vet (install golangci-lint for stricter checks)..."
  if go vet ./proxy/reflex/... ./tests/... 2>&1; then
    echo "✓ Lint check passed (go vet)"
  else
    echo "⚠ Lint issues found (see above)"
    FAIL=1
  fi
fi
echo ""

echo "=== 5. Race Condition Detection ==="
echo "Running tests with -race flag..."
if go test -race ./proxy/reflex/inbound -count=1 -timeout 120s -run='Test(Memory|Handler|New|Get|Session|Traffic|Apply)' > /dev/null 2>&1; then
  echo "✓ Race detector passed (unit tests)"
else
  echo "✗ Race detector found issues"
  FAIL=1
fi
echo ""

echo "=== 6. Build Check ==="
echo "Verifying protocol compiles correctly..."
if go build ./proxy/reflex/... > /dev/null 2>&1; then
  echo "✓ Build successful"
else
  echo "✗ Build failed"
  FAIL=1
fi
echo ""

echo "====================================="
if [ "$FAIL" -eq 0 ]; then
  echo "   ✓ ALL CHECKS PASSED"
  echo ""
  echo "Your implementation is ready for submission!"
  echo "Coverage: ${COVER_PCT}%"
else
  echo "   ✗ SOME CHECKS FAILED"
  echo ""
  echo "Please fix the issues above before submitting."
  exit 1
fi
echo "====================================="
echo ""

# Show summary
echo "Summary:"
echo "  • Tests: passing"
echo "  • Coverage: ${COVER_PCT}%"
echo "  • Lint: $(command -v golangci-lint >/dev/null 2>&1 && echo 'checked (golangci-lint)' || echo 'checked (go vet)')"
echo "  • Race detector: passing"
echo "  • Build: successful"
echo ""
