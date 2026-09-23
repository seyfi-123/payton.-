#!/bin/bash

echo "========================================="
echo " Security Tests - Tajik Fintech"
echo "========================================="
echo ""

# 1. Bandit
echo "📊 Running Bandit..."
bandit -r . -ll
BANDIT_EXIT=$?

echo ""
echo "========================================="

# 2. Pip-audit
echo "📦 Running Pip-audit..."
pip-audit -r 3_requirements.txt
PIP_AUDIT_EXIT=$?

echo ""
echo "========================================="
echo "✅ Security Tests Completed"
echo "========================================="
echo ""
echo "Bandit exit code: $BANDIT_EXIT"
echo "Pip-audit exit code: $PIP_AUDIT_EXIT"
echo ""

if [ $BANDIT_EXIT -eq 0 ] && [ $PIP_AUDIT_EXIT -eq 0 ]; then
    echo "✅ All security tests PASSED!"
    exit 0
else
    echo "❌ Security tests FAILED!"
    exit 1
fi