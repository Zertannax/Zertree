#!/bin/bash
set -e

SBOM_PATH="${INPUT_SBOM_PATH:-sbom.json}"
MODE="${INPUT_MODE:-dev}"
FAIL_ON_CRITICAL="${INPUT_FAIL_ON_CRITICAL:-true}"
OUTPUT_FORMAT="${INPUT_OUTPUT_FORMAT:-json}"
RULES_PATH="${INPUT_RULES_PATH:-}"

echo "🌳 ZertTree SBOM Scanner"
echo "========================"
echo "SBOM: $SBOM_PATH"
echo "Mode: $MODE"
echo ""

# Build args
ARGS="--input $SBOM_PATH --mode $MODE --output $OUTPUT_FORMAT"

if [ -n "$RULES_PATH" ]; then
    ARGS="$ARGS --rules $RULES_PATH"
fi

# Run scanner
echo "📦 Scanning SBOM..."
zertree $ARGS

# Parse results
REPORT_FILE="zertree-report.$OUTPUT_FORMAT"

if [ -f "$REPORT_FILE" ]; then
    echo "report-path=$REPORT_FILE" >> "$GITHUB_OUTPUT"
    
    # Extract summary if JSON
    if [ "$OUTPUT_FORMAT" = "json" ] && command -v jq >/dev/null 2>&1; then
        CRITICAL=$(jq '.summary.critical_count // 0' "$REPORT_FILE")
        WARNING=$(jq '.summary.warning_count // 0' "$REPORT_FILE")
        SCORE=$(jq '.overall_score // 0' "$REPORT_FILE")
        
        echo "critical-count=$CRITICAL" >> "$GITHUB_OUTPUT"
        echo "warning-count=$WARNING" >> "$GITHUB_OUTPUT"
        echo "overall-score=$SCORE" >> "$GITHUB_OUTPUT"
        
        # Post PR comment if in PR context
        if [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ] && [ -n "$GITHUB_EVENT_PATH" ]; then
            PR_NUMBER=$(jq --raw-output .pull_request.number "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
            
            if [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
                COMMENT="## 🌳 ZertTree Security Scan

| Metric | Value |
|--------|-------|
| 🔴 Critical | $CRITICAL |
| 🟡 Warning | $WARNING |
| 📊 Score | ${SCORE}/10 |

<details>
<summary>View full report</summary>

\`\`\`json
$(cat "$REPORT_FILE" | head -n 50)
\`\`\`
</details>"
                
                curl -s -X POST \
                    -H "Authorization: token $GITHUB_TOKEN" \
                    -H "Content-Type: application/json" \
                    -d "{\"body\":\"$COMMENT\"}" \
                    "https://api.github.com/repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments" > /dev/null
            fi
        fi
        
        # Fail if critical found
        if [ "$FAIL_ON_CRITICAL" = "true" ] && [ "$CRITICAL" -gt 0 ]; then
            echo ""
            echo "❌ Critical issues found! Failing check."
            exit 1
        fi
    fi
    
    echo ""
    echo "✅ Scan complete. Report: $REPORT_FILE"
else
    echo "⚠️ Report file not generated"
fi
