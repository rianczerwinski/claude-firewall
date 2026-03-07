#!/bin/bash
# claude-firewall installer
# Copies firewall.sh into ~/.claude/hooks/ and wires it into settings.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOKS_DIR="$HOME/.claude/hooks"
SETTINGS="$HOME/.claude/settings.json"

# Ensure directories exist
mkdir -p "$HOOKS_DIR"
mkdir -p "$(dirname "$SETTINGS")"

# Copy firewall
cp "$SCRIPT_DIR/firewall.sh" "$HOOKS_DIR/firewall.sh"
chmod +x "$HOOKS_DIR/firewall.sh"

echo "Installed firewall.sh to $HOOKS_DIR/firewall.sh"

# Wire into settings.json
if [ ! -f "$SETTINGS" ]; then
  cat > "$SETTINGS" <<'EOF'
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/firewall.sh"
          }
        ]
      }
    ]
  }
}
EOF
  echo "Created $SETTINGS with firewall hook"
else
  # Check if hook is already configured
  if grep -q 'firewall.sh' "$SETTINGS" 2>/dev/null; then
    echo "Hook already configured in $SETTINGS"
  else
    echo ""
    echo "NOTE: $SETTINGS already exists."
    echo "Add this to your hooks.PreToolUse array manually:"
    echo ""
    echo '  {'
    echo '    "matcher": "Bash",'
    echo '    "hooks": ['
    echo '      {'
    echo '        "type": "command",'
    echo '        "command": "~/.claude/hooks/firewall.sh"'
    echo '      }'
    echo '    ]'
    echo '  }'
    echo ""
  fi
fi

echo ""
echo "Done. Remove any Bash(*) entries from your permissions allow list —"
echo "the firewall replaces them."
