# claude-firewall

This repo contains a PreToolUse hook for Claude Code that implements tiered Bash command policy. When working in this repo, you are working on security-critical infrastructure.

## Architecture

`firewall.sh` is a Bash script that receives JSON on stdin from Claude Code's hook system and routes commands through tiers:

- **Tier 1 (DENY):** `exit 2` — hard block, stderr message. Pattern array + special cases (rm -rf, reformattable patterns, subshell guard).
- **Tier 2 (ALLOW):** `exit 0` + JSON permission decision — auto-approve. Pattern array checked per-segment after compound-command splitting.
- **Tier 3 (ASK):** `exit 0`, no output — falls through to user prompt. Logged to TSV.

Key security properties:
- Compound commands (`&&`, `||`, `|`, `;`) are split and each segment checked independently. Quote-aware splitting via awk.
- `$()`, backticks, and process substitutions force ASK tier (never auto-approved).
- DENY patterns are checked before ALLOW — deny always wins.

## ASK log

The ASK log (`~/.claude/hooks/firewall-ask.log`) is a TSV with columns: `timestamp`, `tier` (always "ASK"), `command`. To synthesize ALLOW patterns from an ASK log:

1. Read the log: `cut -f3 ~/.claude/hooks/firewall-ask.log | sort | uniq -c | sort -rn`
2. Identify commands that are safe to auto-approve
3. Write an ERE pattern that matches the command prefix
4. Verify the pattern doesn't over-match by considering: what other commands could this regex match? Could any of them be dangerous?
5. Add to the appropriate section of `ALLOW_PATTERNS` with a comment

## Contribution format

When adding patterns to `ALLOW_PATTERNS`:
- Add a comment naming the tool/category
- Use `^` anchor and `\s` or `(\s|$)` boundary
- Place in the appropriate section (or create a new commented section)
- Include the ASK-log entries that motivated the pattern in the PR description

When adding patterns to `DENY_PATTERNS`:
- Include a comment explaining what attack the pattern prevents
- Include example commands the pattern catches
- Verify the pattern doesn't false-positive on legitimate commands

## Testing changes

To test a pattern against a command without running it live:

```bash
echo '{"tool_input":{"command":"your test command here"}}' | ./firewall.sh
```

- Exit 2 = DENY
- Exit 0 + JSON output = ALLOW
- Exit 0 + no output = ASK

Check stderr for DENY messages.
