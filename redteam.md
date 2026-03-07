# Red Team Findings

Threat model: cooperative agent, firewall protects against mistakes not malice.

## Remediated

| Finding | Severity | Fix |
|---------|----------|-----|
| Missing privilege escalation variants (`doas`, `pkexec`, `su`, `run0`) | High | Added to DENY_PATTERNS |
| Two-step download-then-execute (`curl -o /tmp/x.sh && sh /tmp/x.sh`) | High | Added shell-execute-file DENY: `^(ba)?sh\s+[/~.]`, `^zsh\s+[/~.]` |
| No self-tampering protection | High | Added Tier 1e: denies cp/mv/sed-i/tee/redirects to `~/.claude/hooks/`, `settings.json`, `rules/` |
| Newline-in-segment grep bypass | Medium | Segments containing literal newlines forced to ASK |
| `gh api` too broad | Medium | Removed from ALLOW, falls to ASK |
| `open`/`xdg-open` phishing vector | Low | Removed from ALLOW, falls to ASK |

## Accepted Risk (friendly-agent model)

| Finding | Severity | Rationale |
|---------|----------|-----------|
| Python/node/interpreters in ALLOW | High (hostile) / Low (friendly) | Constraining inline code execution via regex breaks normal developer workflows. If agent is hostile, regex filtering is insufficient regardless. |
| `npm install` lifecycle scripts | Medium (hostile) / Low (friendly) | Same as above — `preinstall`/`postinstall` hooks execute arbitrary code, but blocking `npm install` breaks normal use. |
| curl/wget in ALLOW | Medium (hostile) / Low (friendly) | High-frequency tool. Upload/exfiltration patterns are denied. Shell-execute-file deny catches the download-then-execute path. |
| `rm -rf ./src` not caught by deny | Low | Deny tier blocks dangerous scopes (`/`, `~`, `..`, `.`). Relative paths like `./src` are legitimate CC operations. |
| `cp`/`mv` broadly allowed | Low | Self-tampering guard covers security-critical paths. General cp/mv is routine. |
| `sed -i` on non-protected files | Low | Only self-tampering paths are guarded. Editing project files with sed is routine. |
| `xargs` pipeline bypass (`find | xargs cat`) | Low | Both segments match ALLOW individually. On friendly-agent model, this is normal usage. |
| `chmod 666` on arbitrary files | Low | `chmod 777` and `-R` are denied. Single-file permission changes are routine. |
| ASK log tamperable | Low | Log is diagnostic, not security-critical. Tampering by a friendly agent is not a concern. |

## Architecture Notes

- Regex-based security is inherently incomplete against a hostile agent. The firewall's value is catching common mistakes and enforcing a safety floor, not sandboxing.
- The compound-command splitter is the key structural defense — it prevents smuggling dangerous commands after allowed prefixes.
- The subshell guard (`$()`, backticks, process substitutions) forces human review of commands that could hide arbitrary operations inside allowed command shapes.
