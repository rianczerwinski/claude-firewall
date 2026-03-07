#!/bin/bash
# claude-firewall — Tiered Bash command policy for Claude Code
# https://github.com/rianczerwinski/claude-firewall
#
# Tier 1 — DENY:  Hard-block catastrophic patterns (exit 2)
# Tier 2 — ALLOW: Auto-approve known-good commands (exit 0 + permissionDecision: allow)
# Tier 3 — ASK:   Anything else falls through to normal permission prompt (exit 0, no output)
#
# Install as a PreToolUse hook on Bash in ~/.claude/settings.json.
# This hook is the sole mechanism that grants automatic Bash approval —
# no Bash(*) allow rule is needed.

if ! command -v jq &>/dev/null; then
  echo "claude-firewall: jq is required but not installed" >&2
  exit 2
fi

INPUT=$(cat)
COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command')

# ─── Tier 1: DENY (hard block, no override) ─────────────────────────────────

DENY_PATTERNS=(
  # Pipe/redirect into shell execution
  '\|\s*(ba)?sh(\s|$)'
  '\|\s*zsh(\s|$)'
  '\|\s*/(usr/)?bin/(ba)?sh(\s|$)'    # full-path pipe to shell
  '\|\s*/(usr/)?bin/zsh(\s|$)'
  '\beval\s'
  '\bsource\s+<\('
  '(^|\s)\.\s+<\('                    # POSIX dot-source via process substitution

  # Privilege escalation
  '\bsudo\b'
  '\bdoas\b'
  '\bpkexec\b'
  '\bsu\s'
  '\brun0\b'

  # Shell execution of file paths (two-step download-then-execute)
  '^(ba)?sh\s+[/~.]'
  '^zsh\s+[/~.]'
  '^/(usr/)?bin/(ba)?sh\s+[/~.]'       # full-path shell execution
  '^/(usr/)?bin/zsh\s+[/~.]'
  '\bexec\s+[/~.]'                     # exec with file path
  '\bsource\s+[/~.]'                   # source with file path
  '(^|\s)\.\s+[/~.]'                   # POSIX dot-source with file path

  # Shell -c (arbitrary code execution via string argument)
  '\b(ba)?sh\s+-c\b'
  '\bzsh\s+-c\b'
  '/(usr/)?bin/(ba)?sh\s+-c\b'
  '/(usr/)?bin/zsh\s+-c\b'

  # Destructive git
  'git\s+push\s+.*--force(\s|$)'      # --force but NOT --force-with-lease
  'git\s+push\s+-[a-zA-Z]*f'         # -f immediately after push
  'git\s+push\s+.*\s-[a-zA-Z]*f'     # -f after other args (e.g. push origin -f)
  'git\s+reset\s+--hard'
  'git\s+clean\s+-[a-zA-Z]*f'

  # System destruction
  '\bmkfs\.'
  '\bdd\s+if='
  '>\s*/dev/(sd|hd|nvme|disk|random|zero|mem|kmem|loop)'
  '\bchmod\s+777'
  '\bchmod\s+-R'

  # Remote code execution
  'curl.*\|\s*(ba)?sh'
  'wget.*\|\s*(ba)?sh'

  # Data exfiltration (curl/wget file upload patterns)
  '(curl|wget)\s+.*(-d\s*@|-d@|--data\S*[=\s]+@|--upload-file|-F\s+\S*@|--form\s+\S*@|-T\s+[/~.])'
  'wget\s+.*--post-file'

  # Destructive GitHub operations
  'gh\s+repo\s+delete'
)

for pattern in "${DENY_PATTERNS[@]}"; do
  if printf '%s\n' "$COMMAND" | grep -qE "$pattern"; then
    echo "BLOCKED by claude-firewall: matches deny pattern" >&2
    echo "  Pattern: $pattern" >&2
    echo "  Command: $COMMAND" >&2
    exit 2
  fi
done

# ─── Tier 1b: DENY — rm recursive+force at dangerous scopes ─────────────────
# Separate from the pattern array because the flag combinations (any order,
# any casing, split or combined, short or long) can't be captured cleanly in
# a single ERE. Catches: rm -rf, -Rf, -fr, -fR, -f -r, -r -f,
# --recursive --force, --force --recursive, and all other permutations.

if printf '%s\n' "$COMMAND" | grep -qE '\brm\s'; then
  has_recursive=false
  has_force=false
  printf '%s\n' "$COMMAND" | grep -qE '\brm\s+.*(-[a-zA-Z]*[rR]|--recursive)' && has_recursive=true
  printf '%s\n' "$COMMAND" | grep -qE '\brm\s+.*(-[a-zA-Z]*f|--force)' && has_force=true
  if $has_recursive && $has_force; then
    # Block if targeting dangerous scope: /, /*, ~, ~/, ~/* ../, ., ..
    if printf '%s\n' "$COMMAND" | grep -qE '\brm\s+.*\s+(/\*?|~/?\*?|\.\./|\.\s*$|\.\.\s*$)(\s|$)'; then
      echo "BLOCKED by claude-firewall: rm with recursive+force at dangerous scope" >&2
      echo "  Command: $COMMAND" >&2
      exit 2
    fi
  fi
fi

# ─── Tier 1c: AUTO-REJECT reformattable patterns ─────────────────────────────
# Commands containing $() that have a known safe mechanical rewrite.
# Auto-reject with reformatting instructions so Claude retries correctly,
# rather than hanging on ASK tier waiting for human approval.

if printf '%s' "$COMMAND" | grep -qE 'git\s+commit\s+.*-m\s.*\$\('; then
  cat >&2 <<'GUIDANCE'
BLOCKED by claude-firewall: git commit with subshell in message.
Reformat using: printf 'message line 1\n\nline 2' | git commit -F -
Do not use $(cat <<EOF) or any $() in commit commands.
GUIDANCE
  exit 2
fi

# ─── Tier 1d: Subshell / substitution guard ──────────────────────────────────
# Commands containing $(...), `...`, or >(…) / <(…) process substitutions
# could hide arbitrary operations inside an otherwise-allowed command.
# Force these to ASK tier rather than auto-approve.

if printf '%s' "$COMMAND" | grep -qE '\$\(|`|<\(|>\('; then
  exit 0
fi

# ─── Tier 2: ALLOW (auto-approve, no prompt) ────────────────────────────────

ALLOW_PATTERNS=(
  # Git — read
  # Optional safe global flags before subcommand: -C <path>, --git-dir=, --work-tree=,
  # --namespace=, --bare, --no-pager/-P, --no-replace-objects, --no-optional-locks,
  # --literal-pathspecs, --glob-pathspecs, --icase-pathspecs.
  # Excluded: -c (config execution vectors), --exec-path= (redirects command lookup).
  '^git\s+(-C\s+\S+\s+|--git-dir=\S+\s+|--work-tree=\S+\s+|--namespace=\S+\s+|--bare\s+|--no-pager\s+|-P\s+|--no-replace-objects\s+|--no-optional-locks\s+|--literal-pathspecs\s+|--glob-pathspecs\s+|--icase-pathspecs\s+)*(log|status|diff|show|branch|tag|rev-parse|remote|describe|shortlog|blame|ls-files|ls-tree|stash\s+list|config\s+--get|config\s+--list|rev-list|cat-file|for-each-ref|name-rev|reflog)'

  # Git — write (common safe operations; force-push caught by deny tier)
  '^git\s+(-C\s+\S+\s+|--git-dir=\S+\s+|--work-tree=\S+\s+|--namespace=\S+\s+|--bare\s+|--no-pager\s+|-P\s+|--no-replace-objects\s+|--no-optional-locks\s+|--literal-pathspecs\s+|--glob-pathspecs\s+|--icase-pathspecs\s+)*(add|commit|stash|checkout|switch|merge|rebase|cherry-pick|fetch|pull|push|restore|mv|tag\s+-a|tag\s+-m|init|clone)'

  # File inspection
  '^(ls|cat|head|tail|wc|file|stat|which|type|readlink|realpath|du|df|man)(\s|$)'

  # Search
  '^(find|grep|rg|ag|fd|fzf)(\s|$)'

  # Environment / info
  '^(pwd|echo|printf|date|env|printenv|hostname|uname|whoami|id|uptime|sw_vers|system_profiler)(\s|$)'

  # Node / npm / JS tooling
  '^(npm\s+(run|test|start|install|ci|build|exec|info|ls|outdated|audit|pack|version|init|create|link|unlink)|npx\s|node\s|tsx\s|ts-node\s|bun\s|deno\s)'

  # Python
  '^(python3?|pip3?|poetry|pdm|uv|ruff|black|mypy|pyright)(\s|$)'

  # Rust
  '^cargo\s+(build|test|run|check|clippy|fmt|doc|bench|tree|add|remove|update|publish|install)'

  # Go
  '^go\s+(build|test|run|vet|fmt|mod|generate|tool|get|install|clean|env|version)'

  # General build / lint / test
  '^(make|cmake|tsc|eslint|prettier|jest|vitest|pytest|mocha|phpunit|rubocop|mix)(\s|$)'

  # Directory navigation / creation
  '^cd(\s|$)'
  '^mkdir\s'

  # Text processing (tee omitted — it's a file-write tool, falls to ASK)
  '^(jq|sed|awk|sort|uniq|cut|tr|xargs|diff|patch|column|paste|comm|join|expand|fold|fmt|nl|pr|rev|shuf)(\s|$)'

  # Network reads (pipe-to-shell and file exfil caught by deny tier)
  '^(curl|wget|http|httpie)(\s|$)'

  # Docker read operations
  '^docker\s+(ps|logs|images|inspect|stats|top|port|network\s+ls|volume\s+ls|info|version)'
  '^docker-compose\s+(ps|logs|config)'

  # Removal of specific files (not -rf; deny tier catches dangerous rm)
  '^rm\s+[^-]'
  '^rm\s+-[^rR]*\s'

  # cp / mv (generally safe, source of data not destroyed)
  '^(cp|mv)\s'

  # Touch / chmod single files (chmod 777 and -R caught by deny)
  '^touch\s'
  '^chmod\s+[0-7]{3}\s'

  # Homebrew
  '^brew\s+(info|list|search|leaves|deps|doctor|config)'

  # gh CLI (read + common write ops; gh repo delete caught by deny, gh api falls to ASK)
  '^gh\s+(pr|issue|repo|run|search|auth\s+status|status)\s'
  # gh gist — only list/view (create/edit can exfiltrate files, falls to ASK)
  '^gh\s+gist\s+(list|view)\s'

  # Misc dev tools (open/xdg-open fall to ASK — can open arbitrary URLs)
  '^(pbcopy|pbpaste|code|subl)(\s|$)'

  # Universal read-only flags (any tool)
  '^[a-zA-Z0-9_.-]+\s+--version(\s|$)'
  '^[a-zA-Z0-9_.-]+\s+(-v|-V)(\s|$)'
  '^[a-zA-Z0-9_.-]+\s+--help(\s|$)'
  '^[a-zA-Z0-9_.-]+\s+(-h)(\s|$)'
)

# ─── Compound command splitting ──────────────────────────────────────────────
# Split on &&, ||, |, ;, and & so each segment is checked independently.
# This prevents smuggling an ASK-tier command after an allowed prefix
# (e.g. "echo hi && brew install malware").
#
# Splitting is quote-aware: operators inside single or double quotes are
# preserved as literal text. Unrecognized segments fall to ASK tier (safe).

SEGMENTS=()
while IFS= read -r -d '' seg; do
  seg="${seg#"${seg%%[![:space:]]*}"}"   # trim leading whitespace
  seg="${seg%"${seg##*[![:space:]]}"}"   # trim trailing whitespace
  [[ -z "$seg" || "$seg" == \#* ]] && continue
  SEGMENTS+=("$seg")
done < <(printf '%s' "$COMMAND" | awk 'BEGIN{RS="\0"} {
  n = length($0)
  in_sq = 0; in_dq = 0
  seg_start = 1
  for (i = 1; i <= n; i++) {
    c = substr($0, i, 1)
    if (c == "\"" && !in_sq) { in_dq = !in_dq }
    else if (c == "'"'"'" && !in_dq) { in_sq = !in_sq }

    if (!in_sq && !in_dq) {
      two = substr($0, i, 2)
      if (two == "&&" || two == "||") {
        printf "%s", substr($0, seg_start, i - seg_start)
        printf "%c", 0
        i++
        seg_start = i + 1
        continue
      }
      if (c == "|" || c == ";" || c == "&") {
        printf "%s", substr($0, seg_start, i - seg_start)
        printf "%c", 0
        seg_start = i + 1
        continue
      }
    }
  }
  printf "%s", substr($0, seg_start)
  printf "%c", 0
}')

[[ ${#SEGMENTS[@]} -eq 0 ]] && SEGMENTS=("$COMMAND")

# ─── Tier 1e: Self-tampering guard (per-segment) ────────────────────────────
# Deny segments that write to firewall infrastructure paths.
# Runs after splitting so "echo x | tee ~/.claude/hooks/firewall.sh" is caught.

PROTECTED_PATHS='(\.claude/hooks/|\.claude/settings\.json|\.claude/rules/)'
WRITE_TOOLS='\b(cp|mv|tee|sed\s.*-i|ln|curl\s.*-o|curl\s.*--output|wget\s.*-O|wget\s.*--output-document|rm|rm\s+-)\b'

for segment in "${SEGMENTS[@]}"; do
  # Normalize paths to defeat bypass tricks (//  /../  $HOME  ~)
  norm_seg="$segment"
  norm_seg="${norm_seg//$HOME/\~}"                       # /home/user → ~
  while [[ "$norm_seg" == *'//'* ]]; do                  # collapse //
    norm_seg="${norm_seg//\/\///}"
  done
  # Collapse /foo/../ → / (simple single-level only)
  norm_seg=$(printf '%s' "$norm_seg" | sed 's|/[^/]*/\.\./|/|g')
  if printf '%s' "$norm_seg" | grep -qE "$PROTECTED_PATHS"; then
    if printf '%s' "$segment" | grep -qE "$WRITE_TOOLS"; then
      echo "BLOCKED by claude-firewall: write to protected path" >&2
      echo "  Command: $COMMAND" >&2
      exit 2
    fi
    # Redirect-based overwrites (> or >>) to protected paths
    if printf '%s' "$segment" | grep -qE '>\s*\S*'"$PROTECTED_PATHS"; then
      echo "BLOCKED by claude-firewall: redirect to protected path" >&2
      echo "  Command: $COMMAND" >&2
      exit 2
    fi
  fi
done

# ─── Tier 1f: Sensitive dotfile guard (per-segment) ─────────────────────────
# Force ASK for writes to sensitive user dotfiles. These are legitimate write
# targets sometimes, but warrant human review — a friendly agent accidentally
# overwriting ~/.bashrc is a more likely mistake than spawning a reverse shell.

SENSITIVE_DOTFILES='(/\.(ssh|gnupg)/|/\.(bashrc|bash_profile|profile|zshrc|zshenv|zprofile|npmrc|gitconfig|env)(\s|$))'

dotfile_write=false
for segment in "${SEGMENTS[@]}"; do
  if printf '%s' "$segment" | grep -qE "$SENSITIVE_DOTFILES"; then
    if printf '%s' "$segment" | grep -qE "$WRITE_TOOLS|>\s"; then
      # Force ASK, not DENY — legitimate writes to these files do occur
      dotfile_write=true
      break
    fi
  fi
done

# ALL segments must independently match an allow pattern for auto-approve
all_allowed=true
if $dotfile_write; then all_allowed=false; fi
for segment in "${SEGMENTS[@]}"; do
  # Newline guard: if a segment contains a literal newline, force ASK.
  # grep is line-oriented so "echo hi\nrm -rf /" would match ^echo on line 1.
  if [[ "$segment" == *$'\n'* ]]; then
    all_allowed=false
    break
  fi
  segment_allowed=false
  for pattern in "${ALLOW_PATTERNS[@]}"; do
    if printf '%s\n' "$segment" | grep -qE "$pattern"; then
      segment_allowed=true
      break
    fi
  done
  if ! $segment_allowed; then
    all_allowed=false
    break
  fi
done

if $all_allowed; then
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Matched auto-approve pattern"}}'
  exit 0
fi

# ─── Tier 3: ASK (unknown command — fall through to permission prompt) ───────

# Log ASK-tier hits so you can review and promote patterns over time.
FIREWALL_LOG="${CLAUDE_FIREWALL_LOG:-$HOME/.claude/hooks/firewall-ask.log}"
printf '%s\tASK\t%s\n' "$(date '+%Y%m%dT%H%M%S')" "$COMMAND" >> "$FIREWALL_LOG"

# No output, exit 0. Without Bash(*) in the permission allow list,
# the default permission system will prompt the user.
exit 0
