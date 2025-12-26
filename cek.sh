#!/usr/bin/env bash
set -euo pipefail

VERSION="0.1.0"
TOOL_NAME="nextjs-whitebox-audit"

OUT_FILE="result.json"
ROOT="."
SEND_TELEGRAM=1
SKIP_DEPS=0
TOP_FINDINGS=8
MAX_FILESIZE="${MAX_FILESIZE:-2M}"

usage() {
  cat <<'USAGE'
Next.js / React / RSC whitebox audit (secrets + risky patterns) -> result.json + Telegram (HTML).

Usage:
  tools/nextjs_whitebox_audit.sh [--root DIR] [--out FILE] [--no-telegram] [--skip-deps]

Env (Telegram):
  TELEGRAM_BOT_TOKEN=...   (required unless --no-telegram)
  TELEGRAM_CHAT_ID=...     (required unless --no-telegram)

Notes:
  - Output is always redacted (no raw secret values).
  - Designed for source review; findings are heuristic (false positives possible).
USAGE
}

log() { printf '[%s] %s\n' "$TOOL_NAME" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"
}

sha256_12() {
  local input="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$input" | sha256sum | awk '{print substr($1,1,12)}'
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$input" | shasum -a 256 | awk '{print substr($1,1,12)}'
  else
    printf 'nohash'
  fi
}

redact_value() {
  local v="$1"
  local len="${#v}"
  if (( len <= 8 )); then
    printf '<redacted:%s:%s>' "$len" "$(sha256_12 "$v")"
    return 0
  fi
  printf '%s…%s<redacted:%s:%s>' "${v:0:4}" "${v: -4}" "$len" "$(sha256_12 "$v")"
}

html_escape() {
  local s="$1"
  s="${s//&/&amp;}"
  s="${s//</&lt;}"
  s="${s//>/&gt;}"
  s="${s//\"/&quot;}"
  s="${s//\'/&#39;}"
  printf '%s' "$s"
}

json_escape_newlines() {
  tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/^ //; s/ $//'
}

parse_args() {
  while (($#)); do
    case "$1" in
      --root)
        ROOT="${2:-}"; shift 2 || true
        ;;
      --out)
        OUT_FILE="${2:-}"; shift 2 || true
        ;;
      --no-telegram)
        SEND_TELEGRAM=0; shift
        ;;
      --skip-deps)
        SKIP_DEPS=1; shift
        ;;
      -h|--help)
        usage; exit 0
        ;;
      *)
        die "unknown arg: $1"
        ;;
    esac
  done
}

make_tmpdir() {
  local d
  d="$(mktemp -d)"
  printf '%s' "$d"
}

is_git_repo() {
  git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1
}

git_meta_json() {
  if ! is_git_repo; then
    jq -n '{present:false}'
    return 0
  fi
  local commit branch dirty
  commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
  branch="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  dirty="false"
  if ! git -C "$ROOT" diff --quiet -- 2>/dev/null; then dirty="true"; fi
  if ! git -C "$ROOT" diff --cached --quiet -- 2>/dev/null; then dirty="true"; fi
  jq -n --arg commit "$commit" --arg branch "$branch" --argjson dirty "$dirty" \
    '{present:true, commit:$commit, branch:$branch, dirty:$dirty}'
}

detect_next_layout() {
  local pkg="$ROOT/package.json"
  [[ -f "$pkg" ]] || die "package.json not found at root ($ROOT). Run with --root <nextjs-project>."

  local has_next
  has_next="$(jq -r '(.dependencies.next // .devDependencies.next // empty) | tostring' "$pkg" 2>/dev/null || true)"
  if [[ -z "$has_next" ]]; then
    log "WARN: package.json does not mention 'next' dependency; continuing anyway."
  fi

  local router="unknown"
  if [[ -d "$ROOT/app" ]]; then router="app"; fi
  if [[ -d "$ROOT/pages" ]]; then
    if [[ "$router" == "unknown" ]]; then router="pages"; else router="${router}+pages"; fi
  fi

  jq -n --arg router "$router" '{router:$router}'
}

RG_EXCLUDES=(
  -g '!**/node_modules/**'
  -g '!**/.next/**'
  -g '!**/dist/**'
  -g '!**/build/**'
  -g '!**/.turbo/**'
  -g '!**/.git/**'
  -g '!**/coverage/**'
  -g '!**/*.min.*'
  -g '!**/pnpm-store/**'
  -g '!**/.yarn/**'
)

rg_base() {
  rg --pcre2 --hidden --no-ignore --max-filesize "$MAX_FILESIZE" "${RG_EXCLUDES[@]}" "$@"
}

FINDINGS_JSONL=""
FINDING_SEQ=0

add_finding() {
  local severity="$1" category="$2" title="$3" file="$4" line="$5" snippet="$6" match_type="$7" redacted="$8" scenario="$9" recommendation="${10}" confidence="${11:-medium}"
  FINDING_SEQ=$((FINDING_SEQ + 1))
  local id
  id="$(printf 'F-%04d' "$FINDING_SEQ")"
  jq -n \
    --arg id "$id" \
    --arg severity "$severity" \
    --arg category "$category" \
    --arg title "$title" \
    --arg file "$file" \
    --argjson line "$line" \
    --arg snippet "$snippet" \
    --arg match_type "$match_type" \
    --arg redacted "$redacted" \
    --arg scenario "$scenario" \
    --arg recommendation "$recommendation" \
    --arg confidence "$confidence" \
    '{
      id:$id,
      severity:$severity,
      category:$category,
      title:$title,
      evidence:{file:$file, line:$line, snippet:$snippet},
      match:{type:$match_type, redacted:$redacted},
      attack_scenario:$scenario,
      recommendation:$recommendation,
      confidence:$confidence
    }' >>"$FINDINGS_JSONL"
}

read_line_snippet() {
  local file="$1" line="$2"
  if [[ "$file" == "<runtime:env>" || "$file" == "<runtime:set>" ]]; then
    printf '%s' "$3"
    return 0
  fi
  sed -n "${line}p" "$file" 2>/dev/null | json_escape_newlines
}

scan_token_rg() {
  local severity="$1" category="$2" title="$3" match_type="$4" pattern="$5" includes=("${!6}") scenario="$7" recommendation="$8"

  local out
  # Print matches as: file:line:match
  out="$(rg_base -n -o "${includes[@]}" "$pattern" "$ROOT" 2>/dev/null || true)"
  [[ -n "$out" ]] || return 0

  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    local file line match rest
    file="${row%%:*}"
    rest="${row#*:}"
    line="${rest%%:*}"
    match="${rest#*:}"
    local redacted snippet
    redacted="$(redact_value "$match")"
    snippet="$(sed -n "${line}p" "$file" 2>/dev/null | json_escape_newlines)"
    if [[ -z "$snippet" ]]; then snippet="$match_type match (redacted)"; fi
    snippet="${snippet//$match/$redacted}"
    add_finding "$severity" "$category" "$title" "$file" "$line" "$snippet" "$match_type" "$redacted" "$scenario" "$recommendation" "high"
  done <<<"$out"
}

scan_line_rg() {
  local severity="$1" category="$2" title="$3" match_type="$4" pattern="$5" includes=("${!6}") scenario="$7" recommendation="$8"
  local out
  out="$(rg_base -n "${includes[@]}" "$pattern" "$ROOT" 2>/dev/null || true)"
  [[ -n "$out" ]] || return 0

  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    local file line rest snippet
    file="${row%%:*}"
    rest="${row#*:}"
    line="${rest%%:*}"
    snippet="${rest#*:}"
    snippet="$(printf '%s' "$snippet" | json_escape_newlines)"
    add_finding "$severity" "$category" "$title" "$file" "$line" "$snippet" "$match_type" "<redacted>" "$scenario" "$recommendation" "medium"
  done <<<"$out"
}

scan_env_files() {
  local includes=( -g '**/.env*' )
  local out
  out="$(rg_base -n "${includes[@]}" '^(?:export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=' "$ROOT" 2>/dev/null || true)"
  [[ -n "$out" ]] || return 0

  while IFS= read -r row; do
    local file line rest kv key val
    file="${row%%:*}"
    rest="${row#*:}"
    line="${rest%%:*}"
    kv="${rest#*:}"
    kv="$(printf '%s' "$kv" | json_escape_newlines)"
    key="$(printf '%s' "$kv" | sed -E 's/^(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=.*$/\\2/')"
    val="$(printf '%s' "$kv" | sed -E 's/^(export[[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*//')"
    val="${val%%#*}"
    val="$(printf '%s' "$val" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$val" ]] && continue

    local key_upper redacted severity title scenario recommendation
    key_upper="$(printf '%s' "$key" | tr '[:lower:]' '[:upper:]')"
    redacted="$(redact_value "$val")"
    severity="info"
    title="Env var set: $key"
    scenario="If this value is a credential and the file is committed or shared, an attacker who obtains the source can reuse it for unauthorized access."
    recommendation="Move secrets to a secret manager (or CI/env injection), rotate if exposed, and ensure .env files are excluded from VCS."

    if [[ "$key_upper" =~ (SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY|SESSION_SECRET|JWT_SECRET|NEXTAUTH_SECRET|ENCRYPTION_KEY) ]]; then
      severity="high"
      title="Potential secret in .env: $key"
    fi
    if [[ "$key_upper" =~ ^NEXT_PUBLIC_ && "$key_upper" =~ (SECRET|TOKEN|PASSWORD|KEY) ]]; then
      severity="critical"
      title="Client-exposed secret-like NEXT_PUBLIC var: $key"
      scenario="NEXT_PUBLIC_* values can end up in client bundles. If this is a real secret, it may be exposed to any user and enable API abuse or account takeover."
      recommendation="Never put secrets in NEXT_PUBLIC_*; move to server-only env vars and rotate the exposed credential immediately."
    fi

    local snippet
    snippet="$key=$redacted"
    add_finding "$severity" "secrets" "$title" "$file" "$line" "$snippet" "env_assignment" "$redacted" "$scenario" "$recommendation" "medium"
  done <<<"$out"
}

var_name_looks_secret() {
  local name_upper
  name_upper="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
  [[ "$name_upper" =~ (SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|ACCESS[_-]?KEY|AWS|GCP|GOOGLE|STRIPE|SENDGRID|MAILGUN|TWILIO|SLACK|GITHUB|GITLAB|JWT|NEXTAUTH|ENCRYPTION|DATABASE_URL|MONGODB_URI|REDIS_URL) ]]
}

value_looks_token() {
  local v="$1"
  [[ "$v" =~ ^(AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA)[A-Z0-9]{16}$ ]] && return 0
  [[ "$v" =~ ^AIza[0-9A-Za-z\-_]{35}$ ]] && return 0
  [[ "$v" =~ ^ghp_[A-Za-z0-9]{36}$ ]] && return 0
  [[ "$v" =~ ^github_pat_[A-Za-z0-9_]{40,}$ ]] && return 0
  [[ "$v" =~ ^glpat-[A-Za-z0-9\-_]{20,}$ ]] && return 0
  [[ "$v" =~ ^xox[baprs]-[0-9A-Za-z-]{10,}$ ]] && return 0
  [[ "$v" =~ ^(sk|rk)_(live|test)_[0-9a-zA-Z]{16,}$ ]] && return 0
  [[ "$v" =~ ^SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}$ ]] && return 0
  [[ "$v" =~ ^key-[0-9a-f]{32}$ ]] && return 0
  [[ "$v" =~ ^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}$ ]] && return 0
  return 1
}

scan_runtime_vars() {
  local source_label="$1"
  shift
  local output="$1"
  local max_lines=5000
  local count=0

  while IFS= read -r row; do
    ((count++))
    ((count > max_lines)) && break
    [[ "$row" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    [[ "$row" =~ ^BASH_FUNC_ ]] && continue
    local name="${row%%=*}"
    local value="${row#*=}"
    [[ -z "$value" ]] && continue
    if ! var_name_looks_secret "$name" && ! value_looks_token "$value"; then
      continue
    fi

    local redacted severity title scenario recommendation
    redacted="$(redact_value "$value")"
    severity="high"
    title="Runtime var may contain secret: $name"
    scenario="If this runtime environment is shared, logged, or compromised, secrets in process variables can be extracted and reused for unauthorized access."
    recommendation="Store secrets in a managed secret store, avoid logging env, limit scope/permissions, and rotate if leakage is suspected."
    if [[ "$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')" =~ ^NEXT_PUBLIC_ ]]; then
      severity="critical"
      title="Client-exposed runtime var (NEXT_PUBLIC_*) looks secret: $name"
      scenario="NEXT_PUBLIC_* values can end up in client bundles. If a secret is placed here, it can be harvested by any user."
      recommendation="Move secret server-side (non-NEXT_PUBLIC) and rotate immediately."
    fi
    add_finding "$severity" "runtime_secrets" "$title" "<runtime:$source_label>" 0 "$name=$redacted" "runtime_var" "$redacted" "$scenario" "$recommendation" "low"
  done <<<"$output"
}

scan_secrets() {
  log "Scanning hardcoded secrets..."

  local inc_code=( -g '**/*.{js,jsx,ts,tsx,mjs,cjs}' -g '**/*.{json,yml,yaml}' -g '**/.env*' -g '**/Dockerfile*' -g '**/docker-compose*.yml' -g '**/docker-compose*.yaml' -g '**/vercel.json' -g '**/.github/workflows/*.{yml,yaml}' )
  local inc_keys=( -g '**/*.{pem,key,p12,pfx,der,crt,cer,keystore}' )

  scan_line_rg "critical" "secrets" "Private key material (BEGIN PRIVATE KEY)" "private_key_block" \
    '-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----' inc_keys[@] \
    "If a private key is committed, anyone with repo access can impersonate the service/user and decrypt or sign traffic where applicable." \
    "Remove the key from the repo history, revoke/rotate the keypair, and store keys in a secret manager or secure vault."

  scan_token_rg "high" "secrets" "Possible AWS Access Key ID" "aws_access_key_id" \
    '\\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA)[A-Z0-9]{16}\\b' inc_code[@] \
    "If the key is active, an attacker can use it for API calls within its IAM permissions." \
    "Revoke/rotate the credential, audit IAM usage, and move secrets to environment/secret manager."

  scan_token_rg "high" "secrets" "Possible Google API Key" "gcp_api_key" \
    '\\bAIza[0-9A-Za-z\\-_]{35}\\b' inc_code[@] \
    "If unrestricted, an attacker can abuse Google APIs billed to your project or access protected resources." \
    "Restrict the key (HTTP referrer/IP), rotate it, and avoid embedding server keys in client code."

  scan_token_rg "high" "secrets" "Possible GitHub token" "github_token" \
    '\\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})\\b' inc_code[@] \
    "If valid, an attacker can access GitHub resources (repos, issues, packages) scoped by the token." \
    "Revoke/rotate the token, scope it minimally, and store it in a secret manager/CI secret."

  scan_token_rg "high" "secrets" "Possible GitLab token" "gitlab_token" \
    '\\bglpat-[A-Za-z0-9\\-_]{20,}\\b' inc_code[@] \
    "If valid, an attacker can access GitLab resources within the token scope." \
    "Revoke/rotate the token and store it in CI/secret manager."

  scan_token_rg "high" "secrets" "Possible Slack token" "slack_token" \
    '\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b' inc_code[@] \
    "If valid, an attacker can call Slack APIs as the associated bot/app/user, depending on token type." \
    "Revoke/rotate the token and use a secret manager; avoid embedding tokens in code."

  scan_token_rg "high" "secrets" "Possible Stripe secret key" "stripe_key" \
    '\\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\\b' inc_code[@] \
    "If valid, an attacker can abuse Stripe APIs within key permissions (payments, refunds, data access)." \
    "Rotate the key, restrict it if possible, and keep it server-side only."

  scan_token_rg "high" "secrets" "Possible SendGrid API key" "sendgrid_key" \
    '\\bSG\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\b' inc_code[@] \
    "If valid, an attacker can send email or access SendGrid resources in scope." \
    "Rotate the key and move it to a secret manager."

  scan_token_rg "high" "secrets" "Possible Mailgun API key" "mailgun_key" \
    '\\bkey-[0-9a-f]{32}\\b' inc_code[@] \
    "If valid, an attacker can send email or manage Mailgun resources in scope." \
    "Rotate the key and keep it in a secret manager."

  scan_token_rg "medium" "secrets" "Possible JWT token literal in code/log" "jwt_literal" \
    '\\beyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\b' inc_code[@] \
    "If this JWT is still valid and not bound to device/session, it may allow impersonation until expiry." \
    "Avoid logging tokens, invalidate sessions if needed, and ensure short expiry + rotation."

  scan_token_rg "high" "secrets" "Database URL with embedded credentials" "db_url_with_creds" \
    '\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqp)\\:\\/\\/[^\\s\\x22\\x27]{1,256}\\:[^\\s\\x22\\x27]{1,256}\\@[^\\s\\x22\\x27]+\\b' inc_code[@] \
    "Embedded DB credentials can allow direct database access if exposed and reachable." \
    "Move DB creds to secret manager/env, rotate credentials, and restrict network access."

  # Generic assignment (match only the value part via \\K)
  scan_token_rg "medium" "secrets" "Generic hardcoded secret-like value" "generic_secret_value" \
    '(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|access[_-]?token|refresh[_-]?token)\\s*[:=]\\s*["\\x27]\\K[^"\\x27\\n]{6,}(?=["\\x27])' inc_code[@] \
    "Hardcoded secrets in source may be extracted by anyone with repo access, logs, or client bundle access (if shipped)." \
    "Use environment/secret manager, rotate exposed secrets, and avoid committing credentials."

  scan_env_files
}

scan_risky_patterns() {
  log "Scanning risky code patterns (incl. RCE)..."

  local inc_js=( -g '**/*.{js,jsx,ts,tsx,mjs,cjs}' )
  local inc_all_code=( -g '**/*.{js,jsx,ts,tsx,mjs,cjs,json,yml,yaml}' )

  # RCE primitives
  scan_line_rg "high" "rce" "Possible OS command execution sink (child_process)" "child_process_exec" \
    '\\bchild_process\\b|\\b(execSync|exec|spawn|spawnSync|fork)\\s*\\(' inc_js[@] \
    "If attacker-controlled input reaches command arguments, it may lead to remote code execution or arbitrary command execution." \
    "Avoid shell execution; use safe APIs, validate/allowlist inputs, and never pass untrusted strings to a shell."

  scan_line_rg "high" "rce" "Dynamic code execution (eval / Function)" "dynamic_eval" \
    '\\beval\\s*\\(|\\bnew\\s+Function\\s*\\(' inc_js[@] \
    "If attacker-controlled input reaches dynamic evaluation, it can become arbitrary code execution." \
    "Remove eval/Function usage; use safe parsers or structured data formats."

  # File upload & extraction chains (common precursors to RCE/path traversal)
  scan_line_rg "high" "file_upload" "File upload handler detected (multer/formidable/busboy)" "file_upload_handler" \
    '\\b(multer|formidable|busboy)\\b' inc_js[@] \
    "Unsafe upload handling can enable path traversal, stored XSS, or RCE chains depending on storage and post-processing." \
    "Validate file type/size, store outside webroot, randomize filenames, and enforce strict allowlists."

  scan_line_rg "high" "file_upload" "Archive extraction detected (zip/tar) - watch for Zip Slip" "archive_extract" \
    '\\b(unzipper|adm-zip|node-tar|tar\\.x|tar\\.extract|extract-zip)\\b' inc_js[@] \
    "If extracting attacker-controlled archives without path validation, it may overwrite arbitrary files (Zip Slip) and lead to RCE or data loss." \
    "Validate archive entries, strip absolute/.. paths, extract to isolated directory, and avoid auto-executing extracted content."

  scan_line_rg "medium" "file_upload" "Writes files to disk (watch for path traversal)" "fs_write" \
    '\\bfs\\.(writeFileSync|writeFile|createWriteStream|appendFileSync|appendFile)\\b' inc_js[@] \
    "If the path is derived from user input, an attacker may write/overwrite arbitrary files (path traversal) and potentially reach RCE." \
    "Normalize/allowlist paths, generate server-side filenames, and write only under a dedicated directory."

  # XSS
  scan_line_rg "medium" "xss" "dangerouslySetInnerHTML usage" "dangerously_set_inner_html" \
    '\\bdangerouslySetInnerHTML\\b' inc_js[@] \
    "If attacker-controlled HTML reaches this sink, it can result in stored/reflected XSS." \
    "Avoid raw HTML rendering; sanitize with a strict allowlist and set CSP."

  scan_line_rg "medium" "xss" "rehype-raw / raw HTML in Markdown pipeline" "rehype_raw" \
    '\\brehype-raw\\b|\\ballowDangerousHtml\\b' inc_all_code[@] \
    "If untrusted Markdown/HTML is rendered with raw HTML enabled, it can lead to XSS." \
    "Disable raw HTML, sanitize input, and enforce a strong CSP."

  # SSRF-ish
  scan_line_rg "medium" "ssrf" "Potential SSRF sink (fetch/axios with dynamic URL)" "ssrf_sink" \
    '\\b(fetch|axios\\.(get|post|request)|got)\\s*\\(\\s*[^\\x22\\x27\\)]' inc_js[@] \
    "If user-controlled URL reaches server-side requests, it may access internal services (SSRF)." \
    "Allowlist hostnames, block private IP ranges, and avoid proxying arbitrary URLs."

  # Open redirect-ish
  scan_line_rg "low" "open_redirect" "Potential open redirect (redirect with variable)" "redirect_variable" \
    '\\bredirect\\s*\\(\\s*[^\\x22\\x27\\)]' inc_js[@] \
    "If redirect targets are attacker-controlled, it can enable phishing or auth-token leakage via redirect chains." \
    "Allowlist redirect targets and validate against same-origin or known paths."
}

audit_deps() {
  (( SKIP_DEPS == 1 )) && return 0
  log "Auditing dependencies (npm/pnpm/yarn audit)..."

  local audit_json="$1"
  local pm="unknown"
  if [[ -f "$ROOT/pnpm-lock.yaml" ]]; then pm="pnpm"; fi
  if [[ -f "$ROOT/yarn.lock" ]]; then pm="yarn"; fi
  if [[ -f "$ROOT/package-lock.json" ]]; then pm="npm"; fi

  local cmd=()
  case "$pm" in
    pnpm) cmd=(pnpm audit --json) ;;
    yarn) cmd=(yarn audit --json) ;;
    npm|unknown) cmd=(npm audit --json) ;;
  esac

  if ! command -v "${cmd[0]}" >/dev/null 2>&1; then
    log "WARN: ${cmd[0]} not available; skipping dependency audit."
    printf '{"skipped":true,"reason":"package manager not available"}' >"$audit_json"
    return 0
  fi

  (cd "$ROOT" && "${cmd[@]}" >"$audit_json" 2>/dev/null) || {
    log "WARN: dependency audit command failed; continuing."
    printf '{"failed":true,"cmd":%s}' "$(jq -nc --arg c "${cmd[*]}" '$c')" >"$audit_json"
  }
}

counts_json() {
  jq -s 'reduce .[] as $f ({"critical":0,"high":0,"medium":0,"low":0,"info":0}; .[$f.severity] += 1 )' "$FINDINGS_JSONL"
}

make_result_json() {
  local layout_json="$1"
  local git_json="$2"
  local deps_json="$3"
  local counts
  counts="$(counts_json)"
  jq -n \
    --arg tool "$TOOL_NAME" \
    --arg version "$VERSION" \
    --arg timestamp "$(date -Iseconds)" \
    --arg root "$(cd "$ROOT" && pwd -P)" \
    --slurpfile findings "$FINDINGS_JSONL" \
    --argjson layout "$layout_json" \
    --argjson git "$git_json" \
    --argjson deps "$deps_json" \
    --argjson counts "$counts" \
    '{
      meta:{
        tool:$tool,
        version:$version,
        timestamp:$timestamp,
        root:$root,
        layout:$layout,
        git:$git
      },
      counts:$counts,
      deps_audit:$deps,
      findings:$findings
    }'
}

severity_emoji() {
  case "$1" in
    critical) printf '🔥' ;;
    high) printf '🚨' ;;
    medium) printf '⚠️' ;;
    low) printf 'ℹ️' ;;
    info) printf '✅' ;;
    *) printf '•' ;;
  esac
}

telegram_send_message() {
  local token="$1" chat_id="$2" html="$3"
  curl -fsS \
    -X POST "https://api.telegram.org/bot${token}/sendMessage" \
    -d "chat_id=${chat_id}" \
    --data-urlencode "text=${html}" \
    -d "parse_mode=HTML" \
    -d "disable_web_page_preview=true" >/dev/null
}

telegram_send_document() {
  local token="$1" chat_id="$2" file="$3" caption_html="$4"
  curl -fsS \
    -X POST "https://api.telegram.org/bot${token}/sendDocument" \
    -F "chat_id=${chat_id}" \
    -F "document=@${file}" \
    -F "caption=${caption_html}" \
    -F "parse_mode=HTML" >/dev/null
}

telegram_summary_html() {
  local counts_json="$1"
  local root_disp
  root_disp="$(cd "$ROOT" && pwd -P)"

  local critical high medium low info
  critical="$(jq -r '.critical' <<<"$counts_json")"
  high="$(jq -r '.high' <<<"$counts_json")"
  medium="$(jq -r '.medium' <<<"$counts_json")"
  low="$(jq -r '.low' <<<"$counts_json")"
  info="$(jq -r '.info' <<<"$counts_json")"

  local header
  header="<b>🛡️ Next.js Whitebox Audit</b>\n<b>📁 Root:</b> <code>$(html_escape "$root_disp")</code>\n"
  header+="<b>📊 Summary:</b> 🔥 Critical: ${critical} | 🚨 High: ${high} | ⚠️ Medium: ${medium} | ℹ️ Low: ${low} | ✅ Info: ${info}\n"

  local top
  top="$(jq -s --argjson n "$TOP_FINDINGS" '
    def rank(s):
      if s=="critical" then 0
      elif s=="high" then 1
      elif s=="medium" then 2
      elif s=="low" then 3
      else 4 end;
    sort_by(rank(.severity), .id)
    | .[0:$n]
    | map({id, severity, title, file:.evidence.file, line:.evidence.line})
  ' "$FINDINGS_JSONL")"

  local body="<b>🚩 Top Findings</b>\n"
  local i=0
  while IFS= read -r row; do
    i=$((i + 1))
    local id sev title file line
    id="$(jq -r '.id' <<<"$row")"
    sev="$(jq -r '.severity' <<<"$row")"
    title="$(jq -r '.title' <<<"$row")"
    file="$(jq -r '.file' <<<"$row")"
    line="$(jq -r '.line' <<<"$row")"
    body+="${i}) $(severity_emoji "$sev") <b>[$(html_escape "$id")]</b> $(html_escape "$title")\n"
    body+="<code>$(html_escape "$file"):${line}</code>\n"
  done < <(jq -c '.[]' <<<"$top")

  printf '%b%b' "$header" "$body"
}

exit_code_from_counts() {
  local counts_json="$1"
  local critical high
  critical="$(jq -r '.critical' <<<"$counts_json")"
  high="$(jq -r '.high' <<<"$counts_json")"
  if [[ "$critical" != "0" || "$high" != "0" ]]; then
    return 2
  fi
  return 0
}

main() {
  parse_args "$@"
  ROOT="$(cd "$ROOT" && pwd -P)"

  need_cmd rg
  need_cmd jq
  need_cmd curl
  command -v git >/dev/null 2>&1 || true

  local tmp
  tmp="$(make_tmpdir)"
  trap 'rm -rf "$tmp"' EXIT
  FINDINGS_JSONL="$tmp/findings.jsonl"
  : >"$FINDINGS_JSONL"

  local layout git_json deps_json_file deps_json
  layout="$(detect_next_layout)"
  git_json="$(git_meta_json)"

  deps_json_file="$tmp/deps_audit.json"
  audit_deps "$deps_json_file"
  deps_json="$(cat "$deps_json_file" 2>/dev/null || printf '{}')"

  scan_secrets

  log "Scanning runtime variables via env/set (redacted)..."
  scan_runtime_vars "env" "$(env 2>/dev/null || true)"
  scan_runtime_vars "set" "$(set 2>/dev/null || true)"

  scan_risky_patterns

  log "Writing $OUT_FILE ..."
  make_result_json "$layout" "$git_json" "$deps_json" >"$OUT_FILE"
  local counts
  counts="$(jq -c '.counts' "$OUT_FILE")"

  if (( SEND_TELEGRAM == 1 )); then
    local token="${TELEGRAM_BOT_TOKEN:-}"
    local chat_id="${TELEGRAM_CHAT_ID:-}"
    if [[ -z "$token" || -z "$chat_id" ]]; then
      log "WARN: TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID not set; skipping Telegram send."
    else
      local msg
      msg="$(telegram_summary_html "$counts")"
      if ((${#msg} > 3500)); then
        msg="${msg:0:3400}\n<b>…truncated…</b>\n"
      fi
      telegram_send_message "$token" "$chat_id" "$msg" || log "WARN: Telegram sendMessage failed"
      telegram_send_document "$token" "$chat_id" "$OUT_FILE" "<b>📎 Attached:</b> <code>$(html_escape "$OUT_FILE")</code>" || log "WARN: Telegram sendDocument failed"
    fi
  fi

  exit_code_from_counts "$counts"
}

main "$@"

