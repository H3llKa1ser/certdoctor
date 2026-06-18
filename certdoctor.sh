#!/usr/bin/env bash
###############################################################################
# certdoctor.sh — Comprehensive PKI / SSL Certificate Diagnostic Tool
#
# Covers: expiry, chain completeness & order, SAN/CN match, CA trust,
#         cert/key match, TLS versions, ciphers, OCSP stapling, SNI, ALPN/HTTP2,
#         weak keys/signatures, self-signed detection, clock skew, revocation,
#         file format detection, key permissions, and more.
#
# Usage:
#   ./certdoctor.sh <host[:port]> [host2[:port]] ...        # remote check(s)
#   ./certdoctor.sh --file cert.pem [--key key.pem] [--ca ca.pem]  # local files
#   ./certdoctor.sh --list hosts.txt                        # batch from file
#   ./certdoctor.sh --quiet <host>                          # only warnings/errors
#   ./certdoctor.sh --summary-only <host>                   # only final summary
#
# Exit codes: 0=all OK, 1=warnings, 2=critical/errors, 3=usage error
###############################################################################

set -uo pipefail

# ─── Config ──────────────────────────────────────────────────────────────────
WARN_DAYS=${WARN_DAYS:-30}
CRIT_DAYS=${CRIT_DAYS:-7}
TIMEOUT=${TIMEOUT:-10}
MIN_RSA_BITS=2048
MIN_EC_BITS=256
MAX_VALIDITY_DAYS=398          # Browser max (Chrome/Safari/Apple)

# ─── Colors ──────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; CYN=$'\e[36m'
  BOLD=$'\e[1m'; RST=$'\e[0m'
else
  RED=''; GRN=''; YEL=''; BLU=''; CYN=''; BOLD=''; RST=''
fi

# ─── Globals ─────────────────────────────────────────────────────────────────
EXIT_CODE=0
QUIET=0
JSON=0
SUMMARY_ONLY=0
ISSUES_CRIT=()
ISSUES_WARN=()
CURRENT_HOST=""
TMPDIR_C="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_C"' EXIT

# ─── Output helpers ──────────────────────────────────────────────────────────
# SUMMARY_ONLY suppresses live output but still collects issues for the summary.
ok()    { (( QUIET==0 && SUMMARY_ONLY==0 )) && printf "  ${GRN}✅ %s${RST}\n" "$*"; }
warn()  {
  (( SUMMARY_ONLY==0 )) && printf "  ${YEL}⚠️  %s${RST}\n" "$*"
  ISSUES_WARN+=("${CURRENT_HOST:+[$CURRENT_HOST] }$*")
  (( EXIT_CODE < 1 )) && EXIT_CODE=1
}
err()   {
  (( SUMMARY_ONLY==0 )) && printf "  ${RED}❌ %s${RST}\n" "$*"
  ISSUES_CRIT+=("${CURRENT_HOST:+[$CURRENT_HOST] }$*")
  EXIT_CODE=2
}
info()  { (( QUIET==0 && SUMMARY_ONLY==0 )) && printf "  ${CYN}ℹ️  %s${RST}\n" "$*"; }
hdr()   { (( QUIET==0 && SUMMARY_ONLY==0 )) && printf "\n${BOLD}${BLU}%s${RST}\n" "$*"; }
sub()   { (( QUIET==0 && SUMMARY_ONLY==0 )) && printf "${BOLD}— %s${RST}\n" "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required tool: $1"; exit 3; }; }
need openssl

# ─── Date parsing (Linux + macOS compatible) ─────────────────────────────────
to_epoch() {
  local d="$1"
  date -d "$d" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$d" +%s 2>/dev/null || echo 0
}

# ─── Fetch certificate chain from a live host ────────────────────────────────
fetch_chain() {
  local host="$1" port="$2" out="$3"
  echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
       -servername "$host" -showcerts 2>/dev/null > "$out"
  [[ -s "$out" ]]
}

# ─── Split a chain file into individual certs ────────────────────────────────
split_chain() {
  local infile="$1" prefix="$2"
  awk -v pfx="$prefix" '
    /-----BEGIN CERTIFICATE-----/ {n++; f=sprintf("%s%02d.pem", pfx, n)}
    n>0 {print > f}
  ' "$infile"
}

# ─── 1. EXPIRY CHECK (whole chain) ───────────────────────────────────────────
check_expiry() {
  local cert="$1" label="${2:-certificate}"
  local nb na nb_e na_e now days
  nb=$(openssl x509 -in "$cert" -noout -startdate 2>/dev/null | cut -d= -f2)
  na=$(openssl x509 -in "$cert" -noout -enddate   2>/dev/null | cut -d= -f2)
  nb_e=$(to_epoch "$nb"); na_e=$(to_epoch "$na"); now=$(date +%s)

  if (( now < nb_e )); then
    err "$label: NOT YET VALID (starts $nb) — check server clock / clock skew!"
    return
  fi
  days=$(( (na_e - now) / 86400 ))
  if (( days < 0 )); then
    err "$label: EXPIRED ${days#-} days ago ($na)"
  elif (( days < CRIT_DAYS )); then
    err "$label: expires in $days days ($na) — CRITICAL"
  elif (( days < WARN_DAYS )); then
    warn "$label: expires in $days days ($na)"
  else
    ok "$label: valid for $days more days ($na)"
  fi
}

# ─── 2. VALIDITY PERIOD (browser 398-day rule) ───────────────────────────────
check_validity_period() {
  local cert="$1"
  local nb na nb_e na_e total
  nb=$(openssl x509 -in "$cert" -noout -startdate 2>/dev/null | cut -d= -f2)
  na=$(openssl x509 -in "$cert" -noout -enddate   2>/dev/null | cut -d= -f2)
  nb_e=$(to_epoch "$nb"); na_e=$(to_epoch "$na")
  total=$(( (na_e - nb_e) / 86400 ))
  if (( total > MAX_VALIDITY_DAYS )); then
    warn "Validity period is $total days (>$MAX_VALIDITY_DAYS) — modern browsers may reject"
  else
    ok "Validity period: $total days (within browser limits)"
  fi
}

# ─── 3. KEY STRENGTH & SIGNATURE ALGORITHM ───────────────────────────────────
check_key_strength() {
  local cert="$1"
  local txt algo bits sig
  txt=$(openssl x509 -in "$cert" -noout -text 2>/dev/null)
  algo=$(grep -m1 "Public Key Algorithm" <<<"$txt" | awk '{print $NF}')
  bits=$(grep -m1 -oE "\(([0-9]+) bit\)" <<<"$txt" | grep -oE "[0-9]+")
  sig=$(grep -m1 "Signature Algorithm" <<<"$txt" | awk '{print $NF}')

  if [[ "$algo" == *rsa* || "$algo" == *RSA* || "$bits" -gt 600 ]] 2>/dev/null; then
    if [[ -n "$bits" ]] && (( bits < MIN_RSA_BITS )) && (( bits > 400 )); then
      warn "Weak RSA key: ${bits}-bit (minimum $MIN_RSA_BITS)"
    else
      ok "Key strength: ${bits:-?}-bit ($algo)"
    fi
  else
    ok "Key: $algo (${bits:-EC} bit)"
  fi

  case "$sig" in
    *sha1*|*md5*|*md2*) err "Weak signature algorithm: $sig (use SHA-256+)" ;;
    *sha256*|*sha384*|*sha512*|*ecdsa*|*Ed25519*) ok "Signature algorithm: $sig" ;;
    *) info "Signature algorithm: $sig" ;;
  esac
}

# ─── 4. SUBJECT / SAN / CN ───────────────────────────────────────────────────
check_san() {
  local cert="$1" host="${2:-}"
  local subj san_line sans cn
  subj=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/subject=//')
  cn=$(grep -oE "CN ?= ?[^,/]+" <<<"$subj" | sed 's/CN ?= ?//' | head -1)
  san_line=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
             | grep -v "X509v3" | tr -d ' ')
  sans=$(grep -oE "DNS:[^,]+" <<<"$san_line" | sed 's/DNS://' | tr '\n' ' ')

  info "Subject CN: ${cn:-<none>}"
  if [[ -z "$san_line" ]]; then
    warn "No Subject Alternative Name (SAN) — modern browsers REQUIRE SAN, ignore CN!"
  else
    info "SANs: ${sans:-<non-DNS>}"
    # count SANs
    local cnt; cnt=$(grep -oc "DNS:" <<<"$san_line")
    (( cnt > 100 )) && warn "Large SAN list ($cnt names) — consider wildcard/split"
  fi

  # Hostname match check
  if [[ -n "$host" ]]; then
    local matched=0 s
    for s in $sans; do
      if [[ "$s" == "$host" ]]; then matched=1; break; fi
      # wildcard match (one level)
      if [[ "$s" == \*.* ]]; then
        local base="${s#\*.}"
        local hbase="${host#*.}"
        [[ "$hbase" == "$base" && "$host" == *.* ]] && { matched=1; break; }
      fi
    done
    if (( matched )); then
      ok "Hostname '$host' matches a SAN"
    else
      err "Hostname '$host' does NOT match any SAN — name mismatch!"
      [[ "$host" == *[^a-zA-Z0-9.-]* ]] && info "Host has non-ASCII chars — IDN must use punycode (xn--)"
    fi
  fi
}

# ─── 5. SELF-SIGNED DETECTION ────────────────────────────────────────────────
check_self_signed() {
  local cert="$1"
  local s i
  s=$(openssl x509 -in "$cert" -noout -subject 2>/dev/null | sed 's/^subject=//')
  i=$(openssl x509 -in "$cert" -noout -issuer  2>/dev/null | sed 's/^issuer=//')
  if [[ "$s" == "$i" ]]; then
    warn "Certificate is SELF-SIGNED (subject == issuer)"
  else
    ok "CA-signed (issuer: $(grep -oE 'CN ?= ?[^,/]+' <<<"$i" | head -1))"
  fi
}

# ─── 6. CHAIN COMPLETENESS & ORDER ───────────────────────────────────────────
check_chain() {
  local chainfile="$1"
  local cnt; cnt=$(grep -c "BEGIN CERTIFICATE" "$chainfile")
  info "Certificates presented in chain: $cnt"
  if (( cnt < 2 )); then
    warn "Only $cnt cert served — chain likely INCOMPLETE (works in browser via AIA, fails in tools!)"
  fi

  # Split & verify order: each cert's issuer should == next cert's subject
  split_chain "$chainfile" "$TMPDIR_C/chain-"
  local files=( "$TMPDIR_C"/chain-*.pem )
  (( ${#files[@]} < 2 )) && return

  local order_ok=1 idx
  for (( idx=0; idx<${#files[@]}-1; idx++ )); do
    local this_issuer next_subject
    this_issuer=$(openssl x509 -in "${files[$idx]}" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    next_subject=$(openssl x509 -in "${files[$((idx+1))]}" -noout -subject 2>/dev/null | sed 's/^subject=//')
    if [[ "$this_issuer" != "$next_subject" ]]; then
      order_ok=0
      warn "Chain order issue at position $((idx+1)): issuer != next subject"
    fi
  done
  (( order_ok )) && ok "Chain order looks correct (leaf → intermediate → root)"
}

# ─── 7. CHAIN VERIFICATION AGAINST TRUST STORE ───────────────────────────────
check_trust() {
  local chainfile="$1" cafile="${2:-}"
  split_chain "$chainfile" "$TMPDIR_C/v-"
  local files=( "$TMPDIR_C"/v-*.pem )
  (( ${#files[@]} == 0 )) && return
  local leaf="${files[0]}"
  local untrusted=""
  local i
  for (( i=1; i<${#files[@]}; i++ )); do untrusted+=" -untrusted ${files[$i]}"; done

  local result
  if [[ -n "$cafile" ]]; then
    result=$(openssl verify -CAfile "$cafile" $untrusted "$leaf" 2>&1)
  else
    result=$(openssl verify $untrusted "$leaf" 2>&1)
  fi

  if grep -q ": OK" <<<"$result"; then
    ok "Chain verifies against trust store"
  else
    err "Chain verification FAILED: $result"
    case "$result" in
      *"unable to get local issuer"*) info "→ error 20: missing intermediate. Serve full chain." ;;
      *"self signed certificate in certificate chain"*) info "→ error 19: root not trusted. Add CA to trust store." ;;
      *"self signed certificate"*) info "→ error 18: self-signed leaf. Use a CA-signed cert." ;;
      *"certificate has expired"*) info "→ error 10: something in the chain expired." ;;
      *"unable to verify the first certificate"*) info "→ error 21: missing intermediate." ;;
    esac
  fi
}

# ─── 8. CERT / KEY MATCH ─────────────────────────────────────────────────────
check_key_match() {
  local cert="$1" key="$2"
  local cm km
  cm=$(openssl x509 -noout -modulus -in "$cert" 2>/dev/null | openssl md5)
  # try RSA, then EC pubkey comparison
  if km=$(openssl rsa -noout -modulus -in "$key" 2>/dev/null | openssl md5); then :; else km=""; fi
  if [[ -n "$km" ]]; then
    if [[ "$cm" == "$km" ]]; then ok "Certificate and private key MATCH"
    else err "Certificate and key DO NOT match!"; fi
  else
    # EC keys — compare public key
    local cpub kpub
    cpub=$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null | openssl md5)
    kpub=$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl md5)
    if [[ -n "$kpub" && "$cpub" == "$kpub" ]]; then ok "Certificate and key MATCH (EC)"
    else err "Certificate and key DO NOT match (or key unreadable)!"; fi
  fi
}

# ─── 9. KEY FILE PERMISSIONS ─────────────────────────────────────────────────
check_key_perms() {
  local key="$1"
  [[ -f "$key" ]] || return
  local perms
  perms=$(stat -c "%a" "$key" 2>/dev/null || stat -f "%Lp" "$key" 2>/dev/null)
  if [[ "$perms" != "600" && "$perms" != "400" ]]; then
    # check if group/other have any access bits
    local go="${perms: -2}"
    if [[ "$go" != "00" ]]; then
      warn "Private key permissions are $perms — should be 600 or 400"
    else
      ok "Private key permissions: $perms"
    fi
  else
    ok "Private key permissions: $perms"
  fi
}

# ─── 10. FILE FORMAT DETECTION ───────────────────────────────────────────────
detect_format() {
  local f="$1"
  if openssl x509 -in "$f" -noout 2>/dev/null; then echo "PEM (x509)"
  elif openssl x509 -in "$f" -inform DER -noout 2>/dev/null; then echo "DER"
  elif openssl pkcs12 -in "$f" -noout -passin pass: 2>/dev/null; then echo "PKCS#12"
  elif openssl pkcs7 -in "$f" -noout 2>/dev/null; then echo "PKCS#7 (PEM)"
  else echo "unknown/encrypted"; fi
}

# ─── 11. LIVE TLS: VERSIONS, CIPHER, SNI, ALPN, OCSP ─────────────────────────
check_tls_live() {
  local host="$1" port="$2"

  sub "TLS protocol support"
  local v
  for v in 1_2 1_3; do
    if echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
         -servername "$host" -tls$v 2>/dev/null | grep -q "Cipher is"; then
      ok "TLS $v supported"
    else
      info "TLS $v not supported/negotiated"
    fi
  done
  # legacy (should be OFF)
  for v in 1 1_1; do
    if echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
         -servername "$host" -tls$v 2>/dev/null | grep -q "Cipher is"; then
      warn "TLS $v is ENABLED (deprecated/insecure — disable it)"
    fi
  done

  sub "Negotiated cipher"
  local cipher
  cipher=$(echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
           -servername "$host" 2>/dev/null | grep -m1 "Cipher" | sed 's/^ *//')
  [[ -n "$cipher" ]] && info "$cipher"

  sub "SNI behavior"
  local with_sni without_sni
  with_sni=$(echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
             -servername "$host" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  without_sni=$(echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
                2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  info "With SNI:    ${with_sni:-<none>}"
  [[ "$with_sni" != "$without_sni" ]] && info "Without SNI: ${without_sni:-<none>} (default vhost differs)"

  sub "ALPN / HTTP-2"
  if echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
       -servername "$host" -alpn h2 2>/dev/null | grep -q "ALPN protocol: h2"; then
    ok "HTTP/2 (ALPN h2) supported"
  else
    info "HTTP/2 not negotiated"
  fi

  sub "OCSP stapling"
  if echo | timeout "$TIMEOUT" openssl s_client -connect "${host}:${port}" \
       -servername "$host" -status 2>/dev/null | grep -q "OCSP Response Status: successful"; then
    ok "OCSP stapling active"
  else
    info "OCSP stapling not active (adds client-side latency)"
  fi
}

# ─── 12. CLOCK CHECK ─────────────────────────────────────────────────────────
check_clock() {
  local synced
  synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo "unknown")
  case "$synced" in
    yes) ok "System clock NTP-synchronized (UTC now: $(date -u '+%Y-%m-%d %H:%M:%S'))" ;;
    no)  warn "System clock NOT NTP-synchronized — risk of clock-skew cert errors!" ;;
    *)   info "Clock sync status unknown (UTC now: $(date -u '+%Y-%m-%d %H:%M:%S'))" ;;
  esac
}

# ─── Run all checks against a single live host ───────────────────────────────
diagnose_host() {
  local target="$1"
  local host="${target%%:*}"
  local port="${target##*:}"
  [[ "$host" == "$port" ]] && port=443
  CURRENT_HOST="${host}:${port}"

  hdr "════════════════════════════════════════════════════════════"
  hdr "🔬 DIAGNOSING: ${host}:${port}"
  hdr "════════════════════════════════════════════════════════════"

  # Connectivity
  sub "Connectivity"
  if ! command -v getent >/dev/null 2>&1 || getent hosts "$host" >/dev/null 2>&1 \
       || host "$host" >/dev/null 2>&1 || nslookup "$host" >/dev/null 2>&1; then
    ok "DNS resolves for $host"
  else
    warn "DNS may not resolve for $host"
  fi
  if timeout "$TIMEOUT" bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
    ok "TCP port $port reachable"
  else
    err "Cannot reach $host:$port (TCP) — check firewall/service"
    return
  fi

  # Fetch chain
  local chainfile="$TMPDIR_C/chain.txt"
  if ! fetch_chain "$host" "$port" "$chainfile"; then
    err "TLS handshake failed — no certificate retrieved (cipher/protocol/cert issue)"
    return
  fi

  # Leaf cert
  local leaf="$TMPDIR_C/leaf.pem"
  openssl x509 -in "$chainfile" -out "$leaf" 2>/dev/null

  hdr "📅 Expiry & Validity"
  check_expiry "$leaf" "Leaf cert"
  check_validity_period "$leaf"
  # check each chain cert expiry
  split_chain "$chainfile" "$TMPDIR_C/exp-"
  local f
  for f in "$TMPDIR_C"/exp-*.pem; do
    local subj; subj=$(openssl x509 -in "$f" -noout -subject 2>/dev/null \
                       | grep -oE 'CN ?= ?[^,/]+' | head -1)
    [[ "$f" == *"01.pem" ]] && continue   # skip leaf, already done
    check_expiry "$f" "Chain: ${subj:-cert}"
  done

  hdr "🏷️  Identity (Subject / SAN)"
  check_san "$leaf" "$host"

  hdr "🔍 Trust & Chain"
  check_self_signed "$leaf"
  check_chain "$chainfile"
  check_trust "$chainfile"

  hdr "💪 Cryptographic Strength"
  check_key_strength "$leaf"

  hdr "🔐 Live TLS Configuration"
  check_tls_live "$host" "$port"

  hdr "⏰ Environment"
  check_clock
}

# ─── Run checks against local files ──────────────────────────────────────────
diagnose_files() {
  local cert="$1" key="${2:-}" ca="${3:-}"
  CURRENT_HOST="$(basename "$cert")"

  hdr "════════════════════════════════════════════════════════════"
  hdr "🔬 DIAGNOSING LOCAL FILES"
  hdr "════════════════════════════════════════════════════════════"

  sub "File format detection"
  info "Cert format: $(detect_format "$cert")"
  [[ -n "$key" ]] && info "Key format:  $(detect_format "$key")"
  [[ -n "$ca"  ]] && info "CA format:   $(detect_format "$ca")"

  # normalize cert to PEM if DER
  local pcert="$cert"
  if [[ "$(detect_format "$cert")" == "DER" ]]; then
    pcert="$TMPDIR_C/cert.pem"
    openssl x509 -in "$cert" -inform DER -out "$pcert" 2>/dev/null
    info "Converted DER → PEM for analysis"
  fi

  hdr "📅 Expiry & Validity"
  check_expiry "$pcert" "Certificate"
  check_validity_period "$pcert"

  hdr "🏷️  Identity (Subject / SAN)"
  check_san "$pcert"

  hdr "🔍 Trust & Chain"
  check_self_signed "$pcert"
  check_trust "$pcert" "$ca"

  hdr "💪 Cryptographic Strength"
  check_key_strength "$pcert"

  if [[ -n "$key" ]]; then
    hdr "🔑 Key Match & Permissions"
    check_key_match "$pcert" "$key"
    check_key_perms "$key"
  fi
}

# ─── Print summary ───────────────────────────────────────────────────────────
print_summary() {
  # Always-print helpers (bypass SUMMARY_ONLY/QUIET suppression)
  local SEP="════════════════════════════════════════════════════════════"
  local THIN="────────────────────────────────────────────────────────────"

  printf "\n${BOLD}${BLU}%s${RST}\n" "$SEP"
  printf "${BOLD}${BLU}📋 SUMMARY${RST}\n"
  printf "${BOLD}${BLU}%s${RST}\n" "$SEP"

  local n_crit=${#ISSUES_CRIT[@]}
  local n_warn=${#ISSUES_WARN[@]}

  if (( n_crit > 0 )); then
    printf "\n${RED}${BOLD}❌ CRITICAL ISSUES (%d):${RST}\n" "$n_crit"
    local i
    for i in "${ISSUES_CRIT[@]}"; do
      printf "   ${RED}•${RST} %s\n" "$i"
    done
  fi

  if (( n_warn > 0 )); then
    printf "\n${YEL}${BOLD}⚠️  WARNINGS (%d):${RST}\n" "$n_warn"
    local i
    for i in "${ISSUES_WARN[@]}"; do
      printf "   ${YEL}•${RST} %s\n" "$i"
    done
  fi

  printf "\n${BOLD}${BLU}%s${RST}\n" "$THIN"
  case $EXIT_CODE in
    0) printf "${GRN}${BOLD}  ✅ ALL CHECKS PASSED — no issues found${RST}\n" ;;
    1) printf "${YEL}${BOLD}  ⚠️  COMPLETED WITH %d WARNING(S)${RST}\n" "$n_warn" ;;
    2) printf "${RED}${BOLD}  ❌ FAILED: %d CRITICAL, %d WARNING(S)${RST}\n" "$n_crit" "$n_warn" ;;
  esac
  printf "${BOLD}${BLU}%s${RST}\n" "$SEP"
}

# ─── Usage ───────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}certdoctor.sh — PKI / SSL Certificate Diagnostic Tool${RST}

USAGE:
  $0 <host[:port]> [more hosts...]      Check live host(s) (default port 443)
  $0 --file <cert> [--key <key>] [--ca <ca>]   Check local files
  $0 --list <file>                      Batch check hosts from file (one per line)
  $0 --quiet <host>                     Only show warnings/errors (inline)
  $0 --summary-only <host>              Suppress scan; show ONLY final summary
  $0 -h | --help                        Show this help

ENV VARS:
  WARN_DAYS=$WARN_DAYS   CRIT_DAYS=$CRIT_DAYS   TIMEOUT=$TIMEOUT

EXAMPLES:
  $0 example.com
  $0 example.com:8443 api.example.com
  $0 --file server.crt --key server.key --ca ca-bundle.crt
  $0 --list hosts.txt
  $0 --summary-only --list hosts.txt
  WARN_DAYS=60 $0 example.com

EXIT CODES: 0=OK  1=warnings  2=critical  3=usage error
EOF
}

# ─── Argument parsing ────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && { usage; exit 3; }

MODE="host"
CERT=""; KEY=""; CA=""; LISTFILE=""
HOSTS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)       usage; exit 0 ;;
    --quiet)         QUIET=1; shift ;;
    --summary-only)  SUMMARY_ONLY=1; shift ;;
    --json)          JSON=1; shift ;;
    --file)          MODE="file"; CERT="$2"; shift 2 ;;
    --key)           KEY="$2"; shift 2 ;;
    --ca)            CA="$2"; shift 2 ;;
    --list)          MODE="list"; LISTFILE="$2"; shift 2 ;;
    -*)              echo "Unknown option: $1"; usage; exit 3 ;;
    *)               HOSTS+=("$1"); shift ;;
  esac
done

# ─── Dispatch ────────────────────────────────────────────────────────────────
case "$MODE" in
  file)
    [[ -f "$CERT" ]] || { echo "Cert file not found: $CERT"; exit 3; }
    diagnose_files "$CERT" "$KEY" "$CA"
    ;;
  list)
    [[ -f "$LISTFILE" ]] || { echo "List file not found: $LISTFILE"; exit 3; }
    while IFS= read -r line; do
      line="$(echo "$line" | tr -d '[:space:]')"
      [[ -z "$line" || "$line" == \#* ]] && continue
      diagnose_host "$line"
    done < "$LISTFILE"
    ;;
  host)
    (( ${#HOSTS[@]} == 0 )) && { usage; exit 3; }
    for h in "${HOSTS[@]}"; do diagnose_host "$h"; done
    ;;
esac

print_summary
exit $EXIT_CODE
