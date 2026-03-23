#!/bin/bash

set -uo pipefail

TENANT="vsphere.local"
IDENTITY_SOURCE_NAME="dominio.io"
DOMAIN_NAME="dominio.io"
DOMAIN_ALIAS="DOMINIO"
BASE_USER_DN="DC=dominio,DC=io"
BASE_GROUP_DN="DC=dominio,DC=io"
BIND_USERNAME="CN=Pascal,OU=it,DC=dominio,DC=io"
PRIMARY_LDAPS_URL="ldaps://dc1.dominio.io:636"
SECONDARY_LDAPS_URL="ldaps://dc2.dominio.io:636"
SSO_CONFIG_BIN="/opt/vmware/bin/sso-config.sh"

SCRIPT_NAME="$(basename "$0")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${HOME}/ldaps-refresh-${DOMAIN_NAME}-${TIMESTAMP}"
LOG_FILE="${RUN_DIR}/90_actions.log"
SUMMARY_FILE="${RUN_DIR}/20_certificate_recap.txt"
CONFIG_BEFORE_FILE="${RUN_DIR}/00_identity_sources_before.txt"
CONFIG_AFTER_FILE="${RUN_DIR}/99_identity_sources_after.txt"
VARS_FILE="${RUN_DIR}/00_effective_variables.txt"
PRIMARY_RAW_FILE="${RUN_DIR}/10_primary_s_client_raw.txt"
PRIMARY_CHAIN_FILE="${RUN_DIR}/11_primary_chain.crt"
SECONDARY_RAW_FILE="${RUN_DIR}/12_secondary_s_client_raw.txt"
SECONDARY_CHAIN_FILE="${RUN_DIR}/13_secondary_chain.crt"
PRIMARY_CERT_DIR="${RUN_DIR}/certs_primary"
SECONDARY_CERT_DIR="${RUN_DIR}/certs_secondary"

umask 077

log() {
  local msg="$1"
  printf '%s %s\n' "[$(date '+%F %T')]" "$msg" | tee -a "$LOG_FILE"
}

fail() {
  local msg="$1"
  printf '\nERRORE: %s\n' "$msg" | tee -a "$LOG_FILE" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Comando non trovato: $1"
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "Eseguire lo script come root sul vCenter."
}

validate_vars() {
  [ -n "$TENANT" ] || fail "TENANT non valorizzato"
  [ -n "$IDENTITY_SOURCE_NAME" ] || fail "IDENTITY_SOURCE_NAME non valorizzato"
  [ -n "$DOMAIN_NAME" ] || fail "DOMAIN_NAME non valorizzato"
  [ -n "$DOMAIN_ALIAS" ] || fail "DOMAIN_ALIAS non valorizzato"
  [ -n "$BASE_USER_DN" ] || fail "BASE_USER_DN non valorizzato"
  [ -n "$BASE_GROUP_DN" ] || fail "BASE_GROUP_DN non valorizzato"
  [ -n "$BIND_USERNAME" ] || fail "BIND_USERNAME non valorizzato"
  [ -n "$PRIMARY_LDAPS_URL" ] || fail "PRIMARY_LDAPS_URL non valorizzato"
  [ -x "$SSO_CONFIG_BIN" ] || fail "sso-config.sh non trovato o non eseguibile in $SSO_CONFIG_BIN"
}

init_run_dir() {
  mkdir -p "$RUN_DIR" "$PRIMARY_CERT_DIR" "$SECONDARY_CERT_DIR"
  : > "$LOG_FILE"
  cat > "$VARS_FILE" <<EOFVARS
TIMESTAMP=${TIMESTAMP}
TENANT=${TENANT}
IDENTITY_SOURCE_NAME=${IDENTITY_SOURCE_NAME}
DOMAIN_NAME=${DOMAIN_NAME}
DOMAIN_ALIAS=${DOMAIN_ALIAS}
BASE_USER_DN=${BASE_USER_DN}
BASE_GROUP_DN=${BASE_GROUP_DN}
BIND_USERNAME=${BIND_USERNAME}
PRIMARY_LDAPS_URL=${PRIMARY_LDAPS_URL}
SECONDARY_LDAPS_URL=${SECONDARY_LDAPS_URL}
SSO_CONFIG_BIN=${SSO_CONFIG_BIN}
RUN_DIR=${RUN_DIR}
EOFVARS
}

extract_host_port() {
  local url="$1"
  local stripped host port
  stripped="${url#ldaps://}"
  host="${stripped%%:*}"
  port="${stripped##*:}"
  printf '%s;%s\n' "$host" "$port"
}

fetch_chain() {
  local url="$1"
  local raw_file="$2"
  local chain_file="$3"
  local split_dir="$4"
  local host port

  IFS=';' read -r host port < <(extract_host_port "$url")
  [ -n "$host" ] || fail "Impossibile estrarre l'host da $url"
  [ -n "$port" ] || fail "Impossibile estrarre la porta da $url"

  log "Raccolgo certificati live da ${host}:${port}"

  if ! openssl s_client -showcerts -connect "${host}:${port}" </dev/null >"$raw_file" 2>&1; then
    fail "Connessione openssl fallita verso ${host}:${port}. Controllare reachability, DNS o certificato."
  fi

  sed -ne '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' "$raw_file" > "$chain_file"
  [ -s "$chain_file" ] || fail "Nessun certificato PEM estratto da ${host}:${port}"

  split_chain "$chain_file" "$split_dir"
  summarize_chain "$url" "$split_dir" >> "$SUMMARY_FILE"
}

split_chain() {
  local chain_file="$1"
  local out_dir="$2"
  mkdir -p "$out_dir"
  rm -f "$out_dir"/*.crt
  awk -v dir="$out_dir" '
    /-----BEGIN CERTIFICATE-----/ {n++; file=sprintf("%s/cert-%02d.crt", dir, n)}
    file {print > file}
    /-----END CERTIFICATE-----/ {close(file)}
  ' "$chain_file"
  ls "$out_dir"/cert-*.crt >/dev/null 2>&1 || fail "Impossibile suddividere la chain $chain_file"
}

summarize_chain() {
  local url="$1"
  local cert_dir="$2"
  local cert_file idx subject issuer not_before not_after san fingerprint

  printf '=== %s ===\n' "$url"
  for cert_file in "$cert_dir"/cert-*.crt; do
    [ -f "$cert_file" ] || continue
    idx="$(basename "$cert_file")"
    subject="$(openssl x509 -in "$cert_file" -noout -subject | sed 's/^subject=//')"
    issuer="$(openssl x509 -in "$cert_file" -noout -issuer | sed 's/^issuer=//')"
    not_before="$(openssl x509 -in "$cert_file" -noout -startdate | sed 's/^notBefore=//')"
    not_after="$(openssl x509 -in "$cert_file" -noout -enddate | sed 's/^notAfter=//')"
    san="$(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')"
    fingerprint="$(openssl x509 -in "$cert_file" -noout -fingerprint -sha256 | sed 's/^sha256 Fingerprint=//')"
    printf '  [%s]\n' "$idx"
    printf '    Subject     : %s\n' "$subject"
    printf '    Issuer      : %s\n' "$issuer"
    printf '    Not Before  : %s\n' "$not_before"
    printf '    Not After   : %s\n' "$not_after"
    printf '    SHA256      : %s\n' "$fingerprint"
    if [ -n "$san" ]; then
      printf '    SAN         : %s\n' "$san"
    fi
  done
  printf '\n'
}

save_current_config() {
  log "Salvo configurazione corrente dell'identity source"
  if ! "$SSO_CONFIG_BIN" -t "$TENANT" -get_identity_sources > "$CONFIG_BEFORE_FILE" 2>&1; then
    fail "Impossibile leggere la configurazione corrente con sso-config.sh -get_identity_sources"
  fi
}

save_after_config() {
  log "Salvo configurazione finale dell'identity source"
  "$SSO_CONFIG_BIN" -t "$TENANT" -get_identity_sources > "$CONFIG_AFTER_FILE" 2>&1 || true
}

print_header() {
  cat <<EOFHDR

============================================================
${SCRIPT_NAME}
Directory di lavoro: ${RUN_DIR}
Tenant SSO         : ${TENANT}
Identity Source    : ${IDENTITY_SOURCE_NAME}
Dominio            : ${DOMAIN_NAME}
Alias              : ${DOMAIN_ALIAS}
============================================================
EOFHDR
}

build_add_cmd() {
  local ssl_cert_arg
  ssl_cert_arg="$PRIMARY_CHAIN_FILE"
  if [ -n "$SECONDARY_LDAPS_URL" ]; then
    ssl_cert_arg="$PRIMARY_CHAIN_FILE,$SECONDARY_CHAIN_FILE"
  fi

  ADD_CMD=(
    "$SSO_CONFIG_BIN"
    -t "$TENANT"
    -add_identity_source
    -type adldap
    -baseUserDN "$BASE_USER_DN"
    -baseGroupDN "$BASE_GROUP_DN"
    -domain "$DOMAIN_NAME"
    -alias "$DOMAIN_ALIAS"
    -username "$BIND_USERNAME"
    -password "$BIND_PASSWORD"
    -primaryURL "$PRIMARY_LDAPS_URL"
  )

  if [ -n "$SECONDARY_LDAPS_URL" ]; then
    ADD_CMD+=( -secondaryURL "$SECONDARY_LDAPS_URL" )
  fi

  ADD_CMD+=(
    -useSSL true
    -sslCert "$ssl_cert_arg"
  )
}

show_recap() {
  printf '\n'
  printf 'Recap certificati raccolti:\n\n'
  cat "$SUMMARY_FILE"
  printf 'File salvati in: %s\n' "$RUN_DIR"
  printf 'Configurazione corrente salvata in: %s\n' "$CONFIG_BEFORE_FILE"
  printf '\n'
}

confirm_or_abort() {
  local prompt="$1"
  local answer
  read -r -p "$prompt [yes/NO]: " answer
  case "$answer" in
    yes|YES|y|Y) return 0 ;;
    *)
      log "Operazione annullata dall'utente"
      printf 'Nessuna modifica applicata. I file raccolti restano in %s\n' "$RUN_DIR"
      exit 0
      ;;
  esac
}

run_delete() {
  log "Elimino l'identity source corrente: ${IDENTITY_SOURCE_NAME}"
  if ! "$SSO_CONFIG_BIN" -t "$TENANT" -delete_identity_source -i "$IDENTITY_SOURCE_NAME"; then
    fail "Cancellazione dell'identity source fallita. Nessun add eseguito."
  fi
}

run_add() {
  log "Ricreo l'identity source LDAPS con i certificati live appena raccolti"
  if ! "${ADD_CMD[@]}"; then
    fail "Creazione del nuovo identity source fallita. Verificare file in ${RUN_DIR} e ricreare manualmente se necessario."
  fi
}

main() {
  require_root
  require_cmd openssl
  require_cmd sed
  require_cmd awk
  validate_vars
  init_run_dir
  print_header

  log "Inizio raccolta stato"
  save_current_config

  : > "$SUMMARY_FILE"
  fetch_chain "$PRIMARY_LDAPS_URL" "$PRIMARY_RAW_FILE" "$PRIMARY_CHAIN_FILE" "$PRIMARY_CERT_DIR"

  if [ -n "$SECONDARY_LDAPS_URL" ]; then
    fetch_chain "$SECONDARY_LDAPS_URL" "$SECONDARY_RAW_FILE" "$SECONDARY_CHAIN_FILE" "$SECONDARY_CERT_DIR"
  fi

  show_recap

  printf "%s\n\n" "Prima di procedere: Broadcom raccomanda uno snapshot del VCSA prima di rimuovere/ricreare l'identity source LDAPS."

  confirm_or_abort "Confermi che vuoi proseguire fino alla richiesta password del bind user?"

  read -r -s -p "Inserisci la password del bind user LDAP (non verrà salvata): " BIND_PASSWORD
  printf '\n'
  [ -n "$BIND_PASSWORD" ] || fail "Password del bind user vuota"

  build_add_cmd

  confirm_or_abort "ATTENZIONE: verrà cancellato l'identity source '${IDENTITY_SOURCE_NAME}' e subito ricreato. Continuare?"

  run_delete
  run_add
  unset BIND_PASSWORD

  save_after_config

  printf '\nOperazione completata.\n'
  printf 'Directory di lavoro : %s\n' "$RUN_DIR"
  printf 'Config prima        : %s\n' "$CONFIG_BEFORE_FILE"
  printf 'Config dopo         : %s\n' "$CONFIG_AFTER_FILE"
  printf 'Recap certificati   : %s\n' "$SUMMARY_FILE"
  printf '\n'
  log "Operazione completata con successo"
}

main "$@"
