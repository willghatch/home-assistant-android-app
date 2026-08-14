#!/usr/bin/env bash
#
# Fork-local helper: install the CA certificate for your own Home Assistant
# server. The build fails until this has been run.
#
# Usage:
#   ./set-real-hass-cert.sh path/to/fullchain.pem [ha.mydomain.lan|192.168.1.10 ...]
#
# The input is a PEM bundle such as the fullchain.pem Home Assistant serves
# (server certificate followed by its CA), or a CA certificate alone (PEM or
# DER). The bundle's CA certificate, preferably its self-signed root, becomes
# the trust anchor and is copied into both res/raw locations (:app, which
# :automotive shares, and :wear). Nothing else from the input is copied. Both
# network_security_config.xml files are generated from
# private-ca/network_security_config.xml.template, trusting the anchor for the
# hostnames and IPv4 addresses given as arguments or, without any, for the DNS
# and IP subjectAltName entries of the server certificates in the bundle (of the
# CA itself when there are none). For an IP address to pass TLS checks, the
# server certificate must list it as an IP (not DNS) subjectAltName entry.  None
# of these files are tracked by git. A rebase onto upstream deletes the
# generated configs, so rerun this afterwards.

set -euo pipefail

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CERT_TARGETS=(
    "app/src/main/res/raw/homelab_ca.pem"
    "wear/src/main/res/raw/homelab_ca.pem"
)
readonly CONFIG_TARGETS=(
    "app/src/main/res/xml/network_security_config.xml"
    "wear/src/main/res/xml/network_security_config.xml"
)
readonly CONFIG_TEMPLATE="private-ca/network_security_config.xml.template"
readonly DOMAINS_MARKER="@DOMAIN_ELEMENTS@"
readonly HOSTNAME_PATTERN='^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
readonly IPV4_PATTERN='^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
readonly PEM_BEGIN="-----BEGIN CERTIFICATE-----"
readonly PEM_END="-----END CERTIFICATE-----"
readonly USAGE_LAST_LINE=21

die() {
    echo "error: $*" >&2
    exit 1
}

usage() {
    sed -n "3,${USAGE_LAST_LINE}p" "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

# Succeed if $1 is a dotted-quad IPv4 address with every octet in 0-255.
is_ipv4() {
    local octet
    [[ "$1" =~ $IPV4_PATTERN ]] || return 1
    for octet in ${1//./ }; do
        ((10#$octet <= 255)) || return 1
    done
}

# Succeed if $1 can be used as a <domain> value: a hostname or an IPv4 address.
# IPv6 is not accepted: the config matches the host string literally, and the
# many spellings of one IPv6 address make that match unreliable.
is_trustable_name() {
    is_ipv4 "$1" || { [[ "$1" != *:* ]] && [[ "$1" =~ $HOSTNAME_PATTERN ]] && ! [[ "$1" =~ ^[0-9.]+$ ]]; }
}

# Append every certificate in file $1 to CERTS, normalized to PEM. A PEM file
# may hold several certificates among other blocks (a private key, say), which
# are ignored; a file without any PEM certificate is read as one DER certificate.
load_certs() {
    local line block="" in_block=false pem
    if ! grep -qF -- "$PEM_BEGIN" "$1"; then
        pem="$(openssl x509 -in "$1" -inform der -outform pem 2>/dev/null)" \
            || die "$1 is not a readable X.509 certificate (PEM or DER)"
        echo "note: input was DER, converting to PEM"
        CERTS+=("$pem")
        return
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        if [[ "$line" == "$PEM_BEGIN" ]]; then
            in_block=true
            block=""
        fi
        "$in_block" && block+="$line"$'\n'
        if "$in_block" && [[ "$line" == "$PEM_END" ]]; then
            in_block=false
            pem="$(openssl x509 -outform pem <<<"$block" 2>/dev/null)" \
                || die "$1 contains a certificate that does not parse"
            CERTS+=("$pem")
        fi
    done <"$1"
}

# Succeed if PEM certificate $1 has basicConstraints CA:TRUE.
is_ca() {
    openssl x509 -noout -ext basicConstraints <<<"$1" 2>/dev/null | grep -q 'CA:TRUE'
}

# Succeed if PEM certificate $1 names itself as its issuer.
is_self_signed() {
    local subject issuer
    subject="$(openssl x509 -noout -subject -nameopt RFC2253 <<<"$1")"
    issuer="$(openssl x509 -noout -issuer -nameopt RFC2253 <<<"$1")"
    [[ "${subject#subject=}" == "${issuer#issuer=}" ]]
}

# Print the subject of PEM certificate $1.
cert_subject() {
    openssl x509 -noout -subject <<<"$1" | sed 's/^subject= *//'
}

# Warn if PEM certificate $2, described by $1, has already expired.
warn_if_expired() {
    if ! openssl x509 -noout -checkend 0 <<<"$2" >/dev/null 2>&1; then
        echo "warning: the $1 is already expired ($(openssl x509 -noout -enddate <<<"$2" | sed 's/^notAfter=//'))" >&2
    fi
}

# Print the index in CA_CERTS of the trust anchor: the last self-signed CA, as
# a chain lists its root last, or else the last CA.
anchor_index() {
    local i
    for ((i = ${#CA_CERTS[@]} - 1; i >= 0; i--)); do
        if is_self_signed "${CA_CERTS[i]}"; then
            echo "$i"
            return
        fi
    done
    echo "$((${#CA_CERTS[@]} - 1))"
}

# Fail unless server certificate $1 chains up to ANCHOR, possibly through the
# bundle's other CA certificates. Validity dates are warned about separately.
verify_server_cert() {
    local output untrusted=()
    printf '%s\n' "$1" >"$WORK_DIR/server.pem"
    [[ -s "$WORK_DIR/intermediates.pem" ]] && untrusted=(-untrusted "$WORK_DIR/intermediates.pem")
    if ! output="$(openssl verify -partial_chain -no_check_time -CAfile "$WORK_DIR/anchor.pem" \
        "${untrusted[@]}" "$WORK_DIR/server.pem" 2>&1)"; then
        die "the server certificate '$(cert_subject "$1")' is not issued by the anchor '$(cert_subject "$ANCHOR")':"$'\n'"$output"
    fi
}

# Print the subjectAltName entries of PEM certificate $1 usable as <domain>
# values, one per line. A wildcard "*.example.lan" becomes "example.lan", which
# the includeSubdomains attribute already covers. An IP address stored as a DNS
# entry is skipped with a warning, because hostname verification ignores it.
cert_names() {
    local entry name
    openssl x509 -noout -ext subjectAltName <<<"$1" 2>/dev/null \
        | tail -n +2 | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | while IFS= read -r entry; do
            case "$entry" in
                DNS:*)
                    name="${entry#DNS:}"
                    name="${name#\*.}"
                    if is_ipv4 "$name" || [[ "$name" == *:* ]]; then
                        echo "warning: skipping DNS:$name from subjectAltName; re-issue it as IP:$name for IP connections to pass TLS checks" >&2
                        continue
                    fi
                    ;;
                "IP Address:"*)
                    name="${entry#IP Address:}"
                    ;;
                *)
                    continue
                    ;;
            esac
            if is_trustable_name "$name"; then
                echo "$name"
            else
                echo "warning: skipping '$name' from subjectAltName; only hostnames and IPv4 addresses are supported" >&2
            fi
        done
}

# Print the <domain> element for one hostname or IPv4 address. Subdomains only
# make sense for hostnames.
domain_element() {
    local include_subdomains="true"
    is_ipv4 "$1" && include_subdomains="false"
    printf '<domain includeSubdomains="%s">%s</domain>\n' "$include_subdomains" "$1"
}

# Print the config template with its marker line replaced by one <domain>
# element per argument, indented like the marker.
render_config() {
    local name elements=""
    for name in "$@"; do
        elements+="$(domain_element "$name")"$'\n'
    done
    ELEMENTS="$elements" awk -v marker="$DOMAINS_MARKER" '
        index($0, marker) {
            match($0, /^[ \t]*/)
            indent = substr($0, 1, RLENGTH)
            count = split(ENVIRON["ELEMENTS"], lines, "\n")
            for (i = 1; i <= count; i++) if (lines[i] != "") print indent lines[i]
            next
        }
        { print }
    ' "$REPO_ROOT/$CONFIG_TEMPLATE"
}

[[ $# -ge 1 ]] || usage
case "$1" in
    -h|--help) usage ;;
esac

readonly SOURCE_CERT="$1"
shift
readonly NAME_OVERRIDES=("$@")

[[ -f "$SOURCE_CERT" ]] || die "no such file: $SOURCE_CERT"

command -v openssl >/dev/null 2>&1 || die "openssl is required to validate the certificate"

WORK_DIR="$(mktemp -d)"
readonly WORK_DIR
trap 'rm -rf -- "$WORK_DIR"' EXIT

CERTS=()
load_certs "$SOURCE_CERT"
readonly CERTS

CA_CERTS=()
SERVER_CERTS=()
for cert in "${CERTS[@]}"; do
    if is_ca "$cert"; then
        CA_CERTS+=("$cert")
    else
        SERVER_CERTS+=("$cert")
    fi
done
readonly CA_CERTS SERVER_CERTS

# Android builds a chain to the anchor, so a server (leaf) certificate alone will not do.
[[ ${#CA_CERTS[@]} -gt 0 ]] \
    || die "$SOURCE_CERT has no certificate with basicConstraints CA:TRUE; pass the full chain including the CA, or the CA certificate itself, not only the server certificate"

ANCHOR_INDEX="$(anchor_index)"
readonly ANCHOR="${CA_CERTS[ANCHOR_INDEX]}"
printf '%s\n' "$ANCHOR" >"$WORK_DIR/anchor.pem"
for i in "${!CA_CERTS[@]}"; do
    [[ "$i" -eq "$ANCHOR_INDEX" ]] || printf '%s\n' "${CA_CERTS[i]}"
done >"$WORK_DIR/intermediates.pem"

warn_if_expired "anchor" "$ANCHOR"
for cert in "${SERVER_CERTS[@]}"; do
    verify_server_cert "$cert"
    warn_if_expired "server certificate '$(cert_subject "$cert")'" "$cert"
done

if [[ ${#NAME_OVERRIDES[@]} -gt 0 ]]; then
    for name in "${NAME_OVERRIDES[@]}"; do
        is_trustable_name "$name" || die "'$name' is neither a hostname nor an IPv4 address"
    done
    mapfile -t DOMAINS < <(printf '%s\n' "${NAME_OVERRIDES[@]}" | sort -u)
elif [[ ${#SERVER_CERTS[@]} -gt 0 ]]; then
    mapfile -t DOMAINS < <(for cert in "${SERVER_CERTS[@]}"; do cert_names "$cert"; done | sort -u)
    [[ ${#DOMAINS[@]} -gt 0 ]] \
        || die "the server certificate in $SOURCE_CERT has no usable names in subjectAltName; pass the hostnames and IP addresses as arguments"
else
    mapfile -t DOMAINS < <(cert_names "$ANCHOR" | sort -u)
    [[ ${#DOMAINS[@]} -gt 0 ]] \
        || die "$SOURCE_CERT is a CA certificate without names in subjectAltName; pass the full chain including the server certificate, or the hostnames and IP addresses as arguments"
fi
readonly DOMAINS

# Check everything before writing anything, so a failure leaves no partial update.
[[ -f "$REPO_ROOT/$CONFIG_TEMPLATE" ]] || die "missing $CONFIG_TEMPLATE; run this from the repository checkout"
[[ "$(grep -cF "$DOMAINS_MARKER" "$REPO_ROOT/$CONFIG_TEMPLATE")" -eq 1 ]] \
    || die "$CONFIG_TEMPLATE must contain $DOMAINS_MARKER exactly once"
for target in "${CERT_TARGETS[@]}" "${CONFIG_TARGETS[@]}"; do
    # The res/raw or res/xml directory itself may be missing: upstream has no raw resources in
    # :app, and git removes a directory once its only file is gone (after a rebase, for example).
    res_dir="$(dirname -- "$(dirname -- "$REPO_ROOT/$target")")"
    [[ -d "$res_dir" ]] || die "missing directory for $target; run this from the repository checkout"
done

for target in "${CERT_TARGETS[@]}"; do
    mkdir -p -- "$(dirname -- "$REPO_ROOT/$target")"
    printf '%s\n' "$ANCHOR" >"$REPO_ROOT/$target"
    echo "wrote $target"
done

for target in "${CONFIG_TARGETS[@]}"; do
    mkdir -p -- "$(dirname -- "$REPO_ROOT/$target")"
    render_config "${DOMAINS[@]}" >"$REPO_ROOT/$target"
    echo "generated $target for ${DOMAINS[*]}"
done

echo
echo "Anchor subject: $(cert_subject "$ANCHOR")"
for cert in "${SERVER_CERTS[@]}"; do
    echo "Server cert:    $(cert_subject "$cert")"
done
echo "Trusted for:    ${DOMAINS[*]} (hostnames include subdomains)"
echo "Expires:        $(openssl x509 -noout -enddate <<<"$ANCHOR" | sed 's/^notAfter=//')"
echo "Next: ./gradlew assembleDebug"
