#!/bin/sh
# Checks a running pqwrap from the outside with openssl (3.5 or newer).
#
#   ./check.sh [host:port] [ca-file] [server-name]
TARGET=${1:-localhost:443}
CA=${2:-}
NAME=${3:-${TARGET%:*}}

try() {
    printf "%-40s " "$1"
    shift
    out=$(timeout 5 openssl s_client -connect "$TARGET" -servername "$NAME" \
        ${CA:+-CAfile "$CA"} "$@" </dev/null 2>&1)
    group=$(echo "$out" | grep -o "Negotiated TLS1.3 group: [A-Za-z0-9]*" | cut -d' ' -f4)
    if [ -n "$group" ] && [ "$group" != "<NULL>" ]; then
        echo "accepted ($group)"
    else
        echo "rejected"
    fi
}

try "X25519MLKEM768"                   -groups X25519MLKEM768
try "SecP256r1MLKEM768"                -groups SecP256r1MLKEM768
try "SecP384r1MLKEM1024"               -groups SecP384r1MLKEM1024
try "MLKEM1024"                        -groups MLKEM1024
try "X25519"                           -groups X25519
try "P-256"                            -groups P-256
try "TLS 1.2"                          -tls1_2
try "X25519 first, hybrid second (HRR)" -groups X25519:X25519MLKEM768
