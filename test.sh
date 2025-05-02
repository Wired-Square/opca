#!/bin/bash

generate_random_string() {
    local length="$1"
    local charset="abcdefghijklmnopqrstuvwxyz0123456789"
    local generated=""
    for (( i=0; i<$length; i++ )); do
        local rand_char=${charset:RANDOM % ${#charset}:1}
        generated="$generated$rand_char"
    done
    echo "$generated"
}


run_test() {
TEST=$((TEST+1))

echo -e "[ $HEADER ${COLOUR_WHITE_B}$TEST${COLOUR_RESET} - Test ] $@"

output=$("$OPCA_BIN" -a "$ACCOUNT" -v "$VAULT" "$@" 2>&1)
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo -e "[ $HEADER ${COLOUR_WHITE_B}$TEST${COLOUR_RESET} - Result ] ${COLOUR_GREEN}Success${COLOUR_RESET}"
    SUCCEEDED=$((SUCCEEDED+1))
    echo "----------------"
else
    echo -e "[ $HEADER ${COLOUR_WHITE_B}$TEST${COLOUR_RESET} - Result ] ${COLOUR_RED}Failed${COLOUR_RESET} with exit code [ $exit_code ]"
    FAILED=$((FAILED+1))
    echo "----------------"
    echo "$output"
    echo "----------------"

fi
}


COLOUR_RESET="\033[0m"
COLOUR_RED="\033[31m"
COLOUR_GREEN="\033[32m"
COLOUR_WHITE_B="\033[1;37m"

HEADER="OPCA-TEST"
FAILED=0
SUCCEEDED=0
TEST=0
OPCA_BIN="./opca.py"
VAULT="opca-$(generate_random_string 5)"
VAULT_ICON="wrench"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -a|--account)
          ACCOUNT="$2"
          shift
          ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

echo "Vault: $VAULT"

if [[ -z "$ACCOUNT" ]]; then
    op signin
else
    echo "Account: $ACCOUNT"
    op signin --account "$ACCOUNT"
fi

op vault create "$VAULT" --icon "$VAULT_ICON"

if [ $? -ne 0 ]; then
  echo "Unable to sign in to 1Password"
  exit 1
fi

# Test to create a new CA and then create some certificates
run_test ca init -e "no1@home.com" \
                 -o "Test Organisation" \
                 -n "Test Certificate Authority" \
                 --ou "Web Services" \
                 --city "Canberra" \
                 --state "ACT" \
                 --country "AU" \
                 --ca-days 3650 \
                 --crl-days 45 \
                 --days 365 \
                 --ca-url "https://ca.home.com/ca.crt" \
                 --crl-url "https://ca.home.com/crl.pem"

run_test cert create -t vpnserver -n vpnserver-cert
run_test cert create -t vpnclient -n vpnclient-cert
run_test cert create -t webserver -n webserver-cert --alt www.webserver.com
run_test cert create -t webserver -n mailserver-cert --alt mail.webserver.com
run_test cert renew -n mailserver-cert
run_test cert revoke -n webserver-cert
run_test cert revoke -s 5

# OpenVPN Tests
run_test openvpn gen-sample-vpn-server
run_test openvpn gen-dh
run_test openvpn gen-ta-key
run_test openvpn gen-vpn-profile -t sample -n vpnclient-cert
run_test cert revoke -n vpnclient-cert
run_test cert create -t vpnclient -n vpnclient-cert
run_test openvpn gen-vpn-profile -t sample -n vpnclient-cert

echo "We ran $TEST tests"
echo "Succeeded: $SUCCEEDED"
echo "Failed: $FAILED"
