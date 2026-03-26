# JWTee

<img width="989" height="652" alt="image" src="https://github.com/user-attachments/assets/84a89b2d-4b24-4256-96b7-849b30ed2190" />

JWT Security Toolkit for bug bounty hunting and CTF challenges.
Decode any JWT, sign custom tokens, embed files inside JWTs, and run a full suite of known JWT attacks — all from the command line with zero dependencies.

Made by **Alham Rizvi**

## What it does

- Decode any JWT token without needing the secret
- Encode and sign tokens with HS256 / HS384 / HS512 / none
- Embed any file (binary, text, image, zip) into a JWT and recover it
- Verify HMAC signatures including empty-string secrets
- Run attacks: none-alg bypass, algorithm confusion, secret brute-force, kid injection, JWK injection, claim tampering
- Print a bug bounty / CTF checklist for any token


## Install

No dependencies. Requires Python 3.7+.

```bash
git clone https://github.com/alhamrizvi-cloud/JWTee
cd JWTee
python3 JWTee.py --help
```

---

## Global Install — use `jwtee` from anywhere

After cloning, one command makes `jwtee` available system-wide in any terminal, any directory.

### Linux / macOS

```bash
git clone https://github.com/alhamrizvi-cloud/JWTee
cd JWTee
chmod +x JWTee.py
sudo cp JWTee.py /usr/local/bin/jwtee
```

Done. Now use it from anywhere:

```bash
jwtee --help
jwtee decode eyJhbGci...
jwtee checklist eyJhbGci...
```

To uninstall:

```bash
sudo rm /usr/local/bin/jwtee
```

---

### Windows

Open **PowerShell as Administrator**:

```powershell
# 1. Clone the repo
git clone https://github.com/alhamrizvi-cloud/JWTee
cd JWTee

# 2. Create a tools folder
New-Item -ItemType Directory -Force -Path C:\tools

# 3. Copy the script there
Copy-Item JWTee.py C:\tools\jwtee.py

# 4. Create a wrapper batch file so 'jwtee' works in cmd and PowerShell
Set-Content C:\tools\jwtee.bat '@python "C:\tools\jwtee.py" %*'

# 5. Add C:\tools to system PATH permanently
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\tools",
    "Machine"
)
```

Restart your terminal, then:

```cmd
jwtee --help
jwtee decode eyJhbGci...
```

---

### Shell alias — no sudo required

If you prefer not to copy files, add an alias to your shell config:

```bash
# Bash (~/.bashrc)
echo 'alias jwtee="python3 ~/JWTee/JWTee.py"' >> ~/.bashrc && source ~/.bashrc

# Zsh (~/.zshrc)
echo 'alias jwtee="python3 ~/JWTee/JWTee.py"' >> ~/.zshrc && source ~/.zshrc

# Fish
echo 'alias jwtee="python3 ~/JWTee/JWTee.py"' >> ~/.config/fish/config.fish
```

Replace `~/JWTee/JWTee.py` with the actual path where you cloned the repo.

---

## Usage

### Decode a JWT

```bash
jwtee decode <token>

# Verify HMAC signature at the same time
jwtee decode <token> --verify --secret "mysecret"
```

Highlights expired tokens, sensitive claims (password, key, apikey), and privilege-relevant fields (role, admin, scope).

---

### Encode / Sign a JWT

```bash
# HS256 with secret
jwtee encode '{"sub":"admin","role":"admin"}' --secret "mysecret"

# HS512
jwtee encode '{"sub":"admin"}' --secret "mysecret" --alg HS512

# No signature (none algorithm)
jwtee encode '{"sub":"admin"}' --alg none

# Custom header fields (kid, x5t, etc.)
jwtee encode '{"sub":"admin"}' --secret "s" --header '{"kid":"key-1"}'
```

---

### Attacks

#### none Algorithm Bypass
```bash
jwtee attack --token <token> --type none
```
Generates all none-alg variants: `none`, `None`, `NONE`, `nOnE`.

#### Algorithm Confusion (RS256 -> HS256)
```bash
# Without public key — prints exploitation steps
jwtee attack --token <token> --type alg_confusion

# With RSA public key
jwtee attack --token <token> --type alg_confusion --pubkey pubkey.pem
```

#### Secret Brute-Force
```bash
# Dictionary attack (recommended — use rockyou.txt)
jwtee attack --token <token> --type brute --wordlist /usr/share/wordlists/rockyou.txt

# Raw brute-force (short secrets)
jwtee attack --token <token> --type brute --max-len 5

# Custom charset
jwtee attack --token <token> --type brute --charset "abcdef0123456789" --max-len 6
```

#### kid Header Injection
```bash
# Runs all SQL + path traversal payloads
jwtee attack --token <token> --type kid

# Custom kid payload
jwtee attack --token <token> --type kid --kid "' OR 1=1--"
```

All kid-injected tokens are signed with an empty string — exploits servers that look up the key by kid and return empty or null.

#### JWK Header Injection
```bash
jwtee attack --token <token> --type jwk
```

#### Claim Tampering
```bash
# Default tamper: set role=admin, admin=true, extend exp by 1 year
jwtee attack --token <token> --type tamper --secret "known_secret"

# Custom claims
jwtee attack --token <token> --type tamper --claims '{"role":"superadmin","uid":0}' --secret "known_secret"
```

#### Run All Attacks
```bash
jwtee attack --token <token> --type all
```

---

### Bug Bounty Checklist

```bash
jwtee checklist <token>
```

Decodes the token and prints a checklist of which attack surfaces apply based on the algorithm and claims present.

---

### File Embedding

Embed any file into a JWT — useful for CTF forensics challenges, exfiltration analysis, and covert transport scenarios.

#### Embed a file
```bash
jwtee encode-file flag.txt --secret "key" --alg HS256
jwtee encode-file shell.php --secret "key"
jwtee encode-file secret.json --alg none
jwtee encode-file exploit.py --secret "key" --output token.jwt
```

#### Recover a file from a JWT
```bash
jwtee decode-file @token.jwt --out ./recovered/
jwtee decode-file eyJhbGci... --out ./recovered/
jwtee decode-file @token.jwt --out ./recovered/ --verify --secret "key"
```

The recovered file is written to the output directory with its original filename. SHA-256 integrity is checked automatically.

---

## Attacks Reference

| Attack | What it tests |
|--------|---------------|
| `none` | Server accepts unsigned tokens (missing alg validation) |
| `alg_confusion` | Server uses header alg without checking expected type |
| `brute` | Weak or guessable HMAC secret |
| `kid` | SQL injection or path traversal via kid header field |
| `jwk` | Server trusts attacker-supplied key embedded in header |
| `tamper` | Server doesn't re-verify signature after claim change |
| `all` | All of the above + checklist |

---

## Examples

See `examples.sh` in this repo for a full runnable demo with live output.

Quick CTF workflow:

```bash
# 1. Inspect the token
jwtee decode eyJhbGci...

# 2. Check attack surface
jwtee checklist eyJhbGci...

# 3. Try none bypass
jwtee attack --token eyJhbGci... --type none

# 4. Crack the secret if HS256
jwtee attack --token eyJhbGci... --type brute --wordlist rockyou.txt

# 5. Tamper claims once you have the secret
jwtee attack --token eyJhbGci... --type tamper --secret "found_secret" --claims '{"role":"admin"}'
```

---

## License

MIT
