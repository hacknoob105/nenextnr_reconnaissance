# NextNR (Recon Tool)

NextNR is a simple Python tool made for recon and bug bounty hunting.  
It collects useful information about a target in one place so you don’t need to run many tools separately.

---

## Features
- Checks common paths (like `/admin`, `/login`, etc.) with status code and length  
- Detects important **security headers** (CSP, HSTS, X-Frame-Options, etc.)  
- Finds and analyzes **JavaScript assets**  
  - Extracts hidden endpoints & API paths  
  - Tries to download `.map` files if available  
- Detects **GraphQL endpoints** (with `--graphql` flag)  
- Saves everything into **one report file**  

---

# Usage
```bash
python3 nextnr.py <target_url> [--graphql]
