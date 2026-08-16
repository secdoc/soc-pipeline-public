#!/usr/bin/env python3
"""Scrub-check gate: scan a directory tree for environment-specific facts that
must NEVER appear in the PUBLIC repo. Exit non-zero if any are found.

Run before every public commit:  python3 scripts/scrub_check.py <dir>
Default dir = current directory.
"""
import sys, os, re

# Patterns that indicate real environment leakage. Extend as the estate grows.
FORBIDDEN = [
    (r"\bsecdoc\.home\b",                     "internal domain secdoc.home"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b",       "real RFC1918 192.168.x.x address"),
    (r"\b10\.13\.37\.\d{1,3}\b",              "ESSEXLAB 10.13.37.x address"),
    (r"\bVOID-EFG\b",                          "real gateway hostname"),
    (r"graylog-debian13-lab-kvm-svr",          "real graylog hostname"),
    (r"hermes-agent@pam",                      "real Proxmox token id"),
    (r"\bpvecluster\b",                        "real Proxmox cluster name"),
    (r"ESSEXLAB",                              "internal lab/zone name"),
    (r"\bwskWEw|v7thuqf|eyJhbGciOiJSUzI1",     "credential/token fragment"),
    (r"\bGVM_PASS\s*=\s*\S+",                  "hardcoded GMP password"),
    (r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*_\-]{8,}", "possible hardcoded secret value"),
]
# Values that ARE allowed (documentation placeholders / example ranges)
ALLOW = [
    r"192\.0\.2\.",   # TEST-NET-1 (RFC5737) example
    r"198\.51\.100\.",
    r"203\.0\.113\.",
    r"<[A-Z_]+>",     # <SCANNER_HOST> style placeholders
    r"example\.(com|org|net|local)",
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
# Files that legitimately CONTAIN the forbidden patterns because they DEFINE them
# (the scrubber's own ruleset and the sanitization guide). Excluded from scanning.
SKIP_FILES = {"scrub_check.py", "SANITIZATION.md"}

def allowed(line):
    return any(re.search(a, line) for a in ALLOW)

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    hits = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            if fn in SKIP_FILES:
                continue
            p = os.path.join(dp, fn)
            try:
                with open(p, encoding="utf-8", errors="ignore") as f:
                    for n, line in enumerate(f, 1):
                        for pat, desc in FORBIDDEN:
                            if re.search(pat, line):
                                # allow example ranges / placeholders on the same line
                                if pat.startswith(r"\b192\.168") and allowed(line):
                                    continue
                                hits.append((p, n, desc, line.strip()[:100]))
            except Exception:
                continue
    if hits:
        print(f"SCRUB-CHECK FAILED: {len(hits)} environment leak(s) found\n")
        for p, n, desc, txt in hits:
            print(f"  {p}:{n}  [{desc}]\n      {txt}")
        print("\nRemove or replace with placeholders before publishing. See docs/SANITIZATION.md")
        sys.exit(1)
    print("SCRUB-CHECK PASSED: no environment-specific facts found. Safe to publish.")
    sys.exit(0)

if __name__ == "__main__":
    main()
