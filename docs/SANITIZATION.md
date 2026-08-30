# Sanitization ruleset (private → public)

This project maintains two repos:

- **Private** (`secdoc/soc-pipeline`): explicit internal designs, real IPs/hostnames/IDs, working configs against the live environment.
- **Public** (`secdoc/soc-pipeline-public`): the same transferable implementation patterns, sanitized so anyone can adapt them. No real environment facts, ever.

## The rule

Nothing in the public repo may contain a real environment fact. Treat any accidental leak as a **rotation event** (rotate the exposed credential), not merely a git-history rewrite.

## Placeholder conventions (use these in the public repo)

| Real thing | Public placeholder |
|------------|--------------------|
| Scanner host IP | `<SCANNER_HOST>` |
| Graylog host IP | `<GRAYLOG_HOST>` |
| Wazuh manager IP | `<WAZUH_HOST>` |
| GMP username | `<GMP_USER>` |
| GMP password | `<GMP_PASS>` (from env, never literal) |
| Example networks | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` (RFC5737 TEST-NET) |
| Example domain | `example.local` / `example.com` |
| Real hostnames | generic role names (`scanner-01`, `fw-01`) |
| Real CVE/scan output | synthetic samples in `samples/` clearly labelled SYNTHETIC |

## Forbidden in public (enforced by scrub-check)

- `secdoc.home`, any `192.168.x.x` / `10.13.37.x` real address
- Real hostnames (VOID-EFG, the graylog hostname, etc.)
- Any credential, token, or key fragment
- Internal zone/lab names (ESSEXLAB, pvecluster)
- Named crown-jewel assets or their addresses

## The gate

Before **every** public commit:

```bash
python3 scripts/scrub_check.py .
```

Exit 0 = safe to publish. Non-zero = it found a leak; fix it first. Extend the
`FORBIDDEN` list in `scripts/scrub_check.py` as the estate grows.

## Workflow

1. Build and validate in the **private** repo against the live environment.
2. Copy the artifact to the public repo, replacing every real value with a placeholder from the table above.
3. Run `scrub_check.py` — it must pass.
4. Commit public.

The scrub-check is a safety net, not a substitute for care. It catches known patterns; a human still reviews the diff.

## Issues, milestones, and the public Project board

The same rule extends beyond files. **GitHub Issues, milestone descriptions, and Project board cards are public surface too.**

- **Private-repo issues** (`secdoc/soc-pipeline`): may reference real environment specifics as needed for the internal build.
- **Public-repo issues** (`secdoc/soc-pipeline-public`) and **the public Project board**: generic only. No real IPs/hostnames/domains/credentials. Use the placeholder conventions above. Describe work in adopter-facing, environment-neutral terms.
- **Cross-repo board caution:** the public Project board can pull in issues from *both* repos. A private-repo issue added to a public board exposes its title/body. Keep private-repo issues off the public board, or ensure any cross-referenced item is itself sanitized.

Rule of thumb: if an issue names something only your environment has, it belongs in the private repo and stays off the public board.
