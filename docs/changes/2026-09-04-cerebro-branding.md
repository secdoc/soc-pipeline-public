# 2026-09-04 Cerebro Branding

Status: Implemented in the public reference  
Change type: Product naming and visual identity

## Change

The centralized read-only security visibility component is named Cerebro. The dashboard uses a local 512 by 512 transparent reconstruction of the supplied Secdoc dot-matrix mark and the exact visual tokens extracted from secdoc.tech.

The runtime PNG SHA-256 is `97475375dead46f9eb3b40091e517a465199059cdecd189bfd3253eb5ee7cbd5`. Its reproducible source is `security_portal/static/assets/secdoc-logo-source.svg`.

The public asset is a reconstruction because the original attachment bytes were not available to the build process. It is not represented as a byte-identical copy.

## Security boundary

The logo is served locally under the existing CSP. No external font, script, image, or branding request is made at runtime. Connector behavior, source permissions, and the GET-only API remain unchanged.

## Verification

The public test suite verifies the Cerebro name, local logo route, PNG signature, fixed logo hash, and exact brand CSS variables. The repository scrub gate remains mandatory.
