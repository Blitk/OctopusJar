# OctopusJar

A cautious, open-source CLI foundation for security checks against REST APIs you are authorized to assess.

## Current scope

This initial foundation implements URL scope validation against an explicit allowlist. It does **not**
send HTTP requests or perform security checks yet.

## Install for development

Requires Python 3.12 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest
ruff check .
```

## Scope policy

Allowlist entries are origins, for example:

- `https://api.example.test`
- `http://127.0.0.1:8000`

A target is permitted only when its normalized scheme, hostname, and effective port match an
explicit entry. Subdomains are not implicitly included. URL credentials, malformed URLs, unsupported
schemes, and URLs without a hostname are rejected.

The allowlist is a policy check, not a complete network security boundary. Before HTTP requests are
implemented, each redirect hop and each resolved destination will need additional validation to reduce
redirect-based scope escapes, DNS rebinding, and access to prohibited IP ranges.
