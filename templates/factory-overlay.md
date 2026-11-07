# Repository overlay

Copy to .github/factory-overlay.md. Read from the base SHA and shown to the
reviewer after the contract. State this repo's rules as plain, checkable claims.
A rule broken in the diff is a blocking `invariant` finding.

- Example: every database write goes through `db/client.py`.
- Example: personal data never appears in logs.
