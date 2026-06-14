# Open-Source Notes

This directory was prepared from `<COHERE_REPO>` as a small source-only Git repository.

## Review Before Publishing

- Choose and add a project license in `LICENSE`.
- Review `guest_victim_rsa.c`: it contains an embedded RSA private key that appears to be an experiment fixture. Prefer runtime key generation or a clearly documented demo-only key.
- Review all scripts for hard-coded local paths such as `<COHERE_REPO>`.
- Decide whether `require/`, `report/`, and `latex/` should be public or kept in a separate documentation repository.
- Add exact external dependency versions or commit hashes for AMDSEV, SEV-Step, OpenSSL, and libgcrypt.
- Add a reproducible setup section once the public dependency paths are finalized.

## Excluded From This Repository

- `result/`
- `src/build/`
- `src/third_party/`
- `AMDSEV/`
- `sev-step/`
- `.venv_test_pandas/`
- `chat.json`
- `chat.txt`
- PDF papers
