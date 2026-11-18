# SOPS secrets

Optional secrets the app reads from a [SOPS](https://github.com/getsops/sops)-encrypted file instead of asking for them:

| Key | Used for |
|---|---|
| `flint.master_password` | **Auto-unlock** on startup (the systemd service no longer sits locked after a restart). |
| `split_vpns.<ref>.{username,password,totp_secret}` | Credentials for a Split VPN whose *SOPS reference* is `<ref>` (decrypted on every connect, never copied into `secrets.enc`). |

Template: [`secrets/flint.example.yaml`](../secrets/flint.example.yaml). Values left as `CHANGE_ME` count as unset.

## Files

- `.sops.yaml` — creation rule: `secrets/*.enc.yaml` encrypts to the owner's **age** public key.
- `secrets/flint.enc.yaml` — the encrypted file. **Gitignored** (this repo is public; an encrypted copy in git history would be permanent).
- Private key — standard SOPS location `~/.config/sops/age/keys.txt` (or `SOPS_AGE_KEY_FILE`). Never in the repo.
- Override the file path with `FLINT_SOPS_FILE` or `sops_secrets_file` in `config.json`.

## Editing

```bash
sops secrets/flint.enc.yaml      # decrypts into $EDITOR, re-encrypts on save
```

Changes are picked up automatically (the app re-reads the file when it changes; there's a 30 s cache otherwise). Auto-unlock only happens at startup — restart the service after adding the master password.

## How the app reads it

`backend/persistence/sops_store.py` runs `sops --decrypt --output-type json` (looking for `sops` on `PATH` and in `~/.local/bin`, since systemd services don't have it on `PATH`) and keeps the result in memory only. `routes/auth.auto_unlock_from_sops()` runs once in a background thread when the server starts. Errors (missing file, no key, placeholder values) are logged and the app simply stays locked / uses the other credential source.
