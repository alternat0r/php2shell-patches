# PHP CVE-2026-109618 / CVE-2026-109619 Patch Helper

A remediation script for the **critical unauthenticated RCE vulnerabilities in PHP core**
disclosed in the October 2026 PHP security release ("PHP2Shell"), exploited through
PHP's `session.upload_progress` handling.

This repository contains two scripts:

- **`patch-php-cve-2026-109618-109619.sh`** — patches the local Debian/Ubuntu host it runs on.
- **`check.php`** — verifies a patch from outside by reading the target's PHP version banner.

> **Scope & safety:** neither script exploits anything. The patch script changes only the
> **local host** it runs on. `check.php` makes a single ordinary HTTP request to a target and
> reads its version banner — no attack payload is ever sent. Run both only on hosts you own
> or are authorized to administer and test.

---

## The vulnerability

| | |
|---|---|
| **CVE** | CVE-2026-109618, CVE-2026-109619 |
| **Type** | Unauthenticated remote code execution (PHP core) |
| **Severity** | ~9.2 (CVSS 4.0) / 9.8 (CVSS 3.1) |
| **Root cause** | State corruption via PHP's bailout (`longjmp`-based) error unwinding — use-after-free / uninitialized memory |
| **Delivery path** | `session.upload_progress` (enabled by default) |
| **Affected** | PHP 5.4.0 up to the fixed releases below, **in default configuration** |
| **Disclosed** | 2026-10-21 (PHP out-of-band security release) |

### Fixed versions

| Branch | Fixed in |
|--------|----------|
| 8.5    | **8.5.12** |
| 8.4    | **8.4.27** |
| 8.3    | **8.3.36** |
| 8.2    | **8.2.35** |
| ≤ 8.1  | **No fix — end of life.** You must migrate to a supported branch. |

---

## What the script does

Runs these steps in order. It is idempotent and safe to re-run.

1. **Detect** the installed PHP version and branch.
2. **Assess** the version against the fixed release for its branch (warns if the branch is EOL).
3. **Mitigate** immediately — writes `session.upload_progress.enabled = Off` as a
   `99-cve-2026-109618-mitigation.ini` drop-in into **every** installed SAPI's `conf.d`
   (`cli`, `fpm`, `apache2`).
4. **Upgrade** the `php<branch>*` packages via `apt` — the complete fix. Details:
   - On an **end-of-life branch** (PHP ≤ 8.1, which has no patched build) it does **not**
     attempt an in-branch upgrade — that cannot make the host safe. It exits with migration
     guidance after applying the interim mitigation.
   - All apt calls use `-o DPkg::Lock::Timeout=60`, so the script **waits up to 60s** for a
     busy apt/dpkg lock (e.g. `unattended-upgrades`) instead of failing immediately.
   - Before upgrading it checks the apt *candidate* is already at or above the fixed version
     and **refuses to proceed** if your repositories are not yet serving the patched build
     (so it never pulls from an untrusted source just to appear successful).
5. **Restart** `php<branch>-fpm` / `apache2` / `nginx` if they are running.
6. **Verify** — confirms the running version now meets the fix, performs a
   **mitigation self-check** (that `session.upload_progress.enabled` reads `Off`), then prints
   a post-compromise checklist.

> **Note on the mitigation self-check:** it reads the value from the **CLI** SAPI. The web
> SAPI (FPM/Apache) loads the same drop-in, so this is a reliable proxy — but it is not proof
> the running web worker re-read its config. Confirm externally against the restarted site
> (see `check.php` below).

---

## Requirements

- Debian or Ubuntu (uses `apt-get` / `dpkg`).
- `root` privileges for applying changes (`sudo`). `--dry-run` works without root.
- The patched PHP build must be available from your configured repositories. On Ubuntu that
  is typically the **Ondřej Surý PPA** (`ppa:ondrej/php`); on Debian, the **Sury** repo
  (`packages.sury.org`). The script stops with guidance if the fixed version is not offered.

---

## Usage

```bash
chmod +x patch-php-cve-2026-109618-109619.sh

# 1. Preview every action without changing anything (no root needed):
sudo ./patch-php-cve-2026-109618-109619.sh --dry-run

# 2. Apply mitigation + upgrade + verify:
sudo ./patch-php-cve-2026-109618-109619.sh

# Apply only the interim mitigation (e.g. before a scheduled maintenance window):
sudo ./patch-php-cve-2026-109618-109619.sh --mitigate-only

# Help:
./patch-php-cve-2026-109618-109619.sh --help
```

### Options

| Flag | Effect |
|------|--------|
| `--dry-run` | Print the exact actions without executing them. Works without root. |
| `--mitigate-only` | Apply only step 3 (disable `session.upload_progress`); skip the package upgrade. |
| `-h`, `--help` | Show the header documentation. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Already patched, dry run completed, or patch applied and verified. |
| `1`  | Not fully patched — repo lacks the fixed build, branch is EOL, or verification failed. |
| `2`  | Unknown option. |

---

## Interim mitigation (what step 3 does, manually)

If you cannot run the script yet, you can close the confirmed attack path in seconds:

```ini
; in php.ini or a conf.d drop-in for the SAPI serving your site
session.upload_progress.enabled = Off
```

Then reload the web PHP process (`systemctl restart php8.5-fpm` / `apache2`).

> This blocks the **confirmed** exploitation path but is **not** the complete fix.
> Upgrading the PHP packages is the only full remediation.

---

## External verification — `check.php`

A companion script confirms the patch from the **outside**, the way a client sees the server.

```bash
php check.php <domain-or-URL> [--insecure] [--json]

php check.php ly.my
php check.php https://ly.my/ --json
```

It sends a **single ordinary HTTP request** and reads the PHP version from the
`X-Powered-By` / `Server` response header, then compares it to the fixed releases.

| Status | Meaning | Exit code |
|--------|---------|-----------|
| `PATCHED` | Advertised version ≥ the fixed release for its branch | `0` |
| `VULNERABLE` | Below the fixed release, or an EOL branch | `1` |
| `UNKNOWN` | No version exposed (banner hidden or stripped by a proxy/CDN) | `2` |
| *(error)* | Usage error or connection failure | `3` |

**It sends no exploit payload** — no `session.upload_progress` / attack traffic, nothing that
could crash or alter the target. It reads version banners only, so it verifies the *deployed
version* (which is what proves a patch landed) without attacking anything.

**Interpreting results:**
- `UNKNOWN` is common and usually **good** — it means the server hides its version
  (`expose_php = Off`, or a CDN/proxy strips the header). That is correct hardening, not a
  failure. Confirm on the host with `php -v`.
- A banner can be stale or spoofed. Treat `PATCHED` as "consistent with a completed patch"
  and `VULNERABLE` / `UNKNOWN` as "verify on the server." The server-side `php -v` from the
  patch script remains the authoritative source of truth.

> Run `check.php` only against hosts you own or are authorized to test.

## After patching: check for prior compromise

Mass exploitation has been reported in the wild. If your server ran a vulnerable,
default-configuration version while internet-exposed, **patching does not undo a breach that
may have already happened.** Review at minimum:

- Unexpected or recently-created files in web roots and in `session.save_path`
  (default `/var/lib/php/sessions`).
- Unknown cron jobs, `systemd` units, or startup items.
- Unexpected outbound network connections or listening ports.
- PHP files modified around or after your exposure window.

If you find evidence of compromise, treat the host as breached: isolate it, preserve
evidence, and rebuild from a known-good state rather than relying on the patch alone.

---

## Logs

Each run writes a timestamped log to:

```
/var/log/php-cve-2026-patch.<YYYYMMDD-HHMMSS>.log
```

---

## References

- PHP ChangeLog: <https://www.php.net/ChangeLog-8.php>
- Sansec research (PHP2Shell): <https://sansec.io/research/php2shell>
- Cisco Talos: <https://blog.talosintelligence.com/two-critical-rces-in-php-core/>
- Unit 42 (Palo Alto Networks): <https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/>

> Verify the fixed version numbers and advisory details against the official php.net
> security advisory before acting in production.

---

## Disclaimer

Provided for authorized system administration and defensive remediation only. Test with
`--dry-run` first, and ideally on a staging host, before running in production. You are
responsible for backups and for validating the result in your environment.
