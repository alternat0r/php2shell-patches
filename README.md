# PHP CVE-2026-109618 / CVE-2026-109619 Patch Helper

A remediation script for the **critical unauthenticated RCE vulnerabilities in PHP core**
disclosed in the October 2026 PHP security release ("PHP2Shell"), exploited through
PHP's `session.upload_progress` handling.

> **Scope:** this tool **patches the local Debian/Ubuntu host it runs on**. It does not
> scan, probe, or exploit any system — remote or local. Run it only on servers you own
> or are authorized to administer.

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
4. **Upgrade** the `php<branch>*` packages via `apt` — the complete fix. Before upgrading it
   checks that the apt *candidate* is already at or above the fixed version, and **refuses to
   proceed** if your repositories are not yet serving the patched build (so it never pulls
   from an untrusted source just to appear successful).
5. **Restart** `php<branch>-fpm` / `apache2` / `nginx` if they are running.
6. **Verify** the running version now meets the fix, then prints a post-compromise checklist.

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
