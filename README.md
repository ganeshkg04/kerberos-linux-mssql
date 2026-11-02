# Kerberos from Linux to SQL Server — debugging layer by layer

A practical guide and validation script for connecting a **Linux** application (Python / Django / pyodbc) to **Microsoft SQL Server** using **Active Directory (Windows) authentication**.

It is written from a real troubleshooting session: the Linux server sat in a separate network zone, the client's DNS was not reachable, LDAP was blocked by the security team, and the SQL Server was behind a NAT address. Each problem had a different symptom, and each one is covered below.

> All names, IPs and accounts in this repo are placeholders (`CORP.LOCAL`, `sqlhost01`, `10.0.0.x`).

---

## Why Linux fails when Windows works

Windows has two ways to authenticate with Active Directory:

| | NTLM | Kerberos |
|---|---|---|
| Needs an SPN | No | **Yes** |
| How it works | SQL Server checks your credentials with the DC | You get a ticket from the DC first, then present it to SQL Server |
| Security | Older, weaker | Modern, mutual authentication |
| Windows clients (SSMS) | Used as a silent fallback | Tried first |
| Linux ODBC driver | **Not supported** | **Only option** |

So when SSMS connects fine from a Windows laptop but Linux fails, it usually means **Kerberos is broken and Windows is silently falling back to NTLM**. Linux has no fallback, so it exposes the real problem.

---

## The layers

Kerberos authentication to SQL Server needs every one of these to work. Test them **in order** — a failure in one layer shows up as a confusing error in the next.

```
1. Realm        → is the Kerberos realm what you think it is?
2. KDC reach    → can the Linux box reach a domain controller on port 88?
3. Ticket (TGT) → does kinit succeed?
4. Server name  → are you using the SQL Server's real hostname (not the IP)?
5. SPN          → is an MSSQLSvc SPN registered for that hostname?
6. SQL login    → does the AD user have a login on the SQL Server?
```

---

### Layer 1 — Find the real realm

The email / UPN suffix (`user@company.com`) is often **not** the AD domain. Kerberos needs the actual AD DNS domain, in uppercase.

From any domain-joined Windows machine:

```cmd
echo %USERDNSDOMAIN%
nltest /dsgetdc:%USERDNSDOMAIN%
nslookup -type=SRV _kerberos._tcp.%USERDNSDOMAIN%
```

`%USERDNSDOMAIN%` is your realm (e.g. `CORP.LOCAL`). The SRV lookup lists every domain controller (KDC) and its IP.

**Symptom if wrong:** `kinit: Cannot find KDC for realm "COMPANY.COM"`

---

### Layer 2 — Reach a KDC on port 88

Kerberos needs **port 88 (TCP and UDP)** to a domain controller. It does **not** need LDAP (389/636).

Test every DC you found — in segmented networks, only some may be reachable:

```bash
for dc in 10.0.0.11 10.0.0.12 10.0.1.11 10.0.1.12; do
  timeout 3 bash -c "</dev/tcp/$dc/88" 2>/dev/null && echo "$dc  OPEN" || echo "$dc  blocked"
done
```

If the Linux server's DNS can't see the AD zones (common when it lives in another network), **skip DNS entirely** and list the reachable KDCs in `krb5.conf` by IP. See [`examples/krb5.conf`](examples/krb5.conf).

Key settings when DNS isn't available:

```ini
dns_lookup_kdc = false            # don't look up KDCs via DNS
rdns = false                      # don't reverse-resolve the server IP
dns_canonicalize_hostname = false # use the hostname exactly as typed
udp_preference_limit = 1          # force TCP (if only TCP 88 is open)
```

**Symptom if wrong:** `Cannot contact any KDC for realm`

---

### Layer 3 — Get a ticket

```bash
kinit username@CORP.LOCAL && klist
```

If your account's UPN suffix differs from the realm, try the enterprise-principal form:

```bash
kinit -E username@company.com
```

| Error | Meaning |
|---|---|
| `Cannot find KDC for realm` | Realm missing or misspelled in `krb5.conf` (must be uppercase) |
| `Cannot contact any KDC` | KDC configured, but port 88 blocked |
| `Client not found in Kerberos database` | Wrong realm or principal name |
| `Preauthentication failed` | Wrong password, or account locked |
| `Clock skew too great` | Time differs > 5 min from the DC — fix NTP |

A successful `klist` shows `krbtgt/CORP.LOCAL@CORP.LOCAL`.

---

### Layer 4 — Use the real hostname, never the IP

Kerberos asks the DC for a ticket for `MSSQLSvc/<hostname>:<port>`. If you connect with an IP, the driver asks for `MSSQLSvc/10.0.5.20:1433`, which never exists.

**The trap:** the IP you connect to may be a **NAT / VIP address**. Reverse DNS returns nothing, and no AD hostname resolves to it. Matching by IP will never work.

The reliable fix is to ask SQL Server itself. Connect from any Windows client that already works (via NTLM) and run — this needs no special permissions:

```sql
SELECT SERVERPROPERTY('MachineName') AS MachineName,
       @@SERVERNAME                 AS ServerName,
       DEFAULT_DOMAIN()             AS Domain;
```

Then map the real hostname to the IP you can reach:

```bash
echo "10.0.5.20  sqlhost01.corp.local  sqlhost01" | sudo tee -a /etc/hosts
```

Kerberos only cares that the **name** matches the SPN — it works fine through NAT.

---

### Layer 5 — Check the SPN

```bash
kvno MSSQLSvc/sqlhost01.corp.local:1433@CORP.LOCAL
```

- `kvno = N` → SPN exists, move on.
- `Server not found in Kerberos database` → no SPN for that name.

Narrow it down by testing variants, including the computer's `host/` SPN:

```bash
for spn in \
  MSSQLSvc/sqlhost01.corp.local:1433 \
  MSSQLSvc/sqlhost01.corp.local \
  MSSQLSvc/sqlhost01:1433 \
  host/sqlhost01.corp.local; do
  kvno "$spn@CORP.LOCAL" >/dev/null 2>&1 && echo "FOUND     $spn" || echo "not found $spn"
done
```

| Result | Meaning |
|---|---|
| An `MSSQLSvc` line found | Use that exact name |
| Only `host/` found | Server is domain-joined, **SQL Server has no SPN** — AD admin must register it |
| Nothing found | Server isn't in this domain under that name |

The fix (run by an AD admin, against the account SQL Server runs as):

```cmd
setspn -S MSSQLSvc/sqlhost01.corp.local:1433 CORP\<sql-service-account>
setspn -S MSSQLSvc/sqlhost01.corp.local      CORP\<sql-service-account>
```

If SQL runs as a built-in account (`NT Service\MSSQLSERVER`, Network Service, LocalSystem), register on the computer account `CORP\sqlhost01$` instead. Registering on the wrong account breaks Kerberos for everyone, so check **SQL Server Configuration Manager → SQL Server Services → Log On As** first.

This is a common gap: SQL Server tries to register its own SPN at startup, but silently fails when its domain service account lacks permission. Windows clients never notice because of the NTLM fallback.

---

### Layer 6 — SQL login

Once Kerberos succeeds, SQL Server still needs a login for the AD user or a group they belong to:

```sql
CREATE LOGIN [CORP\username] FROM WINDOWS;
```

**Symptom if missing:** `Login failed for user ... (18456)` — note this means Kerberos itself worked.

---

## Verify it's really Kerberos

```python
import pyodbc

conn = pyodbc.connect(
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=sqlhost01.corp.local,1433;"   # FQDN, not IP
    "Trusted_Connection=yes;"
    "Encrypt=yes;TrustServerCertificate=yes;"
)
print(conn.execute(
    "SELECT SYSTEM_USER, auth_scheme FROM sys.dm_exec_connections WHERE session_id=@@SPID"
).fetchone())
# ('CORP\\username', 'KERBEROS')
```

(`sys.dm_exec_connections` needs `VIEW SERVER STATE`; drop that part if you lack it.)

For Django with `mssql-django`, see [`examples/django_settings.py`](examples/django_settings.py).

---

## Validation script

[`validate_mssql_kerberos.py`](validate_mssql_kerberos.py) runs every layer in order and stops at the first failure with a hint:

```bash
pip install pyodbc
export MSSQL_HOST=sqlhost01.corp.local
export AD_PRINCIPAL=username@CORP.LOCAL
python3 validate_mssql_kerberos.py
```

The password is prompted only if there's no valid ticket. Never hardcode it.

---

## Running in production

Don't type passwords into `kinit` for a service. Use a **keytab** for a dedicated service account, and renew the ticket automatically:

```bash
ktutil
  addent -password -p svc_app@CORP.LOCAL -k 1 -e aes256-cts-hmac-sha1-96
  wkt /etc/app/svc_app.keytab
  quit

kinit -kt /etc/app/svc_app.keytab svc_app@CORP.LOCAL
```

Renew with a cron job or `k5start`, and protect the keytab like a password (`chmod 600`).

---

## Ports summary (for your security team)

| Port | To | Purpose |
|---|---|---|
| 88 TCP/UDP | Domain controllers | Kerberos — **required** |
| 1433 TCP | SQL Server | Database — **required** |
| 464 TCP/UDP | Domain controllers | Password change — optional |
| 53 | AD DNS | Optional (replaceable by `krb5.conf` + `/etc/hosts`) |
| 389 / 636 | Domain controllers | **Not needed** for this setup |

---

## License

MIT
