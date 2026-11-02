"""
Validate Active Directory (Kerberos) authentication from Linux to SQL Server.

Each layer is checked separately so a failure points at the real cause:
  1. Name resolution        -> Kerberos needs the hostname, not the IP
  2. TCP reachability       -> firewall / port
  3. Kerberos TGT           -> kinit / krb5.conf / clock skew
  4. SPN service ticket     -> MSSQLSvc SPN registered in AD?
  5. SQL login              -> connects and reports the auth scheme

Usage:
  export MSSQL_HOST=sqlhost01.corp.local     # FQDN, NOT the IP
  export AD_PRINCIPAL=username@CORP.LOCAL
  python3 validate_mssql_kerberos.py

Optional: MSSQL_PORT (default 1433), MSSQL_DRIVER (default ODBC Driver 17 for SQL Server).
The password is prompted only if no valid Kerberos ticket exists. Never hardcode it.
"""
import getpass
import ipaddress
import os
import shutil
import socket
import subprocess
import sys

HOST = os.environ.get("MSSQL_HOST", "")
PORT = int(os.environ.get("MSSQL_PORT", "1433"))
PRINCIPAL = os.environ.get("AD_PRINCIPAL", "")
DRIVER = os.environ.get("MSSQL_DRIVER", "ODBC Driver 17 for SQL Server")
REALM = PRINCIPAL.split("@")[-1].upper() if "@" in PRINCIPAL else ""


def ok(msg):
    print(f"  [OK]   {msg}")


def warn(msg):
    print(f"  [WARN] {msg}")


def fail(msg, hint=None):
    print(f"  [FAIL] {msg}")
    if hint:
        print(f"         Hint: {hint}")
    sys.exit(1)


def run(cmd, input_text=None):
    return subprocess.run(cmd, input=input_text, capture_output=True, text=True)


def check_config():
    if not HOST:
        fail("MSSQL_HOST is not set.", "export MSSQL_HOST=<sql-server-fqdn>")
    if not PRINCIPAL or not REALM:
        fail("AD_PRINCIPAL is not set or has no realm.", "export AD_PRINCIPAL=username@CORP.LOCAL")


def check_name():
    print("\n1. Name resolution")
    try:
        ipaddress.ip_address(HOST)
        fail(f"MSSQL_HOST is an IP address ({HOST}).",
             "Kerberos needs the server's hostname. Get it with "
             "SELECT SERVERPROPERTY('MachineName') from a working client, "
             "then map it in /etc/hosts.")
    except ValueError:
        pass

    try:
        ip = socket.gethostbyname(HOST)
        ok(f"{HOST} -> {ip}")
    except socket.gaierror as e:
        fail(f"Cannot resolve {HOST}: {e}",
             "Add an /etc/hosts entry, or point DNS at the AD DNS servers.")

    try:
        rev = socket.gethostbyaddr(ip)[0]
        if rev.lower() != HOST.lower():
            warn(f"Reverse lookup gives {rev}. Set 'rdns = false' in /etc/krb5.conf.")
        else:
            ok(f"Reverse lookup matches ({rev})")
    except (socket.herror, socket.gaierror):
        warn("No reverse DNS record (common behind NAT). "
             "Set 'rdns = false' and 'dns_canonicalize_hostname = false' in /etc/krb5.conf.")
    return ip


def check_tcp(ip):
    print("\n2. TCP reachability")
    try:
        with socket.create_connection((ip, PORT), timeout=5):
            ok(f"Port {PORT} open on {ip}")
    except OSError as e:
        fail(f"Cannot reach {ip}:{PORT}: {e}", "Check firewall rules and the SQL Server TCP listener.")


def check_tgt():
    print("\n3. Kerberos ticket (TGT)")
    for tool in ("kinit", "klist", "kvno"):
        if not shutil.which(tool):
            fail(f"{tool} not found.",
                 "Install: sudo apt install krb5-user   (RHEL: sudo dnf install krb5-workstation)")

    if run(["klist", "-s"]).returncode == 0:
        ok("Valid ticket already in cache")
    else:
        pwd = getpass.getpass(f"  Password for {PRINCIPAL}: ")
        r = run(["kinit", PRINCIPAL], input_text=pwd + "\n")
        if r.returncode != 0:
            err = r.stderr.strip()
            low = err.lower()
            hint = "Check the [realms] section of /etc/krb5.conf."
            if "cannot find kdc" in low or "cannot locate kdc" in low:
                hint = (f"No KDC configured for realm {REALM}. The realm is the AD DNS domain "
                        "(echo %USERDNSDOMAIN% on Windows), not the email suffix.")
            elif "cannot contact any kdc" in low:
                hint = "KDC configured but unreachable. Check port 88 to the domain controllers."
            elif "client not found" in low:
                hint = "Wrong realm or principal. Try: kinit -E user@upn-suffix"
            elif "skew" in low:
                hint = "Clock differs > 5 min from the DC. Fix NTP / chrony."
            elif "preauthentication failed" in low:
                hint = "Wrong password, or the account is locked or expired."
            fail(f"kinit failed: {err}", hint)
        ok("kinit succeeded")

    print("  " + run(["klist"]).stdout.replace("\n", "\n  ").rstrip())


def check_spn():
    print("\n4. SQL Server SPN (service ticket)")
    spn = f"MSSQLSvc/{HOST}:{PORT}@{REALM}"
    r = run(["kvno", spn])
    if r.returncode == 0:
        ok(f"Service ticket issued for {spn}")
        return

    host_spn = f"host/{HOST}@{REALM}"
    if run(["kvno", host_spn]).returncode == 0:
        fail(f"No SPN: {spn}",
             "The computer is in AD but SQL Server has no MSSQLSvc SPN. An AD admin must run: "
             f"setspn -S MSSQLSvc/{HOST}:{PORT} <DOMAIN>\\<sql-service-account>")
    fail(f"No SPN: {spn} (and no host/ SPN either)",
         "This hostname is not a computer in this realm. Check the hostname and realm.")


def check_sql():
    print("\n5. SQL Server login (Windows Integrated / Kerberos)")
    try:
        import pyodbc
    except ImportError:
        fail("pyodbc not installed.", "pip install pyodbc")

    conn_str = (
        f"DRIVER={{{DRIVER}}};"
        f"SERVER={HOST},{PORT};"
        "Trusted_Connection=yes;"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
        "Connection Timeout=10;"
    )
    try:
        conn = pyodbc.connect(conn_str)
    except pyodbc.Error as e:
        msg = str(e)
        hint = None
        if "18456" in msg:
            hint = ("Kerberos worked, but SQL Server has no login for this user. "
                    "DBA: CREATE LOGIN [DOMAIN\\user] FROM WINDOWS;")
        elif "SSPI" in msg or "GSSAPI" in msg:
            hint = "Ticket problem. Re-check layers 3-4 and that MSSQL_HOST is the FQDN."
        fail(f"Connection failed: {msg}", hint)

    with conn:
        cur = conn.cursor()
        server, user = cur.execute("SELECT @@SERVERNAME, SYSTEM_USER").fetchone()
        ok(f"Server: {server}")
        ok(f"Authenticated as: {user}")
        try:
            scheme = cur.execute(
                "SELECT auth_scheme FROM sys.dm_exec_connections WHERE session_id = @@SPID"
            ).fetchone()[0]
            if scheme == "KERBEROS":
                ok("auth_scheme = KERBEROS")
            else:
                warn(f"auth_scheme = {scheme} (expected KERBEROS)")
        except pyodbc.Error:
            warn("Could not read auth_scheme (needs VIEW SERVER STATE). Connection itself succeeded.")


if __name__ == "__main__":
    if sys.platform == "win32":
        sys.exit("This script is for Linux. On Windows, Trusted_Connection uses the logged-on user.")
    check_config()
    print(f"Target: {HOST}:{PORT}   Principal: {PRINCIPAL}   Driver: {DRIVER}")
    ip = check_name()
    check_tcp(ip)
    check_tgt()
    check_spn()
    check_sql()
    print("\nAll checks passed.")
