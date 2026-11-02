# Django DATABASES entry for SQL Server with Kerberos (mssql-django).
# Requires a valid Kerberos ticket for the process user (kinit, or a keytab).
#
# Quick test:
#   python manage.py shell -c "from django.db import connections; \
#     c = connections['sqlserver'].cursor(); \
#     c.execute('SELECT @@SERVERNAME, SYSTEM_USER'); print(c.fetchone())"

DATABASES = {
    "sqlserver": {
        "ENGINE": "mssql",
        "NAME": "<database_name>",
        "HOST": "sqlhost01.corp.local",  # FQDN matching the SPN, not the IP
        "PORT": "1433",
        "USER": "",                      # empty = Windows / Kerberos auth
        "PASSWORD": "",
        "OPTIONS": {
            "driver": "ODBC Driver 17 for SQL Server",
            "extra_params": "Trusted_Connection=yes;Encrypt=yes;TrustServerCertificate=yes",
        },
    },
}
