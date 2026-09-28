"""Static config: patterns and lists Cerberus scans against."""

# Common sensitive paths probed with a plain GET (non-invasive recon).
EXPOSED_PATHS = [
    "/.git/config", "/.env", "/.env.local", "/.env.production",
    "/config.php.bak", "/wp-config.php.bak", "/.DS_Store",
    "/backup.zip", "/backup.sql", "/db.sql", "/.htpasswd",
    "/server-status", "/phpinfo.php", "/.svn/entries",
]

# Security headers we expect present, with why they matter.
SECURITY_HEADERS = {
    "content-security-policy": "Missing CSP: no defense-in-depth against XSS / injection.",
    "strict-transport-security": "Missing HSTS: connection can be downgraded to HTTP.",
    "x-frame-options": "Missing X-Frame-Options: clickjacking risk.",
    "x-content-type-options": "Missing X-Content-Type-Options: MIME-sniffing risk.",
    "referrer-policy": "Missing Referrer-Policy: URLs may leak to third parties.",
    "permissions-policy": "Missing Permissions-Policy: no restriction on browser features.",
}

# Secret patterns for JS bundle scanning. name -> regex
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Live Secret Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Live Publishable Key": r"pk_live_[0-9a-zA-Z]{24,}",
    "Generic Bearer Token": r"(?i)bearer\s+[a-z0-9\-_\.=]{20,}",
    "Private Key Block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
}

USER_AGENT = "CerberusScanner/0.1 (+https://ctfdesigns.com/security)"
