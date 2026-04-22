"""
parser.py — NGINX Combined Log Format Parser
Detects: failed logins, SQLi/XSS suspicious requests, bot activity.
"""

import re
from collections import defaultdict

LOG_FILE = "access.log"

# ------------------------------------------------------------------ #
# Compiled regex patterns
# ------------------------------------------------------------------ #

# NGINX combined log format:
# IP - - [timestamp] "METHOD /path HTTP/x.x" STATUS size "referrer" "user-agent"
LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'          # IP address
    r' - - \[(?P<timestamp>[^\]]+)\] '            # timestamp
    r'"(?P<method>[A-Z]+) (?P<path>\S+) HTTP/[^"]+" '  # method + path
    r'(?P<status>\d{3}) '                         # HTTP status
    r'(?P<size>\d+) '                             # response size
    r'"(?P<referrer>[^"]*)" '                     # referrer
    r'"(?P<user_agent>[^"]*)"'                    # user agent
)

# Suspicious payload signatures
SQLI_PATTERN = re.compile(
    r'(UNION\s+SELECT|DROP\s+TABLE|OR\s+1=1|information_schema|'
    r'INSERT\s+INTO|UPDATE\s+SET|DELETE\s+FROM|EXEC\s*\(|CAST\s*\(|'
    r"'--|\bOR\b.*=.*--|;\s*DROP|SLEEP\s*\(|BENCHMARK\s*\()",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r'(<script[\s>]|</script>|javascript:|onerror\s*=|onload\s*=|'
    r'<iframe|<svg.*onload|<img[^>]+onerror|eval\s*\(|document\.cookie|'
    r'alert\s*\(|onmouseover\s*=)',
    re.IGNORECASE,
)

BOT_UA_PATTERN = re.compile(
    r'(curl/|python-requests/|python-urllib|Go-http-client|Wget/|'
    r'libwww-perl|scrapy|mechanize|httpclient|apache-httpclient|'
    r'java/|okhttp|axios/|node-fetch|bot|crawler|spider|slurp)',
    re.IGNORECASE,
)

# ------------------------------------------------------------------ #
# Public API
# ------------------------------------------------------------------ #

def parse_logs(log_file: str = LOG_FILE) -> dict:
    """
    Parse an NGINX combined-format access log and return a metrics dict.

    Returns:
        {
            "failed_logins":       {ip: count, ...},
            "suspicious_requests": {"SQLi": count, "XSS": count},
            "bot_activity":        {ip: count, ...},
        }
    """
    failed_logins: dict[str, int] = defaultdict(int)
    suspicious_requests: dict[str, int] = {"SQLi": 0, "XSS": 0}
    bot_activity: dict[str, int] = defaultdict(int)

    # Track per-IP request velocity to catch bots not identified by UA alone.
    # Any IP with BOT_UA_PATTERN is always flagged; additionally, IPs making
    # 30+ requests are also included in bot_activity.
    ip_request_count: dict[str, int] = defaultdict(int)
    ip_is_bot: dict[str, bool] = defaultdict(bool)

    BOT_VELOCITY_THRESHOLD = 30

    try:
        with open(log_file, "r", errors="replace") as fh:
            for line_number, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line:
                    continue

                match = LOG_PATTERN.match(line)
                if not match:
                    continue

                ip          = match.group("ip")
                method      = match.group("method")
                path        = match.group("path")
                status      = match.group("status")
                user_agent  = match.group("user_agent")

                # Decode URL-encoded characters for better pattern matching
                decoded_path = _url_decode(path)

                # ---- 1. Failed Login Detection ---- #
                if method == "POST" and "/api/login" in path and status == "401":
                    failed_logins[ip] += 1

                # ---- 2. Suspicious Request Detection ---- #
                if SQLI_PATTERN.search(decoded_path):
                    suspicious_requests["SQLi"] += 1
                elif XSS_PATTERN.search(decoded_path):
                    suspicious_requests["XSS"] += 1

                # ---- 3. Bot Detection (by User-Agent) ---- #
                if BOT_UA_PATTERN.search(user_agent):
                    ip_is_bot[ip] = True

                # Track all request counts for velocity analysis
                ip_request_count[ip] += 1

    except FileNotFoundError:
        raise FileNotFoundError(
            f"Log file '{log_file}' not found. "
            "Run generate_logs.py first."
        )

    # Apply velocity threshold: flag any IP with excessive requests as bot
    for ip, count in ip_request_count.items():
        if count >= BOT_VELOCITY_THRESHOLD:
            ip_is_bot[ip] = True

    # Build bot_activity from confirmed bot IPs
    for ip, is_bot in ip_is_bot.items():
        if is_bot:
            bot_activity[ip] = ip_request_count[ip]

    return {
        "failed_logins":       dict(failed_logins),
        "suspicious_requests": suspicious_requests,
        "bot_activity":        dict(bot_activity),
    }


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _url_decode(text: str) -> str:
    """Minimal URL percent-decode without importing urllib (pure regex)."""
    def replace_hex(m):
        try:
            return chr(int(m.group(1), 16))
        except ValueError:
            return m.group(0)
    return re.sub(r'%([0-9A-Fa-f]{2})', replace_hex, text)


# ------------------------------------------------------------------ #
# CLI convenience
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    import json
    metrics = parse_logs()
    print(json.dumps(metrics, indent=2))
