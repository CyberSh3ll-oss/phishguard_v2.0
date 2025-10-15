import tkinter as tk
from tkinter import simpledialog, scrolledtext, ttk
import threading, time, re
from urllib.parse import urlparse
import requests, tldextract, validators, os
from bs4 import BeautifulSoup  # Add this import for HTML parsing (install via pip if needed: pip install beautifulsoup4)
import ssl
import socket

# ---------- Config ----------
BLACKLIST_FILE = "blacklist.txt"
TIMEOUT = 5
SUSPICIOUS_KEYWORDS = ("login", "secure", "account", "update", "verify",
                       "bank", "confirm", "signin", "paypal", "apple", "reset", "password")
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "microsoft": "login.microsoft.com",
    "bankofamerica": "bankofamerica.com",
    # Add more known brands and their official domains as needed
}
SUSPICIOUS_HOSTS = ("ngrok.io", "ngrok.com", "localtunnel.me", "duckdns.org", "noip.com", "trycloudflare.com",
                    "serveo.net", "pagekite.net", "nip.io", "zapto.org")  # Known tunneling/free dynamic DNS services
MAX_REDIRECTS_THRESHOLD = 5
# ----------------------------

def normalize_url(u: str) -> str:
    return u if "://" in u else "http://" + u

def load_blacklist(path: str) -> set:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return set([ln.strip().lower() for ln in f if ln.strip() and not ln.strip().startswith("#")])

def domain_of(url: str) -> str:
    return urlparse(normalize_url(url)).netloc.lower()

def is_ip_host(host: str) -> bool:
    return re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) is not None

def get_cert_info(host: str):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(TIMEOUT)
            s.connect((host, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert['issuer'])
            issuer_name = issuer.get('commonName', 'Unknown')
            return True, issuer_name, cert['notBefore'], cert['notAfter']
    except Exception as e:
        return False, None, None, None

def quick_http_info(url: str):
    try:
        r = requests.get(normalize_url(url), timeout=TIMEOUT,
                         allow_redirects=True, headers={"User-Agent": "PhishGuard/1.0"},
                         verify=True)  # Enforce SSL verification
        content = r.text if r.status_code == 200 else None
        return True, r.url, r.status_code, len(r.history), content, None
    except Exception as e:
        return False, None, None, 0, None, str(e)

def heuristic_score(url: str, content: str = None, redirect_count: int = 0, cert_issuer: str = None):
    score = 0
    reasons = []
    norm = normalize_url(url).lower()
    host = domain_of(norm)
    full = norm

    # URL-based heuristics
    if is_ip_host(host.split(":")[0]):
        score += 30
        reasons.append(("HIGH", "Host is an IP address"))
    if len(full) > 80:
        score += 8
        reasons.append(("MED", "URL length > 80"))
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full:
            score += 7
            reasons.append(("MED", f"Suspicious keyword in URL: '{kw}'"))
    if "@" in full:
        score += 15
        reasons.append(("HIGH", "Contains '@' (credential-steering trick)"))
    extracted = tldextract.extract(full)
    sub = extracted.subdomain or ""
    if sub.count(".") >= 2:
        score += 5
        reasons.append(("MED", "Many subdomains (possible cloak)"))
    path = urlparse(full).path or ""
    if "//" in path:
        score += 4
        reasons.append(("LOW", "Double slashes in path"))

    # Redirect heuristics
    if redirect_count > MAX_REDIRECTS_THRESHOLD:
        score += 10
        reasons.append(("MED", f"Excessive redirects ({redirect_count})"))

    # Suspicious host check (tunneling services)
    for sh in SUSPICIOUS_HOSTS:
        if sh in host:
            score += 20
            reasons.append(("HIGH", f"Hosted on suspicious service: {sh}"))
            break

    # Certificate heuristics
    if cert_issuer:
        if "Let's Encrypt" in cert_issuer or "ZeroSSL" in cert_issuer:  # Common for quick/free certs in phishing
            score += 5
            reasons.append(("LOW", "Uses free certificate authority (common in phishing)"))

    # Content-based heuristics (if content available)
    if content:
        soup = BeautifulSoup(content, 'html.parser')
        # Check for login forms
        password_inputs = soup.find_all('input', {'type': 'password'})
        if password_inputs:
            score += 15
            reasons.append(("HIGH", "Contains password input field (potential login form)"))
        # Check for suspicious keywords in content
        content_lower = content.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in content_lower:
                score += 5
                reasons.append(("MED", f"Suspicious keyword in content: '{kw}'"))
        # Brand mismatch check
        for brand, official_domain in KNOWN_BRANDS.items():
            if brand in full or brand in content_lower:
                if host != official_domain and not host.endswith('.' + official_domain):
                    score += 25
                    reasons.append(("HIGH", f"Mentions '{brand}' but domain doesn't match official '{official_domain}'"))

    return score, reasons

def verdict(score: int) -> str:
    if score >= 40: return "PHISHING"
    if score >= 15: return "POTENTIALLY DANGEROUS"
    return "SAFE"

def analyze(url: str, blacklist_path: str):
    out = {"url": url, "score": 0, "indicators": [], "checks": {}}
    bl = load_blacklist(blacklist_path)

    u_low = url.lower().strip()
    host = domain_of(u_low)
    if u_low in bl or host in bl:
        out["score"] += 60
        out["indicators"].append(("HIGH", "Found in local blacklist"))
        out["checks"]["blacklist"] = True
    else:
        out["checks"]["blacklist"] = False

    is_valid = validators.url(normalize_url(url))
    out["checks"]["valid_url"] = bool(is_valid)
    if not is_valid:
        out["score"] += 6
        out["indicators"].append(("MED", "Malformed or suspicious URL format"))

    ok, final, status, redirect_count, content, err = quick_http_info(url)
    out["checks"]["http_ok"] = ok
    out["checks"]["http_status"] = status
    out["checks"]["final_url"] = final
    out["checks"]["redirect_count"] = redirect_count
    if not ok:
        out["score"] += 8
        out["indicators"].append(("MED", f"Request failed: {err}"))
    else:
        final_host = domain_of(final)
        if final_host != host:
            out["score"] += 6
            out["indicators"].append(("MED", f"Redirects to different domain: {final_host}"))
        parsed = urlparse(normalize_url(final))
        if parsed.scheme != "https":
            out["score"] += 5
            out["indicators"].append(("LOW", "No HTTPS on final URL"))

        # Get cert info for final host
        cert_ok, cert_issuer, cert_start, cert_end = get_cert_info(final_host)
        out["checks"]["cert_ok"] = cert_ok
        out["checks"]["cert_issuer"] = cert_issuer
        if not cert_ok:
            out["score"] += 10
            out["indicators"].append(("MED", "Failed to retrieve SSL certificate info"))

    hscore, hreasons = heuristic_score(url if not final else final, content, redirect_count, cert_issuer)
    out["checks"]["heuristic_score"] = hscore
    out["checks"]["heuristic_reasons"] = hreasons
    out["score"] += hscore
    out["indicators"].extend(hreasons)

    out["final_verdict"] = verdict(out["score"])
    return out

# ---------- GUI ----------
class PhishGuardFreeGUI:
    def __init__(self, master):
        self.master = master
        master.title("PhishGuard Free")
        master.configure(bg="black")
        master.geometry("900x700")

        # Title
        self.title_label = tk.Label(master, text="PhishGuard Free",
                                    font=("Courier New", 28, "bold"),
                                    fg="lime", bg="black")
        self.title_label.pack(pady=15)

        # URL Entry
        self.url_label = tk.Label(master, text="Enter URL:", fg="lime", bg="black", font=("Courier New", 12))
        self.url_label.pack()
        self.url_entry = tk.Entry(master, width=75, fg="black")
        self.url_entry.pack(pady=5)

        # Scan Button
        self.scan_button = tk.Button(master, text="Scan URL", command=self.start_scan,
                                     bg="lime", fg="black")
        self.scan_button.pack(pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(master, orient="horizontal", length=650, mode="indeterminate")
        self.progress.pack(pady=5)
        self.progress.stop()

        # Result display
        self.result_area = scrolledtext.ScrolledText(master, width=110, height=30,
                                                     bg="black", fg="lime",
                                                     font=("Courier New", 10))
        self.result_area.pack(pady=10)

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            self.result_area.insert(tk.END, "Please enter a URL.\n")
            return
        self.result_area.delete(1.0, tk.END)
        self.progress.start()
        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()

    def run_scan(self, url):
        time.sleep(1)  # Simulate delay for progress bar
        result = analyze(url, BLACKLIST_FILE)
        self.progress.stop()

        # Overview
        self.result_area.insert(tk.END, f"\n--- Verdict ---\n")
        self.result_area.insert(tk.END, f"URL: {result['url']}\n")
        self.result_area.insert(tk.END, f"Total Score: {result['score']}\n")
        self.result_area.insert(tk.END, f"Verdict: {result['final_verdict']}\n\n")

        # Only top 3 indicators for free
        self.result_area.insert(tk.END, "--- Top Indicators ---\n")
        for sev, text in result["indicators"][:3]:
            self.result_area.insert(tk.END, f" - {text}\n")
        self.result_area.insert(tk.END, "\nUpgrade to Premium for full analysis!\n")

# ---------- Main ----------
if __name__ == "__main__":
    root = tk.Tk()
    gui = PhishGuardFreeGUI(root)
    root.mainloop()
