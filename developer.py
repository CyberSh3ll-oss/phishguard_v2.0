#!/usr/bin/env python3
"""
PhishGuard — Developer GUI Version
Advanced, detailed, and rich interface for developers.
"""

import tkinter as tk
from tkinter import simpledialog, scrolledtext, ttk, messagebox
import threading, time, re
from urllib.parse import urlparse
import requests, tldextract, validators, os
import socket, ssl

# ---------- Config ----------
BLACKLIST_FILE = "blacklist.txt"
TIMEOUT = 5
SUSPICIOUS_KEYWORDS = ("login","secure","account","update","verify",
                       "bank","confirm","signin","paypal","apple","reset")
DEV_KEY = "DEVACCESS2025"
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

def quick_http_info(url: str):
    try:
        r = requests.get(normalize_url(url), timeout=TIMEOUT,
                         allow_redirects=True, headers={"User-Agent":"PhishGuard/Dev/1.0"})
        ssl_info = None
        parsed = urlparse(r.url)
        if parsed.scheme=="https":
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(), server_hostname=parsed.hostname)
            conn.settimeout(TIMEOUT)
            conn.connect((parsed.hostname, 443))
            cert = conn.getpeercert()
            ssl_info = cert.get("subject", [])
            conn.close()
        return True, r.url, r.status_code, ssl_info, None
    except Exception as e:
        return False, None, None, None, str(e)

def heuristic_score(url: str):
    score = 0
    reasons = []
    norm = normalize_url(url).lower()
    host = domain_of(norm)
    full = norm

    if is_ip_host(host.split(":")[0]):
        score += 30
        reasons.append(("HIGH","Host is an IP address"))
    if len(full) > 80:
        score += 8
        reasons.append(("MED","URL length > 80"))
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full:
            score += 7
            reasons.append(("MED",f"Suspicious keyword: '{kw}'"))
    if "@" in full:
        score += 15
        reasons.append(("HIGH","Contains '@' (credential-steering trick)"))
    extracted = tldextract.extract(full)
    sub = extracted.subdomain or ""
    if sub.count(".") >= 2:
        score += 5
        reasons.append(("MED","Many subdomains (possible cloak)"))
    path = urlparse(full).path or ""
    if "//" in path:
        score += 4
        reasons.append(("LOW","Double slashes in path"))
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
        out["indicators"].append(("HIGH","Found in local blacklist"))
        out["checks"]["blacklist"] = True
    else:
        out["checks"]["blacklist"] = False

    is_valid = validators.url(normalize_url(url))
    out["checks"]["valid_url"] = bool(is_valid)
    if not is_valid:
        out["score"] += 6
        out["indicators"].append(("MED","Malformed or suspicious URL format"))

    ok, final, status, ssl_info, err = quick_http_info(url)
    out["checks"]["http_ok"] = ok
    out["checks"]["http_status"] = status
    out["checks"]["final_url"] = final
    out["checks"]["ssl_info"] = ssl_info
    if not ok:
        out["score"] += 8
        out["indicators"].append(("MED",f"Request failed: {err}"))
    else:
        final_host = domain_of(final)
        if final_host != host:
            out["score"] += 6
            out["indicators"].append(("MED",f"Redirects to different domain: {final_host}"))
        parsed = urlparse(normalize_url(final))
        if parsed.scheme != "https":
            out["score"] += 5
            out["indicators"].append(("LOW","No HTTPS on final URL"))

    hscore, hreasons = heuristic_score(url)
    out["checks"]["heuristic_score"] = hscore
    out["checks"]["heuristic_reasons"] = hreasons
    out["score"] += hscore
    out["indicators"].extend(hreasons)

    out["final_verdict"] = verdict(out["score"])
    return out

# ---------- GUI ----------
class PhishGuardDevGUI:
    def __init__(self, master):
        self.master = master
        master.title("PhishGuard Developer Version")
        master.configure(bg="black")
        master.geometry("1000x750")
        self.user_type = "free"
        self.ask_dev_key()

        # Title
        self.title_label = tk.Label(master, text="PhishGuard Developer",
                                    font=("Courier New",28,"bold"),
                                    fg="#00ffff" if self.user_type=="dev" else "lime", bg="black")
        self.title_label.pack(pady=10)
        if self.user_type=="dev": self.animate_title_glow()

        # URL Entry
        self.url_label = tk.Label(master, text="Enter URL:", fg="lime", bg="black", font=("Courier New",12))
        self.url_label.pack()
        self.url_entry = tk.Entry(master, width=90, fg="black")
        self.url_entry.pack(pady=5)

        # Scan Button
        self.scan_button = tk.Button(master, text="Scan URL", command=self.start_scan,
                                     bg="#00ffff" if self.user_type=="dev" else "lime", fg="black")
        self.scan_button.pack(pady=10)

        # Progress bar
        self.progress = ttk.Progressbar(master, orient="horizontal", length=700, mode="indeterminate")
        self.progress.pack(pady=5)
        self.progress.stop()

        # Result display
        self.result_area = scrolledtext.ScrolledText(master, width=120, height=35,
                                                     bg="black", fg="#00ffff" if self.user_type=="dev" else "lime",
                                                     font=("Courier New",10))
        self.result_area.pack(pady=10)

    def ask_dev_key(self):
        key = simpledialog.askstring("Developer Access","Enter developer key (leave blank for Free):",show="*")
        if key and key.strip() == DEV_KEY: self.user_type="dev"

    def animate_title_glow(self):
        colors = ["#00ffff","#ff00ff","#ffff00","#00ff00"]
        def glow(idx=0):
            self.title_label.config(fg=colors[idx%len(colors)])
            self.master.after(500, glow, idx+1)
        glow()

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            self.result_area.insert(tk.END,"Please enter a URL.\n")
            return
        self.result_area.delete(1.0, tk.END)
        self.progress.start()
        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()

    def run_scan(self, url):
        time.sleep(1)
        result = analyze(url, BLACKLIST_FILE)
        self.progress.stop()

        # Print overview
        self.result_area.insert(tk.END,f"\n=== Verdict ===\n")
        self.result_area.insert(tk.END,f"URL: {result['url']}\n")
        self.result_area.insert(tk.END,f"Total Score: {result['score']}\n")
        self.result_area.insert(tk.END,f"Verdict: {result['final_verdict']}\n\n")

        # Checks and Technical Details
        self.result_area.insert(tk.END,"=== Technical Checks ===\n")
        for k, v in result["checks"].items():
            self.result_area.insert(tk.END,f"{k}: {v}\n")
        self.result_area.insert(tk.END,"\n")

        # Indicators breakdown
        self.result_area.insert(tk.END,"=== Heuristic Indicators ===\n")
        for sev, text in result["indicators"]:
            self.result_area.insert(tk.END,f"[{sev}] {text}\n")

        if self.user_type!="dev":
            self.result_area.insert(tk.END,"\nUpgrade to Developer version to see full technical analysis.\n")
        else:
            self.result_area.insert(tk.END,"\nDeveloper features unlocked: Full analysis and technical insights displayed.\n")

# ---------- Main ----------
if __name__=="__main__":
    root = tk.Tk()
    gui = PhishGuardDevGUI(root)
    root.mainloop()
