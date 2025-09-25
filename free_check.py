#!/usr/bin/env python3
"""
PhishGuard — Free GUI Version
"""

import tkinter as tk
from tkinter import simpledialog, scrolledtext, ttk
import threading, time, re
from urllib.parse import urlparse
import requests, tldextract, validators, os

# ---------- Config ----------
BLACKLIST_FILE = "blacklist.txt"
TIMEOUT = 5
SUSPICIOUS_KEYWORDS = ("login","secure","account","update","verify",
                       "bank","confirm","signin","paypal","apple","reset")
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
                         allow_redirects=True, headers={"User-Agent":"PhishGuard/1.0"})
        return True, r.url, r.status_code, None
    except Exception as e:
        return False, None, None, str(e)

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

    ok, final, status, err = quick_http_info(url)
    out["checks"]["http_ok"] = ok
    out["checks"]["http_status"] = status
    out["checks"]["final_url"] = final
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
class PhishGuardFreeGUI:
    def __init__(self, master):
        self.master = master
        master.title("PhishGuard Free")
        master.configure(bg="black")
        master.geometry("900x700")

        # Title
        self.title_label = tk.Label(master, text="PhishGuard Free",
                                    font=("Courier New",28,"bold"),
                                    fg="lime", bg="black")
        self.title_label.pack(pady=15)

        # URL Entry
        self.url_label = tk.Label(master, text="Enter URL:", fg="lime", bg="black", font=("Courier New",12))
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
                                                     font=("Courier New",10))
        self.result_area.pack(pady=10)

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

        # Overview
        self.result_area.insert(tk.END,f"\n--- Verdict ---\n")
        self.result_area.insert(tk.END,f"URL: {result['url']}\n")
        self.result_area.insert(tk.END,f"Total Score: {result['score']}\n")
        self.result_area.insert(tk.END,f"Verdict: {result['final_verdict']}\n\n")

        # Only top 3 indicators for free
        self.result_area.insert(tk.END,"--- Top Indicators ---\n")
        for sev,text in result["indicators"][:3]:
            self.result_area.insert(tk.END,f" - {text}\n")
        self.result_area.insert(tk.END,"\nUpgrade to Premium for full analysis!\n")

# ---------- Main ----------
if __name__=="__main__":
    root = tk.Tk()
    gui = PhishGuardFreeGUI(root)
    root.mainloop()
