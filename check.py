#!/usr/bin/env python3
import re
import requests
import tldextract
import validators
from urllib.parse import urlparse
import tkinter as tk
from tkinter import scrolledtext, messagebox, PhotoImage
import threading
import os

# ------------------ Config ------------------
BLACKLIST_FILE = "blacklist.txt"
TIMEOUT = 3
SUSPICIOUS_KEYWORDS = (
    "login", "secure", "account", "update", "verify",
    "bank", "confirm", "signin", "paypal", "apple", "reset"
)

# Mapping for indicator explanations
INDICATOR_EXPLANATIONS = {
    "Host is an IP address": "Using raw IPs is suspicious; phishing sites often do this.",
    "URL length > 80 characters": "Very long URLs are often used to hide malicious domains.",
    "Suspicious keyword:": "Contains potentially dangerous keyword commonly used in phishing.",
    "Contains '@' (credential-stealing trick)": "URLs with '@' redirect to malicious sites.",
    "Too many subdomains": "Excessive subdomains may be used to confuse users.",
    "Found in local blacklist": "This domain/URL is blacklisted and considered risky.",
    "Malformed or suspicious URL format": "The URL is invalid or suspiciously formatted.",
    "Request failed:": "Could not reach the URL; may indicate inactive or blocked site.",
    "Redirected to": "The URL redirects to another domain; could be suspicious."
}

# ------------------ Utility Functions ------------------
def normalize_url(u: str) -> str:
    if "://" not in u:
        u = "http://" + u
    return u

def normalize_host(host: str) -> str:
    return host.lower().strip()

def load_blacklist(path: str):
    domains = set()
    full_urls = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "://" in line:
                    full_urls.add(normalize_url(line.lower()))
                else:
                    domains.add(normalize_host(line.lower()))
    except FileNotFoundError:
        pass
    return domains, full_urls

BLACKLIST_DOMAINS, BLACKLIST_URLS = load_blacklist(BLACKLIST_FILE)

def quick_http_info(url: str):
    try:
        session = requests.Session()
        response = session.head(normalize_url(url), allow_redirects=True, timeout=TIMEOUT)
        return True, response.url, response.status_code, None
    except requests.exceptions.RequestException as e:
        return False, None, None, str(e)

def heuristic_score(url: str):
    score = 0
    reasons = []
    norm_url = normalize_url(url).lower()
    host = normalize_host(urlparse(norm_url).netloc)

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 30
        reasons.append("Host is an IP address")

    if len(norm_url) > 80:
        score += 8
        reasons.append("URL length > 80 characters")

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in norm_url:
            score += 7
            reasons.append(f"Suspicious keyword: '{kw}'")

    if "@" in norm_url:
        score += 15
        reasons.append("Contains '@' (credential-stealing trick)")

    subdomain = tldextract.extract(norm_url).subdomain
    if subdomain and subdomain.count(".") >= 2:
        score += 5
        reasons.append("Too many subdomains")

    return score, reasons

def analyze(url: str):
    result = {"url": url, "score": 0, "indicators": [], "verdict": "SAFE"}

    host = normalize_host(urlparse(url).netloc)
    if url.lower() in BLACKLIST_URLS or host in BLACKLIST_DOMAINS:
        result["score"] += 60
        result["indicators"].append("Found in local blacklist")

    if not validators.url(url):
        result["score"] += 6
        result["indicators"].append("Malformed or suspicious URL format")

    ok, final_url, status_code, error = quick_http_info(url)
    if not ok:
        result["score"] += 8
        result["indicators"].append(f"Request failed: {error}")
        final_url = None
    else:
        if final_url != url:
            result["score"] += 6
            result["indicators"].append(f"Redirected to {final_url}")

    score, reasons = heuristic_score(url)
    result["score"] += score
    result["indicators"].extend(reasons)

    # Apply user-defined thresholds
    if result["score"] >= 40:
        result["verdict"] = "PHISHING"
    elif 15 <= result["score"] <= 39:
        result["verdict"] = "POTENTIALLY DANGEROUS"
    else:
        result["verdict"] = "SAFE"

    result["final_url"] = final_url
    result["status_code"] = status_code
    return result

# ------------------ GUI ------------------
class PhishGuardGUI:
    def __init__(self, root):
        self.root = root
        root.title("PhishGuard — Hacker Vibe Scanner")
        root.geometry("950x700")
        root.configure(bg="#0f111a")

        # Optional logo
        logo_path = "gov_logo.png"
        if os.path.exists(logo_path):
            img = PhotoImage(file=logo_path)
            self.logo_label = tk.Label(root, image=img, bg="#0f111a")
            self.logo_label.image = img
            self.logo_label.pack(pady=5)

        # URL input
        tk.Label(root, text="Enter URL:", bg="#0f111a", fg="#39ff14", font=("Consolas", 12, "bold")).pack(pady=(10,0))
        self.url_entry = tk.Entry(root, font=("Consolas", 12), width=80, bg="#1c1f2a", fg="#39ff14", insertbackground="#39ff14")
        self.url_entry.insert(0, "https://example.com")
        self.url_entry.pack(pady=5)

        # Blacklist input
        tk.Label(root, text="Blacklist File Path:", bg="#0f111a", fg="#39ff14", font=("Consolas", 12, "bold")).pack(pady=(10,0))
        self.blacklist_entry = tk.Entry(root, font=("Consolas", 12), width=80, bg="#1c1f2a", fg="#39ff14", insertbackground="#39ff14")
        self.blacklist_entry.insert(0, BLACKLIST_FILE)
        self.blacklist_entry.pack(pady=5)

        # Scan button
        self.scan_button = tk.Button(root, text="Scan URL", font=("Consolas", 12, "bold"), bg="#39ff14", fg="#0f111a", command=self.scan_url)
        self.scan_button.pack(pady=10)

        # Results
        self.verdict_label = tk.Label(root, text="Verdict: ", bg="#0f111a", fg="#39ff14", font=("Consolas", 12, "bold"))
        self.verdict_label.pack(pady=5)
        self.score_label = tk.Label(root, text="Score: ", bg="#0f111a", fg="#39ff14", font=("Consolas", 12, "bold"))
        self.score_label.pack(pady=5)
        self.final_url_label = tk.Label(root, text="Final URL: ", bg="#0f111a", fg="#39ff14", font=("Consolas", 12, "bold"))
        self.final_url_label.pack(pady=5)

        # Indicators panel
        tk.Label(root, text="Indicators & Explanation:", bg="#0f111a", fg="#39ff14", font=("Consolas", 12, "bold")).pack(pady=(10,0))
        self.indicator_text = scrolledtext.ScrolledText(root, width=110, height=20, font=("Consolas", 11), bg="#1c1f2a", fg="#39ff14", insertbackground="#39ff14")
        self.indicator_text.pack(pady=5)

    # Threaded scan
    def scan_url(self):
        threading.Thread(target=self._scan_url_worker, daemon=True).start()

    def _scan_url_worker(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL!")
            return
        self.indicator_text.delete(1.0, tk.END)
        result = analyze(url)
        self.root.after(0, self.display_result, result)

    def display_result(self, result):
        color = "#39ff14" if result["verdict"]=="SAFE" else "#ffa500" if result["verdict"]=="POTENTIALLY DANGEROUS" else "#ff073a"
        self.verdict_label.config(text=f"Verdict: {result['verdict']}", fg=color)
        self.score_label.config(text=f"Score: {result['score']}")
        self.final_url_label.config(text=f"Final URL: {result['final_url']}")
        self.indicator_text.delete(1.0, tk.END)
        for ind in result["indicators"]:
            explanation = ""
            for key in INDICATOR_EXPLANATIONS:
                if key in ind:
                    explanation = INDICATOR_EXPLANATIONS[key]
                    break
            self.indicator_text.insert(tk.END, f"- {ind}\n  → {explanation}\n")

# ------------------ Run GUI ------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PhishGuardGUI(root)
    root.mainloop()
