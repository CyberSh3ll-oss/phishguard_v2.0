# phishguard_v2.0
This is the much more sofisticated and with gui version of the previous version of the phishguard v 1.0
# PhishGuard — Hacker-Style Phishing URL Scanner (Python GUI)

![PhishGuard Logo](gov_logo.png)  <!-- Optional: include if you have a logo -->

PhishGuard is a **Python-based phishing URL detection tool** with a **hacker-style GUI**. It allows users to quickly analyze URLs and domains for potential phishing threats using **heuristics, blacklist checks, and URL analysis**. Designed for students, cybersecurity enthusiasts, and ethical hackers.  

---

## Features

- **Hacker-style GUI** using **Tkinter** with neon colors and dark theme.  
- **Local blacklist support** to block known malicious domains or URLs.  
- **Heuristic checks** including:  
  - IP-as-host detection  
  - Long URLs  
  - Suspicious keywords (`login`, `bank`, `update`, etc.)  
  - '@' trick detection  
  - Many subdomains  
  - Double slashes in path  
- **HTTP/HTTPS & redirect checks**  
- **Score-based verdict**:  
  - **SAFE:** 0–14  
  - **POTENTIALLY DANGEROUS:** 15–39  
  - **PHISHING:** 40+  
- **Explanation panel** in GUI shows why a URL is flagged.  
- Optional support for **future GUI frameworks** like **PySide6** or **DearPyGUI**.

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/<username>/phishguard.git
cd phishguard
