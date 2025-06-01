FORBIDDEN FRUIT SCANNER is an advanced, asynchronous web vulnerability scanner designed to detect a wide range of security issues such as XSS, SQL Injection, Remote Code Execution, Local File Inclusion, and more. This ethical hacking tool aims to surpass existing scanners like XSStrike by leveraging modern Python async capabilities, detailed payloads, context-aware scanning, and more.

Features
Asynchronous scanning for faster results

Multiple vulnerability detection types: XSS, SQLi, RCE, LFI, and more

WAF (Web Application Firewall) detection and evasion techniques

Context-aware payload injection and DOM-based XSS detection

Advanced crawling and fuzzing capabilities

Plugin/template system for extensibility

Generates detailed JSON reports

Ethical use only — only scan systems you own or have permission to test

Installation
This scanner is designed to run on Kali Linux or any Debian-based system with Python 3.8+.

Required dependencies
Make sure you have the following installed:

Python 3.8 or newer (check with python3 --version)

pip (Python package installer)

Install Python packages with:

bash
Copy
Edit
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install -r requirements.txt
Typical Python dependencies
Your requirements.txt should include (depending on your code):

nginx
Copy
Edit
httpx
beautifulsoup4
lxml
playwright
colorama
tqdm
If you use Playwright, install browsers:

bash
Copy
Edit
playwright install
Usage
Run the scanner with:

bash
Copy
Edit
python3 ffd.py
