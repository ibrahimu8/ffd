🍇 Forbidden Fruit Scanner (FFS) v8.0
"The XSStrike Killer" - Advanced Web Vulnerability Scanner with WAF Evasion

Demo:

🔥 Features
Context-aware XSS (HTML/JS/Attribute/URL)

WAF Bypass (Cloudflare, ModSecurity, Akamai)

Multi-Vulnerability Detection: XSS, SQLi, RCE, LFI

DOM-based XSS Scanning

Stealth Mode: Randomized delays, IP spoofing, header rotation

JSON Reports with attack stats

⚡ Kali Linux Setup
📦 Dependencies
Run these commands in Kali:

sudo apt update && sudo apt install -y python3 python3-pip git
git clone https://github.com/ibrahimu8/ffd.git
cd ffd
pip3 install -r requirements.txt
🛠️ Required Packages
Python 3.10+ (python3 --version)

Libraries:

pip3 install aiohttp beautifulsoup4 colorama urllib3
Optional (For Tor Proxy):

sudo apt install tor
sudo service tor start
Set PROXY = "socks5://localhost:9050" in the script.

🚀 Usage
python3 ffs.py
Enter target URL (e.g., http://testphp.vulnweb.com)

Select scan type (XSS/SQLi/RCE/LFI/All)

Wait for results!

🎯 Example
python3 ffs.py
[?] Enter target URL: http://example.com
[?] Select tests (comma separated): 1,2,3
📝 Output Example
[+] Found 23 URLs
[!] Found XSS in "search" @ http://example.com/search?q=<script>alert(1)</script>
[*] Report saved to scan_example.com_123456789.json
📌 Pro Tips
Stealth Mode: Add longer delays in REQUEST_DELAY = (1.0, 3.0)

Tor Proxy: Enable in config for anonymity.

Custom Payloads: Edit PayloadGenerator class.

📜 Legal Warning
⚠️ Only scan systems you own or have explicit permission to test!
This tool is for educational and authorized pentesting only.

🛑 Known Issues
False positives on binary files (images/PDFs) - Will be fixed in v8.1

Slow on large sites - Optimize with MAX_CONCURRENT = 25
