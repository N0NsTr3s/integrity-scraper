import asyncio
import json
import time
import hashlib
import os
import base64
import requests
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from utils import get_versioned_directory, is_image_url

class EnhancedNetworkMonitor:
    def __init__(self, driver_path=None, headless=True, wait_time=10, output_directory='./output', excluded_domains=None, excluded_paths=None):
        self.driver_path = driver_path
        self.headless = headless
        self.wait_time = wait_time
        self.driver = None
        self.driver_executable_path = ChromeDriverManager().install()
        self.base_output_directory = output_directory  # Store original for reference
        self.output_directory = output_directory
        self.main_domain = None  # Will store the initial domain from arguments
        
        # Exclusion lists for crawler
        self.excluded_domains = excluded_domains or [
            'github.githubassets.com', 'avatars.githubusercontent.com',
            'api.github.com', 'docs.github.com', 'github.blog', 'githubstatus.com',
            'raw.githubusercontent.com', 'github-cloud.s3.amazonaws.com',
            'support.github.com', 'docs.', 'documentation.', 'help.',
            'fonts.googleapis.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
            'youtube.com', 'tiktok.com', 'twitch.tv', 'docs.stripe.com',
            'github.com'
        ]
        
        self.excluded_paths = excluded_paths or [
            '/docs/', '/documentation/', '/help/', '/support/', '/api/',
            '/manifest.json', '/opensearch.xml', '/sitemap', '/robots.txt',
            '/favicon', '/.well-known/', '/security/', '/privacy/',
            '/terms/', '/legal/', '/about/', '/contact/', '/careers/', '/guides/', '/blog/'
        ]
        
        # Enhanced data storage
        self.requests = {}
        self.responses = {}
        self.response_bodies = {}
        self.extra_info = {}
        self.sources = {}
        self.source_contents = {}
        self.failed_requests = {}
        self.security_info = {}
        self.timing_info = {}
        self.processes_urls = {}
        
        # Network events storage
        self.network_events = []
        
        # New: Enhanced resource tracking
        self.linked_resources = {}  # Maps request_id to complete request/response/body data
        self.unique_urls = set()    # Track unique URLs found
        self.captured_files = {}    # Maps URL to saved file info with hash
        self.resource_metadata = {} # Comprehensive metadata for all resources
        self.additional_elements = {} # Elements found during individual navigations
        
        # New: Processed URLs tracking
        self.processed_urls = set()  # Track URLs that have been processed to avoid duplicates
        
    def should_visit(self, url):
        """Check if a URL should be visited based on exclusion rules"""
        try:
            parsed = urlparse(url)
            
            # Skip data URLs, mailto, javascript, etc.
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Skip very long URLs (likely data URLs)
            if len(url) > 2000:
                return False
            
            # Skip if no domain
            if not parsed.netloc:
                return False
            
            # Check excluded domains
            for excluded_domain in self.excluded_domains:
                if excluded_domain in parsed.netloc.lower():
                    print(f"⏭️ Skipping excluded domain: {url}")
                    return False
            
            # Check excluded paths
            for excluded_path in self.excluded_paths:
                if excluded_path.lower() in parsed.path.lower():
                    print(f"⏭️ Skipping excluded path: {url}")
                    return False
            
            return True
            
        except Exception as e:
            print(f"⚠️ Error checking URL {url}: {e}")
            return False
    
    def set_output_directory(self, domain):
        """Set output directory based on the initial domain and create subfolders for each domain"""
        if self.main_domain is None:
            # First time - set the main domain based on the initial URL
            self.main_domain = domain
            self.output_directory = get_versioned_directory(domain)
            print(f"📁 Created main output directory: {self.output_directory}")
        
        # Always return the full path including the subdomain folder
        return self.output_directory
    
    # _get_versioned_directory removed; using utils.get_versioned_directory instead
    
    def get_domain_output_directory(self, url_domain):
        """Get the output directory for a specific domain"""
        if self.main_domain is None:
            raise ValueError("Main domain not set. Call set_output_directory first.")
        
        # Create subdirectory for this specific domain
        domain_dir = os.path.join(self.output_directory, url_domain)
        os.makedirs(domain_dir, exist_ok=True)
        return domain_dir
    
    def setup_driver(self):
        """Setup Chrome driver with CDP logging enabled"""
        chrome_options = Options()
        
        if self.headless:
            chrome_options.add_argument('--headless')
        
        # Essential arguments for CDP
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-web-security')
        chrome_options.add_argument('--allow-running-insecure-content')
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--ignore-ssl-errors')
        chrome_options.add_argument('--disable-extensions')
        chrome_options.add_argument('--disable-plugins')
        
        # Enable performance and network logging
        chrome_options.add_experimental_option('perfLoggingPrefs', {
            'enableNetwork': True,
            'enablePage': True,
        })
        
        # Enable CDP logging
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        
        # Set logging preferences
        chrome_options.set_capability('goog:loggingPrefs', {
            'performance': 'ALL',
            'browser': 'ALL'
        })
        
        if self.driver_path:
            service = Service(self.driver_path)
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
        else:
            self.driver = webdriver.Chrome(options=chrome_options)
        
        # Enable CDP domains
        self.enable_cdp_domains()
        
        return self.driver
    
    def enable_cdp_domains(self):
        """Enable CDP domains for network monitoring"""
        try:
            # Enable Network domain
            self.driver.execute_cdp_cmd('Network.enable', {}) # type: ignore
            
            # Enable Runtime domain for better error handling
            self.driver.execute_cdp_cmd('Runtime.enable', {}) # type: ignore
            
            # Enable Page domain
            self.driver.execute_cdp_cmd('Page.enable', {}) # type: ignore
            
            # Set cache disabled to capture all requests
            self.driver.execute_cdp_cmd('Network.setCacheDisabled', {'cacheDisabled': True}) # type: ignore
            
            # Set user agent override to avoid bot detection
            self.driver.execute_cdp_cmd('Network.setUserAgentOverride', { # type: ignore
                'userAgent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            })
            
            print("✓ CDP domains enabled successfully")
            
        except Exception as e:
            print(f"Warning: Could not enable CDP domains: {e}")
    
    def collect_network_logs(self):
        """Collect network logs using CDP and performance logs"""
        try:
            # Get performance logs
            logs = self.driver.get_log('performance') # type: ignore
            
            print(f"📊 Collected {len(logs)} performance log entries")
            
            for log_entry in logs:
                try:
                    message = json.loads(log_entry['message'])
                    if message.get('message', {}).get('method', '').startswith('Network.'):
                        self.process_network_event(message['message'])
                        self.network_events.append(message['message'])
                except Exception as e:
                    print(f"Error processing log entry: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error collecting network logs: {e}")
    
    def process_network_event(self, event):
        """Process individual network events"""
        try:
            method = event.get('method', '')
            params = event.get('params', {})
            
            if method == 'Network.requestWillBeSent':
                self.process_request_will_be_sent(params)
            elif method == 'Network.responseReceived':
                self.process_response_received(params)
            elif method == 'Network.loadingFinished':
                self.process_loading_finished(params)
            elif method == 'Network.loadingFailed':
                self.process_loading_failed(params)
            elif method == 'Network.requestWillBeSentExtraInfo':
                self.process_request_extra_info(params)
            elif method == 'Network.responseReceivedExtraInfo':
                self.process_response_extra_info(params)
                
        except Exception as e:
            print(f"Error processing network event {method}: {e}")
    
    def process_request_will_be_sent(self, params):
        """Process Network.requestWillBeSent event"""
        request_id = params.get('requestId')
        request = params.get('request', {})
        
        self.requests[request_id] = {
            'requestId': request_id,
            'url': request.get('url', ''),
            'method': request.get('method', ''),
            'headers': request.get('headers', {}),
            'postData': request.get('postData', ''),
            'timestamp': params.get('timestamp', 0),
            'wallTime': params.get('wallTime', 0),
            'initiator': params.get('initiator', {}),
            'type': params.get('type', ''),
            'frameId': params.get('frameId', ''),
            'hasUserGesture': params.get('hasUserGesture', False),
            'redirectResponse': params.get('redirectResponse')
        }
        
        print(f"📤 Request: {request.get('method', '')} {request.get('url', '')}")
    
    def process_response_received(self, params):
        """Process Network.responseReceived event"""
        request_id = params.get('requestId')
        response = params.get('response', {})
        
        self.responses[request_id] = {
            'requestId': request_id,
            'url': response.get('url', ''),
            'status': response.get('status', 0),
            'statusText': response.get('statusText', ''),
            'headers': response.get('headers', {}),
            'mimeType': response.get('mimeType', ''),
            'charset': response.get('charset', ''),
            'timestamp': params.get('timestamp', 0),
            'type': params.get('type', ''),
            'frameId': params.get('frameId', ''),
            'fromDiskCache': response.get('fromDiskCache', False),
            'fromServiceWorker': response.get('fromServiceWorker', False),
            'encodedDataLength': response.get('encodedDataLength', 0),
            'timing': response.get('timing', {}),
            'protocol': response.get('protocol', ''),
            'securityState': response.get('securityState', ''),
            'securityDetails': response.get('securityDetails', {})
        }
        
        # Try to get response body
        try:
            result = self.driver.execute_cdp_cmd('Network.getResponseBody', {'requestId': request_id}) # type: ignore
            if result.get('body'):
                self.response_bodies[request_id] = {
                    'body': result['body'],
                    'base64Encoded': result.get('base64Encoded', False)
                }
        except Exception as e:
            # Response body not available for this request
            pass
        
        # Create linked resource entry
        self.create_linked_resource(request_id)
        
        print(f"📥 Response: {response.get('status', 0)} {response.get('url', '')}")
    
    def create_linked_resource(self, request_id):
        """Create a complete linked resource entry combining request, response, and body"""
        if request_id in self.requests:
            linked_resource = {
                'request_id': request_id,
                'request': self.requests.get(request_id, {}),
                'response': self.responses.get(request_id, {}),
                'body': self.response_bodies.get(request_id, {}),
                'extra_info': {
                    'request': self.extra_info.get(f"{request_id}_request", {}),
                    'response': self.extra_info.get(f"{request_id}_response", {})
                },
                'failed': request_id in self.failed_requests,
                'failure_info': self.failed_requests.get(request_id, {}),
                'captured_at': time.time()
            }
            
            self.linked_resources[request_id] = linked_resource
            
            # Add URL to unique URLs set
            url = self.requests[request_id].get('url', '')
            if url:
                self.unique_urls.add(url)
    
    def process_loading_finished(self, params):
        """Process Network.loadingFinished event"""
        request_id = params.get('requestId')
        
        if request_id in self.responses:
            self.responses[request_id]['loadingFinished'] = True
            self.responses[request_id]['encodedDataLength'] = params.get('encodedDataLength', 0)
            self.responses[request_id]['shouldReportCorbBlocking'] = params.get('shouldReportCorbBlocking', False)
    
    def process_loading_failed(self, params):
        """Process Network.loadingFailed event"""
        request_id = params.get('requestId')
        
        self.failed_requests[request_id] = {
            'requestId': request_id,
            'timestamp': params.get('timestamp', 0),
            'type': params.get('type', ''),
            'errorText': params.get('errorText', ''),
            'canceled': params.get('canceled', False),
            'blockedReason': params.get('blockedReason', '')
        }
        
        print(f"❌ Failed: {params.get('errorText', 'Unknown error')}")
    
    def process_request_extra_info(self, params):
        """Process Network.requestWillBeSentExtraInfo event"""
        request_id = params.get('requestId')
        
        self.extra_info[f"{request_id}_request"] = {
            'associatedCookies': params.get('associatedCookies', []),
            'headers': params.get('headers', {}),
            'connectTiming': params.get('connectTiming', {})
        }
    
    def process_response_extra_info(self, params):
        """Process Network.responseReceivedExtraInfo event"""
        request_id = params.get('requestId')
        
        self.extra_info[f"{request_id}_response"] = {
            'blockedCookies': params.get('blockedCookies', []),
            'headers': params.get('headers', {}),
            'headersText': params.get('headersText', ''),
            'resourceIPAddressSpace': params.get('resourceIPAddressSpace', '')
        }
    
    def collect_page_sources(self):
        """Collect all page sources including scripts, links, images, etc."""
        try:
            print("📄 Collecting page sources...")
            
            # Wait for page to be fully loaded
            WebDriverWait(self.driver, 15).until( # type: ignore
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            time.sleep(3)  # Extra time for JS frameworks
            
            # Then execute your JS collector
            # Execute JavaScript to collect elements and their attributes
            js_script = """
            return JSON.stringify((function() {
                function allAttributes(el) {
                    const attrs = {};
                    try {
                        for (let i = 0; i < el.attributes.length; i++) {
                            const a = el.attributes[i];
                            let val = a.value;
                            if (typeof val === 'string' && val.length > 5000) {
                                val = val.slice(0, 5000) + '...<truncated>';
                            }
                            attrs[a.name] = val;
                        }
                    } catch (e) {}
                    return attrs;
                }

                function copyDataset(el) {
                    const ds = {};
                    if (el.dataset) {
                        for (const k of Object.keys(el.dataset)) ds[k] = el.dataset[k];
                    }
                    return ds;
                }

                function copyAria(el) {
                    const aria = {};
                    for (let i = 0; i < el.attributes.length; i++) {
                        const a = el.attributes[i];
                        if (a.name.startsWith('aria-')) aria[a.name] = a.value;
                    }
                    return aria;
                }

                function safeComputedStyles(el) {
                    const keys = ['display','position','visibility','opacity','width','height'];
                    const out = {};
                    const cs = window.getComputedStyle(el);
                    for (const k of keys) out[k] = cs.getPropertyValue(k);
                    return out;
                }

                function recordForElement(el, context='top') {
                    if (!el || !el.tagName) return null;
                    const rec = {
                        tag: el.tagName.toLowerCase(),
                        context: context,
                        attributes: allAttributes(el),
                        dataset: copyDataset(el),
                        aria: copyAria(el),
                        classList: Array.from(el.classList || []),
                        childrenCount: el.children ? el.children.length : 0,
                        boundingRect: null,
                        computedStyles: safeComputedStyles(el),
                        outerHTML: (el.outerHTML || '').slice(0, 2000)
                    };
                    try {
                        const r = el.getBoundingClientRect();
                        rec.boundingRect = {top: r.top, left: r.left, width: r.width, height: r.height};
                    } catch (e) {}
                    return rec;
                }

                const allEls = Array.from(document.querySelectorAll('*'));
                const records = [];
                const seen = new WeakSet();

                for (const el of allEls) {
                    if (!el.attributes || el.attributes.length === 0) continue;
                    if (seen.has(el)) continue;
                    seen.add(el);
                    const rec = recordForElement(el, 'document');
                    if (rec) records.push(rec);
                }

                const iframes = Array.from(document.getElementsByTagName('iframe') || []);
                for (const frame of iframes) {
                    const fRec = recordForElement(frame, 'top');
                    if (!fRec) continue;
                    fRec.iframe_inner = { sameOrigin: false, src: frame.getAttribute('src') || null, elements: null };
                    try {
                        const doc = frame.contentDocument;
                        if (doc) {
                            fRec.iframe_inner.sameOrigin = true;
                            const innerEls = Array.from(doc.querySelectorAll('*')).filter(e => e.attributes && e.attributes.length);
                            const innerRecords = [];
                            for (const ie of innerEls) {
                                const irec = recordForElement(ie, 'iframe:' + (frame.getAttribute('src')||'inline'));
                                innerRecords.push(irec);
                            }
                            fRec.iframe_inner.elements = innerRecords;
                        }
                    } catch (err) {
                        fRec.iframe_inner.sameOrigin = false;
                        fRec.iframe_inner.error = String(err);
                    }
                    records.push(fRec);
                }


                return {
                    scanned_at: (new Date()).toISOString(),
                    count: records.length,
                    elements: records
                };
            })());
            """  # JavaScript code to collect elements as JSON string

            # Execute the JavaScript and collect the JSON string result
            records_json = self.driver.execute_script(js_script)  # type: ignore
            print("🔍 JS collector raw JSON string length:", len(records_json) if records_json else 0)

            # Try to parse JSON into Python objects
            records = None
            try:
                if records_json:
                    records = json.loads(records_json)
                    # Add the current URL to the records
                    current_url = self.driver.current_url # type: ignore
                    if records and isinstance(records, dict):
                        records['source_url'] = current_url
                        print(f"📄 Collected {records.get('count', 0)} elements from: {current_url}")
                    elif records and isinstance(records, list):
                        # If records is directly a list, create a wrapper dict
                        records = {
                            'source_url': current_url,
                            'count': len(records),
                            'elements': records
                        }
                        print(f"📄 Collected {len(records['elements'])} elements from: {current_url}")
            except Exception as e:
                print(f"⚠️ Failed to parse JS collector JSON: {e}")

            # Store the collected DOM elements in self.sources for later use
            self.sources['collected_elements'] = records

            # Collect performance resources
            self.collect_performance_resources()

            return records

        except Exception as e:
            print(f"Error collecting page sources: {e}")
    
    def collect_performance_resources(self):
        """Collect performance resources using Performance API"""
        try:
            performance_entries = self.driver.execute_script(""" 
                return performance.getEntriesByType('resource').map(entry => ({
                    name: entry.name,
                    entryType: entry.entryType,
                    startTime: entry.startTime,
                    duration: entry.duration,
                    initiatorType: entry.initiatorType,
                    transferSize: entry.transferSize,
                    encodedBodySize: entry.encodedBodySize,
                    decodedBodySize: entry.decodedBodySize,
                    responseStart: entry.responseStart,
                    responseEnd: entry.responseEnd,
                    fetchStart: entry.fetchStart,
                    domainLookupStart: entry.domainLookupStart,
                    domainLookupEnd: entry.domainLookupEnd,
                    connectStart: entry.connectStart,
                    connectEnd: entry.connectEnd,
                    secureConnectionStart: entry.secureConnectionStart,
                    requestStart: entry.requestStart,
                    nextHopProtocol: entry.nextHopProtocol
                }));
            """)
            
            for i, entry in enumerate(performance_entries):
                perf_type = f"performance_{entry.get('initiatorType', 'unknown')}"
                self.sources[f"perf_resource_{i}"] = {
                    'script_id': f"perf_resource_{i}",
                    'url': entry.get('name', ''),
                    'type': perf_type,
                    'element_type': 'performance',
                    'performance_data': entry
                }
                
        except Exception as e:
            print(f"Error collecting performance resources: {e}")
    
    def monitor_url(self, url, scroll_behavior='end', wait_after_load=None, max_depth=3):
        """Monitor a URL and capture all network activity"""
        print(f"🌐 Starting enhanced network monitoring for: {url} (max_depth={max_depth})")
        
        # Skip if URL should not be visited
        if not self.should_visit(url):
            print(f"⏭️ Skipping excluded URL: {url}")
            return None
        
        try:
            # Set output directory based on initial domain
            domain = urlparse(url).netloc
            self.set_output_directory(domain)
            
            if not self.driver:
                self.setup_driver()
            
            # Check if the URL is unique before navigating
            if url in self.unique_urls:
                print(f"🔍 URL already processed: {url}")
                return None  # Skip navigation if the URL is not unique
            
            # Clear any existing data
            self.clear_data()
            
            # Enable network monitoring before navigation
            self.enable_cdp_domains()
            
            print(f"📍 Navigating to: {url}")
            start_time = time.time()
            
            # Navigate to the URL
            self.driver.get(url) # type: ignore
            
            # Wait for page load
            WebDriverWait(self.driver, self.wait_time).until( # type: ignore
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Collect initial network logs (short pause)
            time.sleep(min(5, self.wait_time))
            self.collect_network_logs()
            
            # Scroll behavior
            if scroll_behavior == 'end':
                self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);") # type: ignore
                time.sleep(min(2, self.wait_time))
                self.collect_network_logs()
            elif scroll_behavior == 'all':
                self.scroll_page_gradually()
            
            # Determine effective wait_after_load (use configured self.wait_time when None)
            effective_wait = wait_after_load if wait_after_load is not None else self.wait_time
            print(f"⏱️ Waiting {effective_wait} seconds for additional network activity...")
            time.sleep(effective_wait)
            
            # Final collection of network logs
            self.collect_network_logs()
            
            # Collect page sources - this will populate self.sources['collected_elements']
            dom_elements = self.collect_page_sources()
            
            # Capture additional elements with SRI attributes from the main page
            domain = urlparse(url).netloc
            output_dir = self.get_domain_output_directory(domain)
            self.capture_additional_elements(url, output_dir)
            
            # Add the URL to unique URLs set
            self.unique_urls.add(url)
            
            # Extract all unique URLs and navigate to them
            self.extract_and_process_unique_urls(url, current_depth=0, max_depth=max_depth)
            
            end_time = time.time()
            print(f"✅ Monitoring completed in {end_time - start_time:.2f} seconds")
            print(f"🔍 Found {len(self.requests)} network requests")
            print(f"📥 Will attempt to download {len(self.unique_urls)} unique resources")
            
            # Prepare scan_data from results
            scan_data = self.get_results()
            
            # Handle DOM elements collection properly
            if 'collected_elements' in self.sources:
                collected = self.sources['collected_elements']
                
                # Check if it's a dict with 'elements' key (normal case)
                if isinstance(collected, dict) and 'elements' in collected:
                    scan_data['elements'] = collected['elements']
                    scan_data['element_count'] = collected['count']
                    print(f"✓ Added {collected['count']} DOM elements to scan report")
                
                # Handle the case where it's a list directly
                elif isinstance(collected, list):
                    scan_data['elements'] = collected
                    scan_data['element_count'] = len(collected)
                    print(f"✓ Added {len(collected)} DOM elements to scan report")
                
                # Handle empty case
                else:
                    print("⚠️ No DOM elements collected or invalid format")
                    scan_data['elements'] = []
                    scan_data['element_count'] = 0
            else:
                print("⚠️ No DOM elements collection found")
                scan_data['elements'] = []
                scan_data['element_count'] = 0
                
            # Add DOM resources to scan data
            dom_resources = dom_elements
            
            
            scan_data['dom_resources'] = dom_resources
            print(f"✓ Added {len(dom_resources)} DOM resources to scan report") # type: ignore
            
            # Scan data is returned but scan_report.json is no longer saved
            return scan_data
            
        except Exception as e:
            print(f"❌ Error monitoring URL: {e}")
            return None
    
    def scroll_page_gradually(self):
        """Scroll through the page gradually to trigger lazy loading"""
        try:
            # Get page height
            page_height = self.driver.execute_script("return document.body.scrollHeight") # type: ignore
            viewport_height = self.driver.execute_script("return window.innerHeight") # type: ignore
            
            # Scroll in steps
            scroll_position = 0
            scroll_step = viewport_height // 2
            
            while scroll_position < page_height:
                scroll_position += scroll_step
                self.driver.execute_script(f"window.scrollTo(0, {scroll_position});") # type: ignore
                time.sleep(1)
                self.collect_network_logs()
                
                # Update page height in case of dynamic content
                page_height = self.driver.execute_script("return document.body.scrollHeight") # type: ignore
                
        except Exception as e:
            print(f"Error during gradual scrolling: {e}")
    
    def extract_and_process_unique_urls(self, base_url, current_depth=0, max_depth=2):
        """Extract all unique URLs from page and process them"""
        if current_depth >= max_depth:
            print(f"🛑 Max depth {max_depth} reached, stopping recursion for {base_url}")
            return
            
        # Get all links and resource URLs
        all_urls = set()
        
        # Extract links from anchor tags
        for a_tag in self.driver.find_elements(By.TAG_NAME, "a"): # type: ignore
            href = a_tag.get_attribute('href')
            if href and href not in self.processed_urls:
                all_urls.add(href)
        
        # Extract resource URLs from scripts, stylesheets, images
        for tag_name, attr in [("script", "src"), ("link", "href"), ("img", "src")]:
            for element in self.driver.find_elements(By.TAG_NAME, tag_name): # type: ignore
                url = element.get_attribute(attr)
                if url and url not in self.processed_urls:
                    all_urls.add(url)
                    
        # Also check network requests we've captured
        for request_id, request in self.requests.items():
            url = request.get('url')
            if url and url not in self.processed_urls:
                all_urls.add(url)
        
        # Process each URL
        print(f"📑 Found {len(all_urls)} unique URLs at depth {current_depth}")
        # Filter URLs to only include processable ones
        processable_urls = self.filter_processable_urls(base_url)
        print(f"🔍 Found {len(all_urls)} URLs, {len(processable_urls)} are processable")
        
        for url in processable_urls:
            # Skip already processed
            if url in self.processed_urls:
                continue
            
            # Process this URL
            self.process_individual_url(url, current_depth + 1, max_depth)

    
    def collect_unique_urls(self):
        """Collect unique URLs from all captured data sources"""
        urls = set()

        # URLs from linked resources (already added during response processing)
        for lr in self.linked_resources.values():
            req_url = lr.get('request', {}).get('url', '')
            if req_url and req_url != 'inline':
                urls.add(req_url)
            resp_url = lr.get('response', {}).get('url', '')
            if resp_url and resp_url != 'inline':
                urls.add(resp_url)

        # URLs from page sources
        for source in self.sources.values():
            url = source.get('url', '')
            if url and url != 'inline':
                urls.add(url)

        # URLs from performance entries
        for source in self.sources.values():
            if source.get('element_type') == 'performance':
                perf_data = source.get('performance_data', {})
                url = perf_data.get('name', '')
                if url:
                    urls.add(url)

        # Exclude image URLs
        urls = {u for u in urls if not self.is_image_url(u)}
        self.unique_urls = urls  # Keep as set

        print(f"📋 Collected {len(self.unique_urls)} unique URLs from all sources")
    
    def filter_processable_urls(self, base_url):
        """Filter URLs to only include processable ones"""
        processable = []
        base_domain = urlparse(base_url).netloc
        
        for url in self.unique_urls:
            # Use the global should_visit method
            if self.should_visit(url):
                processable.append(url)
        
        # Sort by domain (same domain first) and remove duplicates
        processable = list(set(processable))
        processable.sort(key=lambda x: (urlparse(x).netloc != base_domain, x))
        
        return processable
    
    def process_individual_url(self, url, current_depth=1, max_depth=2):
        """Process an individual URL"""
        try:
            # Skip already processed URLs
            if url in self.processed_urls:
                return
            
            # Skip if URL should not be visited
            if not self.should_visit(url):
                return
                
            print(f"🔍 Processing URL at depth {current_depth}: {url}")
            
            # Mark as processed
            self.processed_urls.add(url)
            self.unique_urls.add(url)
            
            # Generate output directory based on domain
            domain = urlparse(url).netloc
            output_dir = self.get_domain_output_directory(domain)
            
            # Download content regardless of whether we navigate to it
            result = self.fetch_and_save_via_requests(url, output_dir)
            
            # Debug external resources
            if 'cdnjs' in url or 'jsdelivr' in url:
                print(f"📦 External resource: {url}, Download result: {result}")
                
            # Check if the URL is a webpage based on its extension
            if current_depth < max_depth and self.is_webpage(url):
                self.driver.get(url) # type: ignore
                time.sleep(2)
                self.collect_network_logs()
                
                # Capture additional elements with SRI attributes
                self.capture_additional_elements(url, output_dir)
                
                # Pass current_depth directly since extract_and_process_unique_urls will increment it when calling process_individual_url
                self.extract_and_process_unique_urls(url, current_depth, max_depth)
                
        except Exception as e:
            print(f"❌ Error processing URL {url}: {e}")
    
    def is_webpage(self, url):
        """Check if the URL is likely a webpage based on its extension"""
        webpage_extensions = ['.html', '.htm', '.php', '.asp', '.jsp']
 



    def get_reports_directory(self):
        """Get the reports directory for the main domain with versioning to match output directory"""
        if self.main_domain is None:
            raise ValueError("Main domain not set. Call set_output_directory first.")
        
        # Extract the versioned directory name from output_directory 
        # output_directory could be "./domain" or "./domain_1" etc.
        output_dir_name = os.path.basename(self.output_directory)
        
        # Create matching reports directory structure: ./reports/{same_versioned_name}/
        reports_dir = os.path.join("./reports", output_dir_name)
        os.makedirs(reports_dir, exist_ok=True)
        return reports_dir

    # is_webpage implemented later in the class
    
    def collect_individual_network_logs(self, current_url):
        """Collect network logs specifically for the current navigation"""
        try:
            logs = self.driver.get_log('performance') # type: ignore
            
            new_elements = 0
            for log_entry in logs:
                try:
                    message = json.loads(log_entry['message'])
                    method = message.get('message', {}).get('method', '')
                    
                    if method == 'Network.requestWillBeSent':
                        params = message['message'].get('params', {})
                        request = params.get('request', {})
                        url = request.get('url', '')
                        
                        # Add new unique URLs found during this navigation
                        if url and url not in self.unique_urls:
                            self.unique_urls.add(url)
                            new_elements += 1
                            
                            # Store as additional element
                            self.additional_elements[url] = {
                                'discovered_during': current_url,
                                'method': request.get('method', ''),
                                'headers': request.get('headers', {}),
                                'timestamp': time.time()
                            }
                            
                except Exception as e:
                    continue
            
            if new_elements > 0:
                print(f"  🆕 Found {new_elements} new network elements")
                
        except Exception as e:
            print(f"  ⚠️ Error collecting individual network logs: {e}")
    
    def save_url_content(self, url, content, output_dir, content_type=''):
        """Save URL content to file with hash and check for modifications. Skip images."""
        try:
            # Skip images based on content type or URL
            if 'image/' in content_type.lower() or self.is_image_url(url):
                print(f"  ⏭️ Skipping image: {url}")
                return
                
            # Generate filename from URL with better handling of extensions
            filename = self._generate_filename_from_url(url, content_type)
            file_path = os.path.join(output_dir, filename)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Check for existing file and compare hashes
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    existing_content = f.read()
                    
                # Calculate hashes for comparison
                if isinstance(content, str):
                    content_bytes = content.encode('utf-8')
                else:
                    content_bytes = content
                    
                existing_hash = hashlib.sha256(existing_content).hexdigest()
                new_hash = hashlib.sha256(content_bytes).hexdigest()
                    
                if existing_hash != new_hash:
                    print(f"  🔄 File modified: {filename}")
                    print(f"  - Old hash: {existing_hash[:16]}...")
                    print(f"  - New hash: {new_hash[:16]}...")
                else:
                    print(f"  📁 No changes detected for: {filename}")
                    return  # Exit if no changes
            
            # Save content to file
            with open(file_path, 'wb') as f:
                if isinstance(content, str):
                    f.write(content.encode('utf-8'))
                else:
                    f.write(content)
                    
            # Calculate hash using file_change_detector
            from file_change_detector import get_file_hash, is_javascript_file
            normalize = is_javascript_file(file_path)
            file_hash = get_file_hash(file_path, normalize=normalize)
            
            # Store file info
            self.captured_files[url] = {
                'filename': filename,
                'filepath': file_path,
                'size': len(content) if isinstance(content, str) else len(content),
                'hash': file_hash,
                'content_type': content_type,
                'saved_at': datetime.now().isoformat()
            }
            
            print(f"  💾 Saved: {filename} ({self.captured_files[url]['size']} bytes, hash: {file_hash[:16]}...)")
            
        except Exception as e:
            print(f"  ❌ Error saving content for {url}: {e}")
    
    def fetch_and_save_via_requests(self, url, output_dir, headers=None):
        """Fetch a URL using requests and save the content to a file"""
        # Skip if URL should not be visited
        if not self.should_visit(url):
            return False
        
        from file_change_detector import get_file_hash
        try:
            print(f"  📥 Downloading: {url}")
            import requests
            
            # Make the request first
            response = requests.get(url, headers=headers or {}, verify=False, timeout=10)
            
            # Get content type from response
            content_type = response.headers.get('Content-Type', '')
            
            # Generate filename based on URL and content type
            filename = self._generate_filename_from_url(url, content_type)
            file_path = os.path.join(output_dir, filename)
            
            # Create directory if it doesn't exist
            directory = os.path.dirname(file_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            
            # Save content based on type
            with open(file_path, 'wb') as f:
                f.write(response.content)
            
            # Calculate hash after saving
            content_hash = get_file_hash(file_path)
            
            # Skip images if desired
            if 'image' in content_type.lower() and not url.endswith(('.js', '.css')):
                print(f"  ⏭️ Skipping image file: {url} ({content_type})")
                # Don't return early; still capture metadata
            
            self.captured_files[url] = {
                'filename': filename,
                'filepath': file_path,
                'size': len(response.content),
                'hash': content_hash,
                'content_type': content_type,
                'captured_at': datetime.now().timestamp()
            }
            
            print(f"  💾 Saved: {filename} ({len(response.content)} bytes, hash: {content_hash[:16]}...)")
            return True
        except Exception as e:
            print(f"  ❌ Error saving content for {url}: {str(e)}")
            return False
    
    def capture_additional_elements(self, current_url, output_dir):
        """Capture any additional elements found on the current page"""
        try:
            # Look for any new script, link, or image elements
            additional_sources = {}
            
            # Scripts
            scripts = self.driver.find_elements(By.TAG_NAME, "script") # type: ignore
            for i, script in enumerate(scripts):
                src = script.get_attribute("src")
                if src and src not in self.unique_urls:
                    self.unique_urls.add(src)
                    additional_sources[f"additional_script_{i}"] = {
                        'url': src,
                        'type': 'script',
                        'discovered_on': current_url,
                        'integrity': script.get_attribute("integrity"),
                        'crossorigin': script.get_attribute("crossorigin"),
                        'nonce': script.get_attribute("nonce"),
                        'async': script.get_attribute("async"),
                        'defer': script.get_attribute("defer")
                    }
            
            # Links
            links = self.driver.find_elements(By.TAG_NAME, "link") # type: ignore
            for i, link in enumerate(links):
                href = link.get_attribute("href")
                if href and href not in self.unique_urls:
                    self.unique_urls.add(href)
                    additional_sources[f"additional_link_{i}"] = {
                        'url': href,
                        'type': 'link',
                        'rel': link.get_attribute("rel"),
                        'discovered_on': current_url,
                        'integrity': link.get_attribute("integrity"),
                        'crossorigin': link.get_attribute("crossorigin"),
                        'media': link.get_attribute("media"),
                        'as': link.get_attribute("as")
                    }
            
            if additional_sources:
                print(f"  🔗 Found {len(additional_sources)} additional elements")
                
                # Store additional sources
                for key, source in additional_sources.items():
                    self.additional_elements[source['url']] = source
                
        except Exception as e:
            print(f"  ⚠️ Error capturing additional elements: {e}")
    
    def clear_data(self):
        """Clear all collected data"""
        self.requests.clear()
        self.responses.clear()
        self.response_bodies.clear()
        self.extra_info.clear()
        self.sources.clear()
        self.source_contents.clear()
        self.failed_requests.clear()
        self.security_info.clear()
        self.timing_info.clear()
        self.network_events.clear()
        self.linked_resources.clear()
        self.unique_urls.clear()
        self.captured_files.clear()
        self.resource_metadata.clear()
        self.additional_elements.clear()
    
    def get_results(self):
        """Get comprehensive monitoring results"""
        return {
            'capture_info': {
                'timestamp': datetime.now().isoformat(),
                'total_requests': len(self.requests),
                'total_responses': len(self.responses),
                'total_sources': len(self.sources),
                'total_source_contents': len(self.source_contents),
                'total_bodies': len(self.response_bodies),
                'failed_requests': len(self.failed_requests),
                'linked_resources': len(self.linked_resources),
                'unique_urls': len(self.unique_urls),
                'captured_files': len(self.captured_files),
                'additional_elements': len(self.additional_elements),
                'statistics': self.get_statistics()
            },
            'requests': self.requests,
            'responses': self.responses,
            'extra_info': self.extra_info,
            'bodies': self.response_bodies,
            'sources': self.sources,
            'source_contents': self.source_contents,
            'failed_requests': self.failed_requests,
            'security_info': self.security_info,
            'timing_info': self.timing_info,
            'linked_resources': self.linked_resources,
            'unique_urls': list(self.unique_urls),  # Convert to list for output
            'captured_files': self.captured_files,
            'additional_elements': self.additional_elements
        }
    
    def get_statistics(self):
        """Generate comprehensive statistics"""
        stats = {
            'total_requests': len(self.requests),
            'total_responses': len(self.responses),
            'total_bodies': len(self.response_bodies),
            'total_sources': len(self.sources),
            'total_source_contents': len(self.source_contents),
            'failed_requests': len(self.failed_requests),
            'by_resource_type': {},
            'by_mime_type': {},
            'by_domain': {},
            'by_method': {},
            'by_status': {},
            'security_analysis': {
                'cert_errors': 0
            },
            'performance_summary': {}
        }
        
        # Analyze requests
        for req in self.requests.values():
            # By method
            method = req.get('method', 'UNKNOWN')
            stats['by_method'][method] = stats['by_method'].get(method, 0) + 1
            
            # By domain
            try:
                domain = urlparse(req.get('url', '')).netloc
                stats['by_domain'][domain] = stats['by_domain'].get(domain, 0) + 1
            except:
                pass
        
        # Analyze responses
        for resp in self.responses.values():
            # By status
            status = resp.get('status', 0)
            stats['by_status'][str(status)] = stats['by_status'].get(str(status), 0) + 1
            
            # By MIME type
            mime_type = resp.get('mimeType', 'unknown')
            stats['by_mime_type'][mime_type] = stats['by_mime_type'].get(mime_type, 0) + 1
        
        # Analyze sources
        for source in self.sources.values():
            source_type = source.get('type', 'unknown')
            stats['by_resource_type'][source_type] = stats['by_resource_type'].get(source_type, 0) + 1
        
        return stats
    
    def close(self):
        """Close the driver"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
   

    def is_image_url(self, url):
        return is_image_url(url)
    
    def log_file_changes(self, previous_files):
        """Log changes in files compared to a previous state"""
        current_files = {info['filename']: info for info in self.captured_files.values()}
        
        # Check for new files
        new_files = set(current_files) - set(previous_files)
        for filename in new_files:
            print(f"🆕 New file added: {filename}")
            print(f"  - Details: {current_files[filename]}")
        
        # Check for missing files
        missing_files = set(previous_files) - set(current_files)
        for filename in missing_files:
            print(f"❌ File not found: {filename}")
    
    def compare_file_states(self, previous_files):
        """Compare current captured files with previous state and log changes."""
        current_files = {info['filename']: info for url, info in self.captured_files.items()}
        
        # Check for modified and new files
        for filename, info in current_files.items():
            if filename in previous_files:
                # Compare hashes
                if previous_files[filename]['hash'] != info['hash']:
                    print(f"🔄 File modified: {filename}")
                    print(f"  - Old hash: {previous_files[filename]['hash'][:16]}...")
                    print(f"  - New hash: {info['hash'][:16]}...")
                    # Optionally calculate and show diff for text files
            else:
                print(f"🆕 New file added: {filename}")
                print(f"  - Size: {info['size']} bytes")
                print(f"  - Hash: {info['hash'][:16]}...")

        # Check for missing files
        for filename in previous_files:
            if filename not in current_files:
                print(f"❌ File not found: {filename}")
                print(f"  - Was: {previous_files[filename]['filepath']}")
    
    def extract_urls_from_content(self, content, base_url):
        """Extract additional URLs from file content"""
        found_urls = set()
        
        # Use regex to find URLs in the content
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'url\([\'"]?([^\'")]+)[\'"]?\)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Resolve relative URLs
                full_url = urljoin(base_url, match)
                found_urls.add(full_url)
        
        return found_urls
    
    def analyze_downloaded_resource(self, url, content, content_type):
        """Analyze downloaded resource content for security issues and embedded URLs"""
        analysis = {
            'url': url,
            'content_type': content_type,
            'size': len(content),
            'embedded_urls': [],
            'security_issues': []
        }
        
        try:
            # Extract URLs from content
            if isinstance(content, bytes):
                try:
                    content_str = content.decode('utf-8')
                except:
                    content_str = str(content)
            else:
                content_str = str(content)
                
            embedded_urls = self.extract_urls_from_content(content_str, url)
            analysis['embedded_urls'] = list(embedded_urls)
            
            # Check for security issues in JavaScript
            if 'javascript' in content_type.lower():
                # Check for eval usage
                if 'eval(' in content_str:
                    analysis['security_issues'].append('Uses eval()')
                    
                # Check for document.write
                if 'document.write(' in content_str:
                    analysis['security_issues'].append('Uses document.write()')
                    
                # Check for inline event handlers
                if re.search(r'on\w+\s*=', content_str):
                    analysis['security_issues'].append('Contains inline event handlers')
            
            # Update resource metadata
            self.resource_metadata[url] = analysis
            
            return embedded_urls
            
        except Exception as e:
            print(f"  ⚠️ Error analyzing resource {url}: {e}")
            return set()
    
    def _generate_filename_from_url(self, url, content_type=None):
        """Generate a safe filename from a URL and optional content type."""
        from urllib.parse import urlparse
        import os
        import re
        parsed = urlparse(url)
        path = parsed.path if parsed.path else ''
        
        # If the URL already has a valid extension, use it
        original_extension = os.path.splitext(path)[1].lower()
        valid_extensions = ['.js', '.css', '.html', '.json', '.svg', '.png', '.jpg', '.jpeg', '.gif']
        has_valid_extension = any(original_extension == ext for ext in valid_extensions)
        
        # If path ends with '/', treat it as index
        if path.endswith('/'):
            filename = os.path.join(parsed.netloc, path, 'index')
        else:
            filename = os.path.join(parsed.netloc, path)
        
        # Remove leading slashes and replace remaining slashes with underscores
        filename = filename.lstrip('/').replace('/', '_')
        
        # If there's a query, append it (safely)
        if parsed.query:
            filename += '_' + re.sub(r'[^a-zA-Z0-9._-]', '_', parsed.query)
        
        # Clean unsafe characters
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        
        # Add extension based on content type ONLY if the URL doesn't already have a valid extension
        ext = ''
        if not has_valid_extension:
            if content_type:
                if 'css' in content_type:
                    ext = '.css'
                elif 'javascript' in content_type or 'js' in content_type:
                    ext = '.js'
                elif 'html' in content_type:
                    ext = '.html'
                elif 'json' in content_type:
                    ext = '.json'
                elif 'svg' in content_type:
                    ext = '.svg'
                elif 'png' in content_type:
                    ext = '.png'
                elif 'jpg' in content_type or 'jpeg' in content_type:
                    ext = '.jpg'
                elif 'gif' in content_type:
                    ext = '.gif'
                else:
                    # Default to html ONLY if we couldn't determine anything else
                    ext = '.html'
        
        # Only add extension if not already present
        if ext and not filename.endswith(ext):
            filename += ext
            
        # Fallback if filename is empty
        if not filename:
            filename = 'file_' + str(abs(hash(url)))
            
        return filename