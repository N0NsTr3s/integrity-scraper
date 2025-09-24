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
import threading

# Serialize ChromeDriver installs so concurrent tasks don't trigger parallel downloads
INSTALL_LOCK = threading.Lock()

class EnhancedNetworkMonitor:
    def __init__(self, driver_path=None, headless=True, wait_time=10, output_directory='.', excluded_domains=None, excluded_paths=None, download_images=False):
        self.driver_path = driver_path
        self.headless = headless
        self.wait_time = wait_time
        self.driver = None
        # Defer driver installation to setup_driver to avoid network IO in constructor
        # Use provided `driver_path` when available; otherwise will install on demand
        self.driver_executable_path = driver_path
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
        
        # File extension exclusion for change detection
        self.excluded_extensions = ['.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico']
        # Whether to download image resources (SVG/PNG/JPG/etc.). Default False to avoid large downloads.
        self.download_images = download_images
        
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
        self.processed_urls = set()
        
        # Network events storage
        self.network_events = []
        
        # New: Enhanced resource tracking
        self.linked_resources = {}  # Maps request_id to complete request/response/body data
        self.unique_urls = set()    # Track unique URLs found
        self.captured_files = {}    # Maps URL to saved file info with hash
        self.resource_metadata = {} # Comprehensive metadata for all resources
        self.additional_elements = {} # Elements found during individual navigations
        
    async def should_visit(self, url):
        """Check if a URL should be visited based on exclusion rules"""
        try:
            parsed = urlparse(url)
            
            # Skip data URLs, mailto, javascript, etc.
            if parsed.scheme not in ['http', 'https']:
                print(f"⏭️ Skipping non-HTTP URL: {url}")
                return False
            
            # Skip very long URLs (likely data URLs)
            if len(url) > 2000:
                print(f"⏭️ Skipping very long URL: {url}")
                return False
                
            # Skip if no domain
            if not parsed.netloc:
                print(f"⏭️ Skipping URL with no domain: {url}")
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
            
            # Check file extension for exclusion in change detection
            _, ext = os.path.splitext(parsed.path)
            if ext.lower() in self.excluded_extensions:
                # Allow downloading but flag for exclusion from change detection
                print(f"🔍 Image file detected (will be excluded from change reporting): {url}")
            
            return True
            
        except Exception as e:
            print(f"⚠️ Error checking URL {url}: {e}")
            return False
    
    async def set_output_directory(self, domain):
        """Set output directory based on the initial domain and create subfolders for each domain"""
        if self.main_domain is None:
            self.main_domain = domain
            versioned_dir = get_versioned_directory(os.path.join(self.base_output_directory, domain))
            self.output_directory = versioned_dir
            print(f"📁 Set main output directory to: {self.output_directory}")
            
        # Always return the full path including the subdomain folder
        return self.output_directory
    
    async def get_domain_output_directory(self, url_domain):
        """Get the output directory for a specific domain"""
        if self.main_domain is None:
            # If main_domain hasn't been set, use this domain as the main domain
            return self.set_output_directory(url_domain)
        
        # Create subdirectory for this specific domain
        domain_dir = os.path.join(self.output_directory, url_domain)
        os.makedirs(domain_dir, exist_ok=True)
        return domain_dir
    
    async def setup_driver(self):
        """Set up Chrome WebDriver with appropriate options"""
        options = Options()
        if self.headless:
            options.add_argument("--headless")
            
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-extensions")
        options.add_argument("--log-level=3")  # Reduce logging
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-running-insecure-content")
        
        # Enable CDP logging
        options.set_capability("goog:loggingPrefs", {"performance": "ALL", "browser": "ALL"})
        
        # Ensure the driver executable path is available — install lazily and serialize installs
        if not self.driver_executable_path:
            with INSTALL_LOCK:
                # Check again in case another thread installed while we waited on the lock
                if not self.driver_executable_path:
                    self.driver_executable_path = ChromeDriverManager().install()

        service = Service(executable_path=self.driver_executable_path)
        self.driver = webdriver.Chrome(service=service, options=options)
        self.driver.set_page_load_timeout(60)  # Longer timeout for complex pages
        
        return self.driver
    
    async def enable_cdp_domains(self):
        """Enable Chrome DevTools Protocol domains for monitoring"""
        if not self.driver:
            raise ValueError("Driver not initialized")
            
        self.driver.execute_cdp_cmd("Network.enable", {})
        self.driver.execute_cdp_cmd("Page.enable", {})
        self.driver.execute_cdp_cmd("Security.enable", {})
        # Block image loading to improve performance
        self.driver.execute_cdp_cmd('Network.setBlockedURLs', { # type: ignore
            'urls': ['*.jpg', '*.jpeg', '*.png', '*.gif', '*.webp', 
                        '*.svg', '*.bmp', '*.ico', '*.tiff', '*.avif']
        })
        
    async def collect_network_logs(self):
        """Collect and process network logs from Chrome DevTools Protocol"""
        if not self.driver:
            return []
        
        # Get all performance logs
        logs = self.driver.get_log('performance')
        
        # Process each log entry
        for log_entry in logs:
            try:
                # Parse the message as JSON
                network_event = json.loads(log_entry['message'])
                
                # Store all events for reference
                self.network_events.append(network_event)
                
                # Process the event
                await self.process_network_event(network_event['message'])
                
            except json.JSONDecodeError:
                print(f"Failed to parse log entry as JSON: {log_entry}")
            except Exception as e:
                print(f"Error processing log entry: {e}")
                
        return self.network_events
    
    async def process_network_event(self, event):
        """Process individual network events"""
        try:
            method = event.get('method', '')
            params = event.get('params', {})
            
            if method == 'Network.requestWillBeSent':
                await self.process_request_will_be_sent(params)
            elif method == 'Network.responseReceived':
                await self.process_response_received(params)
            elif method == 'Network.loadingFinished':
                await self.process_loading_finished(params)
            elif method == 'Network.loadingFailed':
                await self.process_loading_failed(params)
            elif method == 'Network.requestWillBeSentExtraInfo':
                await self.process_request_extra_info(params)
            elif method == 'Network.responseReceivedExtraInfo':
                await self.process_response_extra_info(params)
                
        except Exception as e:
            print(f"Error processing network event {method}: {e}")
    
    async def process_request_will_be_sent(self, params):
        """Process Network.requestWillBeSent event"""
        request_id = params.get('requestId')
        if not request_id:
            return
            
        request = params.get('request', {})
        url = request.get('url')
        
        if url and url not in self.unique_urls:
            self.unique_urls.add(url)
        
        # Store request information
        self.requests[request_id] = {
            'url': url,
            'method': request.get('method'),
            'headers': request.get('headers', {}),
            'timestamp': params.get('timestamp'),
            'initiator': params.get('initiator', {})
        }
        
        # Update linked resource
        await self.create_linked_resource(request_id)
    
    async def process_response_received(self, params):
        """Process Network.responseReceived event"""
        request_id = params.get('requestId')
        if not request_id:
            return
            
        response = params.get('response', {})
        
        # Store response information
        self.responses[request_id] = {
            'url': response.get('url'),
            'status': response.get('status'),
            'statusText': response.get('statusText'),
            'headers': response.get('headers', {}),
            'mimeType': response.get('mimeType'),
            'timestamp': params.get('timestamp')
        }
        
        # Update linked resource
        await self.create_linked_resource(request_id)
    
    async def create_linked_resource(self, request_id):
        """Create a complete linked resource entry combining request, response, and body"""
        if request_id not in self.linked_resources:
            self.linked_resources[request_id] = {}
            
        linked = self.linked_resources[request_id]
        
        if request_id in self.requests:
            linked['request'] = self.requests[request_id]
            
        if request_id in self.responses:
            linked['response'] = self.responses[request_id]
            
        if request_id in self.response_bodies:
            linked['body'] = self.response_bodies[request_id]
            
        if f"{request_id}_request" in self.extra_info:
            if 'extra_info' not in linked:
                linked['extra_info'] = {}
            linked['extra_info']['request'] = self.extra_info[f"{request_id}_request"]
            
        if f"{request_id}_response" in self.extra_info:
            if 'extra_info' not in linked:
                linked['extra_info'] = {}
            linked['extra_info']['response'] = self.extra_info[f"{request_id}_response"]
            
        if request_id in self.failed_requests:
            linked['failed'] = True
            linked['failure_info'] = self.failed_requests[request_id]
            
        # Add timestamp for when this resource was captured
        linked['captured_at'] = datetime.now().timestamp()
    
    async def process_loading_finished(self, params):
        """Process Network.loadingFinished event"""
        request_id = params.get('requestId')
        if not request_id:
            return
            
        # Update linked resource
        await self.create_linked_resource(request_id)
    
    async def process_loading_failed(self, params):
        """Process Network.loadingFailed event"""
        request_id = params.get('requestId')
        if not request_id:
            return
            
        # Store failure information
        self.failed_requests[request_id] = {
            'errorText': params.get('errorText'),
            'canceled': params.get('canceled', False),
            'blockedReason': params.get('blockedReason'),
            'timestamp': datetime.now().timestamp()
        }
        
        # Update linked resource
        await self.create_linked_resource(request_id)
    
    async def process_request_extra_info(self, params):
        """Process Network.requestWillBeSentExtraInfo event"""
        request_id = params.get('requestId')
        if not request_id:
            return
            
        # Store extra request information
        self.extra_info[f"{request_id}_request"] = {
            'headers': params.get('headers', {}),
            'connectTiming': params.get('connectTiming', {}),
            'clientSecurityState': params.get('clientSecurityState', {})
        }
        
        # Update linked resource
        await self.create_linked_resource(request_id)
    
    async def process_response_extra_info(self, params):
        """Process Network.responseReceivedExtraInfo event"""
        request_id = params.get('requestId')
        if not request_id:
            return
            
        # Store extra response information
        self.extra_info[f"{request_id}_response"] = {
            'headers': params.get('headers', {}),
            'resourceIPAddressSpace': params.get('resourceIPAddressSpace', {}),
            'statusCode': params.get('statusCode')
        }
        
        # Update linked resource
        await self.create_linked_resource(request_id)
    
    async def collect_page_sources(self):
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
                    try {
                        const computed = window.getComputedStyle(el);
                        for (const k of keys) out[k] = computed.getPropertyValue(k);
                    } catch (e) {}
                    return out;
                }

                // Main collection function
                const records = [];
                
                // Scripts
                const scripts = document.querySelectorAll('script');
                scripts.forEach(script => {
                    let content = '';
                    try {
                        // For inline scripts only
                        if (!script.src) {
                            content = script.textContent || '';
                            // Truncate very large scripts
                            if (content.length > 10000) content = content.substring(0, 10000) + '...<truncated>';
                        }
                    } catch (e) {}
                    
                    records.push({
                        tag: 'script',
                        url: script.src || '',
                        attributes: allAttributes(script),
                        dataset: copyDataset(script),
                        styles: safeComputedStyles(script),
                        content: content
                    });
                });
                
                // Links (CSS, etc.)
                const links = document.querySelectorAll('link');
                links.forEach(link => {
                    records.push({
                        tag: 'link',
                        url: link.href || '',
                        attributes: allAttributes(link),
                        dataset: copyDataset(link),
                        styles: safeComputedStyles(link)
                    });
                });
                
                // Images
                const images = document.querySelectorAll('img');
                images.forEach(img => {
                    records.push({
                        tag: 'img',
                        url: img.src || '',
                        attributes: allAttributes(img),
                        dataset: copyDataset(img),
                        styles: safeComputedStyles(img),
                        aria: copyAria(img)
                    });
                });
                
                // iframes
                const iframes = document.querySelectorAll('iframe');
                iframes.forEach(iframe => {
                    records.push({
                        tag: 'iframe',
                        url: iframe.src || '',
                        attributes: allAttributes(iframe),
                        dataset: copyDataset(iframe),
                        styles: safeComputedStyles(iframe),
                        aria: copyAria(iframe)
                    });
                });
                
                return {
                    scanned_at: (new Date()).toISOString(),
                    count: records.length,
                    elements: records
                };
            })());
            """  # JavaScript code to collect elements as JSON string

            # Execute the JavaScript and collect the JSON string result
            records_json = self.driver.execute_script(js_script) # type: ignore
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
            await self.collect_performance_resources()

            return records

        except Exception as e:
            print(f"Error collecting page sources: {e}")
            return None

    async def collect_performance_resources(self):
        """Collect performance resources using Performance API"""
        try:
            # Execute JavaScript to get performance resource timing entries
            js_script = """
            return JSON.stringify(
                Array.from(performance.getEntriesByType('resource')).map(entry => {
                    return {
                        name: entry.name,
                        entryType: entry.entryType,
                        startTime: entry.startTime,
                        duration: entry.duration,
                        initiatorType: entry.initiatorType,
                        nextHopProtocol: entry.nextHopProtocol
                    };
                })
            );
            """
            
            # Execute the JavaScript and collect the JSON string result
            performance_json = await self.driver.execute_script(js_script) # type: ignore
            
            try:
                if performance_json:
                    performance_data = json.loads(performance_json)
                    print(f"⏱️ Collected {len(performance_data)} performance resources")
                    
                    # Store performance data in sources
                    self.sources['performance_resources'] = {
                        'data': performance_data,
                        'collected_at': datetime.now().isoformat()
                    }
                    
                    # Add resources to unique URLs if not already present
                    for resource in performance_data:
                        url = resource.get('name')
                        if url and url not in self.unique_urls:
                            self.unique_urls.add(url)
                    
                    return performance_data
            except Exception as e:
                print(f"⚠️ Failed to parse performance resources: {e}")
                
        except Exception as e:
            print(f"Error collecting performance resources: {e}")
        
        return None
    
    async def monitor_url(self, url, scroll_behavior='end', wait_after_load=None, max_depth=3):
        """Monitor a URL and capture all network activity"""
        print(f"🌐 Starting enhanced network monitoring for: {url} (max_depth={max_depth})")
        
        # Skip if URL should not be visited
        if not await self.should_visit(url):
            print(f"⏭️ Skipping excluded URL: {url}")
            return None
        
        try:
            # Set output directory based on initial domain
            domain = urlparse(url).netloc
            await self.set_output_directory(domain)
            
            if not self.driver:
                await self.setup_driver()
            
            # Check if the URL is unique before navigating
            if url in self.unique_urls:
                print(f"🔍 URL already processed: {url}")
                return None  # Skip navigation if the URL is not unique
            
            # Clear any existing data
            await self.clear_data()
            
            # Enable network monitoring before navigation
            await self.enable_cdp_domains()
            
            print(f"📍 Navigating to: {url}")
            start_time = time.time()
            
            # Navigate to the URL
            self.driver.get(url) # type: ignore
            
            # Wait for page to load
            WebDriverWait(self.driver, self.wait_time).until( # type: ignore
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
            
            # Collect initial network logs
            await self.collect_network_logs()
            
            # Scroll behavior
            if scroll_behavior == 'end':
                self.driver.execute_script("window.scrollTo(0, document.body.scrollHeight);") # type: ignore
                time.sleep(2)  # Wait for potential lazy loading
                await self.collect_network_logs()
            elif scroll_behavior == 'all':
                await self.scroll_page_gradually()
            
            # Determine effective wait_after_load (use configured self.wait_time when None)
            effective_wait = wait_after_load if wait_after_load is not None else self.wait_time
            print(f"⏱️ Waiting {effective_wait} seconds for additional network activity...")
            time.sleep(effective_wait)
            
            # Final collection of network logs
            await self.collect_network_logs()
            
            # Collect page sources - this will populate self.sources['collected_elements']
            dom_elements = await self.collect_page_sources()
            
            # Capture additional elements with SRI attributes from the main page
            domain = urlparse(url).netloc
            output_dir = await self.get_domain_output_directory(domain)
            await self.capture_additional_elements(url, output_dir)
            
            # Add the URL to unique URLs set
            self.unique_urls.add(url)
            
            # Extract all unique URLs and navigate to them
            await self.extract_and_process_unique_urls(url, current_depth=0, max_depth=max_depth)
            
            end_time = time.time()
            print(f"✅ Monitoring completed in {end_time - start_time:.2f} seconds")
            print(f"🔍 Found {len(self.requests)} network requests")
            print(f"📥 Will attempt to download {len(self.unique_urls)} unique resources")
            
            # Prepare scan_data from results
            scan_data = await self.get_results()
            
            # Handle DOM elements collection properly
            if 'collected_elements' in self.sources:
                collected = self.sources['collected_elements']
                if collected and isinstance(collected, dict) and 'elements' in collected:
                    # Group by tag type for easier stats
                    tags = {}
                    for el in collected['elements']:
                        tag = el.get('tag', 'unknown')
                        tags[tag] = tags.get(tag, 0) + 1
                    
                    tag_counts = [f"{count} {tag}" for tag, count in tags.items()]
                    print(f"📄 DOM elements: {', '.join(tag_counts)}")
            
            return scan_data
        
        except Exception as e:
            print(f"❌ Error monitoring URL {url}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    async def scroll_page_gradually(self):
        """Scroll through the page gradually to trigger lazy loading"""
        try:
            # Get page height
            page_height = await elf.driver.execute_script("return document.body.scrollHeight") # type: ignore
            viewport_height = await self.driver.execute_script("return window.innerHeight") # type: ignore
            
            # Scroll in steps
            scroll_position = 0
            scroll_step = viewport_height // 2
            
            while scroll_position < page_height:
                scroll_position += scroll_step
                await self.driver.execute_script(f"window.scrollTo(0, {scroll_position});") # type: ignore
                time.sleep(1)
                await self.collect_network_logs()
                
                # Update page height in case of dynamic content
                page_height = await self.driver.execute_script("return document.body.scrollHeight") # type: ignore
                
        except Exception as e:
            print(f"Error during gradual scrolling: {e}")
    
    async def extract_and_process_unique_urls(self, base_url, current_depth=0, max_depth=2):
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
        processable_urls = await self.filter_processable_urls(base_url)
        print(f"🔍 Found {len(all_urls)} URLs, {len(processable_urls)} are processable")
        
        for url in processable_urls:
            # Skip already processed
            if url in self.processed_urls:
                continue
                
            # Process the URL at increased depth
            await self.process_individual_url(url, current_depth=current_depth+1, max_depth=max_depth)
    
    async def collect_unique_urls(self):
        """Collect unique URLs from all captured data sources"""
        urls = set()
        
        # Extract from network requests
        for req in self.requests.values():
            url = req.get('url')
            if url:
                urls.add(url)
                
        # Extract from DOM elements
        if 'collected_elements' in self.sources and isinstance(self.sources['collected_elements'], dict):
            elements = self.sources['collected_elements'].get('elements', [])
            for el in elements:
                url = el.get('url')
                if url:
                    urls.add(url)
        
        # Extract from performance resources
        if 'performance_resources' in self.sources and isinstance(self.sources['performance_resources'], dict):
            resources = self.sources['performance_resources'].get('data', [])
            for res in resources:
                name = res.get('name')
                if name:
                    urls.add(name)
        
        # Store in self.unique_urls
        self.unique_urls.update(urls)
        return urls
    
    async def filter_processable_urls(self, base_url):
        """Filter URLs to only include processable ones"""
        processable = []
        base_domain = urlparse(base_url).netloc
        
        for url in self.unique_urls:
            # Only include URLs that should be visited based on exclusion rules
            if await self.should_visit(url):
                processable.append(url)
        
        # Sort by domain (same domain first) and remove duplicates
        processable = list(set(processable))
        processable.sort(key=lambda x: (urlparse(x).netloc != base_domain, x))
        
        return processable
    
    async def process_individual_url(self, url, current_depth=1, max_depth=2):
        """Process an individual URL"""
        try:
            # Skip already processed URLs
            if url in self.processed_urls:
                return
            
            # Skip if URL should not be visited
            if not await self.should_visit(url):
                return
                
            print(f"🔍 Processing URL at depth {current_depth}: {url}")
            
            # Mark as processed
            self.processed_urls.add(url)
            self.unique_urls.add(url)
            
            # Generate output directory based on domain
            domain = urlparse(url).netloc
            output_dir = await self.get_domain_output_directory(domain)
            os.makedirs(output_dir, exist_ok=True) # type: ignore
            
            # Download content regardless of whether we navigate to it
            result = self.fetch_and_save_via_requests(url, output_dir)
            
            # Debug external resources
            if 'cdnjs' in url or 'jsdelivr' in url:
                print(f"📦 External resource: {url}, Download result: {result}")
                
            # Check if the URL is a webpage based on its extension
            if current_depth < max_depth and await self.is_webpage(url):
                self.driver.get(url) # type: ignore
                time.sleep(2)
                await self.collect_network_logs()
                
                # Capture additional elements with SRI attributes
                await self.capture_additional_elements(url, output_dir)
                
                # Pass current_depth directly since extract_and_process_unique_urls will increment it when calling process_individual_url
                await self.extract_and_process_unique_urls(url, current_depth, max_depth)
                
        except Exception as e:
            print(f"❌ Error processing URL {url}: {e}")
    
    async def is_webpage(self, url):
        """Check if the URL is likely a webpage based on its extension"""
        webpage_extensions = ['.html', '.htm', '.php', '.asp', '.jsp']
        
        # If the URL has no extension or ends with /, it's probably a webpage
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        # No path or path ends with /
        if not path or path.endswith('/'):
            return True
            
        # Check for webpage extensions
        for ext in webpage_extensions:
            if path.lower().endswith(ext):
                return True
                
        # Check if there's no file extension at all
        if '.' not in path.split('/')[-1]:
            return True
            
        return False
    
    async def get_reports_directory(self):
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

    async def collect_individual_network_logs(self, current_url):
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
                                'type': 'network_request',
                                'timestamp': datetime.now().isoformat()
                            }
                
                except Exception as e:
                    print(f"⚠️ Error processing individual log entry: {e}")
                    
            if new_elements > 0:
                print(f"  🔔 Found {new_elements} new URLs from navigation to {current_url}")
                    
        except Exception as e:
            print(f"⚠️ Error collecting individual network logs: {e}")
    
    async def save_url_content(self, url, content, output_dir, content_type=''):
        """Save URL content to file with hash and check for modifications. Skip images."""
        try:
            from file_change_detector import get_file_hash
            
            # Skip if not binary content (already handled by requests)
            if not isinstance(content, bytes):
                return None
            
            # Generate filename based on URL
            filename = await self._generate_filename_from_url(url, content_type)
            file_path = os.path.join(output_dir, filename)
            
            # Create directory if it doesn't exist
            directory = os.path.dirname(file_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            
            # Skip image downloads entirely when configured to not download images
            _, ext = os.path.splitext(file_path)
            is_image = ext.lower() in self.excluded_extensions

            if is_image and not self.download_images:
                print(f"  ⏭️ Skipping image download (config): {url}")
                # Do not save or track the file to avoid large image downloads
                return None

            if is_image:
                # Save images but mark as excluded from change detection
                with open(file_path, 'wb') as f:
                    f.write(content)

                file_hash = get_file_hash(file_path)

                print(f"  📸 Image file saved (excluded from change detection): {filename}")

                self.captured_files[url] = {
                    'filename': filename,
                    'filepath': file_path,
                    'size': len(content),
                    'hash': file_hash,
                    'content_type': content_type,
                    'captured_at': datetime.now().timestamp(),
                    'excluded_from_change_detection': True
                }
                return file_path
            
            # Save the content
            with open(file_path, 'wb') as f:
                f.write(content)
                
            # Calculate hash
            file_hash = get_file_hash(file_path)
            
            print(f"  💾 Saved: {filename} ({len(content)} bytes, hash: {file_hash[:16]}...)")
            
            # Track in captured files
            self.captured_files[url] = {
                'filename': filename,
                'filepath': file_path,
                'size': len(content),
                'hash': file_hash,
                'content_type': content_type,
                'captured_at': datetime.now().timestamp()
            }
            
            return file_path
            
        except Exception as e:
            print(f"  ❌ Error saving content for {url}: {str(e)}")
            return None
    
    async def fetch_and_save_async(self, url, output_dir, headers=None):
        """Fetch a URL asynchronously and save the content to a file"""
        import aiohttp
        from file_change_detector import get_file_hash
        
        # Skip if URL should not be visited
        if not self.should_visit(url):
            return False

        # Skip image downloads when configured
        if self.is_image_url(url) and not self.download_images:
            print(f"  ⏭️ Skipping async image download (config): {url}")
            return False
        
        try:
            print(f"  📥 Downloading (async): {url}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers or {}, ssl=False) as response:
                    content_type = response.headers.get('Content-Type', '')
                    content = await response.read()
                    
                    # Generate filename based on URL and content type
                    # Use the generate_filename_from_url method
                    filename = await self._generate_filename_from_url(url, content_type)
                    file_path = os.path.join(output_dir, filename)
                    
                    # Create directory if it doesn't exist
                    directory = os.path.dirname(file_path)
                    if directory:
                        os.makedirs(directory, exist_ok=True)
                    
                    # Save content
                    with open(file_path, 'wb') as f:
                        f.write(content)
                    
                    # Calculate hash
                    file_hash = get_file_hash(file_path)
                    
                    # Skip images from change detection reporting based on content type
                    excluded_from_change_detection = False
                    _, ext = os.path.splitext(file_path)
                    if ext.lower() in self.excluded_extensions:
                        excluded_from_change_detection = True
                        print(f"  ⏭️ Image file (excluded from change detection): {url}")
                    else:
                        print(f"  💾 Saved: {filename} ({len(content)} bytes, hash: {file_hash[:16]}...)")
                    
                    self.captured_files[url] = {
                        'filename': filename,
                        'filepath': file_path,
                        'size': len(content),
                        'hash': file_hash,
                        'content_type': content_type,
                        'captured_at': datetime.now().timestamp(),
                        'excluded_from_change_detection': excluded_from_change_detection
                    }
                    
                    return True
        except Exception as e:
            print(f"  ❌ Error saving content for {url}: {str(e)}")
            return False
    
    async def fetch_and_save_via_requests(self, url, output_dir, headers=None):
        """Fetch a URL using requests and save the content to a file"""
        # Skip if URL should not be visited
        if not await self.should_visit(url):
            return False
        
        from file_change_detector import get_file_hash
        try:
            # Skip image downloads when configured
            if await self.is_image_url(url) and not self.download_images:
                print(f"  ⏭️ Skipping image download (config): {url}")
                return False

            print(f"  📥 Downloading: {url}")
            import requests
            
            # Make the request first
            response = requests.get(url, headers=headers or {}, verify=False, timeout=10)
            
            # Get content type from response
            content_type = response.headers.get('Content-Type', '')
            
            # Generate filename based on URL and content type
            filename = await self._generate_filename_from_url(url, content_type)
            file_path = os.path.join(output_dir, filename)
            
            # Create directory if it doesn't exist
            directory = os.path.dirname(file_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            
            # Save content based on type
            with open(file_path, 'wb') as f:
                f.write(response.content)
            
            # Calculate hash after saving
            file_hash = get_file_hash(file_path)
            
            # Check if this is an image file that should be excluded from change detection
            excluded_from_change_detection = False
            _, ext = os.path.splitext(file_path)
            if ext.lower() in self.excluded_extensions:
                excluded_from_change_detection = True
                print(f"  📸 Image file (excluded from change detection): {url}")
            else:
                print(f"  💾 Saved: {filename} ({len(response.content)} bytes, hash: {file_hash[:16]}...)")
            
            self.captured_files[url] = {
                'filename': filename,
                'filepath': file_path,
                'size': len(response.content),
                'hash': file_hash,
                'content_type': content_type,
                'captured_at': datetime.now().timestamp(),
                'excluded_from_change_detection': excluded_from_change_detection
            }
            
            # Special handling for JavaScript files: ensure they're properly saved and analyzed
            if (content_type and 'javascript' in content_type.lower()) or url.endswith('.js'):
                print(f"  📜 JavaScript file detected: {url}")
                # Additional processing for JS files can be added here
            
            return True
        except Exception as e:
            print(f"  ❌ Error saving content for {url}: {str(e)}")
            return False
    
    async def capture_additional_elements(self, current_url, output_dir):
        """Capture any additional elements found on the current page"""
        try:
            # Collect network logs first
            await self.collect_individual_network_logs(current_url)
            
            # Then extract elements with attributes we care about, like SRI
            additional_sources = {}
            
            # Check for script elements with integrity/crossorigin attributes
            scripts = self.driver.find_elements(By.TAG_NAME, "script") # type: ignore
            for i, script in enumerate(scripts):
                src = script.get_attribute("src")
                integrity = script.get_attribute("integrity")
                crossorigin = script.get_attribute("crossorigin")
                
                if src:
                    # Add to unique URLs if not already there
                    if src not in self.unique_urls:
                        self.unique_urls.add(src)
                        
                    additional_sources[f"additional_script_{i}"] = {
                        'url': src,
                        'type': 'script', 
                        'discovered_on': current_url,
                        'integrity': integrity,
                        'crossorigin': crossorigin
                    }
                    
                    # If it has integrity, fetch and save it
                    if integrity and src not in self.captured_files:
                        await self.fetch_and_save_via_requests(src, output_dir)
            
            # Check for link elements (CSS, etc.)
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
    
    async def clear_data(self):
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
    
    async def get_results(self):
        """Get comprehensive monitoring results"""
        # Build full scan object first, then compact it to keep on-disk artifacts small.
        scan_obj = {
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

        try:
            # Local import to avoid circular imports at module level
            from tools.compact_scan import compact_scan_object
            compact = await compact_scan_object(scan_obj)
            return compact
        except Exception:
            # If compaction fails for any reason, return the full scan object as a fallback
            return scan_obj
    
    async def get_statistics(self):
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
            'performance_summary': {},
            'js_files_count': 0,
            'css_files_count': 0,
            'html_files_count': 0,
            'image_files_count': 0
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
            
            # Count by file type
            if 'javascript' in mime_type.lower():
                stats['js_files_count'] += 1
            elif 'css' in mime_type.lower():
                stats['css_files_count'] += 1
            elif 'html' in mime_type.lower():
                stats['html_files_count'] += 1
            elif 'image/' in mime_type.lower():
                stats['image_files_count'] += 1
        
        # Analyze sources
        for source in self.sources.values():
            source_type = source.get('type', 'unknown')
            stats['by_resource_type'][source_type] = stats['by_resource_type'].get(source_type, 0) + 1
            
        # Analyze captured files
        stats['captured_files_count'] = len(self.captured_files)
        stats['excluded_from_change_detection'] = sum(
            1 for file_info in self.captured_files.values() 
            if file_info.get('excluded_from_change_detection', False)
        )
        
        return stats
    
    async def close(self):
        """Close the WebDriver"""
        if self.driver:
            self.driver.quit()
            self.driver = None
    
    async def monitor_url_async(self, url, scroll_behavior='end', wait_after_load=None, max_depth=3):
        """Async wrapper around the blocking monitor_url method.
        
        Uses asyncio.to_thread to run the blocking method in a thread so callers can await it.
        """
        return await asyncio.to_thread(
            self.monitor_url, url, scroll_behavior, wait_after_load, max_depth
        )

    async def close_async(self):
        """Close the driver asynchronously"""
        if self.driver:
            await asyncio.to_thread(lambda: self.driver.quit()) # type: ignore
            self.driver = None
    
    async def is_image_url(self, url):
        """Check if URL is likely an image"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Check extensions
        for ext in self.excluded_extensions:
            if path.endswith(ext):
                return True
        
        # Also check for query strings with image extensions
        for ext in self.excluded_extensions:
            if f"{ext}?" in path or f"{ext}&" in path:
                return True
                
        return False

    # scan_urls_concurrently was intentionally removed from the class body and
    # is implemented as a module-level function below so it can be imported.
    
    async def log_file_changes(self, previous_files):
        """Log file changes between two scans"""
        changes = await self.compare_file_states(previous_files)
        
        # Log changes
        if changes['new_files']:
            print(f"📊 {len(changes['new_files'])} new files:")
            for file_info in changes['new_files']:
                print(f"  📥 {file_info['url']} ({file_info['size']} bytes)")
        
        if changes['deleted_files']:
            print(f"📊 {len(changes['deleted_files'])} deleted files:")
            for file_info in changes['url']:
                print(f"  🗑️ {file_info}")
        
        if changes['modified_files']:
            print(f"📊 {len(changes['modified_files'])} modified files:")
            for file_info in changes['modified_files']:
                size_change = file_info['current_size'] - file_info['previous_size']
                size_indicator = f"({size_change:+d} bytes)" if size_change != 0 else "(same size)"
                print(f"  🔄 {file_info['url']} - {size_indicator}")
                print(f"     Hash: {file_info['previous_hash'][:8]}... → {file_info['current_hash'][:8]}...")
        
        return changes
    
    async def compare_file_states(self, previous_files):
        """Compare current files with previous files"""
        if not previous_files:
            return {
                'new_files': list(self.captured_files.values()),
                'deleted_files': [],
                'modified_files': []
            }
        
        current_files = self.captured_files
        
        new_files = []
        modified_files = []
        
        # Find new and modified files
        for url, current_info in current_files.items():
            # Skip files that are excluded from change detection
            if current_info.get('excluded_from_change_detection', False):
                continue
                
            if url not in previous_files:
                new_files.append(current_info)
            else:
                previous_info = previous_files[url]
                previous_hash = previous_info.get('hash', '')
                current_hash = current_info.get('hash', '')
                
                if previous_hash != current_hash:
                    modified_files.append({
                        'url': url,
                        'previous_hash': previous_hash,
                        'current_hash': current_hash,
                        'previous_size': previous_info.get('size', 0),
                        'current_size': current_info.get('size', 0),
                        'previous_filepath': previous_info.get('filepath', ''),
                        'current_filepath': current_info.get('filepath', '')
                    })
        
        # Find deleted files
        deleted_files = []
        for url in previous_files:
            if url not in current_files:
                deleted_files.append(url)
        
        return {
            'new_files': new_files,
            'deleted_files': deleted_files,
            'modified_files': modified_files
        }
    
    async def extract_urls_from_content(self, content, base_url):
        """Extract URLs from content (HTML, CSS, JS)"""
        urls = set()
        
        # Extract URLs from href="..." or src="..." patterns
        href_pattern = r'(?:href|src)=[\'"](.*?)[\'"]'
        for match in re.finditer(href_pattern, content):
            url = match.group(1)
            if url:
                # Handle relative URLs
                if url.startswith('/') or not urlparse(url).netloc:
                    url = urljoin(base_url, url)
                urls.add(url)
                
        # Extract URLs from CSS url() patterns
        css_pattern = r'url\([\'"]?(.*?)[\'"]?\)'
        for match in re.finditer(css_pattern, content):
            url = match.group(1)
            if url:
                # Handle relative URLs
                if url.startswith('/') or not urlparse(url).netloc:
                    url = urljoin(base_url, url)
                urls.add(url)
                
        # Extract URLs from JavaScript patterns
        js_patterns = [
            r'[\'"]https?://[^\'"]+[\'"]',  # "http://example.com"
            r'[\'"][^\'"\s]+\.[^\'"\s]+[\'"]'  # "example.com"
        ]
        
        for pattern in js_patterns:
            for match in re.finditer(pattern, content):
                url = match.group(0).strip('\'"')
                if url:
                    # Handle relative URLs
                    if url.startswith('/') or not urlparse(url).netloc:
                        url = urljoin(base_url, url)
                    urls.add(url)
                    
        return urls
    
    async def analyze_downloaded_resource(self, url, content, content_type):
        """Analyze a downloaded resource for security issues, embedded URLs, etc."""
        analysis = {
            'url': url,
            'size': len(content),
            'content_type': content_type,
            'security_issues': [],
            'embedded_urls': [],
            'cdn_detected': False
        }
        
        # Check for common CDN providers
        cdn_providers = [
            'cloudflare.com', 'akamai.net', 'cloudfront.net', 'jsdelivr.net',
            'unpkg.com', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net'
        ]
        
        parsed_url = urlparse(url)
        for cdn in cdn_providers:
            if cdn in parsed_url.netloc:
                analysis['cdn_detected'] = True
                analysis['cdn_provider'] = cdn
                break
        
        # Extract embedded URLs
        if content_type and ('javascript' in content_type or 'html' in content_type or 'css' in content_type):
            try:
                content_str = content.decode('utf-8') if isinstance(content, bytes) else content
                embedded_urls = await self.extract_urls_from_content(content_str, url)
                analysis['embedded_urls'] = list(embedded_urls)
            except Exception as e:
                print(f"Error extracting URLs from content: {e}")
        
        # Check for security issues
        if content_type and 'javascript' in content_type:
            # Check for unsafe patterns in JavaScript
            unsafe_patterns = {
                'eval': r'eval\s*\(',
                'document.write': r'document\.write\s*\(',
                'innerHTML': r'\.innerHTML\s*=',
                'localStorage': r'localStorage\.',
                'sessionStorage': r'sessionStorage\.'
            }
            
            try:
                content_str = content.decode('utf-8') if isinstance(content, bytes) else content
                for issue, pattern in unsafe_patterns.items():
                    if re.search(pattern, content_str):
                        analysis['security_issues'].append({
                            'type': issue,
                            'severity': 'medium',
                            'description': f"Use of potentially unsafe {issue}"
                        })
            except Exception as e:
                print(f"Error checking for security issues: {e}")
        
        return analysis
    
    async def generate_filename_from_url(self, url, content_type=None):
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

    # Backwards-compatible alias: some call sites use the underscored name
    async def _generate_filename_from_url(self, url, content_type=None):
        """Alias for generate_filename_from_url kept for backwards compatibility."""
        # Await the underlying async method so this returns a string (filename),
        # not a coroutine object which would break os.path.join and similar callers.
        return await self.generate_filename_from_url(url, content_type)


async def scan_urls_concurrently(urls, max_concurrency=3, **monitor_kwargs):
    """Scan multiple URLs concurrently using multiple EnhancedNetworkMonitor instances.

    This is a module-level function (not a method) so it can be imported as
    `from monitor import scan_urls_concurrently`.

    Args:
        urls: iterable of URLs to scan
        max_concurrency: maximum number of concurrent monitors to run
        **monitor_kwargs: passed to `EnhancedNetworkMonitor` constructor

    Returns:
        list of scan results in the same order as `urls`
    """
    semaphore = asyncio.Semaphore(max_concurrency)
    results = []

    async def scan_url(url):
        async with semaphore:
            print(f"🔄 Starting async scan of {url}")
            # Construct the monitor off the event loop to avoid blocking
            monitor = await asyncio.to_thread(EnhancedNetworkMonitor, **monitor_kwargs)
            try:
                # Use the monitor's async wrapper which will run the blocking monitor_url in a thread
                return await monitor.monitor_url_async(url)
            finally:
                # prefer async close if available
                if hasattr(monitor, 'close_async'):
                    await monitor.close_async()
                else:
                    await asyncio.to_thread(monitor.close)

    # Create tasks and gather results preserving order
    tasks = [asyncio.create_task(scan_url(url)) for url in urls]  # type: ignore
    results = await asyncio.gather(*tasks)
    return results