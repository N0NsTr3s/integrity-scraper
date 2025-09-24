#!/usr/bin/env python3
"""
Website Integrity Workflow Manager
Handles the entire workflow of scanning, analyzing, and reporting
"""
import os
import json
import time
import asyncio
from typing import Optional

import yaml
from datetime import datetime
from urllib.parse import urlparse

from monitor import EnhancedNetworkMonitor, scan_urls_concurrently
from analyze_pci_compliance import analyze_captured_data
from file_change_detector import detect_changes
from utils import load_config, get_reports_directory_from_domain


def compact_scan_object(scan_obj):
    """Create a compacted scan object grouping data per request (used for smaller artifacts).

    This mirrors the logic in tools/compact_scan.py but is embedded here to avoid
    importing the tools module as a package.
    """
    linked = (scan_obj.get('linked_resources') or {})
    requests = (scan_obj.get('requests') or {})
    responses = (scan_obj.get('responses') or {})
    bodies = (scan_obj.get('bodies') or {})
    extra = (scan_obj.get('extra_info') or {})
    failed = (scan_obj.get('failed_requests') or {})
    captured_files = (scan_obj.get('captured_files') or {})
    sources = (scan_obj.get('sources') or {})

    # Build simple index of sources by URL
    src_idx = {}
    for sid, s in sources.items():
        url = None
        if isinstance(s, dict):
            url = s.get('url')
            if not url:
                pd = s.get('performance_data')
                if pd and isinstance(pd, dict):
                    url = pd.get('name')
        if url:
            src_idx.setdefault(url, []).append({'id': sid, 'source': s})

    grouped = {}
    processed = set()

    for rid, lr in linked.items():
        req = lr.get('request') or {}
        url = req.get('url')
        entry = {
            'request_id': rid,
            'request': req,
            'response': lr.get('response') or responses.get(rid) or {},
            'body': lr.get('body') or bodies.get(rid) or {},
            'extra_info': lr.get('extra_info') or {
                'request': extra.get(f"{rid}_request", {}),
                'response': extra.get(f"{rid}_response", {})
            },
            'failed': lr.get('failed', False) or (rid in failed),
            'failure_info': lr.get('failure_info', {}) or failed.get(rid, {}),
            'captured_at': lr.get('captured_at')
        }

        related_sources = src_idx.get(url, []) if url else []
        if related_sources:
            entry['sources'] = related_sources

        if url in captured_files:
            entry['captured_file'] = captured_files.get(url)
        else:
            if url:
                base = url.split('?', 1)[0]
                if base in captured_files:
                    entry['captured_file'] = captured_files.get(base)

        grouped[rid] = entry
        processed.add(rid)

    for rid, req in requests.items():
        if rid in processed:
            continue
        url = req.get('url')
        entry = {
            'request_id': rid,
            'request': req,
            'response': responses.get(rid, {}),
            'body': bodies.get(rid, {}),
            'extra_info': {
                'request': extra.get(f"{rid}_request", {}),
                'response': extra.get(f"{rid}_response", {})
            },
            'failed': rid in failed,
            'failure_info': failed.get(rid, {}),
        }
        related_sources = src_idx.get(url, []) if url else []
        if related_sources:
            entry['sources'] = related_sources
        if url in captured_files:
            entry['captured_file'] = captured_files.get(url)
        grouped[rid] = entry

    compact_info = {
        'timestamp': scan_obj.get('capture_info', {}).get('timestamp'),
        'total_grouped_resources': len(grouped),
        'total_requests': scan_obj.get('capture_info', {}).get('total_requests'),
        'total_responses': scan_obj.get('capture_info', {}).get('total_responses')
    }

    # Build URL -> request_id map
    url_to_rids = {}
    for r_id, r_req in requests.items():
        u = r_req.get('url') or (responses.get(r_id) or {}).get('url')
        if u:
            url_to_rids.setdefault(u, []).append(r_id)

    def find_rids_for_url(u):
        if not u:
            return []
        if u in url_to_rids:
            return url_to_rids[u]
        base = u.split('?', 1)[0]
        if base in url_to_rids:
            return url_to_rids[base]
        try:
            p = urlparse(u)
            for k in url_to_rids:
                kp = urlparse(k)
                if kp.netloc == p.netloc and kp.path == p.path:
                    return url_to_rids[k]
        except Exception:
            pass
        return []

    for rid, req in requests.items():
        initiator = req.get('initiator') or {}
        initiator_urls = set()
        if isinstance(initiator, dict):
            if 'url' in initiator and initiator.get('url'):
                initiator_urls.add(initiator.get('url'))
            stack = initiator.get('stack') or initiator.get('stackTrace')
            if stack and isinstance(stack, dict):
                for cf in stack.get('callFrames', []) or []:
                    if cf.get('url'):
                        initiator_urls.add(cf.get('url'))

        dependent_on = {}
        for iu in list(initiator_urls):
            for target_rid in find_rids_for_url(iu):
                if target_rid and target_rid != rid:
                    target_url = requests.get(target_rid, {}).get('url') or responses.get(target_rid, {}).get('url')
                    if not target_url:
                        continue
                    dependent_on[target_rid] = target_url
                    tgt = grouped.get(target_rid)
                    if tgt is not None:
                        tgt.setdefault('is_dependency_for', {})
                        tgt['is_dependency_for'][rid] = requests.get(rid, {}).get('url') or responses.get(rid, {}).get('url')

        if dependent_on:
            grouped.setdefault(rid, {}).setdefault('dependent_on', {})
            grouped[rid]['dependent_on'].update(dependent_on)

    # Build a simple map of requestId -> url for quick lookup
    request_map = {}
    for r_id, r_req in requests.items():
        u = r_req.get('url') or (responses.get(r_id) or {}).get('url')
        if u:
            request_map[r_id] = u

    # Determine primary domain (best-effort)
    def determine_primary_domain(requests, responses):
        for r_id, r in requests.items():
            if str(r.get('type', '')).lower() == 'document':
                u = r.get('url')
                if u:
                    return urlparse(u).netloc
        for r_id, resp in responses.items():
            mt = resp.get('mimeType', '') or ''
            if isinstance(mt, str) and mt.startswith('text/html'):
                u = resp.get('url')
                if u:
                    return urlparse(u).netloc
        hosts = {}
        for r in requests.values():
            u = r.get('url')
            if u:
                h = urlparse(u).netloc
                hosts[h] = hosts.get(h, 0) + 1
        if hosts:
            # pick the host with max count
            max_host = None
            max_count = 0
            for h, c in hosts.items():
                if c > max_count:
                    max_count = c
                    max_host = h
            return max_host or ''
        return ''

    primary_domain = determine_primary_domain(requests, responses)

    def host_of(u):
        try:
            return urlparse(u).netloc
        except Exception:
            return ''

    for rid, entry in list(grouped.items()):
        party = 'unknown'
        reason = ''
        url = request_map.get(rid) or (entry.get('request') or {}).get('url')
        host = host_of(url)
        if primary_domain and host == primary_domain:
            party = 'first'
            reason = 'host matches primary domain'
        else:
            req = entry.get('request') or {}
            initiator = req.get('initiator') or {}
            initiator_urls = set()
            if isinstance(initiator, dict):
                if initiator.get('url'):
                    initiator_urls.add(initiator.get('url'))
                stack = initiator.get('stack') or initiator.get('stackTrace')
                if stack and isinstance(stack, dict):
                    for cf in stack.get('callFrames', []) or []:
                        if cf.get('url'):
                            initiator_urls.add(cf.get('url'))
            referer = (req.get('headers') or {}).get('Referer') or (req.get('headers') or {}).get('referer')
            if referer:
                initiator_urls.add(referer)

            deps = entry.get('dependent_on') or {}
            if deps:
                if any(host_of(u) == primary_domain for u in deps.values()):
                    party = 'third'
                    reason = 'immediate dependency points to primary domain'
                else:
                    party = 'fourth'
                    reason = 'depends on non-primary resources (transitive)'
            else:
                if any(host_of(u) == primary_domain for u in initiator_urls):
                    party = 'third'
                    reason = 'initiator/referrer is primary domain'
                else:
                    party = 'third'
                    reason = 'non-primary resource with no detected primary dependency'

        entry['party'] = party
        entry['party_reason'] = reason

    return {'capture_info': compact_info, 'grouped': grouped, 'request_map': request_map}


class IntegrityWorkflow:
    """Workflow manager for website integrity monitoring"""
    
    def __init__(self, url, config=None, config_path="./config.yaml", logger=None):
        """Initialize the workflow manager
        
        Args:
            url (str): The URL to scan
            config (dict, optional): Configuration dictionary
            logger (logging.Logger, optional): Logger instance
        """
        self.url = url
        # Prefer an explicit config dict, else load from provided config_path, else fallback to standard config.yaml
        if config is not None:
            self.config = config
        else:
            cfg_path = config_path if config_path else os.path.join(os.path.dirname(__file__), 'config.yaml')
            self.config = load_config(cfg_path)
        self.logger = logger
        
        # Extract domain for reference (monitor will handle actual directory creation)
        self.domain = urlparse(url).netloc.replace(':', '_')
        
        # Initialize results
        self.scan_results = None
        self.analysis_results = None
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # This will be set after the monitor creates its directory structure
        self.output_dir = None
        
    def get_reports_directory(self):
        """Get the reports directory for this domain with versioning to match output directory"""
        # If we have a monitor instance, use its reports directory
        if hasattr(self, 'monitor') and self.monitor:
            return self.monitor.get_reports_directory()
        # Fallback: create/get a reports directory matching the domain or monitor output
        output_dir = getattr(self, 'output_dir', None)
        return get_reports_directory_from_domain(self.domain, output_dir)
        
    def _load_config(self):
        """Load configuration from config.yaml file"""
        config_file = os.path.join(os.path.dirname(__file__), "config.yaml")
        
        DEFAULT_CONFIG = {
            "output_dir": "scan_results",
            "default_depth": 2,
            "headless": True,
            "wait_time": 10,
            "excluded_domains": [
                "github.com",
                "fonts.googleapis.com",
                "cdn.",
                "docs."
            ]
        }
        
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                try:
                    user_config = yaml.safe_load(f)
                    if user_config:
                        return {**DEFAULT_CONFIG, **user_config}
                except Exception as e:
                    print(f"Error loading config file: {e}")
        
        return DEFAULT_CONFIG
    
    def _log(self, message):
        """Log a message"""
        if self.logger:
            self.logger.info(message)
        else:
            print(message)
    
    def run_full_workflow(self):
        """Run the complete workflow"""
        self._log(f"Starting full workflow for {self.url}")
        
        try:
            self.scan_website()
            self.analyze_results()
            return True
        except Exception as e:
            self._log(f"Error in workflow: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def run_full_workflow_async(self):
        """Run the complete workflow asynchronously"""
        self._log(f"Starting async full workflow for {self.url}")
        
        try:
            await self.scan_website_async()
            # Run analysis in a thread to avoid blocking
            await asyncio.to_thread(self.analyze_results)
            return True
        except Exception as e:
            self._log(f"Error in async workflow: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def scan_website(self):
        """Run the website scan"""
        self._log(f"Starting scan of {self.url}")
        
        # Initialize monitor
        self.monitor = EnhancedNetworkMonitor(
            headless=self.config.get("headless", True), 
            wait_time=self.config.get("wait_time", 10)
        )
        
        try:
            # Perform monitoring to set up directory structure
            depth = self.config.get("default_depth", 3)
            self._log(f"Scanning with depth {depth}")
            
            # First monitor call will set up the directory structure
            # Use configured wait_time for post-load sleeping when available
            results = self.monitor.monitor_url(self.url, wait_after_load=self.config.get('wait_time', 5), max_depth=depth)
            
            # Some monitor implementations may return a coroutine from monitor_url.
            # If so, resolve it here so downstream code receives actual data (dict) instead of a coroutine.
            if asyncio.iscoroutine(results):
                try:
                    # Prefer asyncio.run when there's no running loop
                    results = asyncio.run(results)
                except RuntimeError:
                    # If an event loop is already running, try to safely run the coroutine
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # Create a temporary new loop to avoid interfering with the running loop
                        new_loop = asyncio.new_event_loop()
                        try:
                            asyncio.set_event_loop(new_loop)
                            results = new_loop.run_until_complete(results)
                        finally:
                            asyncio.set_event_loop(loop)
                            new_loop.close()
                    else:
                        results = loop.run_until_complete(results)
            
            # Now get the output directory from the monitor
            self.output_dir = self.monitor.output_directory
            
            # Find previous scan for comparison
            previous_scan = self._find_previous_scan()
            
            # Save scan results
            if results:
                self.scan_results = [results]

                # Save compact scan to reports directory. The monitor may already
                # return a compact object (if it performed compaction). Detect
                # that and avoid double-compaction.
                reports_dir = self.get_reports_directory()
                # If the monitor implementation returns a coroutine for the reports directory,
                # resolve it here so os.path.join receives a string.
                if asyncio.iscoroutine(reports_dir):
                    reports_dir = asyncio.run(reports_dir)
                # Ensure the reports directory exists.
                os.makedirs(reports_dir, exist_ok=True)

                # If results looks like a compact object (has 'grouped' or 'request_map'),
                # write it directly. Otherwise compact it using the embedded helper.
                if isinstance(results, dict) and ('grouped' in results or 'request_map' in results):
                    compact_obj = results
                else:
                    compact_obj = compact_scan_object(results)

                compact_results = [compact_obj]
                compact_file = os.path.join(reports_dir, f"scan_{self.timestamp}_compact.json")
                with open(compact_file, 'w', encoding='utf-8') as f:
                    json.dump(compact_results, f, indent=2, ensure_ascii=False)
                self._log(f"Compact scan results saved to: {compact_file}")

                # Point scan_file to the compact file so downstream steps use it
                self.scan_file = compact_file

                # Compare with previous scan if available. Pass the compact scan
                # object as the "current" scan so comparison works on compact
                # artifacts only.
                if previous_scan:
                    current_compact = compact_obj
                    self._compare_with_previous(previous_scan, current_compact)
            
        finally:
            # Cleanup
            if self.monitor and self.monitor.driver:
                self.monitor.driver.close()
    
    async def scan_website_async(self):
        """Run the website scan asynchronously"""
        self._log(f"Starting async scan of {self.url}")
        
        # Initialize monitor
        self.monitor = EnhancedNetworkMonitor(
            headless=self.config.get("headless", True), 
            wait_time=self.config.get("wait_time", 10)
        )
        
        try:
            # Perform monitoring to set up directory structure
            depth = self.config.get("default_depth", 3)
            self._log(f"Scanning with depth {depth} (async)")
            
            # Use the async version of monitor_url
            results = await self.monitor.monitor_url_async(
                self.url, 
                wait_after_load=self.config.get('wait_time', 5), 
                max_depth=depth
            )
            
            # Now get the output directory from the monitor
            self.output_dir = self.monitor.output_directory
            
            # Find previous scan for comparison
            previous_scan = self._find_previous_scan()
            
            # Save scan results
            if results:
                self.scan_results = [results]
                
                # Define a synchronous function to process results in a thread
                def process_results():
                    # Save compact scan to reports directory
                    reports_dir = self.get_reports_directory()
                    
                    # Resolve coroutine reports_dir (some monitor implementations may return a coroutine)
                    if asyncio.iscoroutine(reports_dir):
                        reports_dir = asyncio.run(reports_dir)
                    
                    # Ensure the reports directory exists
                    os.makedirs(reports_dir, exist_ok=True)
                    
                    # Check if results is already a compact object
                    if isinstance(results, dict) and ('grouped' in results or 'request_map' in results):
                        compact_obj = results
                    else:
                        compact_obj = compact_scan_object(results)
                    
                    compact_results = [compact_obj]
                    compact_file = os.path.join(reports_dir, f"scan_{self.timestamp}_compact.json")
                    
                    with open(compact_file, 'w', encoding='utf-8') as f:
                        json.dump(compact_results, f, indent=2, ensure_ascii=False)
                    
                    self._log(f"Compact scan results saved to: {compact_file}")
                    self.scan_file = compact_file
                    
                    return compact_obj, compact_file
                
                # Run the processing in a thread
                compact_obj, compact_file = await asyncio.to_thread(process_results)
                
                # Compare with previous scan if available
                if previous_scan:
                    # Run comparison in a thread to avoid blocking
                    await asyncio.to_thread(
                        self._compare_with_previous, 
                        previous_scan, 
                        compact_obj
                    )
            
        finally:
            # Cleanup
            if self.monitor and self.monitor.driver:
                await self.monitor.close_async()
    
    async def scan_multiple_urls(self, urls, max_concurrency=3):
        """Scan multiple URLs concurrently
        
        Args:
            urls: List of URLs to scan
            max_concurrency: Maximum number of concurrent scans
            
        Returns:
            List of results in the same order as input URLs
        """
        self._log(f"Starting concurrent scan of {len(urls)} URLs with max concurrency {max_concurrency}")
        
        # Prepare monitor kwargs from config
        monitor_kwargs = {
            'headless': self.config.get('headless', True),
            'wait_time': self.config.get('wait_time', 10),
            'output_directory': self.config.get('output_dir', './output')
        }
        
        # Use scan_urls_concurrently from monitor.py
        results = await scan_urls_concurrently(
            urls=urls,
            max_concurrency=max_concurrency,
            **monitor_kwargs
        )
        
        # Process and save all results
        processed_results = []
        for i, result in enumerate(results):
            # If a monitor returned a coroutine (some implementations do), await it here
            try:
                if asyncio.iscoroutine(result):
                    result = await result
            except Exception as e:
                self._log(f"Error resolving coroutine result for URL index {i}: {e}")
                continue

            if not result:
                continue

            # For each result, compact and save it
            if isinstance(result, dict) and ('grouped' in result or 'request_map' in result):
                compact_obj = result
            else:
                compact_obj = compact_scan_object(result)

            processed_results.append(compact_obj)

            # Save to disk (non-async for simplicity)
            url = urls[i]
            domain = urlparse(url).netloc
            reports_dir = get_reports_directory_from_domain(domain)
            os.makedirs(reports_dir, exist_ok=True)

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            compact_file = os.path.join(reports_dir, f"scan_{timestamp}_url{i}_compact.json")

            with open(compact_file, 'w', encoding='utf-8') as f:
                json.dump([compact_obj], f, indent=2)

            self._log(f"Saved result {i} for {url} to {compact_file}")
        
        self._log(f"Completed concurrent scanning of {len(urls)} URLs")
        return processed_results
    
    def _find_previous_scan(self):
        """Find the most recent scan file"""
        if not os.path.exists(self.output_dir): # type: ignore
            return None
            
        files = [f for f in os.listdir(self.output_dir) 
                if f.startswith('scan_') and f.endswith('.json')]
        
        if not files:
            return None
        
        files.sort(key=lambda f: os.path.getmtime(os.path.join(self.output_dir, f)), reverse=True) # type: ignore
        return os.path.join(self.output_dir, files[0]) if files else None # type: ignore
    
    def _compare_with_previous(self, previous_scan, current_files):
        """Compare current scan with previous scan"""
        from file_change_detector import detect_changes, is_image_file

        # Load the previous captured files
        try:
            with open(previous_scan, 'r', encoding='utf-8') as f:
                previous_scan_data = json.load(f)

            # Initialize previous_files
            previous_files = {}

            # Extract captured files from the previous scan data.
            # Support both full-format scans (with 'captured_files') and
            # compact-format scans (with 'grouped').
            if isinstance(previous_scan_data, list):
                for scan_result in previous_scan_data:
                    if not isinstance(scan_result, dict):
                        continue
                    if 'captured_files' in scan_result:
                        previous_files.update(scan_result['captured_files'] or {})
                    elif 'grouped' in scan_result:
                        # compact format: grouped is dict of rid->entry
                        for entry in (scan_result.get('grouped') or {}).values():
                            # Prefer URL from request or response
                            url = None
                            req = entry.get('request') or {}
                            resp = entry.get('response') or {}
                            url = req.get('url') or resp.get('url')
                            cf = entry.get('captured_file')
                            if url and cf is not None:
                                previous_files[url] = cf
            elif isinstance(previous_scan_data, dict):
                if 'captured_files' in previous_scan_data:
                    previous_files = previous_scan_data.get('captured_files') or {}
                elif 'grouped' in previous_scan_data:
                    for entry in (previous_scan_data.get('grouped') or {}).values():
                        url = None
                        req = entry.get('request') or {}
                        resp = entry.get('response') or {}
                        url = req.get('url') or resp.get('url')
                        cf = entry.get('captured_file')
                        if url and cf is not None:
                            previous_files[url] = cf

            if not previous_files:
                self._log("No previous files found in the scan data")
                return

        except Exception as e:
            self._log(f"Error loading previous scan data: {e}")
            return
        
        # Normalize current_files: support either a captured_files dict (url->info)
        # or a compact scan object with a 'grouped' mapping.
        current_files_map = {}
        try:
            # If current_files is a compact object (dict with 'grouped')
            if isinstance(current_files, dict) and ('grouped' in current_files or 'request_map' in current_files):
                grouped = current_files.get('grouped', {})
                for entry in grouped.values():
                    req = entry.get('request') or {}
                    resp = entry.get('response') or {}
                    url = req.get('url') or resp.get('url')
                    cf = entry.get('captured_file')
                    if url and cf is not None:
                        current_files_map[url] = cf
            elif isinstance(current_files, list) and len(current_files) > 0 and isinstance(current_files[0], dict) and 'grouped' in current_files[0]:
                # List with one compact object
                grouped = current_files[0].get('grouped', {})
                for entry in grouped.values():
                    req = entry.get('request') or {}
                    resp = entry.get('response') or {}
                    url = req.get('url') or resp.get('url')
                    cf = entry.get('captured_file')
                    if url and cf is not None:
                        current_files_map[url] = cf
            else:
                # Assume it's already a url->info mapping
                current_files_map = current_files or {}
        except Exception:
            current_files_map = current_files or {}

        # Create set of modified files for quick lookup
        modified_files = []

        # Iterate over URL->info map (support dict or list-of-tuples fallback)
        if isinstance(current_files_map, dict):
            iterator = current_files_map.items()
        elif isinstance(current_files_map, list):
            iterator = current_files_map
        else:
            try:
                iterator = current_files_map.items()
            except Exception:
                iterator = []

        for curr_pair in iterator:
            if isinstance(curr_pair, tuple) and len(curr_pair) == 2:
                curr_url, curr_info = curr_pair
            else:
                # if list of urls or other structure, skip
                continue
            if curr_url in previous_files:
                prev_info = previous_files[curr_url]
                
                curr_file_path = curr_info.get('filepath') if isinstance(curr_info, dict) else curr_info
                prev_file_path = prev_info.get('filepath') if isinstance(prev_info, dict) else prev_info
                
                # Skip image files from comparison
                if curr_file_path and is_image_file(curr_file_path):
                    continue
                    
                # Compare hashes
                curr_hash = curr_info.get('hash') if isinstance(curr_info, dict) else None
                prev_hash = prev_info.get('hash') if isinstance(prev_info, dict) else None
                
                if curr_hash and prev_hash and curr_hash != prev_hash:
                    # For JS files, show actual diffs
                    if curr_file_path and os.path.exists(curr_file_path) and prev_file_path and os.path.exists(prev_file_path):
                        if curr_file_path.endswith('.js') or curr_file_path.endswith('.css'):
                            added_lines, deleted_lines, is_significant = detect_changes(prev_file_path, curr_file_path)
                            
                            # Only add to modified if significant change
                            if is_significant:
                                modified_files.append({
                                    'url': curr_url,
                                    'previous_hash': prev_hash,
                                    'current_hash': curr_hash,
                                    'previous_size': prev_info.get('size', 0),
                                    'current_size': curr_info.get('size', 0),
                                    'domain': urlparse(curr_url).netloc,
                                    'added_lines': len(added_lines),
                                    'deleted_lines': len(deleted_lines),
                                    'diff_preview': self._generate_diff_preview(added_lines, deleted_lines)
                                })
        
        # Generate changes report
        if modified_files:
            self._log(f"{len(modified_files)} files have changed")
            
            changes_report = os.path.join(self.output_dir, f"changes_{self.timestamp}.txt") # type: ignore
            with open(changes_report, 'w', encoding='utf-8') as f:
                f.write(f"File Changes Report - {datetime.now()}\n")
                f.write(f"Comparing {previous_scan} with current scan\n\n")
                f.write(f"Total Modified Files: {len(modified_files)}\n\n")
                
                f.write("Summary of Modified Files:\n")
                f.write("=" * 80 + "\n")
                
                # Write a summary table of modified files
                for i, file_info in enumerate(modified_files, 1):
                    f.write(f"{i}. {file_info['url']}\n")
                    f.write(f"   Previous Hash: {file_info['previous_hash']}\n")
                    f.write(f"   Current Hash: {file_info['current_hash']}\n")
                    f.write(f"   Previous Size: {file_info['previous_size']} bytes\n")
                    f.write(f"   Current Size: {file_info['current_size']} bytes\n")
                    f.write(f"   Domain: {file_info['domain']}\n")
                    f.write(f"   Added Lines: {file_info['added_lines']}\n")
                    f.write(f"   Deleted Lines: {file_info['deleted_lines']}\n")
                    f.write(f"   Diff Preview:\n{file_info['diff_preview']}\n")
                    f.write("-" * 80 + "\n")
                
                self._log(f"Changes report saved to: {changes_report}")
        else:
            self._log("No files have changed since last scan")
        
    def _generate_diff_preview(self, added_lines, deleted_lines, max_lines=5):
        """Generate a preview of differences"""
        preview = []
        
        # Show deleted lines
        if deleted_lines:
            preview.append("DELETED:")
            for i, line in enumerate(deleted_lines[:max_lines]):
                preview.append(f"- {line.strip()}")
            if len(deleted_lines) > max_lines:
                preview.append(f"... and {len(deleted_lines) - max_lines} more deleted lines")
        
        # Show added lines
        if added_lines:
            preview.append("ADDED:")
            for i, line in enumerate(added_lines[:max_lines]):
                preview.append(f"+ {line.strip()}")
            if len(added_lines) > max_lines:
                preview.append(f"... and {len(added_lines) - max_lines} more added lines")
                
        return "\n".join(preview)
    
    def analyze_results(self):
        """Analyze scan results for PCI compliance"""
        if not self.scan_results:
            self._log("No scan results to analyze")
            return
        
        self._log("Analyzing scan results for PCI compliance")
        
        try:
            # Get reports directory for saving file_hashes.json (only in reports, not in main domain folder)
            reports_dir = self.get_reports_directory()
            # get_reports_directory may be async in some monitor implementations;
            # if it returns a coroutine, resolve it here so os.path.join receives a str.
            if asyncio.iscoroutine(reports_dir):
                reports_dir = asyncio.run(reports_dir)

            analysis_results = analyze_captured_data(
                self.scan_file, 
                return_results=True,
                output_directory=None,  # Don't save file_hashes.json in main domain folder
                reports_directory=reports_dir
            )
            
            # Save analysis results to reports directory
            reports_dir = self.get_reports_directory()
            if asyncio.iscoroutine(reports_dir):
                reports_dir = asyncio.run(reports_dir)
            analysis_file = os.path.join(reports_dir, f"analysis_{self.timestamp}.json")
            with open(analysis_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2)
            
            self._log(f"Analysis results saved to: {analysis_file}")
            self.analysis_results = analysis_results
            self.analysis_file = analysis_file
            
        except Exception as e:
            self._log(f"Error analyzing results: {e}")
    

# Background queue / worker pool for concurrent on-demand scans
_BACKGROUND_QUEUE: Optional[asyncio.Queue] = None
_BACKGROUND_WORKERS: list = []
_BACKGROUND_RUNNING = False

async def _background_worker(worker_id: int, config: dict):
    from workflow_manager import IntegrityWorkflow  # type: ignore
    global _BACKGROUND_QUEUE, _BACKGROUND_RUNNING
    while _BACKGROUND_RUNNING:
        try:
            item = await _BACKGROUND_QUEUE.get() # type: ignore
        except asyncio.CancelledError:
            break
        if item is None:  # sentinel
            _BACKGROUND_QUEUE.task_done() # type: ignore
            break

        url, kwargs = item.get('url'), item.get('kwargs', {})
        print(f"[BG worker {worker_id}] Starting scan: {url}")
        try:
            wf = IntegrityWorkflow(url, config=config)
            # Prefer the async path if available
            if hasattr(wf, 'scan_website_async'):
                await wf.scan_website_async()
            else:
                # run sync version in thread
                await asyncio.to_thread(wf.run_full_workflow)
        except Exception as e:
            print(f"[BG worker {worker_id}] Error scanning {url}: {e}")
        finally:
            _BACKGROUND_QUEUE.task_done() # type: ignore
            print(f"[BG worker {worker_id}] Finished scan: {url}")

async def start_background_workers(max_workers: int = 8, config: dict = None): # type: ignore
    """Start background worker pool (call once)."""
    global _BACKGROUND_QUEUE, _BACKGROUND_WORKERS, _BACKGROUND_RUNNING
    if _BACKGROUND_RUNNING:
        return
    _BACKGROUND_RUNNING = True
    _BACKGROUND_QUEUE = asyncio.Queue()
    _BACKGROUND_WORKERS = []
    for i in range(max_workers):
        task = asyncio.create_task(_background_worker(i + 1, config or {}))
        _BACKGROUND_WORKERS.append(task)
    print(f"[BG] Started {max_workers} background worker(s)")

async def submit_background_scan(url: str, kwargs: dict = None): # type: ignore
    """Submit a scan request to the background queue (async)."""
    global _BACKGROUND_QUEUE
    if _BACKGROUND_QUEUE is None:
        raise RuntimeError("Background workers not started. Call start_background_workers first.")
    await _BACKGROUND_QUEUE.put({'url': url, 'kwargs': kwargs or {}})
    print(f"[BG] Enqueued {url}")

async def stop_background_workers():
    """Gracefully stop background workers (await after enqueuing sentinel)."""
    global _BACKGROUND_QUEUE, _BACKGROUND_WORKERS, _BACKGROUND_RUNNING
    if not _BACKGROUND_RUNNING:
        return
    _BACKGROUND_RUNNING = False
    # push sentinel None for each worker so they exit
    for _ in _BACKGROUND_WORKERS:
        await _BACKGROUND_QUEUE.put(None) # type: ignore
    # wait for queue drained and workers finished
    await _BACKGROUND_QUEUE.join() # type: ignore
    for t in _BACKGROUND_WORKERS:
        t.cancel()
    _BACKGROUND_WORKERS = []
    _BACKGROUND_QUEUE = None
    print("[BG] Background workers stopped")

def main():
    """Main entry point for the workflow manager"""
    import argparse
    import sys
    from tools.compact_scan import compact_scan_object
    
    parser = argparse.ArgumentParser(description="Website Integrity Workflow Manager")
    parser.add_argument("url", help="URL to scan (or comma-separated list of URLs when using --concurrent)")
    parser.add_argument("--depth", type=int, help="Recursion depth")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--output-dir", help="Output directory")
    parser.add_argument("--use-async", action="store_true", help="Use asyncio for scanning")
    parser.add_argument("--concurrent", type=int, help="Scan multiple URLs concurrently (specify max concurrency)")
    parser.add_argument("--config", help="Path to config file")
    
    args = parser.parse_args()
    
    # Load default config
    config_file = args.config or os.path.join(os.path.dirname(__file__), "config.yaml")
    config = {}
    
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            try:
                config = yaml.safe_load(f)
            except Exception as e:
                print(f"Error loading config file: {e}")
    
    # Override config with command line args
    if args.depth:
        config["default_depth"] = args.depth
    
    if args.headless:
        config["headless"] = args.headless
    
    if args.output_dir:
        config["output_dir"] = args.output_dir
    
    # Check for multiple URLs
    urls = [u.strip() for u in args.url.split(",") if u.strip()]
    
    # Run workflow
    if len(urls) > 1 or args.concurrent:
        # Multiple URLs mode - must use async
        async def run_multi():
            workflow = IntegrityWorkflow(urls[0], config=config)  # First URL for config
            await workflow.scan_multiple_urls(urls, max_concurrency=args.concurrent or 3)
            
        asyncio.run(run_multi())
    elif args.use_async:
        # Single URL with async
        async def run_async():
            workflow = IntegrityWorkflow(args.url, config=config)
            await workflow.run_full_workflow_async()
            
        asyncio.run(run_async())
    else:
        # Traditional synchronous mode
        workflow = IntegrityWorkflow(args.url, config=config)
        workflow.run_full_workflow()

if __name__ == "__main__":
    main()