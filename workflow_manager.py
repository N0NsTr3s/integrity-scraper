#!/usr/bin/env python3
"""
Website Integrity Workflow Manager
Handles the entire workflow of scanning, analyzing, and reporting
"""
import os
import json
import time
import hashlib
import yaml
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from enhanced_monitor_demo import EnhancedNetworkMonitor
from analyze_pci_compliance import analyze_captured_data
from file_change_detector import detect_changes, get_file_hash

class IntegrityWorkflow:
    """Workflow manager for website integrity monitoring"""
    
    def __init__(self, url, config=None, logger=None):
        """Initialize the workflow manager
        
        Args:
            url (str): The URL to scan
            config (dict, optional): Configuration dictionary
            logger (logging.Logger, optional): Logger instance
        """
        self.url = url
        self.config = config or self._load_config()
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
            
        # Fallback: try to determine the versioned directory from domain
        # This should match whatever main directory structure was created
        base_dir = f'./{self.domain}'
        
        if os.path.exists(base_dir):
            # Use base directory name for reports
            reports_dir = os.path.join("./reports", self.domain)
        else:
            # Find the versioned directory that exists
            counter = 1
            while os.path.exists(f"{base_dir}_{counter}"):
                counter += 1
            
            # Use the last existing version for reports consistency
            if counter > 1:
                versioned_domain = f"{self.domain}_{counter-1}"
                reports_dir = os.path.join("./reports", versioned_domain)
            else:
                reports_dir = os.path.join("./reports", self.domain)
        
        os.makedirs(reports_dir, exist_ok=True)
        return reports_dir
        
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
            self.generate_report()
            return True
        except Exception as e:
            self._log(f"Error in workflow: {e}")
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
            depth = self.config.get("default_depth", 2)
            self._log(f"Scanning with depth {depth}")
            
            # First monitor call will set up the directory structure
            results = self.monitor.monitor_url(self.url, wait_after_load=5, max_depth=depth)
            
            # Now get the output directory from the monitor
            self.output_dir = self.monitor.output_directory
            
            # Find previous scan for comparison
            previous_scan = self._find_previous_scan()
            
            # Save scan results  
            if results:
                self.scan_results = [results]
                
                # Save scan results to reports directory
                reports_dir = self.get_reports_directory()
                scan_file = os.path.join(reports_dir, f"scan_{self.timestamp}.json")
                with open(scan_file, 'w', encoding='utf-8') as f:
                    json.dump([results], f, indent=2, ensure_ascii=False)
                
                self._log(f"Scan results saved to: {scan_file}")
                self.scan_file = scan_file
                
                # Compare with previous scan if available
                if previous_scan:
                    self._compare_with_previous(previous_scan, self.monitor.captured_files)
            
        finally:
            # Cleanup
            self.monitor.close()
    
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
            
            # Extract captured files from the previous scan data
            if isinstance(previous_scan_data, list):
                for scan_result in previous_scan_data:
                    if isinstance(scan_result, dict) and 'captured_files' in scan_result:
                        previous_files.update(scan_result['captured_files'])
            elif isinstance(previous_scan_data, dict) and 'captured_files' in previous_scan_data:
                previous_files = previous_scan_data['captured_files']
                
            if not previous_files:
                self._log("No previous files found in the scan data")
                return
                
        except Exception as e:
            self._log(f"Error loading previous scan data: {e}")
            return
        
        # Create set of modified files for quick lookup
        modified_files = []
        
        for curr_url, curr_info in current_files.items():
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
            analysis_results = analyze_captured_data(
                self.scan_file, 
                return_results=True,
                output_directory=None,  # Don't save file_hashes.json in main domain folder
                reports_directory=reports_dir
            )
            
            # Save analysis results to reports directory
            reports_dir = self.get_reports_directory()
            analysis_file = os.path.join(reports_dir, f"analysis_{self.timestamp}.json")
            with open(analysis_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2)
            
            self._log(f"Analysis results saved to: {analysis_file}")
            self.analysis_results = analysis_results
            self.analysis_file = analysis_file
            
        except Exception as e:
            self._log(f"Error analyzing results: {e}")
    
    def generate_report(self):
        """Generate HTML report from results"""
        if not self.scan_results:
            self._log("No scan results to generate report")
            return
        
        self._log("Generating HTML report")
        
        # Create a simple HTML report in reports directory
        reports_dir = self.get_reports_directory()
        report_file = os.path.join(reports_dir, f"report_{self.timestamp}.html")
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Website Integrity Report - {self.domain}</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 20px; }}
                        .score {{ font-size: 24px; font-weight: bold; }}
                        .good {{ color: green; }}
                        .warning {{ color: orange; }}
                        .critical {{ color: red; }}
                        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        th {{ background-color: #f2f2f2; }}
                        tr:nth-child(even) {{ background-color: #f9f9f9; }}
                        .section {{ margin: 20px 0; padding: 10px; border: 1px solid #eee; }}
                        h2 {{ color: #333; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
                    </style>
                </head>
                <body>
                    <h1>Website Integrity Report - {self.domain}</h1>
                    <p>Generated on {datetime.now()}</p>
                    
                    <div class="section">
                        <h2>Scan Summary</h2>
                        <p>URL: {self.url}</p>
                        <p>Scan time: {self.timestamp}</p>
                """)
                
                # Add scan statistics
                if self.scan_results:
                    f.write("<h3>Scan Statistics</h3>")
                    f.write("<table>")
                    f.write("<tr><th>Metric</th><th>Value</th></tr>")
                    
                    # Extract statistics from the first result
                    if self.scan_results and isinstance(self.scan_results, list) and len(self.scan_results) > 0:
                        first_result = self.scan_results[0]
                        stats = first_result.get('capture_info', {}).get('statistics', {})
                        
                        if stats:
                            f.write(f"<tr><td>Total Requests</td><td>{stats.get('total_requests', 0)}</td></tr>")
                            f.write(f"<tr><td>Total Responses</td><td>{stats.get('total_responses', 0)}</td></tr>")
                            f.write(f"<tr><td>Failed Requests</td><td>{stats.get('failed_requests', 0)}</td></tr>")
                    
                    f.write("</table>")
                
                # Add analysis results if available
                if self.analysis_results:
                    f.write("""
                    <div class="section">
                        <h2>PCI Compliance Analysis</h2>
                    """)
                    
                    # Add compliance score if available
                    if isinstance(self.analysis_results, dict) and 'compliance_score' in self.analysis_results:
                        score = self.analysis_results['compliance_score']
                        score_class = "good" if score >= 80 else ("warning" if score >= 60 else "critical")
                        f.write(f'<p class="score {score_class}">Compliance Score: {score}%</p>')
                    
                    # Add issues if available
                    if isinstance(self.analysis_results, dict) and 'issues' in self.analysis_results:
                        f.write("<h3>Identified Issues</h3>")
                        f.write("<table>")
                        f.write("<tr><th>Severity</th><th>Issue</th><th>Recommendation</th></tr>")
                        
                        for issue in self.analysis_results['issues']:
                            severity = issue.get('severity', 'Unknown')
                            severity_class = "good" if severity == "Low" else ("warning" if severity == "Medium" else "critical")
                            f.write(f'<tr>')
                            f.write(f'<td class="{severity_class}">{severity}</td>')
                            f.write(f'<td>{issue.get("description", "No description")}</td>')
                            f.write(f'<td>{issue.get("recommendation", "No recommendation")}</td>')
                            f.write(f'</tr>')
                        
                        f.write("</table>")
                    
                    f.write("</div>")
                
                f.write("""
                    </div>
                </body>
                </html>
                """)
            
            self._log(f"HTML report saved to: {report_file}")
            
        except Exception as e:
            self._log(f"Error generating report: {e}")

def main():
    """Main entry point for the workflow manager"""
    import argparse
    import sys
    
    
    parser = argparse.ArgumentParser(description="Website Integrity Workflow Manager")
    parser.add_argument("url", help="URL to scan")
    parser.add_argument("--depth", type=int, help="Recursion depth")
    parser.add_argument("--headless", action="store_true", help="Run browser in headless mode")
    parser.add_argument("--output-dir", help="Output directory")
    
    args = parser.parse_args()
    
    # Load default config
    config_file = os.path.join(os.path.dirname(__file__), "config.yaml")
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
    
    # Run workflow
    workflow = IntegrityWorkflow(args.url, config=config)
    workflow.run_full_workflow()

if __name__ == "__main__":
    main()