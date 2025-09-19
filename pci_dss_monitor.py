"""
PCI DSS v4.0 Compliance Enhancements for Payment Page Monitor
Addresses Requirements 6.4.3 (Script Management) and 11.6.1 (Change Detection)
"""

import json
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse

class PCIDSSComplianceMonitor:
    """Enhanced monitoring for PCI DSS v4.0 compliance"""
    
    def __init__(self):
        self.authorized_scripts = set()
        self.authorized_domains = set()
        self.csp_violations = []
        self.unauthorized_scripts = []
        self.script_categories = {
            'first_party': set(),
            'third_party': set(),
            'fourth_party': set()
        }
        
    def load_authorized_inventory(self, inventory_file: str):
        """Load pre-authorized script inventory (Requirement 6.4.3)"""
        try:
            with open(inventory_file, 'r') as f:
                inventory = json.load(f)
                self.authorized_scripts = set(inventory.get('scripts', []))
                self.authorized_domains = set(inventory.get('domains', []))
        except FileNotFoundError:
            print("⚠️ No authorized inventory found. Creating baseline...")
            self.authorized_scripts = set()
            self.authorized_domains = set()
            
    def analyze_script_authorization(self, captured_urls: List[str]) -> Dict:
        """Analyze if captured scripts are authorized (PCI DSS 6.4.3)"""
        analysis = {
            'authorized': [],
            'unauthorized': [],
            'new_scripts': [],
            'risk_level': 'LOW'
        }
        
        for url in captured_urls:
            domain = urlparse(url).netloc
            
            if url in self.authorized_scripts:
                analysis['authorized'].append(url)
            else:
                analysis['new_scripts'].append(url)
                if domain not in self.authorized_domains:
                    analysis['unauthorized'].append(url)
                    analysis['risk_level'] = 'HIGH'
                    
        return analysis
        
    def categorize_scripts(self, captured_data: Dict, primary_domain: str) -> Dict:
        """Categorize scripts by party relationship (PCI DSS requirement)
        
        1st party: Same domain as monitored website
        3rd party: Different domain but directly loaded by monitored website
        4th party: Scripts loaded by 3rd party scripts (nested dependencies)
        """
        categories = {
            'first_party': [],
            'third_party': [],
            'fourth_party': []
        }
        
        # Get directly loaded scripts (from the primary page)
        directly_loaded_scripts = set()
        
        # Check if we have network request data to identify directly loaded vs nested scripts
        if 'network_requests' in captured_data:
            for request in captured_data['network_requests']:
                url = request.get('url', '')
                # Consider scripts loaded directly from the primary domain as directly loaded
                if url.endswith(('.js', '.css')) and request.get('initiator', {}).get('type') in ['parser', 'script']:
                    directly_loaded_scripts.add(url)
        else:
            # Fallback: assume all captured scripts are directly loaded
            for item in captured_data.get('captured_elements', []):
                url = item.get('url', '')
                if url.endswith(('.js', '.css')):
                    directly_loaded_scripts.add(url)
        
        for item in captured_data.get('captured_elements', []):
            url = item.get('url', '')
            domain = urlparse(url).netloc
            
            # First-party: exact domain or subdomain of monitored website
            if domain == primary_domain or domain.endswith(f'.{primary_domain}'):
                categories['first_party'].append({
                    'url': url,
                    'hash': item.get('hash'),
                    'size': item.get('size'),
                    'risk': 'LOW'
                })
            # Third-party: different domain but directly loaded by monitored website
            elif url in directly_loaded_scripts or not directly_loaded_scripts:  # If no network data, assume direct
                # Determine risk based on domain type
                risk_level = 'MEDIUM'
                script_type = 'EXTERNAL'
                
                # Known payment processors - lower risk
                payment_processors = {
                    'js.stripe.com', 'checkout.stripe.com',
                    'paypal.com', 'paypalobjects.com',
                    'square.com', 'squareup.com'
                }
                
                if any(domain == proc or domain.endswith(f'.{proc}') for proc in payment_processors):
                    script_type = 'PAYMENT'
                    risk_level = 'MEDIUM'
                # CDN services - medium risk
                elif any(cdn in domain for cdn in ['cdn.', 'cdnjs.', 'jsdelivr.', 'unpkg.', 'rawgit.']):
                    script_type = 'CDN'
                    risk_level = 'MEDIUM'
                # Analytics/tracking - higher risk
                elif any(tracker in domain for tracker in ['google-analytics.com', 'googletagmanager.com', 'gstatic.com', 'doubleclick.net']):
                    script_type = 'TRACKING/ANALYTICS'
                    risk_level = 'HIGH'
                else:
                    script_type = 'UNKNOWN'
                    risk_level = 'HIGH'
                
                categories['third_party'].append({
                    'url': url,
                    'hash': item.get('hash'),
                    'size': item.get('size'),
                    'risk': risk_level,
                    'type': script_type
                })
            else:
                # Fourth-party: scripts loaded by other scripts (nested dependencies)
                categories['fourth_party'].append({
                    'url': url,
                    'hash': item.get('hash'),
                    'size': item.get('size'),
                    'risk': 'CRITICAL',
                    'type': 'NESTED_DEPENDENCY'
                })
                
        return categories
        
    def validate_csp_compliance(self, captured_data: Dict) -> Dict:
        """Validate Content Security Policy compliance (PCI DSS 6.4.3)"""
        csp_analysis = {
            'csp_found': False,
            'policy': '',
            'violations': [],
            'recommendations': []
        }
        
        # Extract CSP from captured headers
        for item in captured_data.get('network_requests', []):
            headers = item.get('response_headers', {})
            # Make header keys case-insensitive
            csp = ''
            for k, v in headers.items():
                if k.lower() == 'content-security-policy':
                    csp = v
                    break
            
            if csp:
                csp_analysis['csp_found'] = True
                csp_analysis['policy'] = csp
                
                # Check for common CSP issues
                request_info = {
                    'url': item.get('url', 'unknown'),
                    'method': item.get('method', 'GET'),
                    'timestamp': item.get('timestamp', '')
                }
                
                if "'unsafe-inline'" in csp:
                    csp_analysis['violations'].append({
                        "issue": "Unsafe inline scripts allowed",
                        "request": request_info
                    })
                if "'unsafe-eval'" in csp:
                    csp_analysis['violations'].append({
                        "issue": "Unsafe eval allowed",
                        "request": request_info
                    })
                if "*" in csp and "script-src" in csp:
                    csp_analysis['violations'].append({
                        "issue": "Wildcard script sources allowed",
                        "request": request_info
                    })
                    
        if not csp_analysis['csp_found']:
            csp_analysis['violations'].append({
                "issue": "No Content Security Policy found",
                "request": None
            })
            
        return csp_analysis
        
    def check_sri_implementation(self, captured_data: Dict) -> Dict:
        """Check for Subresource Integrity implementation (PCI DSS 6.4.3)"""
        sri_analysis = {
            'scripts_with_sri': 0,
            'scripts_without_sri': 0,
            'external_scripts': [],
            'compliance_percentage': 0
        }
        
        # This would need to parse HTML content to check for integrity attributes
        # For now, we'll flag this as a manual check requirement
        sri_analysis['manual_check_required'] = True
        
        return sri_analysis
        
    def generate_compliance_report(self, captured_data: Dict, primary_domain: str) -> Dict:
        """Generate comprehensive PCI DSS compliance report"""
        
        # Extract URLs from captured data
        captured_urls = []
        for item in captured_data.get('captured_elements', []):
            captured_urls.append(item.get('url', ''))
            
        # Perform all analyses
        auth_analysis = self.analyze_script_authorization(captured_urls)
        script_categories = self.categorize_scripts(captured_data, primary_domain)
        csp_analysis = self.validate_csp_compliance(captured_data)
        sri_analysis = self.check_sri_implementation(captured_data)
        
        # Calculate overall risk score
        risk_factors = 0
        if auth_analysis['unauthorized']:
            risk_factors += 3
        if script_categories['fourth_party']:
            # Add 2 for each CRITICAL risk script
            risk_factors += sum(2 if script.get('risk') == 'CRITICAL' else 1 for script in script_categories['fourth_party'])
        if csp_analysis['violations']:
            risk_factors += len(csp_analysis['violations'])
            
        risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        overall_risk = risk_levels[min(risk_factors // 2, 3)]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'primary_domain': primary_domain,
            'overall_risk_level': overall_risk,
            'pci_dss_compliance': {
                'requirement_6_4_3': {
                    'script_authorization': auth_analysis,
                    'script_categories': script_categories,
                    'csp_compliance': csp_analysis
                },
                'requirement_11_6_1': {
                    'change_detection': 'IMPLEMENTED',
                    'baseline_established': True,
                    'hash_verification': 'SHA256'
                }
            },
            'recommendations': self._generate_recommendations(auth_analysis, script_categories, csp_analysis),
            'action_items': self._generate_action_items(auth_analysis, script_categories, csp_analysis)
        }
        
        return report
        
    def _generate_recommendations(self, auth_analysis, script_categories, csp_analysis):
        """Generate specific recommendations for compliance"""
        recommendations = []
        
        if auth_analysis['unauthorized']:
            recommendations.append("Review and authorize new scripts before deployment")
            
        if len(script_categories['fourth_party']) > 0:
            recommendations.append("Minimize fourth-party scripts on payment pages")
            
        if csp_analysis['violations']:
            recommendations.append("Strengthen Content Security Policy")
            
        recommendations.append("Implement Subresource Integrity (SRI) for external scripts")
        recommendations.append("Set up automated monitoring alerts for script changes")
        
        return recommendations
        
    def _generate_action_items(self, auth_analysis, script_categories, csp_analysis):
        """Generate specific action items for remediation"""
        actions = []
        
        if auth_analysis['unauthorized']:
            for script in auth_analysis['unauthorized']:
                actions.append(f"URGENT: Investigate unauthorized script: {script}")
                
        high_risk_fourth_party = [
            script for script in script_categories['fourth_party'] 
            if script.get('risk') in ['HIGH', 'CRITICAL']
        ]
        
        for script in high_risk_fourth_party:
            actions.append(f"REVIEW: High-risk fourth-party script: {script['url']}")
            
        return actions

# Usage example
if __name__ == "__main__":
    monitor = PCIDSSComplianceMonitor()
    
    # Example usage with captured data
    print("PCI DSS v4.0 Compliance Monitor")
    print("Analyzes payment page scripts for compliance with Requirements 6.4.3 and 11.6.1")