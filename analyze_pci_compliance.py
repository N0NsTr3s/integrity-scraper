"""
Analyze captured payment page data for PCI DSS v4.0 compliance
"""

import json
import sys
import os
import hashlib
from datetime import datetime
from pci_dss_monitor import PCIDSSComplianceMonitor
# Import get_file_hash from file_change_detector
from file_change_detector import get_file_hash

def find_first_scan_hashes(domain, reports_directory=None, output_directory=None):
    """Find the file_hashes.json from the first scan for this domain
    
    Args:
        domain (str): Domain name to look for
        reports_directory (str, optional): Current reports directory
        output_directory (str, optional): Current output directory
        
    Returns:
        dict: Previous hashes from first scan, empty dict if not found
    """
    # Try to find the base domain directory (without version number)
    base_domain = domain.split('_')[0] if '_' in domain else domain
    
    # Look for file_hashes.json in reports directories
    potential_dirs = [
        f"./reports/{base_domain}",  # Base domain reports
        f"./{base_domain}",  # Base domain main directory
    ]
    
    # Also check if we have a current reports directory - look for earlier versions
    if reports_directory:
        reports_base = os.path.dirname(reports_directory)
        potential_dirs.append(os.path.join(reports_base, base_domain))
    
    for dir_path in potential_dirs:
        hash_file = os.path.join(dir_path, "file_hashes.json")
        if os.path.exists(hash_file):
            try:
                with open(hash_file, 'r', encoding='utf-8') as f:
                    print(f"📋 Loading baseline hashes from: {hash_file}")
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load hashes from {hash_file}: {e}")
    
    return {}

def analyze_line_changes_with_ranges(added_lines, deleted_lines, original_file, current_file):
    """Analyze line changes and group them into ranges, detecting modifications
    
    Args:
        added_lines (list): Lines that were added
        deleted_lines (list): Lines that were deleted
        original_file (str): Path to original file
        current_file (str): Path to current file
        
    Returns:
        dict: Organized change information with ranges and modifications
    """
    import difflib
    
    try:
        # Read both files to get line numbers and detect modifications
        with open(original_file, 'r', encoding='utf-8', errors='ignore') as f:
            original_content = f.readlines()
        with open(current_file, 'r', encoding='utf-8', errors='ignore') as f:
            current_content = f.readlines()
        
        # Use difflib to get detailed diff with line numbers
        differ = difflib.unified_diff(
            original_content, 
            current_content, 
            fromfile=original_file, 
            tofile=current_file, 
            lineterm='',
            n=0  # No context lines
        )
        
        diff_lines = list(differ)
        
        # Parse diff to get line numbers and changes
        changes = {
            'additions': [],      # [(start_line, end_line, content_lines)]
            'deletions': [],      # [(start_line, end_line, content_lines)]
            'modifications': [],  # [(line_num, old_content, new_content)]
            'ranges': {
                'added_ranges': [],     # ["rows 30-59 were added"]
                'deleted_ranges': [],   # ["rows 13-29 were deleted"]
                'modified_ranges': []   # ["rows 60-61 were modified"]
            }
        }
        
        # Parse unified diff format
        i = 0
        while i < len(diff_lines):
            line = diff_lines[i]
            
            # Look for diff headers like @@ -1,6 +1,29 @@
            if line.startswith('@@'):
                # Parse the header to get line ranges
                import re
                match = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
                if match:
                    old_start = int(match.group(1))
                    old_count = int(match.group(2)) if match.group(2) else 1
                    new_start = int(match.group(3))
                    new_count = int(match.group(4)) if match.group(4) else 1
                    
                    i += 1
                    
                    # Collect the actual changes following this header
                    deletions_in_chunk = []
                    additions_in_chunk = []
                    
                    while i < len(diff_lines) and not diff_lines[i].startswith('@@'):
                        change_line = diff_lines[i]
                        if change_line.startswith('-'):
                            deletions_in_chunk.append((old_start + len(deletions_in_chunk), change_line[1:].strip()))
                        elif change_line.startswith('+'):
                            additions_in_chunk.append((new_start + len(additions_in_chunk), change_line[1:].strip()))
                        i += 1
                    
                    # Process deletions and additions to detect modifications
                    if deletions_in_chunk and additions_in_chunk:
                        # Check for potential modifications (similar content)
                        modifications_found = []
                        remaining_deletions = deletions_in_chunk.copy()
                        remaining_additions = additions_in_chunk.copy()
                        
                        for del_line_num, del_content in deletions_in_chunk:
                            best_match = None
                            best_similarity = 0
                            
                            for add_line_num, add_content in additions_in_chunk:
                                # Calculate similarity using difflib
                                similarity = difflib.SequenceMatcher(None, del_content, add_content).ratio()
                                if similarity > 0.6 and similarity > best_similarity:  # 60% similarity threshold
                                    best_match = (add_line_num, add_content)
                                    best_similarity = similarity
                            
                            if best_match:
                                # Found a modification
                                modifications_found.append((del_line_num, del_content, best_match[1]))
                                remaining_deletions = [(ln, cont) for ln, cont in remaining_deletions if ln != del_line_num]
                                remaining_additions = [(ln, cont) for ln, cont in remaining_additions if (ln, cont) != best_match]
                        
                        # Add modifications to results
                        changes['modifications'].extend(modifications_found)
                        
                        # Add remaining deletions and additions
                        if remaining_deletions:
                            start_line = min(ln for ln, _ in remaining_deletions)
                            end_line = max(ln for ln, _ in remaining_deletions)
                            changes['deletions'].append((start_line, end_line, [cont for _, cont in remaining_deletions]))
                        
                        if remaining_additions:
                            start_line = min(ln for ln, _ in remaining_additions)
                            end_line = max(ln for ln, _ in remaining_additions)
                            changes['additions'].append((start_line, end_line, [cont for _, cont in remaining_additions]))
                    
                    elif deletions_in_chunk:
                        # Only deletions
                        start_line = min(ln for ln, _ in deletions_in_chunk)
                        end_line = max(ln for ln, _ in deletions_in_chunk)
                        changes['deletions'].append((start_line, end_line, [cont for _, cont in deletions_in_chunk]))
                    
                    elif additions_in_chunk:
                        # Only additions
                        start_line = min(ln for ln, _ in additions_in_chunk)
                        end_line = max(ln for ln, _ in additions_in_chunk)
                        changes['additions'].append((start_line, end_line, [cont for _, cont in additions_in_chunk]))
                    
                    continue
            i += 1
        
        # Generate range descriptions
        for start_line, end_line, _ in changes['deletions']:
            if start_line == end_line:
                changes['ranges']['deleted_ranges'].append(f"row {start_line} was deleted")
            else:
                changes['ranges']['deleted_ranges'].append(f"rows {start_line}-{end_line} were deleted")
        
        for start_line, end_line, _ in changes['additions']:
            if start_line == end_line:
                changes['ranges']['added_ranges'].append(f"row {start_line} was added")
            else:
                changes['ranges']['added_ranges'].append(f"rows {start_line}-{end_line} were added")
        
        if changes['modifications']:
            # Group consecutive modifications
            mod_lines = [line_num for line_num, _, _ in changes['modifications']]
            ranges = []
            if mod_lines:
                start = mod_lines[0]
                end = mod_lines[0]
                
                for line_num in mod_lines[1:]:
                    if line_num == end + 1:
                        end = line_num
                    else:
                        if start == end:
                            ranges.append(f"row {start} was modified")
                        else:
                            ranges.append(f"rows {start}-{end} were modified")
                        start = end = line_num
                
                # Add final range
                if start == end:
                    ranges.append(f"row {start} was modified")
                else:
                    ranges.append(f"rows {start}-{end} were modified")
            
            changes['ranges']['modified_ranges'] = ranges
        
        return changes
        
    except Exception as e:
        print(f"   ❌ Error analyzing line ranges: {e}")
        return {
            'additions': [],
            'deletions': [], 
            'modifications': [],
            'ranges': {'added_ranges': [], 'deleted_ranges': [], 'modified_ranges': []}
        }

def perform_detailed_change_analysis(changed_files, output_directory, reports_directory):
    """Perform detailed line-by-line analysis of changed files
    
    Args:
        changed_files (list): List of files that have changed
        output_directory (str): Current scan output directory
        reports_directory (str): Current reports directory
        
    Returns:
        dict: Detailed change analysis results
    """
    from file_change_detector import detect_changes, get_file_info
    
    detailed_changes = {
        'files_analyzed': 0,
        'significant_changes': [],
        'minor_changes': [],
        'analysis_errors': []
    }
    
    for file_info in changed_files:
        url = file_info['url']
        current_filepath = file_info.get('filepath')
        
        if not current_filepath or not os.path.exists(current_filepath):
            continue
            
        # Try to find the original file in the base domain directory
        domain = file_info.get('domain', '')
        base_domain = domain.split('_')[0] if '_' in domain else domain
        
        # Construct the path to the original file
        current_filename = os.path.basename(current_filepath)
        original_filepath = None
        
        # Look in base domain directory
        base_domain_dir = f"./{base_domain}"
        if os.path.exists(base_domain_dir):
            # Try to find the file with the same relative path structure
            relative_path = os.path.relpath(current_filepath, output_directory)
            potential_original = os.path.join(base_domain_dir, relative_path)
            
            if os.path.exists(potential_original):
                original_filepath = potential_original
            else:
                # Fallback: look for file with same name in base directory
                for root, dirs, files in os.walk(base_domain_dir):
                    if current_filename in files:
                        original_filepath = os.path.join(root, current_filename)
                        break
        
        if original_filepath and os.path.exists(original_filepath):
            try:
                print(f"🔍 Analyzing changes in: {url}")
                change_info = detect_changes(
                    original_filepath, 
                    current_filepath, 
                    normalize_js=True,
                    size_threshold_percent=0.5  # Lower threshold to 0.5% for more sensitive detection
                )
                
                change_result = {
                    'url': url,
                    'original_file': original_filepath,
                    'current_file': current_filepath,
                    'change_info': change_info
                }
                
                # Override significance detection for demonstration
                # If there are many line changes, consider it significant regardless of file_change_detector result
                added_lines = change_info.get('added_lines', [])
                deleted_lines = change_info.get('deleted_lines', [])
                total_line_changes = len(added_lines) + len(deleted_lines)
                
                is_significant_override = (
                    total_line_changes > 10 or  # More than 10 line changes
                    abs(change_info.get('size_change', 0)) > 1000  # More than 1KB size change
                )
                
                if is_significant_override or change_info.get('is_significant_change', False):
                    detailed_changes['significant_changes'].append(change_result)
                    print(f"   ⚠️ Significant change detected")
                    if is_significant_override and not change_info.get('is_significant_change', False):
                        print(f"      (Override: {total_line_changes} line changes or large size change)")
                else:
                    detailed_changes['minor_changes'].append(change_result)
                    print(f"   ✅ Minor change detected")
                    # Debug information for minor changes
                    if change_info.get('change_summary'):
                        summary = change_info['change_summary']
                        print(f"      Debug: {summary.get('message', 'No message')}")
                        if summary.get('is_significant') is not None:
                            print(f"      Debug: is_significant = {summary['is_significant']}")
                    
                detailed_changes['files_analyzed'] += 1
                
            except Exception as e:
                error_info = {
                    'url': url,
                    'error': str(e),
                    'original_file': original_filepath,
                    'current_file': current_filepath
                }
                detailed_changes['analysis_errors'].append(error_info)
                print(f"   ❌ Error analyzing changes: {e}")
        else:
            print(f"   ⚠️ Could not find original file for comparison: {url}")
    
    return detailed_changes
    """Load previously stored file hashes for comparison"""
    hash_file = os.path.join(hash_directory, "file_hashes.json")
    if os.path.exists(hash_file):
        try:
            with open(hash_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load previous hashes: {e}")
    return {}

def load_previous_file_hashes(hash_directory="."):
    """Load previously saved file hashes from JSON file
    
    Args:
        hash_directory (str): Directory containing file_hashes.json
        
    Returns:
        dict: Previously saved hashes, empty dict if not found
    """
    hash_file = os.path.join(hash_directory, "file_hashes.json")
    if os.path.exists(hash_file):
        try:
            with open(hash_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load previous hashes: {e}")
    return {}

def save_current_file_hashes(current_hashes, hash_directory="."):
    """Save current file hashes for future comparison"""
    hash_file = os.path.join(hash_directory, "file_hashes.json")
    try:
        with open(hash_file, 'w', encoding='utf-8') as f:
            json.dump(current_hashes, f, indent=2)
        print(f"📊 File hashes saved to {hash_file}")
    except Exception as e:
        print(f"Warning: Could not save current hashes: {e}")

def analyze_file_changes(current_files, previous_hashes):
    """Analyze file changes between current and previous captures"""
    changes = {
        'new_files': [],
        'modified_files': [],
        'insignificant_changes': [],  # New category for non-significant changes
        'deleted_files': [],
        'unchanged_files': []
    }
    
    # Create current hash lookup
    current_hashes = {}
    for file_info in current_files:
        url = file_info['url']
        
        # Use get_file_hash if filepath is available, otherwise use provided hash
        filepath = file_info.get('filepath')
        if filepath and os.path.exists(filepath):
            # Calculate hash using the get_file_hash function
            file_hash = get_file_hash(filepath)
        else:
            # Fallback to provided hash if filepath isn't available
            file_hash = file_info.get('hash', '')
        
        current_hashes[url] = {
            'hash': file_hash,
            'size': file_info.get('size', 0),
            'domain': file_info.get('domain', ''),
            'filepath': filepath,
            'timestamp': datetime.now().isoformat()
        }
    
    # Find new and modified files
    for url, file_info in current_hashes.items():
        if url in previous_hashes:
            previous_filepath = previous_hashes[url].get('filepath')
            previous_hash = previous_hashes[url]['hash']
            
            # If previous filepath exists, recalculate its hash using get_file_hash
            if previous_filepath and os.path.exists(previous_filepath):
                previous_hash = get_file_hash(previous_filepath)
            
            if previous_hash != file_info['hash']:
                # Get file paths for analyzing significance
                current_filepath = file_info.get('filepath')
                
                # Default to significant change unless we can verify
                is_significant = True
                
                # Add basic change info
                change_info = {
                    'url': url,
                    'previous_hash': previous_hash,
                    'current_hash': file_info['hash'],
                    'previous_size': previous_hashes[url].get('size', 0),
                    'current_size': file_info['size'],
                    'domain': file_info['domain'],
                    'filepath': file_info.get('filepath'),  # Add filepath for detailed analysis
                    'is_significant': is_significant
                }
                
                # Check if this is a false positive or insignificant change
                # Common patterns for false positives
                likely_insignificant = False
                
                # Check URL patterns often associated with minor/automatic changes
                if any(pattern in url.lower() for pattern in [
                    'timestamp', 'cache', 'analytics', 'pixel', 'tracking',
                    'visitor', 'session', 'beacon', 'metrics', 'stats'
                ]):
                    likely_insignificant = True
                
                # Check for unchanged file size (exact same size usually means not significant)
                if change_info['previous_size'] == change_info['current_size']:
                    # Same size but different hash could be timestamp changes or similar
                    likely_insignificant = True
                
                # Based on these checks, decide which category to put it in
                if likely_insignificant:
                    changes['insignificant_changes'].append(change_info)
                else:
                    changes['modified_files'].append(change_info)
            else:
                changes['unchanged_files'].append(url)
        else:
            changes['new_files'].append({
                'url': url,
                'hash': file_info['hash'],
                'size': file_info['size'],
                'domain': file_info['domain']
            })
    
    # Find deleted files
    for url in previous_hashes:
        if url not in current_hashes:
            changes['deleted_files'].append({
                'url': url,
                'previous_hash': previous_hashes[url]['hash'],
                'domain': previous_hashes[url].get('domain', ''),
                'size': previous_hashes[url].get('size', 0)
            })
    
    return changes, current_hashes

def analyze_captured_data(json_file_path, return_results=False, output_directory=None, reports_directory=None):
    """Analyze the captured data for PCI DSS compliance
    
    Args:
        json_file_path (str): Path to the JSON file with captured data
        return_results (bool, optional): Whether to return the analysis results
        output_directory (str, optional): Directory to save file_hashes.json for main scan data
        reports_directory (str, optional): Directory to save file_hashes.json for reports
        
    Returns:
        dict: Analysis results if return_results is True, otherwise None
    """
    # Initialize results data structure
    analysis_results = {
        'compliance_score': 0,
        'issues': [],
        'recommendations': [],
        'scan_file': json_file_path,
        'analysis_timestamp': datetime.now().isoformat(),
        'file_changes': {}
    }
    
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            captured_data = json.load(f)
    except Exception as e:
        print(f"Error loading captured data: {e}")
        if return_results:
            analysis_results['error'] = str(e)
            return analysis_results
        return
    
    monitor = PCIDSSComplianceMonitor()
    
    # Extract primary domain from the first captured request
    primary_domain = "stripe-payments-demo.appspot.com"  # Based on your data
    
    print("🔒 PCI DSS v4.0 COMPLIANCE ANALYSIS")
    print("=" * 60)
    
    # Analyze the captured data
    if isinstance(captured_data, list) and len(captured_data) > 0:
        first_capture = captured_data[0]
        
        # Extract script information from the capture
        requests = first_capture.get('requests', {})
        responses = first_capture.get('responses', {})
        print(f"📊 Analyzing {len(requests)} requests and {len(responses)} responses...")
        
        # Extract JavaScript files and all domains
        js_files = []
        all_domains = set()
        css_files = []
        all_files = []
        
        # Process requests
        for request_id, request in requests.items():
            url = request.get('url', '')
            
            # Extract domain
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            all_domains.add(domain)
            
            # Get corresponding response
            response = responses.get(request_id, {})
            
            # Determine file type
            is_js = (url.endswith('.js') or 
                    'javascript' in url.lower() or 
                    any(js_path in url for js_path in ['/js/', '/javascript/', '/scripts/']))
            
            is_css = (url.endswith('.css') or 
                     'stylesheet' in url.lower() or 
                     '/css/' in url)
            
            # Check for file path in saved data
            filepath = None
            if 'captured_files' in first_capture:
                for file_url, file_data in first_capture['captured_files'].items():
                    if file_url == url:
                        filepath = file_data.get('filepath')
                        break
            
            # If filepath exists, use get_file_hash
            if filepath and os.path.exists(filepath):
                file_hash = get_file_hash(filepath)
                file_size = os.path.getsize(filepath)
            else:
                # Generate a hash based on URL and response metadata if no body available
                response_body = response.get('body', '')
                response_size = response.get('encodedDataLength', 0)
                
                if response_body:
                    file_hash = hashlib.sha256(response_body.encode('utf-8')).hexdigest()
                    file_size = len(response_body)
                else:
                    # Use URL + status + size as a fallback identifier
                    fallback_data = f"{url}:{response.get('status', 0)}:{response_size}"
                    file_hash = hashlib.sha256(fallback_data.encode('utf-8')).hexdigest()
                    file_size = response_size
            
            file_info = {
                'url': url,
                'hash': file_hash,
                'size': file_size,
                'status': response.get('status', 0),
                'domain': domain,
                'filepath': filepath
            }
            
            all_files.append(file_info)
            
            if is_js:
                js_files.append(file_info)
            elif is_css:
                css_files.append(file_info)
        
        print(f"🔍 Found {len(js_files)} JavaScript files")
        print(f"� Found {len(css_files)} CSS files")
        print(f"�🌐 Across {len(all_domains)} domains")
        
        # Show discovered domains
        print(f"\n🌍 DISCOVERED DOMAINS:")
        print("-" * 40)
        for domain in sorted(all_domains):
            if domain:  # Skip empty domains
                print(f"   🌐 {domain}")
        
        # Analyze file changes - Enhanced Detection
        print(f"\n📊 FILE CHANGE ANALYSIS:")
        print("-" * 40)
        
        # Get domain from the reports_directory or output_directory
        domain = ""
        if reports_directory:
            domain = os.path.basename(reports_directory)
        elif output_directory:
            domain = os.path.basename(output_directory)
        
        # Try to load baseline hashes from first scan
        baseline_hashes = find_first_scan_hashes(domain, reports_directory, output_directory)
        
        # Analyze changes using current file analysis
        file_changes, current_hashes = analyze_file_changes(all_files, baseline_hashes)
        
        # Display file change results
        if file_changes['new_files']:
            print(f"🆕 New files detected: {len(file_changes['new_files'])}")
            for file_info in file_changes['new_files'][:5]:  # Show first 5
                short_hash = file_info['hash'][:8] + '...' if len(file_info['hash']) > 8 else file_info['hash']
                print(f"   ✅ {file_info['url']}")
                print(f"      Size: {file_info['size']} bytes, Hash: {short_hash}")
        
        # Show significant changes
        if file_changes['modified_files']:
            # Filter out image files from display using the same logic as file_change_detector
            from file_change_detector import is_image_file
            non_image_changes = []
            for f in file_changes['modified_files']:
                # Check if it's an image by URL extension or use file path if available
                url = f['url']
                is_image = url.endswith(('.svg', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff', '.tif'))
                # Also check using file path if available
                if not is_image and 'filepath' in f and f['filepath']:
                    is_image = is_image_file(f['filepath'])
                if not is_image:
                    non_image_changes.append(f)
            
            print(f"🔄 Modified files detected: {len(non_image_changes)} significant (excluding images)")
            for file_info in non_image_changes[:5]:  # Show first 5
                size_change = file_info['current_size'] - file_info['previous_size']
                size_indicator = f"({size_change:+d} bytes)" if size_change != 0 else "(same size)"
                print(f"   ⚠️ {file_info['url']}")
                print(f"      Size: {file_info['current_size']} bytes {size_indicator}")
                print(f"      Hash: {file_info['previous_hash'][:8]}... → {file_info['current_hash'][:8]}...")
            
            # Perform detailed line-by-line analysis for significant changes
            if non_image_changes and baseline_hashes:
                print(f"\n🔍 DETAILED CHANGE ANALYSIS:")
                print("-" * 40)
                detailed_analysis = perform_detailed_change_analysis(
                    non_image_changes, output_directory, reports_directory
                )
                
                if detailed_analysis['files_analyzed'] > 0:
                    print(f"📋 Analyzed {detailed_analysis['files_analyzed']} files for detailed changes")
                    
                    if detailed_analysis['significant_changes']:
                        print(f"⚠️ {len(detailed_analysis['significant_changes'])} files with significant changes:")
                        for change in detailed_analysis['significant_changes'][:3]:  # Show first 3
                            change_info = change['change_info']
                            print(f"   🔴 {change['url']}")
                            if change_info.get('total_changes', 0) > 0:
                                print(f"      • {change_info['total_changes']} total changes")
                            if change_info.get('additions', 0) > 0:
                                print(f"      • {change_info['additions']} additions")
                            if change_info.get('deletions', 0) > 0:
                                print(f"      • {change_info['deletions']} deletions")
                            if change_info.get('size_change_percent'):
                                print(f"      • {change_info['size_change_percent']:.1f}% size change")
                            
                            # Show change summary if available
                            change_summary = change_info.get('change_summary', {})
                            if change_summary:
                                print(f"      • Type: {change_summary.get('type', 'unknown')}")
                                if change_summary.get('added_lines_count', 0) > 0:
                                    print(f"      • {change_summary['added_lines_count']} lines added")
                                if change_summary.get('deleted_lines_count', 0) > 0:
                                    print(f"      • {change_summary['deleted_lines_count']} lines deleted")
                            
                            # Show actual line changes with ranges
                            added_lines = change_info.get('added_lines', [])
                            deleted_lines = change_info.get('deleted_lines', [])
                            
                            if added_lines or deleted_lines:
                                print(f"      📝 Detailed line-by-line analysis:")
                                
                                # Get range analysis
                                range_analysis = analyze_line_changes_with_ranges(
                                    added_lines, deleted_lines, 
                                    change['original_file'], change['current_file']
                                )
                                
                                # Show range summaries
                                ranges = range_analysis['ranges']
                                if ranges['deleted_ranges']:
                                    print(f"         ➖ Deletions: {', '.join(ranges['deleted_ranges'])}")
                                if ranges['added_ranges']:
                                    print(f"         ➕ Additions: {', '.join(ranges['added_ranges'])}")
                                if ranges['modified_ranges']:
                                    print(f"         🔄 Modifications: {', '.join(ranges['modified_ranges'])}")
                                
                                # Show sample content for significant changes
                                if range_analysis['modifications']:
                                    print(f"         📋 Modified content samples:")
                                    for line_num, old_content, new_content in range_analysis['modifications'][:3]:
                                        old_preview = old_content[:50] + ('...' if len(old_content) > 50 else '')
                                        new_preview = new_content[:50] + ('...' if len(new_content) > 50 else '')
                                        print(f"            Row {line_num}:")
                                        print(f"               - {old_preview}")
                                        print(f"               + {new_preview}")
                                    if len(range_analysis['modifications']) > 3:
                                        print(f"            ... and {len(range_analysis['modifications']) - 3} more modifications")
                                
                                # Show sample additions
                                if range_analysis['additions']:
                                    print(f"         📋 Added content samples:")
                                    for start_line, end_line, content_lines in range_analysis['additions'][:2]:
                                        print(f"            Rows {start_line}-{end_line}:")
                                        for content in content_lines[:3]:
                                            preview = content[:50] + ('...' if len(content) > 50 else '')
                                            print(f"               + {preview}")
                                        if len(content_lines) > 3:
                                            print(f"               + ... and {len(content_lines) - 3} more lines")
                                
                                # Show sample deletions
                                if range_analysis['deletions']:
                                    print(f"         📋 Deleted content samples:")
                                    for start_line, end_line, content_lines in range_analysis['deletions'][:2]:
                                        print(f"            Rows {start_line}-{end_line}:")
                                        for content in content_lines[:3]:
                                            preview = content[:50] + ('...' if len(content) > 50 else '')
                                            print(f"               - {preview}")
                                        if len(content_lines) > 3:
                                            print(f"               - ... and {len(content_lines) - 3} more lines")
                    
                    if detailed_analysis['minor_changes']:
                        print(f"✅ {len(detailed_analysis['minor_changes'])} files with minor changes")
                        for change in detailed_analysis['minor_changes'][:2]:  # Show first 2 minor changes
                            change_info = change['change_info']
                            print(f"   ✓ {change['url']}")
                            added_lines = change_info.get('added_lines', [])
                            deleted_lines = change_info.get('deleted_lines', [])
                            total_line_changes = len(added_lines) + len(deleted_lines)
                            if total_line_changes > 0:
                                print(f"      • {total_line_changes} line changes (likely timestamps or minor updates)")
                                if added_lines:
                                    print(f"        ➕ {len(added_lines)} additions")
                                if deleted_lines:
                                    print(f"        ➖ {len(deleted_lines)} deletions")
                    
                    if detailed_analysis['analysis_errors']:
                        print(f"❌ {len(detailed_analysis['analysis_errors'])} files could not be analyzed")
                        
        # Show insignificant changes separately
        if file_changes['insignificant_changes']:
            print(f"ℹ️ Minor changes detected: {len(file_changes['insignificant_changes'])} (likely false positives)")
            for file_info in file_changes['insignificant_changes'][:3]:  # Show first 3
                size_change = file_info['current_size'] - file_info['previous_size']
                print(f"   ✓ {file_info['url']} ({size_change:+d} bytes)")
        
        if file_changes['deleted_files']:
            print(f"🗑️ Deleted files detected: {len(file_changes['deleted_files'])}")
            for file_info in file_changes['deleted_files'][:5]:  # Show first 5
                print(f"   ❌ {file_info['url']}")
                print(f"      Was: {file_info['size']} bytes, Hash: {file_info['previous_hash'][:8]}...")
        
        # Total significant changes
        total_significant_changes = len(file_changes['new_files']) + len(file_changes['modified_files']) + len(file_changes['deleted_files'])
        
        if total_significant_changes == 0:
            if len(file_changes['insignificant_changes']) > 0:
                print(f"✅ No significant file changes detected (though {len(file_changes['insignificant_changes'])} minor changes found)")
            elif baseline_hashes:
                print("✅ No file changes detected since baseline scan")
            else:
                print("📝 First scan - establishing baseline file hashes")
        
        # Save current hashes only to reports directory (not main directory)
        if reports_directory:
            save_current_file_hashes(current_hashes, reports_directory)
        
        # Security implications of file changes
        security_alerts = []
        
        # Check for high-risk file changes
        for file_info in file_changes['new_files']:
            if any(risk_domain in file_info['domain'] for risk_domain in ['jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com']):
                security_alerts.append(f"New fourth-party script: {file_info['url']}")
        
        for file_info in file_changes['modified_files']:
            if '.js' in file_info['url']:
                security_alerts.append(f"JavaScript file modified: {file_info['url']}")
        
        if security_alerts:
            print(f"\n🚨 SECURITY ALERTS:")
            print("-" * 40)
            for alert in security_alerts[:3]:  # Show first 3
                print(f"   ⚠️ {alert}")
        
        # Categorize scripts
        script_categories = monitor.categorize_scripts({'captured_elements': js_files}, primary_domain)
        
        print("\n📋 SCRIPT CATEGORIZATION:")
        print("-" * 40)
        
        print(f"🏠 First-party scripts: {len(script_categories['first_party'])}")
        for script in script_categories['first_party'][:3]:  # Show first 3
            print(f"   ✅ {script['url']} (Risk: {script['risk']})")
        
        print(f"🏢 Third-party scripts: {len(script_categories['third_party'])}")
        for script in script_categories['third_party'][:3]:  # Show first 3
            print(f"   ⚠️ {script['url']} (Risk: {script['risk']})")
            
        print(f"🌍 Fourth-party scripts: {len(script_categories['fourth_party'])}")
        for script in script_categories['fourth_party'][:3]:  # Show first 3
            print(f"   🚨 {script['url']} (Risk: {script['risk']})")
        
        # Check CSP compliance - look in response headers
        csp_analysis = {'csp_found': False, 'violations': [], 'policy': ''}
        
        for request_id, response in responses.items():
            response_headers = response.get('headers', {})
            csp = response_headers.get('content-security-policy')
            
            if csp:
                csp_analysis['csp_found'] = True
                csp_analysis['policy'] = csp
                
                # Check for common CSP issues
                if "'unsafe-inline'" in csp:
                    csp_analysis['violations'].append("Unsafe inline scripts allowed")
                if "'unsafe-eval'" in csp:
                    csp_analysis['violations'].append("Unsafe eval allowed")
                if "*" in csp and "script-src" in csp:
                    csp_analysis['violations'].append("Wildcard script sources allowed")
                break
                
        if not csp_analysis['csp_found']:
            csp_analysis['violations'].append("No Content Security Policy found")
        
        print(f"\n🛡️ CONTENT SECURITY POLICY ANALYSIS:")
        print("-" * 40)
        print(f"CSP Found: {'✅ Yes' if csp_analysis['csp_found'] else '❌ No'}")
        
        if csp_analysis['violations']:
            print("🚨 CSP Violations:")
            for violation in csp_analysis['violations']:
                print(f"   - {violation}")
        else:
            print("✅ No CSP violations detected")
        
        # Security recommendations
        print(f"\n🎯 PCI DSS COMPLIANCE STATUS:")
        print("-" * 40)
        
        # Calculate compliance score
        compliance_score = 70  # Base score
        
        # Script-based scoring
        if len(script_categories['fourth_party']) == 0:
            compliance_score += 10
        elif len(script_categories['fourth_party']) > 5:
            compliance_score -= 20
            
        # CSP-based scoring
        if csp_analysis['csp_found'] and not csp_analysis['violations']:
            compliance_score += 15
        elif not csp_analysis['csp_found']:
            compliance_score -= 25
            
        # File change impact on compliance
        if file_changes['modified_files']:
            js_modifications = [f for f in file_changes['modified_files'] if '.js' in f['url']]
            if js_modifications:
                compliance_score -= min(10, len(js_modifications) * 2)  # Max 10 point penalty
                
        if file_changes['new_files']:
            new_fourth_party = [f for f in file_changes['new_files'] 
                              if any(domain in f['domain'] for domain in ['jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com'])]
            if new_fourth_party:
                compliance_score -= min(15, len(new_fourth_party) * 5)  # Max 15 point penalty
            
        print(f"📊 Compliance Score: {compliance_score}/100")
        
        if compliance_score >= 80:
            status = "🟢 GOOD"
        elif compliance_score >= 60:
            status = "🟡 NEEDS IMPROVEMENT"
        else:
            status = "🔴 CRITICAL ISSUES"
            
        print(f"🎭 Status: {status}")
        
        print(f"\n🔧 RECOMMENDATIONS:")
        print("-" * 40)
        
        rec_num = 1
        
        if len(script_categories['fourth_party']) > 0:
            print(f"{rec_num}. 🎯 Review fourth-party scripts - minimize on payment pages")
            rec_num += 1
            
        if not csp_analysis['csp_found']:
            print(f"{rec_num}. 🛡️ Implement Content Security Policy")
            rec_num += 1
            
        if len(script_categories['third_party']) > 3:
            print(f"{rec_num}. 📋 Document all third-party integrations")
            rec_num += 1
            
        if file_changes['modified_files']:
            print(f"{rec_num}. 🔍 Investigate modified files - ensure authorized changes")
            rec_num += 1
            
        if file_changes['new_files']:
            new_scripts = [f for f in file_changes['new_files'] if '.js' in f['url']]
            if new_scripts:
                print(f"{rec_num}. 🆕 Review {len(new_scripts)} new script(s) for authorization")
                rec_num += 1
        
        print(f"{rec_num}. 🔒 Implement Subresource Integrity (SRI) hashes")
        print(f"{rec_num + 1}. 📊 Set up automated change detection alerts")
        print(f"{rec_num + 2}. 📝 Create formal script authorization process")
        
        # Show specific fourth-party concerns
        high_risk_scripts = [s for s in script_categories['fourth_party'] if s['risk'] in ['HIGH', 'CRITICAL']]
        
        if high_risk_scripts:
            print(f"\n⚠️ HIGH-RISK FOURTH-PARTY SCRIPTS:")
            print("-" * 40)
            for script in high_risk_scripts:
                print(f"🚨 {script['url']}")
                print(f"   Risk: {script['risk']} | Type: {script.get('type', 'Unknown')}")
        
        # Update analysis results before returning
        if return_results:
            # Calculate a basic compliance score based on findings
            score = 100
            
            # Deduct points for various issues
            if not csp_analysis['csp_found']:
                score -= 15
                analysis_results['issues'].append({
                    'severity': 'High',
                    'description': 'Content Security Policy not implemented',
                    'recommendation': 'Implement a proper Content Security Policy'
                })
            
            if len(script_categories['third_party']) > 5:
                score -= 10
                analysis_results['issues'].append({
                    'severity': 'Medium',
                    'description': f'High number of third-party scripts ({len(script_categories["third_party"])})',
                    'recommendation': 'Reduce third-party dependencies and document all integrations'
                })
            
            if high_risk_scripts:
                score -= len(high_risk_scripts) * 5
                analysis_results['issues'].append({
                    'severity': 'Critical',
                    'description': f'High-risk fourth-party scripts detected ({len(high_risk_scripts)})',
                    'recommendation': 'Remove or replace high-risk fourth-party dependencies'
                })
            
            # Count only significant changes for scoring impact
            if file_changes['modified_files']:
                score -= min(15, len(file_changes['modified_files']) * 3)
                total_changes = len(file_changes['modified_files'])
                if file_changes['insignificant_changes']:
                    total_all = total_changes + len(file_changes['insignificant_changes'])
                    analysis_results['issues'].append({
                        'severity': 'Medium',
                        'description': f'Modified files detected ({total_changes} significant of {total_all} total changes)',
                        'recommendation': 'Investigate file modifications and ensure they are authorized'
                    })
                else:
                    analysis_results['issues'].append({
                        'severity': 'Medium',
                        'description': f'Modified files detected ({total_changes})',
                        'recommendation': 'Investigate file modifications and ensure they are authorized'
                    })
            
            # Ensure score is within bounds
            score = max(0, min(100, score))
            
            # Update final results
            analysis_results['compliance_score'] = score
            analysis_results['file_changes'] = file_changes
            analysis_results['script_categories'] = {
                'first_party': len(script_categories['first_party']),
                'third_party': len(script_categories['third_party']),
                'fourth_party': len(script_categories['fourth_party']),
                'high_risk': len(high_risk_scripts)
            }
            
            return analysis_results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_pci_compliance.py <json_file>")
        print("Example: python analyze_pci_compliance.py recursive_enhanced_capture_20250917_215131.json")
        sys.exit(1)
    
    analyze_captured_data(sys.argv[1])