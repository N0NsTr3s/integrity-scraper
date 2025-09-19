import difflib
import os
import argparse
import logging
import mimetypes
import hashlib
import re
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)

def setup_logging():
    """Set up logging for the module"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"file_changes_{datetime.now().strftime('%Y%m%d')}.log")
    
    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def is_binary_file(file_path):
    """Check if a file is binary by examining its MIME type and contents.
    
    Args:
        file_path (str): Path to the file to check
        
    Returns:
        bool: True if the file is binary, False if it's text
    """
    # Initialize MIME types
    if not mimetypes.inited:
        mimetypes.init()
    
    # Check MIME type
    mime_type, _ = mimetypes.guess_type(file_path)
    
    # If mime_type is None or starts with 'text/', it's likely a text file
    if mime_type and not mime_type.startswith('text/') and not mime_type in ['application/json', 'application/xml']:
        return True
    
    # If MIME type check is inconclusive, try to read the file
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            # Check for common binary signatures
            if b'\x00' in chunk:  # Null bytes are a good indicator of binary
                return True
            # Try decoding as UTF-8
            try:
                chunk.decode('utf-8')
                return False  # Successfully decoded, so it's text
            except UnicodeDecodeError:
                return True   # Failed to decode, likely binary
    except Exception:
        # If in doubt, assume it's binary to avoid mishandling
        return True
    
    return False

def is_image_file(file_path):
    """Check if a file is an image based on MIME type and extension.
    
    Args:
        file_path (str): Path to the file to check
        
    Returns:
        bool: True if the file is an image, False otherwise
    """
    # Initialize MIME types
    if not mimetypes.inited:
        mimetypes.init()
    
    # Check MIME type
    mime_type, _ = mimetypes.guess_type(file_path)
    
    # Check if mime type starts with 'image/'
    if mime_type and mime_type.startswith('image/'):
        return True
    
    # Check file extension as a fallback
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico', '.tiff', '.tif']
    file_ext = os.path.splitext(file_path)[1].lower()
    
    return file_ext in image_extensions

def is_javascript_file(file_path):
    """Check if a file is JavaScript based on MIME type and extension.
    
    Args:
        file_path (str): Path to the file to check
        
    Returns:
        bool: True if the file is JavaScript, False otherwise
    """
    # Initialize MIME types
    if not mimetypes.inited:
        mimetypes.init()
    
    # Check MIME type
    mime_type, _ = mimetypes.guess_type(file_path)
    
    # Check if mime type indicates JavaScript
    if mime_type and mime_type in ['application/javascript', 'text/javascript']:
        return True
    
    # Check file extension as a fallback
    js_extensions = ['.js', '.mjs', '.cjs']
    file_ext = os.path.splitext(file_path)[1].lower()
    
    return file_ext in js_extensions

# Simple helper functions for file operations
def get_file_extension(file_path):
    """Get the file extension from a path.
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        str: File extension (lowercase, without the dot)
    """
    _, ext = os.path.splitext(file_path)
    return ext.lower().lstrip('.')
    
def normalize_javascript_content(content):
    """Normalize JavaScript content to ignore minor differences.
    
    This function removes comments, normalizes whitespace, and performs other
    transformations to focus on the functional code rather than formatting.
    
    Args:
        content (str): JavaScript content to normalize
        
    Returns:
        str: Normalized JavaScript content
    """
    # Basic normalization - this is a simplified approach
    # For production use, consider using a proper JS minifier/parser
    
    # Remove single-line comments
    content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)
    
    # Remove multi-line comments
    content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
    
    # Normalize whitespace around operators and punctuation
    content = re.sub(r'\s*([-+*/%=<>!&|,.;:{}()\[\]])\s*', r'\1', content)
    
    # Normalize consecutive whitespace
    content = re.sub(r'\s+', ' ', content)
    
    # Remove leading/trailing whitespace
    content = content.strip()
    
    # Normalize function declarations (spaces between function name and parenthesis)
    content = re.sub(r'function\s+([a-zA-Z0-9_$]+)\s*\(', r'function \1(', content)
    
    # Normalize variable declarations
    content = re.sub(r'(var|let|const)\s+', r'\1 ', content)
    
    # Remove spaces after certain keywords
    content = re.sub(r'\b(if|for|while|switch)\s*\(', r'\1(', content)
    
    return content

def get_file_hash(file_path, normalize=False):
    """Calculate SHA-256 hash of a file.
    
    Args:
        file_path (str): Path to the file
        normalize (bool, optional): Whether to normalize content before hashing
        
    Returns:
        str: Hex digest of the SHA-256 hash
    """
    hasher = hashlib.sha256()
    
    try:
        # For JavaScript files, normalize the content before hashing
        if normalize and is_javascript_file(file_path):
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                
            # Normalize JavaScript content
            normalized_content = normalize_javascript_content(content)
            hasher.update(normalized_content.encode('utf-8'))
            return hasher.hexdigest()
        
        # Standard binary hash for other files
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        logger.error(f"Error hashing file {file_path}: {e}")
        return ""

def get_file_info(file_path, normalize_js=True):
    """Get comprehensive information about a file.
    
    Args:
        file_path (str): Path to the file
        normalize_js (bool, optional): Whether to normalize JavaScript files before hashing
        
    Returns:
        dict: File information including size, hash, type
    """
    try:
        stat_info = os.stat(file_path)
        is_js = is_javascript_file(file_path)
        
        file_info = {
            'path': file_path,
            'size': stat_info.st_size,
            'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'hash': get_file_hash(file_path, normalize=normalize_js and is_js),
            'is_binary': is_binary_file(file_path),
            'is_image': is_image_file(file_path),
            'is_javascript': is_js
        }
        
        # Get MIME type
        mime_type, _ = mimetypes.guess_type(file_path)
        file_info['mime_type'] = mime_type or 'application/octet-stream'
        
        # For JavaScript files, also store the normalized hash for comparison
        if is_js and normalize_js:
            file_info['normalized_hash'] = file_info['hash']
            file_info['raw_hash'] = get_file_hash(file_path, normalize=False)
        
        return file_info
    except Exception as e:
        logger.error(f"Error getting file info for {file_path}: {e}")
        return {'path': file_path, 'error': str(e)}

def read_file(file_path):
    """Read the contents of a file and return as a list of lines.
    
    Args:
        file_path (str): Path to the file to read
        
    Returns:
        list: Lines of the file
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        IOError: If there's an error reading the file
    """
    try:
        # Check if it's a binary file first
        if is_binary_file(file_path):
            logger.warning(f"Attempting to read binary file as text: {file_path}")
            
        with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
            return file.readlines()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except IOError as e:
        logger.error(f"Error reading file {file_path}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error reading {file_path}: {e}")
        raise

def detect_changes(original_file, modified_file, size_threshold_percent=0.5, normalize_js=True, min_size_threshold_bytes=10):
    """Detect changes between two files and return added, deleted, and modified lines.
    Enhanced to handle binary files, images, and JavaScript files with special processing.
    
    Args:
        original_file (str): Path to the original file
        modified_file (str): Path to the modified file
        size_threshold_percent (float, optional): Size change threshold as percent to consider significant
        normalize_js (bool, optional): Whether to normalize JavaScript files before comparison
        min_size_threshold_bytes (int, optional): Minimum size difference in bytes to be significant
        
    Returns:
        dict: Change information including binary comparison and text diff if applicable
    """
    logger.info(f"Comparing {original_file} with {modified_file}")
    
    try:
        # Get comprehensive file information
        original_info = get_file_info(original_file, normalize_js=normalize_js)
        modified_info = get_file_info(modified_file, normalize_js=normalize_js)
        
        # Check file types
        is_image = is_image_file(original_file) or is_image_file(modified_file)
        is_js = is_javascript_file(original_file) or is_javascript_file(modified_file)
        
        # Calculate size threshold in bytes - max of percentage and minimum bytes
        max_size = max(original_info['size'], modified_info['size'])
        percentage_threshold = max_size * (size_threshold_percent / 100.0)
        size_threshold = max(percentage_threshold, min_size_threshold_bytes)
        size_difference = abs(modified_info['size'] - original_info['size'])
        
        # Create base change info
        change_info = {
            'original_file': original_file,
            'modified_file': modified_file,
            'original_info': original_info,
            'modified_info': modified_info,
            'has_changed': original_info['hash'] != modified_info['hash'],
            'size_change': modified_info['size'] - original_info['size'],
            'is_binary': original_info['is_binary'] or modified_info['is_binary'],
            'is_image': is_image,
            'is_javascript': is_js,
            'is_significant_change': False,  # Default to false, will be updated
            'added_lines': [],
            'deleted_lines': [],
            'change_summary': {}
        }
        
        # For JavaScript files, check both raw and normalized hashes if available
        if is_js and normalize_js:
            orig_norm_hash = original_info.get('normalized_hash')
            mod_norm_hash = modified_info.get('normalized_hash')
            
            if orig_norm_hash and mod_norm_hash:
                # If normalized hashes match, the functional code is the same
                change_info['has_functional_change'] = orig_norm_hash != mod_norm_hash
                
                # If only raw hashes differ but normalized hashes match, it's formatting only
                change_info['formatting_change_only'] = (
                    change_info['has_changed'] and not change_info['has_functional_change']
                )
            else:
                # Fallback if normalized hashes aren't available
                change_info['has_functional_change'] = change_info['has_changed']
                change_info['formatting_change_only'] = False
        
        # If files are identical, return early
        if not change_info['has_changed']:
            change_info['change_summary'] = {
                'type': 'no_change',
                'message': 'Files are identical'
            }
            return change_info
            
        # Determine significance based on file type and changes
        
        # For JavaScript files with normalization
        if change_info['is_javascript'] and normalize_js:
            # If only formatting changed, it's not significant
            if change_info.get('formatting_change_only'):
                change_info['is_significant_change'] = False
                change_info['change_summary'] = {
                    'type': 'js_formatting_change',
                    'mime_type': modified_info['mime_type'],
                    'size_diff': change_info['size_change'],
                    'message': f"JavaScript formatting change only: {abs(change_info['size_change'])} bytes {'larger' if change_info['size_change'] > 0 else 'smaller'}"
                }
                logger.info(f"JavaScript formatting change detected: {change_info['change_summary']['message']}")
                return change_info
                
            # Determine significance based on size change for functional changes
            is_minor_size_change = size_difference <= size_threshold
            change_info['is_significant_change'] = not is_minor_size_change
            
            change_info['change_summary'] = {
                'type': 'js_content_change',
                'mime_type': modified_info['mime_type'],
                'size_diff': change_info['size_change'],
                'message': f"JavaScript code change: {abs(change_info['size_change'])} bytes {'larger' if change_info['size_change'] > 0 else 'smaller'} " +
                          f"({'minor' if is_minor_size_change else 'significant'} change)"
            }
            
            logger.info(f"JavaScript change detected: {change_info['change_summary']['message']}")
            
            # For significant JavaScript changes, still do text comparison for reporting
            if change_info['is_significant_change'] and not change_info['is_binary']:
                # Continue to text comparison
                pass
            else:
                return change_info
                
        # If the file is an image, handle it specially
        if change_info['is_image']:
            # For image files, determine significance based on size threshold
            is_minor_size_change = size_difference <= size_threshold
            change_info['is_significant_change'] = not is_minor_size_change
            
            change_info['change_summary'] = {
                'type': 'image_change',
                'mime_type': modified_info['mime_type'],
                'size_diff': change_info['size_change'],
                'message': f"Image file changed: {abs(change_info['size_change'])} bytes {'larger' if change_info['size_change'] > 0 else 'smaller'} " +
                          f"({'minor' if is_minor_size_change else 'significant'} change)"
            }
            
            logger.info(f"Image file change detected: {change_info['change_summary']['message']}")
            return change_info
        
        # If both are text files, do text comparison
        if not change_info['is_binary']:
            original_lines = read_file(original_file)
            modified_lines = read_file(modified_file)

            # Create a Differ object
            d = difflib.Differ()
            # Get the difflib comparison for a line by line diff
            diff = list(d.compare(original_lines, modified_lines))
            
            # Collect added/deleted lines from diff for reporting
            added_lines = []
            deleted_lines = []
            meaningful_changes = []
            
            # Process the diff to get added/deleted lines
            for line in diff:
                if line.startswith('+ '):
                    content = line[2:]  # Remove the '+ ' prefix
                    added_lines.append(content)
                    # All added lines are considered meaningful changes
                    meaningful_changes.append(content)
                elif line.startswith('- '):
                    content = line[2:]  # Remove the '- ' prefix
                    deleted_lines.append(content)
                    # All deleted lines are considered meaningful changes
                    meaningful_changes.append(content)
            
            change_info['added_lines'] = added_lines
            change_info['deleted_lines'] = deleted_lines
            change_info['meaningful_changes'] = meaningful_changes
            
            # For text files not already processed (e.g., JavaScript)
            if 'is_significant_change' not in change_info or change_info['is_significant_change'] is None:
                # Determine significance based on number of changes and size
                line_change_ratio = (len(added_lines) + len(deleted_lines)) / max(len(original_lines), len(modified_lines)) if max(len(original_lines), len(modified_lines)) > 0 else 0
                is_minor_change = line_change_ratio < 0.01 and size_difference <= size_threshold  # Less than 1% of lines changed and size within threshold
                
                change_info['is_significant_change'] = not is_minor_change and (len(added_lines) > 0 or len(deleted_lines) > 0)
            
            logger.info(f"Found {len(added_lines)} added lines and {len(deleted_lines)} deleted lines")
            
            change_info['change_summary'] = {
                'type': 'text_change',
                'added_lines_count': len(added_lines),
                'deleted_lines_count': len(deleted_lines),
                'meaningful_changes_count': len(meaningful_changes),
                'is_significant': change_info['is_significant_change'],
                'message': f"Text file modified with {len(added_lines)} additions and {len(deleted_lines)} deletions" + 
                           (f" (significant change)" if change_info['is_significant_change'] else " (minor change)")
            }
        else:
            # Binary file comparison
            # For binary files not already processed (e.g., images)
            if 'is_significant_change' not in change_info or change_info['is_significant_change'] is None:
                # Size threshold for binary files
                is_significant = size_difference > size_threshold
                change_info['is_significant_change'] = is_significant
            
            change_info['change_summary'] = {
                'type': 'binary_change',
                'mime_type': modified_info['mime_type'],
                'size_diff': change_info['size_change'],
                'is_significant': change_info['is_significant_change'],
                'message': f"Binary file changed: {abs(change_info['size_change'])} bytes {'larger' if change_info['size_change'] > 0 else 'smaller'}" +
                           (f" (significant change)" if change_info['is_significant_change'] else " (minor change)")
            }
            
            logger.info(f"Binary file change detected: {change_info['change_summary']['message']}")
            
        # Create changes directory if it doesn't exist
        changes_dir = "changes"
        os.makedirs(changes_dir, exist_ok=True)
        
        # Create a filename based on the modified file
        filename = os.path.basename(modified_file)
        change_file_path = os.path.join(changes_dir, f"{os.path.splitext(filename)[0]}_changes.txt")
        
        # Write changes to file for record keeping
        with open(change_file_path, 'w', encoding='utf-8') as f:
            f.write(f"File Changes Report - {datetime.now()}\n")
            f.write(f"Comparing {original_file} with {modified_file}\n\n")
            
            # Determine file type for display
            file_type = "Image" if change_info['is_image'] else ("Binary" if change_info['is_binary'] else "Text")
            f.write(f"File Type: {file_type}\n")
            f.write(f"MIME Type: {modified_info['mime_type']}\n")
            f.write(f"Original Size: {original_info['size']} bytes\n")
            f.write(f"Modified Size: {modified_info['size']} bytes\n")
            f.write(f"Size Change: {change_info['size_change']} bytes\n")
            f.write(f"Original Hash: {original_info['hash']}\n")
            f.write(f"Modified Hash: {modified_info['hash']}\n\n")
            
            if change_info['is_image']:
                f.write("Image file content changes are not compared line by line.\n")
                f.write(f"Summary: {change_info['change_summary']['message']}\n")
            elif not change_info['is_binary']:
                f.write("Added Lines:\n")
                for line in change_info['added_lines']:
                    f.write(f"+ {line}")
                
                f.write("\nDeleted Lines:\n")
                for line in change_info['deleted_lines']:
                    f.write(f"- {line}")
            else:
                f.write("Binary file content changes cannot be displayed line by line.\n")
                f.write(f"Summary: {change_info['change_summary']['message']}\n")
        
        logger.info(f"Changes saved to {change_file_path}")
        
        return change_info
    except Exception as e:
        logger.error(f"Error detecting changes: {e}")
        # Re-raise to handle in calling code
        raise

def main():
    # Set up logging
    setup_logging()
    
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='Detect changes between two files.')
    parser.add_argument('original_file', type=str, help='Path to the original file')
    parser.add_argument('modified_file', type=str, help='Path to the modified file')
    parser.add_argument('--output', '-o', help='Output file for changes')

    args = parser.parse_args()

    try:
        changes = detect_changes(args.original_file, args.modified_file)
        
        print(f"File Comparison: {os.path.basename(args.original_file)} vs {os.path.basename(args.modified_file)}")
        
        # Determine file type for display
        if changes['is_image']:
            file_type = "Image"
        elif changes['is_binary']:
            file_type = "Binary"
        else:
            file_type = "Text"
            
        print(f"File Type: {file_type}")
        print(f"Size Change: {changes['size_change']} bytes")
        print(f"Hash Change: {changes['original_info']['hash'][:8]} → {changes['modified_info']['hash'][:8]}")
        
        if changes['is_image']:
            print(f"\nImage File Change: {changes['change_summary']['message']}")
            # No detailed comparison for images
        elif changes['is_binary']:
            print(f"\nBinary File Change: {changes['change_summary']['message']}")
        else:
            print("\nAdded Lines:")
            for line in changes['added_lines'][:10]:  # Show first 10 lines only
                print(f"+ {line.strip()}")
            
            if len(changes['added_lines']) > 10:
                print(f"... {len(changes['added_lines']) - 10} more lines added")
                
            print("\nDeleted Lines:")
            for line in changes['deleted_lines'][:10]:  # Show first 10 lines only
                print(f"- {line.strip()}")
                
            if len(changes['deleted_lines']) > 10:
                print(f"... {len(changes['deleted_lines']) - 10} more lines deleted")
        
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    main()