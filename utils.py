import os
import json
import re
from datetime import datetime


def load_config(config_path=None, defaults=None):
    """Load configuration from YAML or JSON file if provided, else return defaults."""
    # Keep lightweight: accept JSON or YAML-like files by trying json first
    if defaults is None:
        defaults = {
            "output_dir": "scan_results",
            "default_depth": 2,
            "headless": True,
            "wait_time": 10,
            "excluded_domains": ["github.com", "fonts.googleapis.com", "docs.", "www.paypal.com/xoplatform/logger/api/logger","www.paypalobjects.com/api/checkout.min.js","pay.google.com/gp/p/js/pay.js", "pay.google.com/gp/p/ui/payframe?origin=https%3A%2F%2Fbraintree.github."],
            # Wildcard patterns for files/URLs to ignore during change detection
            "ignore_patterns": ["*/favicon.ico", "*/tagmanager/*"]
        }

    if not config_path:
        return defaults

    if not os.path.exists(config_path):
        return defaults

    # Try JSON first
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict):
                merged = {**defaults, **data}
                return merged
    except Exception:
        pass

    # Try PyYAML if available
    try:
        import yaml
        with open(config_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                merged = {**defaults, **data}
                return merged
    except Exception:
        pass

    # Lightweight fallback parser for simple YAML (lists and key: value pairs)
    try:
        parsed = {}
        current_key = None
        with open(config_path, 'r', encoding='utf-8') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('-') and current_key:
                    # list item
                    item = line.lstrip('-').strip()
                    # Strip surrounding quotes if present
                    if (item.startswith("'") and item.endswith("'")) or (item.startswith('"') and item.endswith('"')):
                        item = item[1:-1]
                    parsed.setdefault(current_key, []).append(item)
                    continue
                if ':' in line:
                    key, val = line.split(':', 1)
                    key = key.strip()
                    val = val.strip()
                    # Strip surrounding quotes for scalar values
                    if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                        val = val[1:-1]
                    if val == '':
                        # start of a list block
                        current_key = key
                        parsed[current_key] = []
                        continue
                    # try to parse JSON-like lists
                    try:
                        if val.startswith('[') and val.endswith(']'):
                            parsed[key] = json.loads(val)
                        else:
                            # basic type conversions
                            if val.lower() in ('true', 'false'):
                                parsed[key] = val.lower() == 'true'
                            else:
                                try:
                                    parsed[key] = int(val)
                                except Exception:
                                    parsed[key] = val
                    except Exception:
                        parsed[key] = val
                    current_key = None

        if parsed:
            merged = {**defaults, **parsed}
            return merged
    except Exception:
        pass

    return defaults


def get_versioned_directory(domain, base='.'):
    """Return a versioned directory for a given domain under base directory."""
    base_dir = os.path.join(base, domain)
    if not os.path.exists(base_dir):
        os.makedirs(base_dir, exist_ok=True)
        return base_dir

    version = 1
    while True:
        candidate = os.path.join(base, f"{domain}_{version}")
        if not os.path.exists(candidate):
            os.makedirs(candidate, exist_ok=True)
            return candidate
        version += 1


def get_reports_directory_from_domain(domain, output_directory=None):
    """Create or return a reports directory matching a versioned output directory name.

    If `output_directory` is provided and is versioned like './domain_1' it will mirror that name.
    """
    if output_directory:
        name = os.path.basename(output_directory)
    else:
        name = domain

    reports_dir = os.path.join('.', 'reports', name)
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def is_image_url(url):
    url_base = url.split('?', 1)[0].split('#', 1)[0]
    return bool(re.search(r'/[^/]+\.(jpg|jpeg|png|gif|bmp|webp|svg|ico)$', url_base, re.IGNORECASE))


def save_json(path, data):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_current_file_hashes(current_hashes, hash_directory='.'):
    path = os.path.join(hash_directory, 'file_hashes.json')
    save_json(path, current_hashes)


def load_previous_file_hashes(hash_directory='.'):
    path = os.path.join(hash_directory, 'file_hashes.json')
    return load_json(path) or {}


def matches_ignore_patterns(url_or_path, patterns):
    """Return True if the provided URL or path matches any of the glob patterns.

    Patterns use Unix shell-style wildcards as implemented by fnmatch.
    """
    if not patterns:
        return False
    from fnmatch import fnmatch
    for pat in patterns:
        try:
            if fnmatch(url_or_path, pat):
                return True
        except Exception:
            # ignore malformed patterns
            continue
    return False
