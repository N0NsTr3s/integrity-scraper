import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utils import load_config, matches_ignore_patterns


def load_scan(scan_path):
    with open(scan_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, list) and len(data) > 0:
        return data[0]
    return data


def main():
    parser = argparse.ArgumentParser(description='Check which requests/files match ignore patterns')
    parser.add_argument('scan_file', help='Path to scan JSON file')
    parser.add_argument('--config', '-c', dest='config', help='Path to config.yaml', default="./config.yaml")
    args = parser.parse_args()

    scan_file = args.scan_file
    cfg_path = args.config if args.config else 'config.yaml'
    config = load_config(cfg_path)
    patterns = config.get('ignore_patterns', [])

    print(f"Loaded {len(patterns)} ignore pattern(s) from {cfg_path}")
    for i, p in enumerate(patterns, 1):
        print(f"  {i}. {p}")

    scan = load_scan(scan_file)
    requests = scan.get('requests', {}) # type: ignore
    captured_files = scan.get('captured_files', {}) # type: ignore

    print('\nChecking requests:')
    missing = []
    for req_id, req in requests.items():
        url = req.get('url', '')
        matched = matches_ignore_patterns(url, patterns)
        fp = ''
        if url in captured_files:
            fp = captured_files[url].get('filepath', '')
        matched_fp = matches_ignore_patterns(fp, patterns) if fp else False
        if not matched and not matched_fp:
            missing.append(url)
        else:
            print(f"IGNORED: {url}  (filepath='{fp}')")

    print(f"\nRequests not matched by ignore patterns: {len(missing)}")
    for u in missing[:50]:
        print(f"  - {u}")

    print('\nDone')


if __name__ == '__main__':
    main()
