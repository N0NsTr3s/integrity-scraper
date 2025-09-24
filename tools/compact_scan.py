#!/usr/bin/env python3
"""Create a compacted version of a scan JSON by grouping correlated data per request.

Usage: python tools/compact_scan.py <scan.json>
Output: writes <scan>_compact.json next to the input file.
"""
import json
import os
import sys
from urllib.parse import urlparse


def load_scan(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def build_index_by_url(sources):
    # Build a mapping from url -> list of source entries
    idx = {}
    for sid, s in (sources or {}).items():
        url = s.get('url') if isinstance(s, dict) else None
        if not url:
            # try performance_data name
            pd = s.get('performance_data') if isinstance(s, dict) else None
            if pd and isinstance(pd, dict):
                url = pd.get('name')
        if url:
            idx.setdefault(url, []).append({'id': sid, 'source': s})
    return idx


async def compact_scan_object(scan_obj):
    # Use linked_resources when available since it already groups
    linked = scan_obj.get('linked_resources', {}) or {}
    requests = scan_obj.get('requests', {}) or {}
    responses = scan_obj.get('responses', {}) or {}
    bodies = scan_obj.get('bodies', {}) or {}
    extra = scan_obj.get('extra_info', {}) or {}
    failed = scan_obj.get('failed_requests', {}) or {}
    captured_files = scan_obj.get('captured_files', {}) or {}
    sources = scan_obj.get('sources', {}) or {}

    src_idx = build_index_by_url(sources)

    grouped = {}

    # Start from linked_resources to preserve existing grouping
    processed = set()
    for rid, lr in linked.items():
        # try to find canonical url
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

        # attach related sources and captured_file if present
        related_sources = src_idx.get(url, []) if url else []
        if related_sources:
            entry['sources'] = related_sources

        # attach captured file metadata if any key matches url
        if url in captured_files:
            entry['captured_file'] = captured_files.get(url)
        else:
            # try match by path (strip query)
            if url:
                base = url.split('?', 1)[0]
                if base in captured_files:
                    entry['captured_file'] = captured_files.get(base)

        grouped[rid] = entry
        processed.add(rid)

    # Also include any remaining requests not present in linked_resources
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

    # Build compact capture_info
    compact_info = {
        'timestamp': scan_obj.get('capture_info', {}).get('timestamp'),
        'total_grouped_resources': len(grouped),
        'total_requests': scan_obj.get('capture_info', {}).get('total_requests'),
        'total_responses': scan_obj.get('capture_info', {}).get('total_responses')
    }

    # Determine dependency relationships using request initiators
    # Build URL -> request_id map for quick lookup
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
        # try match by path/netloc equality
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
            # top-level url
            if 'url' in initiator and initiator.get('url'):
                initiator_urls.add(initiator.get('url'))
            # stack frames
            stack = initiator.get('stack') or initiator.get('stackTrace')
            if stack and isinstance(stack, dict):
                for cf in stack.get('callFrames', []) or []:
                    if cf.get('url'):
                        initiator_urls.add(cf.get('url'))
        # resolve initiator urls to request ids
        dependent_on = {}
        for iu in list(initiator_urls):
            for target_rid in find_rids_for_url(iu):
                if target_rid and target_rid != rid:
                    target_url = requests.get(target_rid, {}).get('url') or responses.get(target_rid, {}).get('url')
                    if not target_url:
                        continue
                    # add mapping id -> url
                    dependent_on[target_rid] = target_url
                    # mark reverse mapping on the target entry as id->url
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
        # Prefer a Document-type request
        for r_id, r in requests.items():
            if str(r.get('type', '')).lower() == 'document':
                u = r.get('url')
                if u:
                    return urlparse(u).netloc
        # Fallback: response with text/html
        for r_id, resp in responses.items():
            mt = resp.get('mimeType', '') or ''
            if isinstance(mt, str) and mt.startswith('text/html'):
                u = resp.get('url')
                if u:
                    return urlparse(u).netloc
        # Fallback: most common host in requests
        hosts = {}
        for r in requests.values():
            u = r.get('url')
            if u:
                h = urlparse(u).netloc
                hosts[h] = hosts.get(h, 0) + 1
        if hosts:
            return max(hosts, key=hosts.get) # type: ignore
        return ''

    primary_domain = determine_primary_domain(requests, responses)

    # Classify party for each grouped entry
    def host_of(u):
        try:
            return urlparse(u).netloc
        except Exception:
            return ''

    for rid, entry in list(grouped.items()):
        # default
        party = 'unknown'
        reason = ''
        url = request_map.get(rid) or (entry.get('request') or {}).get('url')
        host = host_of(url)
        if primary_domain and host == primary_domain:
            party = 'first'
            reason = 'host matches primary domain'
        else:
            # check initiator/referrer
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
            # check referer
            referer = (req.get('headers') or {}).get('Referer') or (req.get('headers') or {}).get('referer')
            if referer:
                initiator_urls.add(referer)

            # immediate dependency check (dependent_on is id->url map)
            deps = entry.get('dependent_on') or {}
            if deps:
                # if any immediate dep is primary, mark third
                if any(host_of(u) == primary_domain for u in deps.values()):
                    party = 'third'
                    reason = 'immediate dependency points to primary domain'
                else:
                    # if immediate deps exist but none are primary -> transitive
                    party = 'fourth'
                    reason = 'depends on non-primary resources (transitive)'
            else:
                # check initiator urls
                if any(host_of(u) == primary_domain for u in initiator_urls):
                    party = 'third'
                    reason = 'initiator/referrer is primary domain'
                else:
                    # fallback: non-primary with no deps -> third (directly included)
                    party = 'third'
                    reason = 'non-primary resource with no detected primary dependency'

        entry['party'] = party
        entry['party_reason'] = reason

    return {'capture_info': compact_info, 'grouped': grouped, 'request_map': request_map}


def main():
    if len(sys.argv) < 2:
        print('Usage: python tools/compact_scan.py <scan.json>')
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.exists(path):
        print('File not found:', path)
        sys.exit(1)

    data = load_scan(path)
    if not isinstance(data, list):
        print('Unexpected scan format: expected list of scan objects')
        sys.exit(1)

    compact_list = []
    for scan_obj in data:
        compact_list.append(compact_scan_object(scan_obj))

    out_path = os.path.splitext(path)[0] + '_compact.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(compact_list, f, indent=2, ensure_ascii=False)

    print('Wrote compact scan to', out_path)


if __name__ == '__main__':
    main()
