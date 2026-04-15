#!/usr/bin/env python3
"""Attack battery orchestrator

Creates a coordinated injection and verification run using existing helpers
in the scripts/ directory. Designed to be safe for local CI testing: runs
pipeline (Redis XADD) injections, seeds tenant state, waits for workers,
and invokes verification helpers. Results and logs are written under tmp/.

Usage examples:
  python scripts/attack_battery.py --tenant perf-tenant --mode pipeline \
    --total 100 --concurrency 10 --wait 30 --output tmp/attack_battery_smoke.json

This file intentionally keeps runtime dependencies to the standard library
and calls existing helper scripts via subprocess so it can run inside the
existing virtualenv.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Any


def load_json_safe(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding='utf-8'))
    except Exception:
        return None


def collect_ints(obj) -> Set[int]:
    out: Set[int] = set()
    if isinstance(obj, int):
        out.add(obj)
        return out
    if isinstance(obj, str):
        return out
    if isinstance(obj, list):
        for v in obj:
            out |= collect_ints(v)
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            out |= collect_ints(v)
        return out
    return out


def gather_event_ids(base_dir: Path) -> List[int]:
    cfg_path = base_dir / 'app' / 'config' / 'config.json'
    ids: Set[int] = set()
    if cfg_path.exists():
        cfg = load_json_safe(cfg_path)
        if cfg is not None:
            ids |= {i for i in collect_ints(cfg) if 0 <= i <= 200000}

    # Scan policy files under app/config for monitored_events arrays
    conf_dir = base_dir / 'app' / 'config'
    if conf_dir.exists():
        for p in conf_dir.glob('*.json'):
            data = load_json_safe(p)
            if not data:
                continue
            # Common keys: monitored_events, events
            if isinstance(data, dict):
                for key in ('monitored_events', 'events', 'target_event_ids'):
                    if key in data and isinstance(data[key], list):
                        ids |= {int(x) for x in data[key] if isinstance(x, int)}
            # Fallback: collect any ints from the file
            ids |= {i for i in collect_ints(data) if 0 <= i <= 200000}

    return sorted(ids)


def run_subprocess(cmd: List[str], cwd: Path, out_path: Path, err_path: Path, env: Dict[str, str] = None) -> int:
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    out_path.write_text(p.stdout, encoding='utf-8')
    err_path.write_text(p.stderr, encoding='utf-8')
    return p.returncode


def find_hex_objectid(text: str) -> str | None:
    m = re.search(r"\b([a-fA-F0-9]{24})\b", text)
    return m.group(1) if m else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--tenant', required=True)
    parser.add_argument('--mode', choices=('pipeline', 'http', 'hybrid'), default='pipeline')
    parser.add_argument('--events', help='Comma-separated event ids to target (overrides SSOT)')
    parser.add_argument('--total', type=int, default=1000)
    parser.add_argument('--concurrency', type=int, default=100)
    parser.add_argument('--wait', type=int, default=60, help='Seconds to wait after injection')
    parser.add_argument('--output', default='tmp/attack_battery_results.json')
    parser.add_argument('--clean', action='store_true', help='Run clean_slate before injection')
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parents[1]
    scripts_dir = base_dir / 'scripts'
    tmp_dir = base_dir / 'tmp'
    ts = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    phase_dir = tmp_dir / 'phase2' / ts
    phase_dir.mkdir(parents=True, exist_ok=True)

    results: Dict[str, Any] = {
        'tenant': args.tenant,
        'mode': args.mode,
        'total': args.total,
        'concurrency': args.concurrency,
        'wait': args.wait,
        'timestamp': ts,
        'injections': [],
        'verifications': {},
    }

    # Optionally clean slate
    if args.clean:
        clean_script = scripts_dir / 'clean_slate.py'
        if clean_script.exists():
            run_subprocess([sys.executable, str(clean_script)], cwd=base_dir, out_path=phase_dir / 'clean_slate.out', err_path=phase_dir / 'clean_slate.err')

    # Seed tenant state
    seed_redis = scripts_dir / 'seed_redis.py'
    seed_mongo = scripts_dir / 'seed_mongo_user.py'
    if seed_redis.exists():
        run_subprocess([sys.executable, str(seed_redis)], cwd=base_dir, out_path=phase_dir / 'seed_redis.out', err_path=phase_dir / 'seed_redis.err')
    if seed_mongo.exists():
        env = os.environ.copy()
        env['TEST_TENANT'] = args.tenant
        run_subprocess([sys.executable, str(seed_mongo)], cwd=base_dir, out_path=phase_dir / 'seed_mongo.out', err_path=phase_dir / 'seed_mongo.err', env=env)

    # Determine event ids
    if args.events:
        events = [int(x.strip()) for x in args.events.split(',') if x.strip()]
    else:
        events = gather_event_ids(base_dir)

    if not events:
        print('No event ids found from SSOT and none provided via --events; aborting.')
        return 2

    # For pipeline mode we will split total across events
    per_event_total = max(1, args.total // len(events))
    per_event_concurrency = max(1, args.concurrency // len(events))

    load_pipeline = scripts_dir / 'load_pipeline.py'
    if args.mode in ('pipeline', 'hybrid') and not load_pipeline.exists():
        print(f'Expected helper not found: {load_pipeline}'); return 3

    # Run injections
    for i, ev in enumerate(events):
        # distribute remainder to first events
        extra = 1 if i < (args.total % len(events)) else 0
        total_for_event = per_event_total + extra

        log_base = phase_dir / f'event_{ev}'
        stdout_log = log_base.with_suffix('.out')
        stderr_log = log_base.with_suffix('.err')

        if args.mode in ('pipeline', 'hybrid'):
            cmd = [sys.executable, str(load_pipeline), '--total', str(total_for_event), '--concurrency', str(per_event_concurrency), '--tenant', args.tenant, '--event', str(ev)]
            print('Running:', ' '.join(cmd))
            rc = run_subprocess(cmd, cwd=base_dir, out_path=stdout_log, err_path=stderr_log)
            results['injections'].append({'event': ev, 'mode': 'pipeline', 'total': total_for_event, 'concurrency': per_event_concurrency, 'rc': rc, 'stdout': str(stdout_log), 'stderr': str(stderr_log)})

    # Wait for workers to process
    print(f'Waiting {args.wait} seconds for workers to process...')
    time.sleep(args.wait)

    # Run verifiers
    verify_results: Dict[str, Any] = {}
    # verify_duties.py
    verify_duties = scripts_dir / 'verify_duties.py'
    if verify_duties.exists():
        vd_out = phase_dir / 'verify_duties.out'
        vd_err = phase_dir / 'verify_duties.err'
        rc = run_subprocess([sys.executable, str(verify_duties)], cwd=base_dir, out_path=vd_out, err_path=vd_err)
        verify_results['verify_duties'] = {'rc': rc, 'stdout': str(vd_out), 'stderr': str(vd_err)}

    # find latest peca and verify signature
    find_latest = scripts_dir / 'find_latest_peca.py'
    if find_latest.exists():
        fl_out = phase_dir / 'find_latest_peca.out'
        fl_err = phase_dir / 'find_latest_peca.err'
        rc = run_subprocess([sys.executable, str(find_latest)], cwd=base_dir, out_path=fl_out, err_path=fl_err)
        content = fl_out.read_text(encoding='utf-8') if fl_out.exists() else ''
        oid = find_hex_objectid(content)
        verify_results['find_latest_peca'] = {'rc': rc, 'stdout': str(fl_out), 'stderr': str(fl_err), 'objectid': oid}
        if oid:
            verify_forensics = scripts_dir / 'verify_forensics.py'
            if verify_forensics.exists():
                vf_out = phase_dir / f'verify_forensics_{oid}.out'
                vf_err = phase_dir / f'verify_forensics_{oid}.err'
                rc2 = run_subprocess([sys.executable, str(verify_forensics), '--id', oid], cwd=base_dir, out_path=vf_out, err_path=vf_err)
                verify_results['verify_forensics'] = {'rc': rc2, 'stdout': str(vf_out), 'stderr': str(vf_err)}

    # verify fbr flow
    verify_fbr = scripts_dir / 'verify_fbr_flow.py'
    if verify_fbr.exists():
        vf_out = phase_dir / 'verify_fbr_flow.out'
        vf_err = phase_dir / 'verify_fbr_flow.err'
        rc = run_subprocess([sys.executable, str(verify_fbr)], cwd=base_dir, out_path=vf_out, err_path=vf_err)
        verify_results['verify_fbr_flow'] = {'rc': rc, 'stdout': str(vf_out), 'stderr': str(vf_err)}

    # index / ttl checks
    inspect_indexes = scripts_dir / 'inspect_indexes.py'
    if inspect_indexes.exists():
        ii_out = phase_dir / 'inspect_indexes.out'
        ii_err = phase_dir / 'inspect_indexes.err'
        rc = run_subprocess([sys.executable, str(inspect_indexes)], cwd=base_dir, out_path=ii_out, err_path=ii_err)
        verify_results['inspect_indexes'] = {'rc': rc, 'stdout': str(ii_out), 'stderr': str(ii_err)}

    check_latest = scripts_dir / 'check_latest_ages.py'
    if check_latest.exists():
        cl_out = phase_dir / 'check_latest_ages.out'
        cl_err = phase_dir / 'check_latest_ages.err'
        rc = run_subprocess([sys.executable, str(check_latest)], cwd=base_dir, out_path=cl_out, err_path=cl_err)
        verify_results['check_latest_ages'] = {'rc': rc, 'stdout': str(cl_out), 'stderr': str(cl_err)}

    results['verifications'] = verify_results

    # Write results JSON
    out_path = base_dir / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding='utf-8')

    print('Attack battery run completed. Results written to', str(out_path))
    print('Phase artifacts:', str(phase_dir))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
