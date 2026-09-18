#!/usr/bin/env python3
"""Elaboration guard regression for aes_gcm_top.

Every illegal parameter set must be rejected at elaboration time with the
documented $fatal message, and every legal set must elaborate cleanly. The
check is run with Verilator (lint-only) and, when available, Icarus Verilog,
because the two tools evaluate generate-scope $fatal differently.

Usage:  python3 tb/elab/run_elab_checks.py [--no-icarus]
Exit code 0 when every expectation holds.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILELIST = ROOT / 'rtl' / 'filelist.f'
TOP = 'aes_gcm_top'

# (description, {param: value}, expected message fragment or None for legal)
CASES = [
    ('default AES-128 / 256 B',                 {},                                   None),
    ('AES-256 / 256 B',                          {'KEY_W': 256},                       None),
    ('smallest legal page (1 block)',           {'PAGE_BYTES': 48},                   None),
    ('AES-256 smallest legal page',             {'KEY_W': 256, 'PAGE_BYTES': 48},     None),
    ('non power-of-two page 528 B',             {'PAGE_BYTES': 528},                  None),
    ('4 KiB page AES-256',                      {'KEY_W': 256, 'PAGE_BYTES': 4096},   None),
    ('custom watchdog',                         {'WDT_TIMEOUT': 1000},                None),
    ('minimum watchdog',                        {'WDT_TIMEOUT': 1},                   None),
    ('unsupported key width 192',               {'KEY_W': 192},                       'KEY_W must be 128 or 256'),
    ('unsupported key width 64',                {'KEY_W': 64},                        'KEY_W must be 128 or 256'),
    ('page not a multiple of 16',               {'PAGE_BYTES': 255},                  'PAGE_BYTES must be a multiple of 16'),
    ('page not a multiple of 16 (large)',       {'PAGE_BYTES': 4100},                 'PAGE_BYTES must be a multiple of 16'),
    ('page too small: metadata only',           {'PAGE_BYTES': 32},                   'PAGE_BYTES must be at least 48'),
    ('page too small: 16 B',                    {'PAGE_BYTES': 16},                   'PAGE_BYTES must be at least 48'),
    ('page too small: 0 B',                     {'PAGE_BYTES': 0},                    'PAGE_BYTES must be at least 48'),
    ('IV width other than 96',                  {'IV_W': 64},                         'IV_W must be 96'),
    ('AAD width other than 128',                {'AAD_W': 256},                       'AAD_W is fixed at 128'),
    ('tag width other than 128',                {'TAG_W': 96},                        'TAG_W is fixed at 128'),
    ('data width other than 128',               {'DATA_W': 64},                       'DATA_W must be 128'),
    ('watchdog threshold 0',                    {'WDT_TIMEOUT': 0},                   'WDT_TIMEOUT must be at least 1'),
]


def run_verilator(params: dict) -> tuple[int, str]:
    cmd = ['verilator', '--lint-only', '-Wno-TIMESCALEMOD', '-Wno-DECLFILENAME',
           '-Wno-fatal', '--top-module', TOP, '-f', str(FILELIST)]
    cmd += [f'-G{k}={v}' for k, v in params.items()]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def run_icarus(params: dict) -> tuple[int, str]:
    out = ROOT / 'build' / 'elab' / 'a.out'
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['iverilog', '-g2012', '-o', str(out), '-s', TOP, '-f', str(FILELIST)]
    cmd += [f'-P{TOP}.{k}={v}' for k, v in params.items()]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def verilator_fatal(out: str) -> bool:
    # generate-scope $fatal surfaces as %Warning-USERFATAL (fatal in a normal
    # build; -Wno-fatal is used above only so the full message list is visible)
    return 'USERFATAL' in out


def icarus_fatal(out: str) -> bool:
    return 'FATAL:' in out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--no-icarus', action='store_true')
    args = ap.parse_args()

    tools = [('verilator', run_verilator, verilator_fatal)]
    if not args.no_icarus and shutil.which('iverilog'):
        tools.append(('icarus', run_icarus, icarus_fatal))

    failures = 0
    print(f'{"tool":9} {"result":6} {"case":40} params')
    for tool, runner, is_fatal in tools:
        for desc, params, expect in CASES:
            rc, out = runner(params)
            fatal = is_fatal(out)
            if expect is None:
                ok = (rc == 0) and not fatal
                detail = '' if ok else f'  rc={rc} fatal={fatal}'
            else:
                ok = fatal and (expect in out)
                detail = '' if ok else f'  rc={rc} fatal={fatal} expected "{expect}"'
            status = 'PASS' if ok else 'FAIL'
            if not ok:
                failures += 1
            pstr = ' '.join(f'{k}={v}' for k, v in params.items()) or '(defaults)'
            print(f'{tool:9} {status:6} {desc:40} {pstr}{detail}')
            if not ok:
                print('    --- tool output (first lines) ---')
                for line in out.splitlines()[:6]:
                    print('    ' + line)
    total = len(CASES) * len(tools)
    print(f'\nelab-check: {total - failures}/{total} expectations met')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
