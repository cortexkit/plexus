#!/usr/bin/env python3
"""Record every probe library test, including additional failures from a source edit."""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

result = subprocess.run(['cargo', 'test', '--locked', '-p', 'plexus-probe', '--lib', '--', '--test-threads=1'],
                        capture_output=True, text=True, timeout=300)
print(result.stdout, end='')
print(result.stderr, end='', file=sys.stderr)
rows = re.findall(r'^test (\S+) \.\.\. (ok|FAILED|ignored[^\n]*)$', result.stdout, re.M)
summary = re.search(r'test result: .*? (\d+) passed; (\d+) failed; (\d+) ignored;', result.stdout)
if not summary or not rows or len(rows) != sum(map(int, summary.groups())):
    raise SystemExit('libtest output did not account for every probe test')
root = ET.Element('testsuite', tests=str(len(rows)))
for name, status in rows:
    case = ET.SubElement(root, 'testcase', name=name, classname=name.rsplit('::', 1)[0])
    if status == 'FAILED':
        ET.SubElement(case, 'failure').text = result.stdout
    elif status.startswith('ignored'):
        ET.SubElement(case, 'skipped', message=status)
path = Path('target/mutations/g-probe-junit.xml')
path.parent.mkdir(parents=True, exist_ok=True)
ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
raise SystemExit(result.returncode)
