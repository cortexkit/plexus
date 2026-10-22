#!/usr/bin/env python3
"""Test one deliberate source edit, list test IDs, or check the full suite."""
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

sys.dont_write_bytecode = True
loader = unittest.TestLoader()
if sys.argv[1:2] == ['--list']:
    suite = loader.discover(str(Path(__file__).parent), pattern='test_*.py')

    def test_ids(tests):
        for test in tests:
            if isinstance(test, unittest.TestSuite):
                yield from test_ids(test)
            else:
                yield test.id()

    if loader.errors or not suite.countTestCases():
        raise SystemExit("expected importable script tests")
    listed = set(test_ids(suite))
    requested = sys.argv[2:]
    if len(requested) > 1 or (requested and requested[0] not in listed):
        raise SystemExit("expected an existing script test name")
    print(json.dumps(requested or sorted(listed)))
    raise SystemExit(0)

broad = sys.argv[1] == '--broad'
suite = loader.discover(str(Path(__file__).parent), pattern='test_*.py') if broad else loader.loadTestsFromName(sys.argv[1])
if loader.errors or not suite.countTestCases() or (not broad and suite.countTestCases() != 1):
    raise SystemExit("expected existing script tests")


class RecordingResult(unittest.TextTestResult):
    def startTest(self, test):
        self.seen = getattr(self, 'seen', []) + [test]
        super().startTest(test)


result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
if broad:
    root = ET.Element('testsuite', tests=str(result.testsRun))
    failures = {test.id(): message for test, message in result.failures + result.errors}
    skipped = {test.id(): reason for test, reason in result.skipped}
    for test in result.seen:
        case = ET.SubElement(root, 'testcase', name=test.id(), classname=test.id().rsplit('.', 1)[0])
        if test.id() in failures:
            ET.SubElement(case, 'failure').text = failures[test.id()]
        elif test.id() in skipped:
            ET.SubElement(case, 'skipped', message=skipped[test.id()])
    path = Path('target/mutations/g-scripts-junit.xml')
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
raise SystemExit(0 if result.wasSuccessful() and result.testsRun == suite.countTestCases() else 1)
