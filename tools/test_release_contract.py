"""Offline release wiring checks; native execution and live media are separate gates."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseContract(unittest.TestCase):
    def test_version_defaults_agree(self):
        main = (ROOT / 'cmd/voxywatch-probe/main.go').read_text()
        version = re.search(r'^var version = "([^"]+)"$', main, re.M).group(1)
        self.assertRegex(version, r'^\d+\.\d+\.\d+$')
        helper = (ROOT / 'tools/native-build.sh').read_text()
        workflow = (ROOT / '.github/workflows/native-build.yml').read_text()
        self.assertIn('version=${BUILD_VERSION:-' + version + '}', helper)
        self.assertIn('default: ' + version, workflow)
        self.assertIn("inputs.version || '" + version + "'", workflow)

    def test_native_ci_boundary(self):
        workflow = (ROOT / '.github/workflows/native-build.yml').read_text()
        self.assertEqual(re.findall(r'uses: ([^\s]+)', workflow), [
            'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
            'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'])
        for expected in ['contents: read', 'persist-credentials: false',
                         'runner: ubuntu-24.04\n', 'runner: ubuntu-24.04-arm\n',
                         'container: golang:1.26.6-bookworm', 'retention-days: 1',
                         "CGO_ENABLED: '1'", 'if-no-files-found: error']:
            self.assertIn(expected, workflow)
        self.assertNotRegex(workflow, r'secrets\.|gpg\s|gh release')


if __name__ == '__main__':
    unittest.main()
