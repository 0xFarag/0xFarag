# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""The release manifest and the public download page must describe the same build."""
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
release = runpy.run_path(str(ROOT / 'scripts/build-team-release.py'))


class DownloadLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.urls.append(dict(attrs).get('href', ''))


class TeamRelease(unittest.TestCase):
    def test_download_page_matches_tagged_release_inventory(self):
        page = DownloadLinks()
        page.feed((ROOT / 'public/downloads/index.html').read_text(encoding='utf-8'))
        base = 'https://github.com/0xFarag/0xFarag/releases/download/team-'
        links = [url for url in page.urls if url.startswith(base)]
        expected = [f'{base}{release["VERSION"]}/{name}' for name in [*release['FILES'], 'SHA256SUMS']]
        self.assertCountEqual(links, expected)

    def test_burp_extension_is_required_and_checksummed(self):
        jar = f'AuthzLedger-Burp-Export-{release["VERSION"]}.jar'
        self.assertIn(jar, release['FILES'])
        with tempfile.TemporaryDirectory() as temp:
            dest = Path(temp)
            for name in release['FILES']:
                if name != jar:
                    (dest / name).write_bytes(name.encode('ascii'))
            with self.assertRaisesRegex(SystemExit, 'inventory mismatch'):
                release['checksums'](dest)
            body = b'Burp release inventory test'
            (dest / jar).write_bytes(body)
            release['checksums'](dest)
            manifest = (dest / 'SHA256SUMS').read_text(encoding='ascii').splitlines()
            self.assertEqual(len(manifest), len(release['FILES']))
            self.assertIn(f'{hashlib.sha256(body).hexdigest()}  {jar}', manifest)
