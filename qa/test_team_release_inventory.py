# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Check staged packages and links to the published Team release."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import runpy
import subprocess
import sys
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
    def test_shared_file_inspection_model_survives_staging_and_installation(self):
        model = Path('public/dateipruefung/model.mjs')
        expected = (ROOT / model).read_bytes()
        with tempfile.TemporaryDirectory() as temp:
            stage, installed = Path(temp)/'stage', Path(temp)/'installed'
            release['stage'](stage)
            self.assertEqual((stage / model).read_bytes(), expected)
            subprocess.run([sys.executable, str(stage/'packaging/team/install.py'), str(installed)], check=True)
            self.assertEqual((installed/'usr/lib/authzledger-team'/model).read_bytes(), expected)

    def test_download_page_matches_tagged_release_inventory(self):
        published = json.loads((ROOT / 'scripts/download-releases.json').read_text(encoding='utf-8'))['publishedTeamVersion']
        self.assertRegex(published, r'^\d+\.\d+\.\d+\.\d+$')
        html = (ROOT / 'public/downloads/index.html').read_text(encoding='utf-8')
        self.assertIn(f'AuthzLedger Team · {published}<', html)
        page = DownloadLinks()
        page.feed(html)
        base = 'https://github.com/0xFarag/0xFarag/releases/download/team-'
        links = [url for url in page.urls if url.startswith(base)]
        expected = [f'{base}{published}/{name}' for name in [*release['asset_names'](published), 'SHA256SUMS']]
        self.assertCountEqual(links, expected)
        guides = 'https://github.com/0xFarag/0xFarag/blob/team-'
        for url in page.urls:
            if url.startswith(guides):
                self.assertTrue(url.startswith(f'{guides}{published}/'), url)

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
