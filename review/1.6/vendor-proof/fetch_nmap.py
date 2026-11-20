"""Download only bounded, pinned public vendor fixtures; accept no target URL."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.request import urlopen

BASE = Path(__file__).resolve().parent
FILES = ('xml_test3.xml', 'xml_test5.xml', 'xml_test13.xml', 'xml_test16.xml')
PREFIX = '/nmap/nmap/80dd68b8d88cbc89e584941e9ba68e57247d2230/zenmap/test/'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('new_directory', type=Path)
    args = parser.parse_args()
    specs = json.loads((BASE / 'provenance.json').read_bytes())['vendor_nmap']['files']
    verified = {}
    for name in FILES:
        spec = specs[name]
        url = 'https://raw.githubusercontent.com' + PREFIX + name
        if spec['url'] != url:
            raise ValueError('unexpected vendor URL')
        with urlopen(url, timeout=30) as response:
            if response.geturl() != url:
                raise ValueError('unexpected redirect')
            data = response.read(100001)
        if len(data) > 100000 or hashlib.sha256(data).hexdigest() != spec['sha256']:
            raise ValueError('upstream digest mismatch: ' + name)
        verified[name] = data
    args.new_directory.mkdir(mode=0o700)
    for name, data in verified.items():
        (args.new_directory / name).write_bytes(data)
    print('Verified four original Nmap XML files.')

if __name__ == '__main__':
    main()
