"""Build translated HTML from the checked-in templates and local UI dictionaries."""
import json
import re
import shutil
from html import escape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'public'
OUTPUT = ROOT / 'dist'
SITE = 'https://authzledger.com'
NAMES = {'de': 'Deutsch', 'en': 'English', 'fr': 'Français', 'it': 'Italiano', 'ar': 'العربية'}
LANGS = list(NAMES)
PICK = ['Sprache wählen', 'Choose language', 'Choisir la langue', 'Scegli la lingua', 'اختر اللغة']
TAGS = {'de': 'de-CH', 'en': 'en', 'fr': 'fr', 'it': 'it', 'ar': 'ar'}
VOID = set('area base br col embed hr img input link meta param source track wbr'.split())
SKIP = {'pre', 'code', 'kbd', 'samp', 'textarea', 'script', 'style'}
ATTRS = {'aria-label', 'alt', 'placeholder', 'title', 'label'}
META = {'description', 'og:title', 'og:description', 'og:image:alt', 'twitter:title', 'twitter:description'}

def normal(text):
    return ' '.join(text.split())

def href(route, lang):
    return '/' + lang + route if lang else route

def route_name(file):
    path = '/' + file.relative_to(SOURCE).as_posix()
    return path.removesuffix('index.html') if path.endswith('/index.html') else path

pages = {route_name(f): f for f in sorted(SOURCE.rglob('*.html'))}
aliases = {alias: route for route in pages for alias in ([route, route + 'index.html', route.rstrip('/')] if route.endswith('/') else [route])}
catalog = {}
for file in sorted((ROOT / 'scripts' / 'locales').glob('*.json')):
    for key, values in json.loads(file.read_text(encoding='utf-8')).items():
        if not normal(key) or not isinstance(values, list) or len(values) != 4 or not all(isinstance(v, str) and v.strip() for v in values):
            raise ValueError(f'Invalid UI copy in {file.name}: {key!r}')
        catalog.setdefault(normal(key), values)
keys = sorted(catalog)
indices = {key: i for i, key in enumerate(keys)}

def picker(route, lang):
    options = ''.join(f'<li><a href="{href(route, code)}" lang="{TAGS[code]}" dir="auto" hreflang="{TAGS[code]}" data-az-lang="{code}"' + (' aria-current="true"' if code == lang else '') + f'>{name}</a></li>' for code, name in NAMES.items())
    return ('<div class="az-language-bar"><div class="az-language-inner"><details class="az-language" id="az-language">'
            f'<summary><span aria-hidden="true">◎</span> <span data-az-language-label>{PICK[LANGS.index(lang)]}</span> · <bdi data-az-language-name>{NAMES[lang]}</bdi></summary>'
            f'<ul>{options}</ul></details></div></div>')

class Page(HTMLParser):
    def __init__(self, route, lang, prefix):
        super().__init__(convert_charrefs=True)
        self.route, self.lang, self.prefix = route, lang, prefix
        self.parts, self.stack = [], []
        self.seen_header = False
        self.inserted_metadata = False

    def append(self, s):
        self.parts.append(s)

    def translate(self, src):
        key = normal(src)
        if key not in catalog:
            return src, None
        lang_index = LANGS.index(self.lang)
        if lang_index == 0:
            return src, indices[key]
        left = re.match(r'^\s*', src).group()
        right = re.search(r'\s*$', src).group()
        return left + catalog[key][lang_index - 1] + right, indices[key]

    def handle_decl(self, decl):
        self.append('<!' + decl + '>')

    def handle_comment(self, data):
        self.append('<!--' + data + '-->')

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'script' and 'head' in self.stack:
            self.metadata()
        if tag == 'link' and attrs.get('rel') in ('canonical', 'alternate'):
            return
        if tag == 'html':
            attrs.update(lang=TAGS[self.lang], dir='rtl' if self.lang == 'ar' else 'ltr')
            attrs['data-az-route'] = self.route
        if tag == 'header' and not self.seen_header:
            self.seen_header = True
            self.append(picker(self.route, self.lang))
        refs = {}
        for attr, val in list(attrs.items()):
            if val is None:
                continue
            if attr in ATTRS or (tag == 'meta' and attr == 'content' and (attrs.get('name') or attrs.get('property')) in META):
                attrs[attr], idx = self.translate(val)
                if idx is not None:
                    refs[attr] = idx
            if attr in {'src', 'poster', 'action', 'href'} and not val.startswith(('data:', 'blob:', 'mailto:', 'tel:')):
                url = urlsplit(urljoin(SITE + self.route, val))
                if url.scheme != 'https' or url.netloc != urlsplit(SITE).netloc:
                    continue
                internal = aliases.get(url.path)
                if attr == 'href' and tag == 'a' and internal is not None:
                    if val.startswith('#'):
                        attrs[attr] = val
                    else:
                        attrs[attr] = urlunsplit(('', '', href(internal, self.prefix), url.query, url.fragment))
                    attrs['data-az-link'] = '1'
                else:
                    attrs[attr] = urlunsplit(('', '', url.path, url.query, url.fragment))
        if tag == 'meta' and attrs.get('property') == 'og:url':
            attrs['content'] = SITE + href(self.route, self.lang if self.lang != 'de' else '')
        if refs:
            attrs['data-az-attrs'] = ' '.join(f'{k}:{v}' for k, v in refs.items())
        if tag == 'title':
            attrs['data-az-title'] = ''
        if tag in ('code', 'pre', 'kbd', 'samp'):
            attrs.setdefault('dir', 'ltr')
        chars = ''.join(' ' + k + ('' if v is None else '="' + escape(str(v), quote=True) + '"') for k, v in attrs.items())
        self.append(f'<{tag}{chars}>')
        if tag not in VOID:
            self.stack.append(tag)
    def metadata(self):
        if not self.inserted_metadata:
            self.inserted_metadata = True
            canonical = SITE + href(self.route, self.lang if self.lang != 'de' else '')
            self.append(f'<link rel="canonical" href="{canonical}">')
            for code in LANGS:
                self.append(f'<link rel="alternate" hreflang="{TAGS[code]}" href="{SITE + href(self.route, code if code != "de" else "")}">')
            self.append(f'<link rel="alternate" hreflang="x-default" href="{SITE + self.route}">')
            self.append('<link rel="stylesheet" href="/i18n/language.css"><script src="/i18n/catalog.js"></script><script src="/i18n/language.js"></script>')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == 'head':
            self.metadata()
        if tag not in VOID:
            self.append(f'</{tag}>')
            if tag in self.stack:
                self.stack = self.stack[:len(self.stack) - self.stack[::-1].index(tag) - 1]

    def handle_data(self, data):
        if any(tag in SKIP for tag in self.stack):
            self.append(data if any(tag in ('script', 'style') for tag in self.stack) else escape(data, quote=False))
            return
        translated, idx = self.translate(data)
        if idx is not None and 'title' not in self.stack:
            self.append(f'<!--az:{idx}-->')
        if idx is not None and 'title' in self.stack:
            self.parts[-1] = self.parts[-1].replace('data-az-title=""', f'data-az-title="{idx}"')
        self.append(escape(translated, quote=False))

def build():
    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)
    shutil.copytree(SOURCE, OUTPUT)
    rows = [[key, *catalog[key]] for key in keys]
    config = {'rows': rows, 'routes': list(pages), 'labels': PICK, 'names': NAMES}
    (OUTPUT / 'i18n' / 'catalog.js').write_text('window.AuthzLocaleData=' + json.dumps(config, ensure_ascii=False, separators=(',', ':')) + ';\n', encoding='utf-8')
    for route, source in pages.items():
        original = source.read_text(encoding='utf-8')
        for prefix in ['', *LANGS]:
            doc = Page(route, prefix or 'de', prefix)
            doc.feed(original)
            doc.close()
            path = OUTPUT / prefix / source.relative_to(SOURCE)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(''.join(doc.parts), encoding='utf-8')
    print(f'Built {len(pages)} pages in {len(LANGS)} languages and default German, using {len(catalog)} localized UI strings.')

if __name__ == '__main__':
    build()
