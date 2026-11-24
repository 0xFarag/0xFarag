"""Offline customer PDFs. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from functools import lru_cache
from io import BytesIO
import json
from pathlib import Path
from threading import Lock

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas

from .documents import INDEX_CAPTIONS

RIGHTS = '© Nasser Aldin Farag (0xFarag). All rights reserved.'
ASSETS = Path(__file__).resolve().parent / 'static' / 'pdf'
FONT = 'AuthzReportSans'
FONT_LOCK = Lock()
LOCALES = ('de', 'en', 'fr', 'it', 'ar')
CAPTIONS = {
    **INDEX_CAPTIONS,
    'case': ('Fall-ID', 'Case ID', 'Dossier', 'ID caso', 'معرّف الحالة'),
    'team': ('Team-ID', 'Team ID', 'Équipe', 'ID team', 'معرّف الفريق'),
    'issued': ('Erstellt am', 'Issued at', 'Date du rapport', 'Data di emissione', 'تاريخ الإصدار'),
    'scope': ('Scope (SHA-256)', 'Scope (SHA-256)', 'Périmètre (SHA-256)', 'Ambito (SHA-256)', 'النطاق (SHA-256)'),
    'finding': ('Befund-ID', 'Finding ID', 'Identifiant du constat', 'ID riscontro', 'معرّف النتيجة'),
    'original': ('Befund (SHA-256)', 'Finding (SHA-256)', 'Constat (SHA-256)', 'Riscontro (SHA-256)', 'النتيجة (SHA-256)'),
    'evidence': ('Ursprünglicher Beleg', 'Original evidence', 'Preuve initiale', 'Evidenza iniziale', 'الدليل الأصلي'),
    'control': ('Ursprüngliche Kontrolle', 'Baseline control', 'Contrôle initial', 'Controllo iniziale', 'الضابط الأصلي'),
    'retest_evidence': ('Retest-Beleg', 'Retest evidence', 'Preuve du nouveau test', 'Evidenza del nuovo test', 'دليل إعادة الاختبار'),
    'retest_control': ('Retest-Kontrolle', 'Retest control', 'Contrôle du nouveau test', 'Controllo del nuovo test', 'ضابط إعادة الاختبار'),
    'file': ('Quelldatei (SHA-256)', 'Source file (SHA-256)', 'Fichier source (SHA-256)', 'File sorgente (SHA-256)', 'الملف المصدر (SHA-256)'),
    'record': ('Datensatz', 'Record', 'Enregistrement', 'Record', 'السجل'),
    'fingerprint': ('Datensatz-Fingerabdruck', 'Record fingerprint', 'Empreinte de l’enregistrement', 'Impronta del record', 'بصمة السجل'),
    'asset': ('Asset-ID', 'Asset ID', 'ID de la ressource', 'ID risorsa', 'معرّف الأصل'),
    'sources': ('Quelleninventar', 'Source inventory', 'Inventaire des sources', 'Inventario delle fonti', 'جرد المصادر'),
    'source_id': ('Quell-ID', 'Source ID', 'ID de la source', 'ID fonte', 'معرّف المصدر'),
    'records': ('Datensätze', 'Records', 'Enregistrements', 'Record', 'السجلات'),
    'bytes': ('Bytes', 'Bytes', 'Octets', 'Byte', 'بايت'),
    'none': ('Keine dokumentierten Befunde.', 'No recorded findings.', 'Aucun constat documenté.', 'Nessun riscontro documentato.', 'لا توجد نتائج موثّقة.'),
}
NAVY, TEAL, GOLD, MUTED = map(HexColor, ('#071722', '#087F7C', '#C8A66B', '#425462'))


@lru_cache(maxsize=1)
def prepared_text():
    # ReportLab needs a registered font before computing widths or creating PDF subsets.
    with FONT_LOCK:
        if FONT not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(FONT, str(ASSETS / 'ReportSans.ttf')))
    return json.loads((ASSETS / 'arabic-lines.json').read_text(encoding='utf-8'))


class ReportLayout:
    def __init__(self, canvas, rtl):
        self.canvas = canvas
        self.rtl = rtl
        self.width, self.height = A4
        self.margin = 46
        self.prepared = prepared_text()
        self.page = 0
        self.new_page()

    def new_page(self):
        c = self.canvas
        if self.page:
            c.showPage()
        self.page += 1
        c.setFillColor(NAVY)
        c.rect(0, self.height - 57, self.width, 57, fill=1, stroke=0)
        c.setFillColor(HexColor('#FFFFFF'))
        c.setFont(FONT, 19)
        c.drawString(self.margin, self.height - 36, 'AuthzLedger')
        c.setFillColor(GOLD)
        c.rect(self.margin, self.height - 58, self.width - 2*self.margin, 2, fill=1, stroke=0)
        c.setFillColor(MUTED)
        c.setFont(FONT, 8)
        c.drawString(self.margin, 25, RIGHTS)
        c.drawRightString(self.width - self.margin, 25, str(self.page))
        self.y = self.height - 91

    def ensure(self, points):
        if self.y - points < 43:
            self.new_page()

    def line(self, logical, visual, size, color, rtl):
        leading = size * 1.48
        self.ensure(leading)
        c = self.canvas
        c.setFillColor(color)
        c.setFont(FONT, size)
        if rtl:
            # ActualText retains the logical, searchable caption while glyphs follow visual order.
            logical_hex = ('\ufeff' + logical).encode('utf-16be').hex()
            c.addLiteral('/Span << /ActualText <' + logical_hex + '> >> BDC')
            c.drawRightString(self.width-self.margin, self.y, visual)
            c.addLiteral('EMC')
        else:
            c.drawString(self.margin, self.y, visual)
        self.y -= leading

    def text(self, value, size=10, color=NAVY, *, technical=False):
        value = str(value)
        # Arabic customer-visible text comes entirely from the localized, redacted report
        # schema. Shaped lines are built with FriBidi before distribution. References,
        # dates and digests are rendered exactly as supplied, in left-to-right order.
        if self.rtl and not technical:
            for logical, visual in self.prepared[value]:
                self.line(logical, visual, size, color, True)
            return
        line = ''
        for word in value.split():
            joined = (line + ' ' + word).strip()
            if line and pdfmetrics.stringWidth(joined, FONT, size) > self.width - 2*self.margin:
                self.line(line, line, size, color, False)
                line = word
            else:
                line = joined
        if line:
            self.line(line, line, size, color, False)

    def pair(self, caption, value):
        self.ensure(33)
        self.text(caption, 9, MUTED)
        self.text(value, 10, technical=True)
        self.y -= 3

    def section(self, caption):
        self.ensure(60)
        self.y -= 8
        self.text(caption, 15, TEAL)
        self.y -= 3


def render_pdf(report, manifest):
    """Render only signed report fields, without raw source documents or external resources."""
    index = LOCALES.index(report['language'])
    cap = {key: labels[index] for key, labels in CAPTIONS.items()}
    output = BytesIO()
    pdf = Canvas(output, pagesize=A4, pageCompression=1, invariant=1)
    pdf.setTitle(report['title'])
    pdf.setAuthor('Nasser Aldin Farag (0xFarag)')
    pdf.setSubject(RIGHTS)
    layout = ReportLayout(pdf, report['language'] == 'ar')
    layout.text(report['title'], 23)
    layout.pair(cap['case'], manifest['case_id'])
    layout.pair(cap['team'], manifest['team_id'])
    layout.pair(cap['issued'], manifest['created_at'])
    layout.pair(cap['scope'], report['scope_sha256'])
    layout.section(report['summary_heading'])
    for name, count in report['counts'].items():
        layout.ensure(18)
        # The value is on the opposite side of the column from its localized label.
        pdf.setFillColor(NAVY)
        pdf.setFont(FONT, 11)
        if layout.rtl:
            pdf.drawString(layout.margin, layout.y, str(count))
        else:
            pdf.drawRightString(layout.width-layout.margin, layout.y, str(count))
        layout.text(report['labels'][name], 10)
    layout.y -= 10
    layout.text(report['limitations'], 10, MUTED)
    layout.section(report['appendix_heading'])
    if not report['appendix']:
        layout.text(cap['none'])
    for item in report['appendix']:
        layout.ensure(118)
        layout.text(item['status_label'], 13, TEAL)
        layout.text(item['retest_label'], 11)
        layout.text(f"{item['status']} / {item['retest']}", 9, MUTED, technical=True)
        layout.pair(cap['finding'], item['id'])
        layout.pair(cap['original'], item['finding_sha256'])
        evidence_index = item.get('evidence_index')
        if evidence_index is None:
            baseline = [(field, item.get(field)) for field in ('evidence', 'control')]
        else:
            layout.section(cap['evidence_index'])
            baseline = [(ref['role'], ref) for ref in evidence_index['observations']]
        for field, ref in baseline + [(field, item.get(field)) for field in ('retest_evidence', 'retest_control')]:
            if ref is None:
                continue
            layout.ensure(70)
            layout.text(cap[field], 12, TEAL)
            layout.pair(cap['record'], f"{ref['format']}  #{ref['record']}")
            layout.pair(cap['file'], ref['sha256'])
            layout.pair(cap['fingerprint'], ref['fingerprint'])
            # The signed index deliberately omits asset IDs. Retain the source
            # reference's asset binding in reports that also have the index.
            source = item.get(field)
            if source and source.get('asset_id'):
                layout.pair(cap['asset'], source['asset_id'])
        if evidence_index is not None:
            if not evidence_index['experiments']:
                layout.text(cap['no_experiment'])
            for plan in evidence_index['experiments']:
                layout.ensure(85)
                layout.pair(cap['experiment'], plan['plan_id'])
                for revision in plan['revisions']:
                    layout.ensure(100)
                    layout.pair(cap['revision'], revision['id'])
                    layout.pair(cap['revision_digest'], revision['sha256'])
                    if revision['parent_sha256'] is not None:
                        layout.pair(cap['parent_digest'], revision['parent_sha256'])
        layout.y -= 8
    if manifest['sources']:
        layout.section(cap['sources'])
        for source in manifest['sources']:
            layout.ensure(100)
            layout.text(source['format'], 13, TEAL, technical=True)
            layout.pair(cap['source_id'], source['id'])
            layout.pair(cap['file'], source['sha256'])
            layout.pair(cap['records'], source['records'])
            layout.pair(cap['bytes'], source['bytes'])
            layout.y -= 7
    pdf.save()
    return output.getvalue()


def smoke_pdf():
    """Exercise the shipped Arabic font, labels, layout and PDF serializer in a packaged build."""
    from team.evidence import _REPORT
    ar = LOCALES.index('ar')
    report = {'language':'ar', 'title':_REPORT['heading'][ar], 'scope_sha256':'0'*64,
              'summary_heading':_REPORT['summary'][ar], 'labels':{'findings': _REPORT['findings'][ar]},
              'counts':{'findings':0}, 'appendix_heading':_REPORT['appendix'][ar],
              'appendix':[], 'limitations':_REPORT['limit'][ar]}
    return render_pdf(report, {'case_id':'test', 'team_id':'test', 'sources':[], 'created_at':'2000-01-01T00:00:00Z'})
