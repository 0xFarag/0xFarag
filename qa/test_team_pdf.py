"""Portable PDF regressions. © Nasser Aldin Farag (0xFarag). All rights reserved."""
import base64
import copy
import re
import unittest
import zlib

from team.evidence import _REPORT, LANGS, MAX_FINDINGS
from team.report_pdf import render_pdf, smoke_pdf


def decoded_streams(pdf):
    for match in re.finditer(rb'(\d+) 0 obj\s*<<(.*?)>>\s*stream\r?\n(.*?)endstream', pdf, re.S):
        dictionary, data = match.group(2), match.group(3).strip()
        if b'/ASCII85Decode' in dictionary:
            data = base64.a85decode(data, adobe=True)
        if b'/FlateDecode' in dictionary:
            data = zlib.decompress(data)
        yield data


def sample(language, size=1):
    idx = LANGS.index(language)
    states = ('findings','hint','confirmed','not_retested','fix_verified','persists','inconclusive')
    r = {'language':language, 'title':_REPORT['heading'][idx], 'scope_sha256':'1'*64,
         'summary_heading':_REPORT['summary'][idx], 'labels':{k:_REPORT[k][idx] for k in states},
         'counts':dict.fromkeys(states,0), 'appendix_heading':_REPORT['appendix'][idx],
         'appendix':[], 'limitations':_REPORT['limit'][idx]}
    ref = {'format':'har','record':14,'sha256':'2'*64,'asset_id':'3'*64,'fingerprint':'4'*64}
    for n in range(size):
        r['appendix'].append({'id':'item-%03d' % n,'finding_sha256':'5'*64,
                              'status':'confirmed','status_label':_REPORT['confirmed'][idx],
                              'retest':'not_retested','retest_label':_REPORT['not_retested'][idx],
                              'evidence':ref,'control':ref,'retest_evidence':None,'retest_control':None})
    r['counts'].update(findings=size,confirmed=size,not_retested=size)
    return r, {'case_id':'testcase','team_id':'testteam','sources':[{'id':'source-inventory-id','format':'har','sha256':'7'*64,'records':size,'bytes':717}], 'created_at':'2026-11-24T12:30:00Z'}


class CustomerPDF(unittest.TestCase):
    def test_supported_locales_and_embedded_typography(self):
        self.assertTrue(smoke_pdf().startswith(b'%PDF-'))
        for lang in LANGS:
            with self.subTest(language=lang):
                report, manifest = sample(lang)
                before = copy.deepcopy(report)
                pdf = render_pdf(report,manifest)
                self.assertEqual(pdf, render_pdf(report,manifest))
                self.assertEqual(report,before)
                self.assertIn(b'/FontFile2', pdf)
                self.assertIn(b'/ToUnicode', pdf)
                text = b'\n'.join(decoded_streams(pdf))
                self.assertIn(b'testcase',text)
                self.assertIn(b'source-inventory-id',text)
                self.assertIn(b'confirmed / not_retested',text)
                self.assertIn(b'2'*64,text)
                self.assertIn(b'Nasser Aldin Farag',text)
                if lang == 'ar':
                    logical = ('\ufeff'+report['title']).encode('utf-16be').hex().encode()
                    self.assertIn(b'/ActualText <'+logical+b'>',text)
                self.assertNotIn(b'/JavaScript',pdf)
                self.assertNotIn(b'/URI ',pdf)

    def test_all_findings_paginate_without_loss(self):
        report, manifest = sample('fr', MAX_FINDINGS)
        pdf = render_pdf(report,manifest)
        self.assertGreater(len(re.findall(rb'/Type /Page\b',pdf)),1)
        self.assertLess(len(pdf), 2*1024*1024)
        text = b'\n'.join(decoded_streams(pdf))
        for row in report['appendix']:
            self.assertEqual(text.count(row['id'].encode()),1)
