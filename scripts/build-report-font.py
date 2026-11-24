"""Rebuild the shipped PDF subset and RTL captions from DejaVu Sans and FriBidi.

© Nasser Aldin Farag (0xFarag). All rights reserved. Distribution of DejaVu
font derivatives is subject to the attached Bitstream Vera font license.

Run once from the project checkout using fonttools, reportlab, libfribidi,
fonts-dejavu-core and the team's runtime dependencies on Linux. Runtime
generation of customer PDFs requires only ReportLab and the two built assets.
"""
import argparse
import ctypes
from ctypes.util import find_library
import json
from pathlib import Path
import sys

from fontTools import subset
from fontTools.ttLib import TTFont as FontToolsFont
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from team.evidence import _REPORT
from team.report_pdf import ASSETS, CAPTIONS, RIGHTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--font', type=Path, default=Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
    args = parser.parse_args()
    lib = ctypes.CDLL(find_library('fribidi'))
    lib.fribidi_log2vis.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
                                    ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.fribidi_get_bidi_type.argtypes = [ctypes.c_uint32]
    lib.fribidi_get_bidi_type.restype = ctypes.c_uint32
    pdfmetrics.registerFont(TTFont('ReportFontFull', str(args.font)))

    def visual(text):
        codepoints = (ctypes.c_uint32 * len(text))(*map(ord, text))
        out = (ctypes.c_uint32 * len(text))()
        base = ctypes.c_uint32(lib.fribidi_get_bidi_type(ord('א')))
        if not lib.fribidi_log2vis(codepoints, len(text), ctypes.byref(base), out, None, None, None):
            raise ValueError('Could not shape report caption')
        return ''.join(chr(cp) for cp in out if cp != 0xfeff)

    all_labels = list(_REPORT.values()) + list(CAPTIONS.values())
    prepared = {}
    for labels in all_labels:
        text = labels[-1]
        line, lines = '', []
        for word in text.split():
            joined = (line + ' ' + word).strip()
            if line and pdfmetrics.stringWidth(visual(joined), 'ReportFontFull', 10) > 497:
                lines.append([line, visual(line)])
                line = word
            else:
                line = joined
        lines.append([line, visual(line)])
        prepared[text] = lines

    chars = set(RIGHTS + ''.join(map(chr, range(32,127))))
    for labels in all_labels:
        for text in labels:
            chars.update(text)
    for lines in prepared.values():
        for _, display in lines:
            chars.update(display)
    options = subset.Options()
    options.recalc_timestamp = False
    options.layout_features = []
    options.drop_tables += ['FFTM']
    options.name_IDs = ['*']
    options.name_languages = ['*']
    font = FontToolsFont(args.font, recalcTimestamp=False)
    missing = set(map(ord, chars)) - set(font.getBestCmap())
    if missing:
        raise ValueError(f'Missing glyphs: {sorted(missing)}')
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=set(map(ord, chars)))
    subsetter.subset(font)
    for record in font['name'].names:
        replacement = {1:'AuthzReportSans',3:'AuthzReportSans-Subset',4:'AuthzReportSans',6:'AuthzReportSans'}.get(record.nameID)
        if replacement:
            record.string = replacement.encode(record.getEncoding())
    font.save(ASSETS / 'ReportSans.ttf')
    (ASSETS / 'arabic-lines.json').write_text(json.dumps(prepared, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
