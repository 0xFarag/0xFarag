#!/usr/bin/env python3
"""Render a restrained release film from genuine Studio captures and verified local evidence.

No avatars, remote generators, synthesized claims or third-party media are used.
Inputs are reproducible local acceptance artifacts; output is 1080p H.264/AAC.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
NAVY = (7, 23, 34)
INK = (11, 32, 45)
WHITE = (231, 242, 244)
MUTED = (143, 171, 188)
TEAL = (67, 214, 207)
GOLD = (200, 166, 107)
FPS = 30
DURATIONS = (4, 4, 4, 5, 4, 5, 4, 6)
TOTAL = sum(DURATIONS)
FONT = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
BOLD = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf')
MONO = Path('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf')


def font(size, *, bold=False, mono=False):
    return ImageFont.truetype(str(MONO if mono else BOLD if bold else FONT), size)


def wrapped(draw, text, face, width):
    lines = []
    for paragraph in text.split('\n'):
        current = ''
        for word in paragraph.split():
            candidate = current + (' ' if current else '') + word
            if current and draw.textlength(candidate, font=face) > width:
                lines.append(current)
                current = word
            else:
                current = candidate
        lines.append(current)
    return lines


def block(draw, text, xy, face, width, fill=WHITE, leading=1.22):
    x, y = xy
    for line in wrapped(draw, text, face, width):
        if draw.textlength(line, font=face) > width:
            raise ValueError('Text does not fit: ' + line)
        draw.text((x, y), line, font=face, fill=fill)
        y += int(face.size * leading)
    return y


def load_json(path):
    return json.loads(path.read_text())


def validate_inputs(evidence):
    from authzledger.intelligence import verify_graph
    before, after = (load_json(evidence / name) for name in ('before-graph.json', 'after-graph.json'))
    if verify_graph(before) or verify_graph(after):
        raise ValueError('Film inputs must be internally consistent authorization graphs.')
    if before['contract_sha256'] != after['contract_sha256'] or before['target'] != after['target']:
        raise ValueError('A same-contract, same-target retest is required.')
    differential = load_json(evidence / 'differential.json')
    resolved = differential['summary']['resolved']
    peer = next(edge for edge in before['edges'] if edge['case_id'] == 'peer-cannot-read-owner')
    if (peer['intended']['decision'], peer['policy']['decision'], peer['observed']['decision']) != ('deny', 'deny', 'allow'):
        raise ValueError('Opening states must be supported by the retained local demo.')
    result = subprocess.run([sys.executable, str(ROOT / 'tools/verify_bundle.py'), str(evidence / 'proof'),
                             '--public-key', str(evidence / 'trusted-public.pem')], check=True, capture_output=True, text=True)
    manifest = load_json(evidence / 'proof/manifest.json')
    return {'resolved': resolved, 'contract': before['contract_sha256'],
            'key': manifest['signer']['public_key_sha256'], 'verification': result.stdout.splitlines()[0],
            'inventory': [entry['path'] for entry in manifest['files']], 'checks': len(before['edges'])}


def soundtrack(path):
    rate = 48000
    t = np.arange(TOTAL * rate, dtype=np.float64) / rate
    bed = np.zeros_like(t)
    # Original, softly evolving A-minor / D-minor tonal bed; no samples or vocals.
    chords = ((110.0, 130.8128, 164.8138), (110.0, 146.8324, 174.6141),
              (110.0, 130.8128, 164.8138), (110.0, 164.8138, 220.0))
    for index, chord in enumerate(chords):
        start, stop = index * TOTAL / 4, (index + 1) * TOTAL / 4
        envelope = np.clip((t - start) / 1.5, 0, 1) * np.clip((stop - t) / 1.5, 0, 1)
        for voice, frequency in enumerate(chord):
            bed += 0.028 * envelope * (np.sin(2 * np.pi * frequency * t + voice * 0.41)
                                      + 0.18 * np.sin(2 * np.pi * 2 * frequency * t))
    beat_length = 60 / 64
    beat = np.mod(t, beat_length)
    pulse = (1 - np.exp(-beat * 90)) * np.exp(-beat * 5)
    bed += 0.065 * np.sin(2 * np.pi * 55 * t) * pulse
    sparkle = np.zeros_like(t)
    for start in (0.4, 8.0, 12.0, 17.0, 21.0, 26.0, 30.0):
        u = np.maximum(0, t - start)
        envelope = np.where(t >= start, (1 - np.exp(-u * 40)) * np.exp(-u * 1.8), 0)
        sparkle += 0.025 * envelope * np.sin(2 * np.pi * 440 * t)
    envelope = np.minimum(1, t / 0.65) * np.minimum(1, np.maximum(0, TOTAL - t) / 1.8)
    left = (bed + sparkle) * envelope
    right = (bed + np.roll(sparkle, 720)) * envelope
    stereo = np.stack((left, right), axis=1) * 2.3
    if np.max(np.abs(stereo)) >= 0.85:
        raise ValueError('Unexpected soundtrack clipping.')
    pcm = (stereo * 32767).astype('<i2')
    with wave.open(str(path), 'wb') as stream:
        stream.setnchannels(2)
        stream.setsampwidth(2)
        stream.setframerate(rate)
        stream.writeframes(pcm.tobytes())


def crop_image(path, box=None):
    image = Image.open(path).convert('RGB')
    return image.crop(box) if box else image


def fit(image, width, height):
    ratio = min(width / image.width, height / image.height)
    return image.resize((round(image.width * ratio), round(image.height * ratio)), Image.Resampling.LANCZOS)


def background(size):
    width, height = size
    # Low-contrast original lighting, with the focal point at the golden-ratio crossing.
    x, y = np.meshgrid(np.linspace(0, 1, width), np.linspace(0, 1, height))
    glow = np.exp(-((x - 0.618)**2 / 0.45 + (y - 0.618)**2 / 0.28))
    array = np.zeros((height, width, 3), dtype=np.uint8)
    for channel, base in enumerate(NAVY):
        array[:, :, channel] = base + glow * (3, 8, 10)[channel]
    return Image.fromarray(array)


def scenes(facts):
    return [
        {'label': '01 / LIVING AUTHORIZATION GRAPH', 'title': 'Policy says deny.\nBehavior says allow.',
         'caption': 'The difference is the evidence.', 'image': 'graph-before.png', 'mode': 'graph'},
        {'label': '02 / CONTRACT · POLICY · OBSERVATION', 'title': 'One boundary.\nThree distinct realities.',
         'caption': 'Intended permission, independent policy and observed behavior stay distinct.',
         'image': 'graph-before.png', 'mode': 'inspector'},
        {'label': '03 / CONTROL-AWARE ORCHESTRATION', 'title': 'A failed control\nnever becomes a pass.',
         'caption': 'Blocked negative checks remain inconclusive. No request is sent.',
         'image': 'expired-controls.png', 'mode': 'controls'},
        {'label': '04 / DIFFERENTIAL RETEST', 'title': 'Same contract.\n' + str(facts['resolved']) + ' boundaries fixed.',
         'caption': 'The local fixture changes. Its authorization expectations stay unchanged.',
         'image': 'diff-demo.png', 'mode': 'diff'},
        {'label': '05 / DURABLE LOCAL HISTORY', 'title': 'Every run\nhas a history.',
         'caption': 'Retain the contract, graph and evidence. Prepare a controlled retest.',
         'image': 'history.png', 'mode': 'history'},
        {'label': '06 / SIGNED EVIDENCE', 'title': 'Sign the evidence.\nVerify independently.',
         'caption': 'Ed25519. Exact inventory. A public key trusted outside the package.',
         'image': 'proof.png', 'mode': 'proof'},
        {'label': '07 / EXPLAINABLE BY DESIGN', 'title': 'Evidence decides.\nAI only advises.',
         'caption': 'Deterministic findings remain authoritative. Optional local AI never changes outcomes.',
         'image': 'reasoning.png', 'mode': 'reasoning'},
        {'label': 'AUTHZLEDGER 1.0 / BY 0xFARAG', 'title': 'Authorization Intelligence,\nbuilt on evidence.',
         'caption': 'Know who can do what. Prove what changed.', 'mode': 'end'},
    ]


def screenshot_for(scene, captures, vertical):
    mode = scene['mode']
    if mode == 'controls':
        source = ROOT / 'artifacts/browser/expired-controls.png'
        return crop_image(source, (24, 367, 1452, 656)) if not vertical else crop_image(source, (26, 367, 1120, 648))
    source = captures / scene['image']
    if not source.exists():
        raise ValueError('Missing genuine Studio capture: ' + str(source))
    image = crop_image(source)
    if mode == 'graph':
        # The actual graph table is intentionally magnified; no UI labels are recreated.
        return image.crop((20, 245, min(870, image.width), min(702, image.height))) if not vertical else image.crop((920, 62, image.width, min(432, image.height)))
    if mode == 'inspector':
        return image.crop((920, 132, image.width, min(359, image.height))) if not vertical else image.crop((920, 65, image.width, min(440, image.height)))
    if mode == 'history':
        return image.crop((0, 330, image.width, image.height)) if not vertical else image.crop((920, 330, image.width, image.height))
    if mode == 'diff':
        return image.crop((27, 343, min(490, image.width), min(665, image.height)))
    if mode == 'reasoning':
        return image.crop((0, 0, image.width, min(620, image.height)))
    return image


def layout(scene, index, facts, captures, size, logo):
    vertical = size[1] > size[0]
    width, height = size
    margin = 88 if vertical else 104
    safe_width = width - 2 * margin
    frame = background(size)
    draw = ImageDraw.Draw(frame)
    icon_size = 62 if vertical else 50
    icon = logo.resize((icon_size, icon_size), Image.Resampling.LANCZOS)
    frame.paste(icon, (margin - 8, 107 if vertical else 49), icon)
    draw.text((margin + 70, 114 if vertical else 50), 'AuthzLedger', font=font(34 if vertical else 29, bold=True), fill=WHITE)
    draw.text((width - margin - 120, 124 if vertical else 58), '1.0', font=font(28 if vertical else 22, mono=True), fill=GOLD)
    draw.line((margin, 196 if vertical else 119, width - margin, 196 if vertical else 119), fill=(32, 56, 69), width=1)
    title_top = 282 if vertical else 174
    label_top = 236 if vertical else 151
    label_font = font(18 if vertical else 16, bold=True)
    block(draw, scene['label'], (margin, label_top), label_font, safe_width, GOLD)
    title_font = font(62 if vertical else 68, bold=True)
    end = block(draw, scene['title'], (margin, title_top), title_font, safe_width, WHITE, 1.19)
    if vertical and end > 525:
        raise ValueError('Vertical title exceeds safe area.')
    image_box = (margin, 614, width - margin, 1315) if vertical else (margin, 374, width - margin, 908)
    if scene['mode'] == 'end':
        draw.line((margin, 620 if vertical else 410, margin + int(safe_width * .618), 620 if vertical else 410), fill=TEAL, width=3)
        y = 728 if vertical else 479
        block(draw, 'Know who can do what.\nProve what changed.', (margin, y), font(52 if vertical else 64), safe_width, TEAL, 1.35)
        block(draw, 'github.com/0xFarag/0xFarag', (margin, 1120 if vertical else 760), font(29 if vertical else 32, mono=True), safe_width, GOLD)
        block(draw, 'Local-first · Studio + CLI', (margin, 1250 if vertical else 829), font(26 if vertical else 25), safe_width, MUTED)
        ui = None
    elif scene['mode'] == 'proof':
        screen = screenshot_for(scene, captures, vertical)
        screen = fit(screen, safe_width, 190 if vertical else 120)
        frame.paste(screen, (margin, image_box[1]))
        y = image_box[1] + (235 if vertical else 155)
        block(draw, 'INDEPENDENT VERIFIER / ACTUAL OUTPUT', (margin, y), font(18 if vertical else 17, bold=True), safe_width, GOLD)
        y += 48 if vertical else 42
        # This text is the actual independent verifier's output, not a simulated terminal.
        output = facts['verification'].replace('VERIFIED: ', 'VERIFIED\n')
        y = block(draw, output, (margin, y), font(34 if vertical else 31, mono=True), safe_width, TEAL, 1.35)
        y += 48 if vertical else 36
        block(draw, 'Trusted key SHA-256\n' + facts['key'][:32] + '…', (margin, y), font(22 if vertical else 20, mono=True), safe_width, MUTED, 1.4)
        ui = None
    else:
        image = screenshot_for(scene, captures, vertical)
        if scene['mode'] == 'graph' and not vertical:
            image_box = (margin, 374, margin + int(safe_width * .618), 908)
        box_width, box_height = image_box[2] - image_box[0], image_box[3] - image_box[1]
        image = fit(image, box_width, box_height)
        x = image_box[0] + (box_width - image.width) // 2
        y = image_box[1] + (box_height - image.height) // 2
        draw.rounded_rectangle((x - 3, y - 3, x + image.width + 3, y + image.height + 3), radius=6,
                               outline=(51, 88, 103), width=1)
        frame.paste(image, (x, y))
        ui = ((x, y), image)
        if scene['mode'] == 'graph' and not vertical:
            # Real case states, extracted from retained evidence; clearly separate from the Studio crop.
            x2 = 1150
            labels = [('INTENDED', 'DENY', MUTED), ('POLICY', 'DENY', MUTED), ('OBSERVED', 'ALLOW', TEAL)]
            for item, (label, decision, color) in enumerate(labels):
                draw.text((x2, 444 + item * 120), label, font=font(20, bold=True), fill=GOLD)
                draw.text((x2, 474 + item * 120), decision, font=font(54, bold=True), fill=color)
    caption_top = 1416 if vertical else 938
    if scene['mode'] != 'end':
        end = block(draw, scene['caption'], (margin, caption_top), font(34 if vertical else 27), safe_width, WHITE, 1.32)
        if end > (1570 if vertical else 1010):
            raise ValueError('Caption exceeds safe area.')
    footer_y = 1675 if vertical else 1030
    draw.text((margin, footer_y), 'SYNTHETIC LOCAL DEMO · ACTUAL STUDIO CAPTURES',
              font=font(16 if vertical else 14), fill=MUTED)
    if vertical:
        draw.text((margin, footer_y + 35), 'AUTHORIZATION INTELLIGENCE / BY 0xFARAG', font=font(16), fill=GOLD)
    return frame, ui


def stamp(seconds):
    milliseconds = round(seconds * 1000)
    hour, remainder = divmod(milliseconds, 3600000)
    minute, remainder = divmod(remainder, 60000)
    second, millisecond = divmod(remainder, 1000)
    return f'{hour:02}:{minute:02}:{second:02},{millisecond:03}'


def render_movie(path, frames, soundtrack_path, size, work):
    width, height = size
    command = ['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error', '-f', 'rawvideo', '-pix_fmt', 'rgb24',
               '-s', f'{width}x{height}', '-r', str(FPS), '-i', '-', '-i', str(soundtrack_path),
               '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '18', '-threads', '4', '-pix_fmt', 'yuv420p',
               '-c:a', 'aac', '-b:a', '192k', '-ar', '48000', '-movflags', '+faststart', '-t', str(TOTAL), str(path)]
    process = subprocess.Popen(command, stdin=subprocess.PIPE)
    try:
        elapsed = 0
        for index, duration in enumerate(DURATIONS):
            base, ui = frames[index]
            # Motion belongs to the real evidence crop. Captions and typography stay anchored.
            for number in range(duration * FPS):
                frame = base.copy()
                if ui is not None:
                    (x, y), source = ui
                    scale = 1 + 0.008 * number / max(1, duration * FPS - 1)
                    zoom = source.resize((round(source.width * scale), round(source.height * scale)), Image.Resampling.BICUBIC)
                    left, top = (zoom.width - source.width) // 2, (zoom.height - source.height) // 2
                    frame.paste(zoom.crop((left, top, left + source.width, top + source.height)), (x, y))
                draw = ImageDraw.Draw(frame)
                margin = 88 if height > width else 104
                progress = (elapsed + number / FPS) / TOTAL
                line_y = 1764 if height > width else 1057
                draw.line((margin, line_y, margin + (width - 2 * margin) * progress, line_y), fill=GOLD, width=2)
                # Short, deliberate dip transitions; no effects conceal the evidence.
                t = number / FPS
                fade = min(1, t / .16, (duration - t) / .16)
                if index == 0 and t < .15:
                    fade = min(1, .4 + t / .15)
                if fade < 1:
                    frame = Image.blend(Image.new('RGB', size, NAVY), frame, max(0, fade))
                if number == duration * FPS // 2:
                    frame.save(work / f'{path.stem}_scene-{index + 1:02}.png')
                process.stdin.write(frame.tobytes())
            elapsed += duration
        process.stdin.close()
        if process.wait() != 0:
            raise RuntimeError('Video encoding failed.')
    except BaseException:
        process.kill()
        process.wait()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--captures', type=Path, default=ROOT / 'artifacts/browser-v1')
    parser.add_argument('--evidence', type=Path, default=ROOT / 'artifacts/acceptance-final')
    parser.add_argument('--out', type=Path, default=ROOT / 'media')
    parser.add_argument('--work', type=Path, default=ROOT / 'artifacts/launch-v1')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ROOT))
    facts = validate_inputs(args.evidence)
    shot_list = scenes(facts)
    elapsed, subtitles = 0, []
    for index, scene in enumerate(shot_list):
        subtitles.append(f'{index + 1}\n{stamp(elapsed)} --> {stamp(elapsed + DURATIONS[index])}\n'
                         + scene['title'].replace('\n', ' ') + '\n' + scene['caption'] + '\n')
        elapsed += DURATIONS[index]
    (args.out / 'AuthzLedger_1.0_en.srt').write_text('\n'.join(subtitles))
    sound = args.work / 'original-score.wav'
    soundtrack(sound)
    logo = Image.open(ROOT / 'authzledger/brand_logo.png').convert('RGBA')
    bounds = logo.getbbox()
    if bounds:
        logo = logo.crop(bounds)
    outputs = []
    for label, size in (('wide', (1920, 1080)), ('vertical', (1080, 1920))):
        frames = [layout(scene, index, facts, args.captures, size, logo) for index, scene in enumerate(shot_list)]
        path = args.out / f'AuthzLedger_1.0_Release_{label}.mp4'
        render_movie(path, frames, sound, size, args.work)
        subprocess.run(['ffmpeg', '-v', 'error', '-i', str(path), '-f', 'null', '-'], check=True)
        info = json.loads(subprocess.check_output(['ffprobe', '-v', 'error', '-show_entries',
                          'format=duration:stream=codec_name,codec_type,width,height', '-of', 'json', str(path)]))
        video = next(stream for stream in info['streams'] if stream['codec_type'] == 'video')
        if (video['width'], video['height']) != size or abs(float(info['format']['duration']) - TOTAL) > .2:
            raise ValueError('Encoded film failed dimension/duration verification.')
        if not any(stream['codec_type'] == 'audio' for stream in info['streams']):
            raise ValueError('Original audio stream is missing.')
        outputs.append({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'probe': info})
    (args.work / 'verification.json').write_text(json.dumps({'source': 'genuine Studio captures and independently verified synthetic evidence',
                    'duration_seconds': TOTAL, 'facts': facts, 'outputs': outputs}, indent=2))
    print(json.dumps({'passed': True, 'duration': TOTAL, 'paths': [item['path'] for item in outputs]}))


if __name__ == '__main__':
    main()
