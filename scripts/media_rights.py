# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Tag the public copies of the project's fast-start MP4s, preserving all media samples."""
from pathlib import Path
from struct import pack, unpack_from, pack_into

NOTICE = '© Nasser Aldin Farag (0xFarag). All rights reserved.'


def boxes(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise ValueError('Incomplete MP4 atom')
        size, kind = unpack_from('>I4s', data, offset)
        if size < 8 or offset + size > len(data):
            raise ValueError('Unsupported MP4 atom size')
        yield kind, data[offset + 8:offset + size]
        offset += size


def box(kind, payload):
    return pack('>I4s', 8 + len(payload), kind) + payload


def tag_movie(data):
    parts = list(boxes(data))
    if [kind for kind, _ in parts] != [b'ftyp', b'moov', b'free', b'mdat']:
        raise ValueError('Review media layout before tagging this movie')
    new_tag = box(b'cprt', box(b'data', pack('>II', 1, 0) + NOTICE.encode()))
    def metadata(payload, path):
        fields = list(boxes(payload))
        target = path[0]
        matches = sum(kind == target for kind, _ in fields)
        if len(path) == 1:
            if matches > 1:
                raise ValueError('Ambiguous rights tags')
            return b''.join(box(k, v) for k, v in fields if k != target) + new_tag
        if matches != 1:
            raise ValueError('Missing or ambiguous movie metadata')
        result = []
        for kind, value in fields:
            if kind == target:
                skip = 4 if kind == b'meta' else 0
                value = value[:skip] + metadata(value[skip:], path[1:])
            result.append(box(kind, value))
        return b''.join(result)

    old_moov = parts[1][1]
    moov = metadata(old_moov, (b'udta', b'meta', b'ilst', b'cprt'))
    shift = len(moov) - len(old_moov)
    first_sample = len(data) - len(parts[-1][1])
    def adjust_chunks(payload):
        result = []
        for kind, value in boxes(payload):
            if kind in (b'trak', b'mdia', b'minf', b'stbl'):
                value = adjust_chunks(value)
            elif kind in (b'stco', b'co64'):
                count = unpack_from('>I', value, 4)[0]
                width, fmt = (4, '>I') if kind == b'stco' else (8, '>Q')
                if len(value) != 8 + count * width:
                    raise ValueError('Invalid media chunk table')
                value = bytearray(value)
                for i in range(8, len(value), width):
                    start = unpack_from(fmt, value, i)[0]
                    if not first_sample <= start < len(data):
                        raise ValueError('Chunk outside local media')
                    pack_into(fmt, value, i, start + shift)
            result.append(box(kind, value))
        return b''.join(result)
    parts[1] = (b'moov', adjust_chunks(moov) if shift else moov)
    return b''.join(box(k, v) for k, v in parts)


def tag_release_media(folder: Path):
    for movie in folder.rglob('*.mp4'):
        source = movie.read_bytes()
        tagged = tag_movie(source)
        if tagged != source:
            movie.write_bytes(tagged)
