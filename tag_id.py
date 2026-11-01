"""Standalone Supercell player-tag <-> LogicLong high/low conversion. No dependencies."""
import argparse
import json

ALPHABET = '0289PYLQGRJCUV'


def tag_to_id(tag: str) -> tuple[int, int]:
    """Return unsigned (high, low) from a player tag, with or without '#'."""
    if not isinstance(tag, str):
        raise TypeError('tag must be a string')
    text = tag.strip().upper()
    if text.startswith('#'):
        text = text[1:]
    if not text:
        raise ValueError('Empty player tag')
    value = 0
    for char in text:
        if char not in ALPHABET:
            raise ValueError(f'Invalid player-tag character: {char!r}')
        value = value * 14 + ALPHABET.index(char)
        if value > 0xffffffffff:
            raise ValueError('Player tag exceeds the 8-bit high / 32-bit low range')
    return value & 0xff, value >> 8


def id_to_tag(high: int, low: int) -> str:
    """Return a canonical '#TAG'. Inputs are unsigned integers."""
    if type(high) is not int or not 0 <= high <= 0xff:
        raise ValueError('high must be an integer in 0..255')
    if type(low) is not int or not 0 <= low <= 0xffffffff:
        raise ValueError('low must be an integer in 0..4294967295')
    value = (low << 8) | high
    if value == 0:
        return '#0'
    result = []
    while value:
        value, digit = divmod(value, 14)
        result.append(ALPHABET[digit])
    return '#' + ''.join(reversed(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    cmd = sub.add_parser('to-id')
    cmd.add_argument('tag')
    cmd = sub.add_parser('to-tag')
    cmd.add_argument('high', type=lambda s: int(s, 16) if s.lower().startswith('0x') else int(s))
    cmd.add_argument('low', type=lambda s: int(s, 16) if s.lower().startswith('0x') else int(s))
    args = parser.parse_args()
    if args.command == 'to-id':
        high, low = tag_to_id(args.tag)
        print(json.dumps({'tag': id_to_tag(high, low), 'high': high, 'low': low}))
    else:
        print(id_to_tag(args.high, args.low))


if __name__ == '__main__':
    main()
