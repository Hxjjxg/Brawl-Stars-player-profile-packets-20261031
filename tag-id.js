'use strict';

// Standalone Node.js / Frida JavaScript. No third-party dependencies.
const TAG_ALPHABET = '0289PYLQGRJCUV';

function tagToId(tag) {
    if (typeof tag !== 'string') throw new TypeError('tag must be a string');
    let text = tag.trim().toUpperCase();
    if (text.startsWith('#')) text = text.slice(1);
    if (!text) throw new RangeError('Empty player tag');
    let value = 0n;
    for (const char of text) {
        const digit = TAG_ALPHABET.indexOf(char);
        if (digit < 0) throw new RangeError(`Invalid player-tag character: ${char}`);
        value = value * 14n + BigInt(digit);
        if (value > 0xffffffffffn) throw new RangeError('Player tag exceeds high/low range');
    }
    return { high: Number(value & 0xffn), low: Number(value >> 8n) };
}

function idToTag(high, low) {
    if (!Number.isInteger(high) || high < 0 || high > 255)
        throw new RangeError('high must be an integer in 0..255');
    if (!Number.isInteger(low) || low < 0 || low > 0xffffffff)
        throw new RangeError('low must be an integer in 0..4294967295');
    let value = (BigInt(low) << 8n) | BigInt(high);
    let result = '';
    do {
        result = TAG_ALPHABET[Number(value % 14n)] + result;
        value /= 14n;
    } while (value !== 0n);
    return '#' + result;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { tagToId, idToTag, TAG_ALPHABET };
    if (require.main === module) {
        const [command, a, b] = process.argv.slice(2);
        if (command === 'to-id') console.log(JSON.stringify(tagToId(a)));
        else if (command === 'to-tag' && a !== undefined && b !== undefined)
            console.log(idToTag(Number(a), Number(b)));
        else {
            console.error('Usage: node tag-id.js to-id TAG | to-tag HIGH LOW');
            process.exitCode = 1;
        }
    }
}
