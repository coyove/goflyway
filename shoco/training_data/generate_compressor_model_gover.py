#!/usr/bin/python

from __future__ import print_function

import collections
import argparse
import itertools
import re
import sys

WHITESPACE = b" \t\n\r\x0b\x0c\xc2\xad"
PUNCTUATION = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
TABLE_C = """package shoco

const MIN_CHR = {min_chr}
const MAX_CHR = {max_chr}

var chrs_by_chr_id = []byte{{
  {chrs},
}}

var chr_ids_by_chr = []int8{{
  {chrs_reversed},
}}

var successor_ids_by_chr_id_and_chr_id = [][]int8{{
  []int8{{{successors_reversed}}},
}}

var chrs_by_chr_and_successor_id = [][]int8{{
  []int8{{{chrs_by_chr_and_successor_id}}},
}}

type Pack struct {{
    word           uint32
    bytes_packed   uint32
    bytes_unpacked uint32
    offsets        []uint32 // {max_elements_len}
    masks          []int16  // {max_elements_len}
    header_mask    byte
    header         byte
}}

const PACK_COUNT = {pack_count}
const MAX_SUCCESSOR_N = {max_successor_len}

var packs = []Pack{{
  {pack_lines},
}}
"""

PACK_LINE = "Pack{{ {word:#x}, {packed}, {unpacked}, []uint32{{ {offsets} }}, []int16{{ {masks} }}, {header_mask:#x}, {header:#x} }}"

def accumulate(seq, start=0):
    total = start
    for elem in seq:
        total += elem
        yield total

class Structure(object):
    def __init__(self, datalist):
        self.datalist = list(datalist)

    @property
    def header(self):
        return self.datalist[0]

    @property
    def lead(self):
        return self.datalist[1]

    @property
    def successors(self):
        return self.datalist[2:]

    @property
    def consecutive(self):
        return self.datalist[1:]


class Bits(Structure):
    def __init__(self, bitlist):
        Structure.__init__(self, bitlist)

class Masks(Structure):
    def __init__(self, bitlist):
        Structure.__init__(self, [((1 << bits) -1) for bits in bitlist])

class Offsets(Structure):
    def __init__(self, bitlist):
        inverse = accumulate(bitlist)
        offsets = [32 - offset for offset in inverse]
        Structure.__init__(self, offsets)


class Encoding(object):
    def __init__(self, bitlist):
        self.bits = Bits(bitlist)
        self.masks = Masks(bitlist)
        self.offsets = Offsets(bitlist)
        self.packed = sum(bitlist) / 8
        self.size = len([bits for bits in bitlist if bits])
        self.unpacked = self.size - 1
        self._hash = tuple(bitlist).__hash__()

    @property
    def header_code(self):
        return ((1 << self.bits.header) - 2) << (8 - self.bits.header)

    @property
    def header_mask(self):
        return self.masks.header << (8 - self.bits.header)

    @property
    def word(self):
        return ((1 << self.bits.header) - 2) << self.offsets.header

    def __hash__(self):
        return self._hash

    def can_encode(self, part, successors, chrs_indices):
        lead_index = chrs_indices.get(part[0], -1)
        if lead_index < 0:
            return False
        if lead_index > (1 << self.bits.header):
            return False
        last_index = lead_index
        last_char = part[0]
        for bits, char in zip(self.bits.consecutive, part[1:]):
            if char not in successors[last_char]:
                return False
            successor_index = successors[last_char].index(char)
            if successor_index > (1 << bits):
                return False
            last_index = successor_index
            last_char = part[0]
            return True

PACK_STRUCTURES = (
    (1, (
        (2, 4, 2),
        (2, 3, 3),
        (2, 4, 1, 1),
        (2, 3, 2, 1),
        (2, 2, 2, 2),
        (2, 3, 1, 1, 1),
        (2, 2, 2, 1, 1),
        (2, 2, 1, 1, 1, 1),
        (2, 1, 1, 1, 1, 1, 1),
    )),
    (2, (
        (3, 5, 4, 2, 2),
        (3, 5, 3, 3, 2),
        (3, 4, 4, 3, 2),
        (3, 4, 3, 3, 3),
        (3, 5, 3, 2, 2, 1),
        (3, 5, 2, 2, 2, 2),
        (3, 4, 4, 2, 2, 1),
        (3, 4, 3, 2, 2, 2),
        (3, 4, 3, 3, 2, 1),
        (3, 4, 2, 2, 2, 2),
        (3, 3, 3, 3, 2, 2),
        (3, 4, 3, 2, 2, 1, 1),
        (3, 4, 2, 2, 2, 2, 1),
        (3, 3, 3, 2, 2, 2, 1),
        (3, 3, 2, 2, 2, 2, 2),
        (3, 2, 2, 2, 2, 2, 2),
        (3, 3, 3, 2, 2, 1, 1, 1),
        (3, 3, 2, 2, 2, 2, 1, 1),
        (3, 2, 2, 2, 2, 2, 2, 1),
    )),
    (4, (
        (4, 5, 4, 4, 4, 3, 3, 3, 2),
        (4, 5, 5, 4, 4, 3, 3, 2, 2),
        (4, 4, 4, 4, 4, 4, 3, 3, 2),
        (4, 4, 4, 4, 4, 3, 3, 3, 3),
    ))

)

ENCODINGS = [(packed, [Encoding(bitlist) for bitlist in bitlists]) for packed, bitlists in PACK_STRUCTURES]

MAX_CONSECUTIVES = 8

def make_log(output):
    if output is None:
        def _(*args, **kwargs):
            pass
        return _
    return print


def bigrams(sequence):
    sequence = iter(sequence)
    last = next(sequence)
    for item in sequence:
        yield last, item
        last = item


def format_int_line(items):
    return r", ".join([r"{}".format(k) for k in items])


def escape(char):
    return r"'\''" if char == "'" else repr(char)


def format_chr_line(items):
    return r", ".join([r"{}".format(escape(k)) for k in items])

def chunkinator(files, split, strip):
    if files:
        all_in = (open(filename, "rb").read() for filename in files)
    else:
        all_in = [sys.stdin.read()]

    split = split.lower()
    if split == "none":
        chunks = all_in
    elif split == "newline":
        chunks = itertools.chain.from_iterable(data.splitlines() for data in all_in)
    elif split == "whitespace":
        chunks = itertools.chain.from_iterable(re.split(b"[" + WHITESPACE + "]", data) for data in all_in)

    strip = strip.lower()
    for chunk in chunks:
        if strip == "whitespace":
            chunk = chunk.strip()
        elif strip == "punctuation":
            chunk = chunk.strip(PUNCTUATION + WHITESPACE)

        if chunk:
            yield chunk


def nearest_lg(number):
    lg = 0
    while (number > 0):
        number >>= 1
        lg += 1
    return lg


def main():
    parser = argparse.ArgumentParser(description="Generate a succession table for 'shoco'.")
    parser.add_argument("file", nargs="*", help="The training data file(s). If no input file is specified, the input is read from STDIN.")
    parser.add_argument("-o", "--output", type=str, help="Output file for the resulting succession table.")
    parser.add_argument("--split", choices=["newline", "whitespace", "none"], default="newline", help=r"Split the input into chunks at this separator. Default: newline")
    parser.add_argument("--strip", choices=["whitespace", "punctuation", "none"], default="whitespace", help="Remove leading and trailing characters from each chunk. Default: whitespace")

    generation_group = parser.add_argument_group("table and encoding generation arguments", "Higher values may provide for better compression ratios, but will make compression/decompression slower. Likewise, lower numbers make compression/decompression faster, but will likely make hurt the compression ratio. The default values are mostly a good compromise.")
    generation_group.add_argument("--max-leading-char-bits", type=int, default=5, help="The maximum amount of bits that may be used for representing a leading character. Default: 5")
    generation_group.add_argument("--max-successor-bits", type=int, default=4, help="The maximum amount of bits that may be used for representing a successor character. Default: 4")
    generation_group.add_argument("--encoding-types", type=int, default=3, choices=[1, 2, 3], help="The number of different encoding schemes. If your input strings are very short, consider lower values. Default: 3")
    generation_group.add_argument("--optimize-encoding", action="store_true", default=False, help="Find the optimal packing structure for the training data. This rarely leads to different results than the default values, and it is *slow*. Use it for very unusual input strings, or when you use non-default table generation arguments.")
    args = parser.parse_args()

    log = make_log(args.output)

    chars_count = 1 << args.max_leading_char_bits
    successors_count = 1 << args.max_successor_bits


    log("finding bigrams ... ", end="")
    sys.stdout.flush()
    bigram_counters = collections.OrderedDict()
    first_char_counter = collections.Counter()
    chunks = list(chunkinator(args.file, args.split, args.strip))
    for chunk in chunks:
        bgs = bigrams(chunk)
        for bg in bgs:
            a, b = bg
            first_char_counter[a] += 1
            if a not in bigram_counters:
                bigram_counters[a] = collections.Counter()
            bigram_counters[a][b] += 1


    log("done.")
    # generate list of most common chars
    successors = collections.OrderedDict()
    for char, freq in first_char_counter.most_common(1 << args.max_leading_char_bits):
        successors[char] = [successor for successor, freq in bigram_counters[char].most_common(1 << args.max_successor_bits)]
        successors[char] += ['\0'] * ((1 << args.max_successor_bits) - len(successors[char]))

    max_chr = max(successors.keys()) + 1
    min_chr = min(successors.keys())

    chrs_indices = collections.OrderedDict(zip(successors.keys(), range(chars_count)))
    chrs_reversed = [chrs_indices.get(chr(i), -1) for i in range(256)]

    successors_reversed = collections.OrderedDict()
    for char, successor_list in successors.items():
        successors_reversed[char] = [None] * chars_count
        s_indices = collections.OrderedDict(zip(successor_list, range(chars_count)))
        for i, s in enumerate(successors.keys()):
            successors_reversed[char][i] = s_indices.get(s, -1)

    zeros_line = ['\0'] * (1 << args.max_successor_bits)
    chrs_by_chr_and_successor_id = [successors.get(chr(i), zeros_line) for i in range(min_chr, max_chr)]


    if args.optimize_encoding:
        log("finding best packing structures ... ", end="")
        sys.stdout.flush()
        counters = {}

        for packed, _ in ENCODINGS[:args.encoding_types]:
            counters[packed] = collections.Counter()

        for chunk in chunks:
            for i in range(len(chunk)):
                for packed, encodings in ENCODINGS[:args.encoding_types]:
                    for encoding in encodings:
                        if (encoding.bits.lead > args.max_leading_char_bits) or (max(encoding.bits.consecutive) > args.max_successor_bits):
                            continue
                        if encoding.can_encode(chunk[i:], successors, chrs_indices):
                            counters[packed][encoding] += packed / float(encoding.unpacked)

        best_encodings_raw = [(packed, counter.most_common(1)[0][0]) for packed, counter in counters.items()]
        max_encoding_len = max(encoding.size for _, encoding in best_encodings_raw)
        best_encodings = [Encoding(encoding.bits.datalist + [0] * (MAX_CONSECUTIVES - encoding.size)) for packed, encoding in best_encodings_raw]
        log("done.")
    else:
        max_encoding_len = 8
        best_encodings = [Encoding([2, 4, 2, 0, 0, 0, 0, 0, 0]),
                          Encoding([3, 4, 3, 3, 3, 0, 0, 0, 0]),
                          Encoding([4, 5, 4, 4, 4, 3, 3, 3, 2])][:args.encoding_types]

    log("formating table file ... ", end="")
    sys.stdout.flush()

    pack_lines_formated = ",\n  ".join(
        PACK_LINE.format(
            word=best_encodings[i].word,
            packed=best_encodings[i].packed,
            unpacked=best_encodings[i].unpacked,
            offsets=format_int_line(best_encodings[i].offsets.consecutive),
            masks=format_int_line(best_encodings[i].masks.consecutive),
            header_mask=best_encodings[i].header_mask,
            header=best_encodings[i].header_code,
        )
        for i in range(args.encoding_types)
    )
    out = TABLE_C.format(
        chrs_count=chars_count,
        successors_count=successors_count,
        chrs=format_chr_line(successors.keys()),
        chrs_reversed=format_int_line(chrs_reversed),
        successors_reversed="},\n  []int8{".join(format_int_line(l) for l in successors_reversed.values()),
        chrs_by_chr_and_successor_id="},\n  []int8{".join(format_chr_line(l) for l in chrs_by_chr_and_successor_id),

        pack_lines=pack_lines_formated,
        max_successor_len=max_encoding_len - 1,
        max_elements_len=MAX_CONSECUTIVES,
        pack_count=args.encoding_types,
        max_chr=max_chr,
        min_chr=min_chr
    )
    log("done.")

    log("writing table file ... ", end="")
    sys.stdout.flush()
    if args.output is None:
        print(out)
    else:
        with open(args.output, "w") as f:
            f.write(out)
            log("done.")

if __name__ == "__main__":
    main()
