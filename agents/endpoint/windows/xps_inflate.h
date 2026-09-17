// xps_inflate.h
//
// Adds best-effort text extraction for XPS-pipeline print spool jobs (ZIP/OPC
// containers with DEFLATE-compressed page XML), closing the gap documented
// in agent.cpp's ReadSpoolText() comment: "Properly parsing XPS content
// would mean shipping a ZIP/DEFLATE decompressor into this agent... Rather
// than guess at that blind, this at least makes the gap LOUD instead of
// silent." This file is that decompressor, added during the September 2026
// Print Content Prevention "enterprise-grade" follow-up after live testing
// against a real v4/XPS-native printer driver (Sharp AR-6020N) confirmed
// print jobs from that class of driver always spool as an XPS/ZIP container
// the old ExtractSpoolStrings() byte-scanner cannot see into.
//
// IMPORTANT CONTEXT FOR FUTURE MAINTAINERS: this agent is built with MinGW-
// w64 g++ (see .github/workflows/build-windows-agent.yml), not MSVC. The
// "normal" Windows way to read an XPS/OPC package is the OS-provided OPC
// Packaging API (msopc.dll, IOpcFactory), but that requires MsOpc.lib and
// msopc.h from the Windows SDK, which MinGW does not ship a prebuilt import
// library for (the same class of gap this codebase already hit once before
// for fltlib.dll -- see the "Generate fltlib import library" CI step).
// Hand-declaring that COM interface's binary vtable layout blind, with no
// compiler available in this development environment to verify it, was
// judged too risky. Instead, this file vendors in a small, well-known,
// heavily-used PUBLIC DOMAIN reference DEFLATE decompressor (puff.c/puff.h
// from the official zlib project, https://github.com/madler/zlib/tree/
// master/contrib/puff -- fetched verbatim from that repository, not
// reconstructed from memory) plus a minimal, defensive ZIP-local-file-header
// reader written specifically for this file. Net effect: no new Windows API
// dependency, no new linker flags, compiles with the exact same g++ command
// line already in build-windows-agent.yml.
//
// HONEST DISCLOSURE: this code has NOT been compiled or run anywhere in this
// development environment (no C++ compiler is available here -- see the
// brace/string-depth-counting verification note in the accompanying commit).
// The vendored puff() implementation below is copied verbatim from zlib's
// own repository, which IS a mature, widely-deployed, well-tested piece of
// code -- that part is low risk. The ZIP-container-parsing glue
// (ExtractXpsText below) is new code written for this fix and is the part
// that most needs careful live testing before being trusted. It is written
// defensively throughout (every offset is bounds-checked against the buffer
// size before use; any parsing failure for one entry or the whole job simply
// yields less text, never a crash or an out-of-bounds read; ReadSpoolText()
// in agent.cpp falls back to the pre-existing ExtractSpoolStrings() behavior
// whenever this returns empty).
//
// ---------------------------------------------------------------------
// puff.c / puff.h -- vendored verbatim from:
//   https://raw.githubusercontent.com/madler/zlib/master/contrib/puff/puff.c
//   https://raw.githubusercontent.com/madler/zlib/master/contrib/puff/puff.h
// Original copyright and license notice (preserved per its terms):
//
//   puff.c
//   Copyright (C) 2002-2013 Mark Adler
//   version 2.3, 21 Jan 2013
//
//   puff.h
//   Copyright (C) 2002-2013 Mark Adler, all rights reserved
//   version 2.3, 21 Jan 2013
//
//   This software is provided 'as-is', without any express or implied
//   warranty.  In no event will the author be held liable for any damages
//   arising from the use of this software.
//
//   Permission is granted to anyone to use this software for any purpose,
//   including commercial applications, and to alter it and redistribute it
//   freely, subject to the following restrictions:
//
//   1. The origin of this software must not be misrepresented; you must not
//      claim that you wrote the original software. If you use this software
//      in a product, an acknowledgment in the product documentation would be
//      appreciated but is not required.
//   2. Altered source versions must be plainly marked as such, and must not
//      be misrepresented as being the original software.
//   3. This notice may not be removed or altered from any source
//      distribution.
//
//   Mark Adler    madler@alumni.caltech.edu
//
// Mechanical changes from the original for this integration only (algorithm
// logic is untouched):
//   - Wrapped in an #pragma once header so it can be #include'd from
//     agent.cpp without a separate .cpp translation unit (avoids needing to
//     add a new file to the CI g++ command line).
//   - puff.h's NIL macro and prototype merged in directly.
//   - puff() itself changed from external linkage to `static` (matching the
//     `local`/static convention already used for every other function in
//     this file), so it can never collide with a real zlib puff()/inflate()
//     symbol if this codebase ever links zlib in the future.
// ---------------------------------------------------------------------

#pragma once

#include <setjmp.h>
#include <string>
#include <cstring>
#include <cstdint>
#include <vector>

namespace seceoknight_puff {

#ifndef NIL
#  define NIL ((unsigned char *)0)      /* for no output option */
#endif

#define local static            /* for local function definitions */

#define MAXBITS 15              /* maximum bits in a code */
#define MAXLCODES 286           /* maximum number of literal/length codes */
#define MAXDCODES 30            /* maximum number of distance codes */
#define MAXCODES (MAXLCODES+MAXDCODES)  /* maximum codes lengths to read */
#define FIXLCODES 288           /* number of fixed literal/length codes */

struct state {
    unsigned char *out;
    unsigned long outlen;
    unsigned long outcnt;

    const unsigned char *in;
    unsigned long inlen;
    unsigned long incnt;
    int bitbuf;
    int bitcnt;

    jmp_buf env;
};

local int bits(struct state *s, int need)
{
    long val;

    val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->incnt == s->inlen)
            longjmp(s->env, 1);
        val |= (long)(s->in[s->incnt++]) << s->bitcnt;
        s->bitcnt += 8;
    }

    s->bitbuf = (int)(val >> need);
    s->bitcnt -= need;

    return (int)(val & ((1L << need) - 1));
}

local int stored(struct state *s)
{
    unsigned len;

    s->bitbuf = 0;
    s->bitcnt = 0;

    if (s->incnt + 4 > s->inlen)
        return 2;
    len = s->in[s->incnt++];
    len |= s->in[s->incnt++] << 8;
    if (s->in[s->incnt++] != (~len & 0xff) ||
        s->in[s->incnt++] != ((~len >> 8) & 0xff))
        return -2;

    if (s->incnt + len > s->inlen)
        return 2;
    if (s->out != NIL) {
        if (s->outcnt + len > s->outlen)
            return 1;
        while (len--)
            s->out[s->outcnt++] = s->in[s->incnt++];
    }
    else {
        s->outcnt += len;
        s->incnt += len;
    }

    return 0;
}

struct huffman {
    short *count;
    short *symbol;
};

local int decode(struct state *s, const struct huffman *h)
{
    int len;
    int code;
    int first;
    int count;
    int index;
    int bitbuf;
    int left;
    short *next;

    bitbuf = s->bitbuf;
    left = s->bitcnt;
    code = first = index = 0;
    len = 1;
    next = h->count + 1;
    while (1) {
        while (left--) {
            code |= bitbuf & 1;
            bitbuf >>= 1;
            count = *next++;
            if (code - count < first) {
                s->bitbuf = bitbuf;
                s->bitcnt = (s->bitcnt - len) & 7;
                return h->symbol[index + (code - first)];
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
            len++;
        }
        left = (MAXBITS+1) - len;
        if (left == 0)
            break;
        if (s->incnt == s->inlen)
            longjmp(s->env, 1);
        bitbuf = s->in[s->incnt++];
        if (left > 8)
            left = 8;
    }
    return -10;
}

local int construct(struct huffman *h, const short *length, int n)
{
    int symbol;
    int len;
    int left;
    short offs[MAXBITS+1];

    for (len = 0; len <= MAXBITS; len++)
        h->count[len] = 0;
    for (symbol = 0; symbol < n; symbol++)
        (h->count[length[symbol]])++;
    if (h->count[0] == n)
        return 0;

    left = 1;
    for (len = 1; len <= MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0)
            return left;
    }

    offs[1] = 0;
    for (len = 1; len < MAXBITS; len++)
        offs[len + 1] = offs[len] + h->count[len];

    for (symbol = 0; symbol < n; symbol++)
        if (length[symbol] != 0)
            h->symbol[offs[length[symbol]]++] = symbol;

    return left;
}

local int codes(struct state *s,
                const struct huffman *lencode,
                const struct huffman *distcode)
{
    int symbol;
    int len;
    unsigned dist;
    static const short lens[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    static const short lext[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    static const short dists[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
        8193, 12289, 16385, 24577};
    static const short dext[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
        12, 12, 13, 13};

    do {
        symbol = decode(s, lencode);
        if (symbol < 0)
            return symbol;
        if (symbol < 256) {
            if (s->out != NIL) {
                if (s->outcnt == s->outlen)
                    return 1;
                s->out[s->outcnt] = (unsigned char)symbol;
            }
            s->outcnt++;
        }
        else if (symbol > 256) {
            symbol -= 257;
            if (symbol >= 29)
                return -10;
            len = lens[symbol] + bits(s, lext[symbol]);

            symbol = decode(s, distcode);
            if (symbol < 0)
                return symbol;
            dist = dists[symbol] + bits(s, dext[symbol]);
            if (dist > s->outcnt)
                return -11;

            if (s->out != NIL) {
                if (s->outcnt + (unsigned long)len > s->outlen)
                    return 1;
                while (len--) {
                    s->out[s->outcnt] = s->out[s->outcnt - dist];
                    s->outcnt++;
                }
            }
            else
                s->outcnt += len;
        }
    } while (symbol != 256);

    return 0;
}

local int fixed_block(struct state *s)
{
    static int virgin = 1;
    static short lencnt[MAXBITS+1], lensym[FIXLCODES];
    static short distcnt[MAXBITS+1], distsym[MAXDCODES];
    static struct huffman lencode, distcode;

    if (virgin) {
        int symbol;
        short lengths[FIXLCODES];

        lencode.count = lencnt;
        lencode.symbol = lensym;
        distcode.count = distcnt;
        distcode.symbol = distsym;

        for (symbol = 0; symbol < 144; symbol++)
            lengths[symbol] = 8;
        for (; symbol < 256; symbol++)
            lengths[symbol] = 9;
        for (; symbol < 280; symbol++)
            lengths[symbol] = 7;
        for (; symbol < FIXLCODES; symbol++)
            lengths[symbol] = 8;
        construct(&lencode, lengths, FIXLCODES);

        for (symbol = 0; symbol < MAXDCODES; symbol++)
            lengths[symbol] = 5;
        construct(&distcode, lengths, MAXDCODES);

        virgin = 0;
    }

    return codes(s, &lencode, &distcode);
}

local int dynamic(struct state *s)
{
    int nlen, ndist, ncode;
    int index;
    int err;
    short lengths[MAXCODES];
    short lencnt[MAXBITS+1], lensym[MAXLCODES];
    short distcnt[MAXBITS+1], distsym[MAXDCODES];
    struct huffman lencode, distcode;
    static const short order[19] =
        {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

    lencode.count = lencnt;
    lencode.symbol = lensym;
    distcode.count = distcnt;
    distcode.symbol = distsym;

    nlen = bits(s, 5) + 257;
    ndist = bits(s, 5) + 1;
    ncode = bits(s, 4) + 4;
    if (nlen > MAXLCODES || ndist > MAXDCODES)
        return -3;

    for (index = 0; index < ncode; index++)
        lengths[order[index]] = (short)bits(s, 3);
    for (; index < 19; index++)
        lengths[order[index]] = 0;

    err = construct(&lencode, lengths, 19);
    if (err != 0)
        return -4;

    index = 0;
    while (index < nlen + ndist) {
        int symbol;
        int len;

        symbol = decode(s, &lencode);
        if (symbol < 0)
            return symbol;
        if (symbol < 16)
            lengths[index++] = (short)symbol;
        else {
            len = 0;
            if (symbol == 16) {
                if (index == 0)
                    return -5;
                len = lengths[index - 1];
                symbol = 3 + bits(s, 2);
            }
            else if (symbol == 17)
                symbol = 3 + bits(s, 3);
            else
                symbol = 11 + bits(s, 7);
            if (index + symbol > nlen + ndist)
                return -6;
            while (symbol--)
                lengths[index++] = (short)len;
        }
    }

    if (lengths[256] == 0)
        return -9;

    err = construct(&lencode, lengths, nlen);
    if (err && (err < 0 || nlen != lencode.count[0] + lencode.count[1]))
        return -7;

    err = construct(&distcode, lengths + nlen, ndist);
    if (err && (err < 0 || ndist != distcode.count[0] + distcode.count[1]))
        return -8;

    return codes(s, &lencode, &distcode);
}

static int puff(unsigned char *dest,
                 unsigned long *destlen,
                 const unsigned char *source,
                 unsigned long *sourcelen)
{
    struct state s;
    int last, type;
    int err;

    s.out = dest;
    s.outlen = *destlen;
    s.outcnt = 0;

    s.in = source;
    s.inlen = *sourcelen;
    s.incnt = 0;
    s.bitbuf = 0;
    s.bitcnt = 0;

    if (setjmp(s.env) != 0)
        err = 2;
    else {
        do {
            last = bits(&s, 1);
            type = bits(&s, 2);
            err = type == 0 ?
                    stored(&s) :
                    (type == 1 ?
                        fixed_block(&s) :
                        (type == 2 ?
                            dynamic(&s) :
                            -1));
            if (err != 0)
                break;
        } while (!last);
    }

    if (err <= 0) {
        *destlen = s.outcnt;
        *sourcelen = s.incnt;
    }
    return err;
}

#undef local
#undef MAXBITS
#undef MAXLCODES
#undef MAXDCODES
#undef MAXCODES
#undef FIXLCODES

// ---------------------------------------------------------------------
// End of vendored puff.c/puff.h. Everything below this line is new code
// written for this fix (not from zlib) -- the ZIP/OPC container parsing
// and XPS text-attribute scanning glue.
// ---------------------------------------------------------------------

// Reads a little-endian 16/32-bit value from `buf` at `off`, returning false
// (and leaving `out` untouched) if that would read past `buf.size()`.
// Every single field read in ExtractXpsText below goes through one of
// these -- no offset is ever trusted without a bounds check first.
inline bool ReadU16LE(const std::vector<unsigned char>& buf, size_t off, uint16_t& out) {
    if (off + 2 > buf.size()) return false;
    out = (uint16_t)(buf[off] | (buf[off + 1] << 8));
    return true;
}
inline bool ReadU32LE(const std::vector<unsigned char>& buf, size_t off, uint32_t& out) {
    if (off + 4 > buf.size()) return false;
    out = (uint32_t)buf[off] | ((uint32_t)buf[off + 1] << 8) |
          ((uint32_t)buf[off + 2] << 16) | ((uint32_t)buf[off + 3] << 24);
    return true;
}

// Scans `hay` for UnicodeString="..." attribute values and appends the
// (minimally XML-unescaped) text to `out`, stopping once `out` reaches
// maxTotalOut. Shared by both the stored (uncompressed) and deflated entry
// paths below.
inline void ScanUnicodeStringAttrs(const std::string& hay, std::string& out, size_t maxTotalOut) {
    const std::string needle = "UnicodeString=\"";
    size_t pos = 0;
    while (out.size() < maxTotalOut) {
        size_t start = hay.find(needle, pos);
        if (start == std::string::npos) break;
        start += needle.size();
        size_t end = hay.find('"', start);
        if (end == std::string::npos) break; // truncated/partial attribute at buffer edge -- stop rather than guess
        std::string raw = hay.substr(start, end - start);
        // Minimal XML-entity unescaping -- enough for the classifier to see
        // real characters instead of literal "&amp;"/"&quot;" runs. Not a
        // full XML decoder; unknown/malformed entities are left as-is.
        std::string decoded;
        decoded.reserve(raw.size());
        for (size_t i = 0; i < raw.size(); ) {
            if (raw[i] == '&') {
                if (raw.compare(i, 5, "&amp;") == 0) { decoded += '&'; i += 5; continue; }
                if (raw.compare(i, 4, "&lt;") == 0) { decoded += '<'; i += 4; continue; }
                if (raw.compare(i, 4, "&gt;") == 0) { decoded += '>'; i += 4; continue; }
                if (raw.compare(i, 6, "&quot;") == 0) { decoded += '"'; i += 6; continue; }
                if (raw.compare(i, 6, "&apos;") == 0) { decoded += '\''; i += 6; continue; }
            }
            decoded += raw[i++];
        }
        out += decoded;
        out += ' ';
        pos = end + 1;
    }
}

// Inflate one entry's compressed bytes into a fixed, bounded scratch buffer
// and append any text found between UnicodeString="..." attributes to `out`.
// Deliberately does NOT do a "discover the real size first" pass (puff()'s
// dest=NIL scanning mode has no output-size cap at all, which would make a
// corrupt or adversarial entry a cheap way to force a huge/unbounded
// allocation or loop -- a "zip bomb" of sorts). Instead this allocates one
// fixed-size buffer up front and lets puff() naturally stop
// ("output space exhausted", error 1) once it's full -- codes()/stored()
// above only ever write into out[0..outcnt-1] before checking outcnt against
// outlen, so everything already written into the buffer up to wherever it
// stopped is valid decoded content regardless of which return code puff()
// gives back, and it is always safe to scan the whole buffer for text.
inline void InflateEntryAndScan(const unsigned char* compressed, size_t compressedLen,
                                 std::string& out, size_t maxTotalOut) {
    if (compressedLen == 0 || compressedLen > 8u * 1024u * 1024u) return; // sanity cap: 8MB compressed input for one part is already generous for a single printed page
    const size_t kScratchSize = 262144; // 256KB decompressed per part -- far more than a page of visible text needs, even with XML markup overhead
    std::vector<unsigned char> scratch(kScratchSize, 0);
    unsigned long destlen = (unsigned long)kScratchSize;
    unsigned long srclen = (unsigned long)compressedLen;
    (void)seceoknight_puff::puff(scratch.data(), &destlen, compressed, &srclen);
    std::string hay(reinterpret_cast<char*>(scratch.data()), scratch.size());
    ScanUnicodeStringAttrs(hay, out, maxTotalOut);
}

// Best-effort text extraction from an XPS/OPC (ZIP) print-spool container.
// Walks local file headers directly (no central directory needed -- we only
// want text content, not a faithful unzip), inflating each entry whose name
// ends in ".fpage" (XPS's fixed-page markup files, where a page's visible
// text lives) via the vendored puff() above. Returns empty string on any
// structural problem -- callers (ReadSpoolText in agent.cpp) already treat
// an empty result as "fall back to the existing ExtractSpoolStrings()
// behavior", so there is no separate error path to wire up here.
inline std::string ExtractXpsText(const std::vector<unsigned char>& bytes) {
    std::string out;
    const size_t kMaxTotalOut = 200000; // matches EvaluatePrintContent()'s own text.substr(0, 200000) cap
    const int kMaxEntries = 200;        // bound total work regardless of how many parts the container has
    int entriesProcessed = 0;
    size_t pos = 0;

    while (pos + 4 <= bytes.size() && out.size() < kMaxTotalOut && entriesProcessed < kMaxEntries) {
        // Find the next local-file-header signature "PK\x03\x04" from pos.
        // Scanning for the signature (rather than trusting strict adjacency
        // between entries) tolerates minor structural oddities and matches
        // this file's "best effort, never crash" philosophy.
        size_t sigPos = std::string::npos;
        for (size_t i = pos; i + 4 <= bytes.size(); ++i) {
            if (bytes[i] == 0x50 && bytes[i+1] == 0x4B && bytes[i+2] == 0x03 && bytes[i+3] == 0x04) {
                sigPos = i;
                break;
            }
        }
        if (sigPos == std::string::npos) break;

        uint16_t genFlag = 0, method = 0, nameLen = 0, extraLen = 0;
        uint32_t compSize = 0, uncompSize = 0;
        bool ok = ReadU16LE(bytes, sigPos + 6, genFlag) &&
                  ReadU16LE(bytes, sigPos + 8, method) &&
                  ReadU32LE(bytes, sigPos + 18, compSize) &&
                  ReadU32LE(bytes, sigPos + 22, uncompSize) &&
                  ReadU16LE(bytes, sigPos + 26, nameLen) &&
                  ReadU16LE(bytes, sigPos + 28, extraLen);
        if (!ok) break; // truncated header -- nothing more we can safely read
        (void)uncompSize; // not trusted/used -- see streaming-mode note below

        size_t nameOff = sigPos + 30;
        if (nameOff + (size_t)nameLen > bytes.size()) break;
        std::string name(reinterpret_cast<const char*>(&bytes[nameOff]), nameLen);

        size_t dataOff = nameOff + (size_t)nameLen + (size_t)extraLen;

        // General-purpose bit 3 ("streaming"/data-descriptor mode) means
        // compSize here may be 0 and the real sizes/CRC follow the compressed
        // data instead of preceding it -- we have no reliable way to know
        // where this entry's data ends without a central directory (which we
        // deliberately don't parse). Skip rather than guess.
        bool streaming = (genFlag & 0x0008) != 0;
        if (streaming || compSize == 0 || dataOff + (size_t)compSize > bytes.size()) {
            // Can't safely locate this entry's end -- and without that, we
            // can't find the NEXT entry's signature reliably either. Advance
            // just past this signature and keep scanning; a real next entry
            // will still be found by the signature search above.
            pos = sigPos + 4;
            ++entriesProcessed;
            continue;
        }

        bool isFpage = name.size() >= 6 &&
            (name.compare(name.size() - 6, 6, ".fpage") == 0 ||
             name.compare(name.size() - 6, 6, ".FPAGE") == 0);

        if (isFpage) {
            if (method == 0) {
                // Stored (uncompressed) -- just scan the raw bytes directly,
                // no inflate needed.
                std::string hay(reinterpret_cast<const char*>(&bytes[dataOff]), compSize);
                ScanUnicodeStringAttrs(hay, out, kMaxTotalOut);
            } else if (method == 8) {
                InflateEntryAndScan(&bytes[dataOff], compSize, out, kMaxTotalOut);
            }
            // Any other compression method (rare/legacy, e.g. shrink/reduce)
            // is intentionally not handled -- OPC/XPS packages are always
            // stored or deflated in practice, so this is not expected to
            // matter, and silently skipping is safer than guessing.
        }

        pos = dataOff + (size_t)compSize;
        ++entriesProcessed;
    }

    return out;
}

} // namespace seceoknight_puff
