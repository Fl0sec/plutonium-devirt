#include "aplib.hpp"

#include <stdexcept>
#include <string>

namespace pdv {
namespace {

class Reader {
public:
    explicit Reader(std::span<const std::uint8_t> src) : src_(src) {}

    std::uint8_t byte() {
        if (pos_ >= src_.size()) throw std::runtime_error("aplib: read past end of packed data");
        return src_[pos_++];
    }

    unsigned bit() {
        if (bits_ == 0) {
            tag_ = byte();
            bits_ = 8;
        }
        --bits_;
        const unsigned b = (tag_ >> 7) & 1u;
        tag_ = static_cast<std::uint8_t>(tag_ << 1);
        return b;
    }

    // Elias-gamma style variable-length number, always >= 2.
    std::uint32_t gamma() {
        std::uint32_t r = 1;
        do {
            r = (r << 1) + bit();
        } while (bit());
        return r;
    }

    std::size_t pos() const { return pos_; }

private:
    std::span<const std::uint8_t> src_;
    std::size_t pos_ = 0;
    std::uint8_t tag_ = 0;
    unsigned bits_ = 0;
};

}  // namespace

DepackResult aplib_depack(std::span<const std::uint8_t> src, std::size_t max_out) {
    DepackResult res;
    auto& out = res.out;
    out.reserve(max_out);
    Reader in(src);

    auto put = [&](std::uint8_t v) {
        if (out.size() >= max_out) throw std::runtime_error("aplib: output exceeds limit");
        out.push_back(v);
    };
    auto copy = [&](std::uint32_t offset, std::uint32_t length) {
        if (offset == 0 || offset > out.size())
            throw std::runtime_error("aplib: bad match offset " + std::to_string(offset) + " at output " +
                                     std::to_string(out.size()));
        for (std::uint32_t i = 0; i < length; ++i) put(out[out.size() - offset]);
    };

    put(in.byte());  // the first byte is always a literal
    std::uint32_t last_offset = 0;
    bool after_match = false;  // aPLib's "LWM": a match may not directly reuse the last offset
    for (;;) {
        if (!in.bit()) {  // 0: literal byte
            put(in.byte());
            after_match = false;
            continue;
        }
        if (!in.bit()) {  // 10: block match
            std::uint32_t offs = in.gamma();
            if (!after_match && offs == 2) {  // repeat the last offset
                copy(last_offset, in.gamma());
            } else {
                offs -= after_match ? 2 : 3;
                offs = (offs << 8) + in.byte();
                std::uint32_t length = in.gamma();
                if (offs >= 32000) ++length;
                if (offs >= 1280) ++length;
                if (offs < 128) length += 2;
                copy(offs, length);
                last_offset = offs;
            }
            after_match = true;
            continue;
        }
        if (!in.bit()) {  // 110: short match (7-bit offset, length 2 or 3) or end marker
            const std::uint8_t b = in.byte();
            const std::uint32_t length = 2u + (b & 1u);
            const std::uint32_t offs = b >> 1;
            if (offs == 0) break;
            copy(offs, length);
            last_offset = offs;
            after_match = true;
            continue;
        }
        std::uint32_t offs = 0;  // 111: single byte from a 4-bit offset, 0 means a zero byte
        for (int i = 0; i < 4; ++i) offs = (offs << 1) + in.bit();
        if (offs != 0 && offs > out.size()) throw std::runtime_error("aplib: bad short offset");
        put(offs ? out[out.size() - offs] : std::uint8_t{0});
        after_match = false;
    }
    res.consumed = in.pos();
    return res;
}

}  // namespace pdv
