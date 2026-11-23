// vjcc_vmd: VM-D's virtual conditional jump (handler vmd_078) as C++, checked against recorded executions.
//
// vmd_078 reads an operand at the context's VIP, tests one condition code against a flags word held in
// a context slot, stores the outcome in the context's taken byte and moves VIP to one of two successors.
// Operands are read statically from the reader's own file (.themida depacked as stage 0 does it), so the
// operand layout is tested against real bytecode, not against values copied from the trace.
//
// usage: vjcc_vmd <plutonium-bootstrapper-win32.exe> [vmd_vjcc_observed.csv]

#include <array>
#include <cstring>
#include <cstdio>
#include <exception>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "image.hpp"

namespace {

// ---- VM-D context (0xC0 bytes at 0x13239763 in the image) ----------------------------------------
constexpr std::uint32_t kVmdContextSize = 0xC0;
constexpr std::uint32_t kVipField = 0x25;    // dword: pointer to the current operand
constexpr std::uint32_t kTakenField = 0xBF;  // byte: VJCC outcome written by the handler
constexpr std::uint32_t kVmdHandlerTable = 0x1344F7C8;
constexpr std::uint32_t kVmdHandlerCount = 498;

struct VmdContext {
    std::array<std::uint8_t, kVmdContextSize> b{};
    std::uint32_t u32(std::uint32_t off) const { return pdv::load_le<std::uint32_t>(b, off); }
    void set_u32(std::uint32_t off, std::uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
    std::uint32_t vip() const { return u32(kVipField); }
};

// ---- condition map recovered from the handler bodies ------------------------------------------------
constexpr std::uint32_t CF = 0x1, PF = 0x4, ZF = 0x40, SF = 0x80, OF = 0x800;
constexpr bool has(std::uint32_t f, std::uint32_t m) { return (f & m) != 0; }

struct Condition {
    std::uint8_t code;
    const char* x86;
    const char* predicate;
    bool (*test)(std::uint32_t flags);
};

constexpr std::array<Condition, 16> kConditionMap = {{
    {0x02, "je", "ZF", [](std::uint32_t f) { return has(f, ZF); }},
    {0x8D, "jne", "!ZF", [](std::uint32_t f) { return !has(f, ZF); }},
    {0x20, "ja", "!ZF && !CF", [](std::uint32_t f) { return !has(f, ZF) && !has(f, CF); }},
    {0x12, "jae", "!CF", [](std::uint32_t f) { return !has(f, CF); }},
    {0x32, "jb", "CF", [](std::uint32_t f) { return has(f, CF); }},
    {0x34, "jbe", "ZF || CF", [](std::uint32_t f) { return has(f, ZF) || has(f, CF); }},
    {0x91, "jg", "!ZF && SF == OF", [](std::uint32_t f) { return !has(f, ZF) && has(f, SF) == has(f, OF); }},
    {0x44, "jge", "SF == OF", [](std::uint32_t f) { return has(f, SF) == has(f, OF); }},
    {0xAD, "jl", "SF != OF", [](std::uint32_t f) { return has(f, SF) != has(f, OF); }},
    {0x67, "jle", "ZF || SF != OF", [](std::uint32_t f) { return has(f, ZF) || has(f, SF) != has(f, OF); }},
    {0xD2, "jno", "!OF", [](std::uint32_t f) { return !has(f, OF); }},
    {0x82, "jo", "OF", [](std::uint32_t f) { return has(f, OF); }},
    {0x13, "jnp", "!PF", [](std::uint32_t f) { return !has(f, PF); }},
    {0x1E, "jp", "PF", [](std::uint32_t f) { return has(f, PF); }},
    {0xDE, "jns", "!SF", [](std::uint32_t f) { return !has(f, SF); }},
    {0x2F, "js", "SF", [](std::uint32_t f) { return has(f, SF); }},
}};

const Condition* find_condition(std::uint8_t code) {
    for (const auto& c : kConditionMap)
        if (c.code == code) return &c;
    return nullptr;  // code 0x00 (and anything else) is not a case: the taken byte stays 0
}

// ---- vmd_078 ----------------------------------------------------------------------------------------
struct Vmd078Operand {
    std::uint16_t taken_index;   // +0x0  next handler if taken
    std::uint32_t taken_disp;    // +0x4  bit 31 set: VIP -= low 31 bits, else VIP += disp
    std::uint16_t flags_slot;    // +0x8  context offset of the flags word
    std::uint8_t code;           // +0xA  condition code
    std::uint16_t fall_index;    // +0xB  next handler if not taken, stored minus 0x3A55538F (16-bit)
    std::uint32_t fall_delta;    // +0xD  VIP += delta (mod 2^32)
};

Vmd078Operand decode_vmd078(const pdv::ProtectedImage& img, std::uint32_t vip) {
    return {img.u16(vip + 0x0),
            img.u32(vip + 0x4),
            img.u16(vip + 0x8),
            img.u8(vip + 0xA),
            static_cast<std::uint16_t>((img.u16(vip + 0xB) + 0x3A55538Fu) & 0xFFFF),
            img.u32(vip + 0xD)};
}

std::uint32_t taken_target(std::uint32_t vip, std::uint32_t disp) {
    return (disp & 0x80000000u) ? vip - (disp & 0x7FFFFFFFu) : vip + disp;
}

struct Vmd078Step {
    bool taken;
    std::uint32_t next_vip;
    std::uint16_t next_index;
};

Vmd078Step vmd_078(VmdContext& ctx, const pdv::ProtectedImage& bytecode) {
    const std::uint32_t vip = ctx.vip();
    const Vmd078Operand op = decode_vmd078(bytecode, vip);
    const std::uint32_t flags = ctx.u32(op.flags_slot);
    const Condition* c = find_condition(op.code);
    const bool taken = c != nullptr && c->test(flags);
    ctx.b[kTakenField] = taken ? 1 : 0;
    const std::uint32_t next = taken ? taken_target(vip, op.taken_disp) : vip + op.fall_delta;
    ctx.set_u32(kVipField, next);
    return {taken, next, taken ? op.taken_index : op.fall_index};
}

// Independent reference: x86 Jcc semantics from the tttn condition encoding (Intel SDM, appendix B).
bool x86_jcc(const std::string& m, std::uint32_t f) {
    static const std::map<std::string, int> tttn = {{"jo", 0},  {"jno", 1}, {"jb", 2},  {"jae", 3},
                                                    {"je", 4},  {"jne", 5}, {"jbe", 6}, {"ja", 7},
                                                    {"js", 8},  {"jns", 9}, {"jp", 10}, {"jnp", 11},
                                                    {"jl", 12}, {"jge", 13}, {"jle", 14}, {"jg", 15}};
    const int t = tttn.at(m);
    bool r = false;
    switch (t >> 1) {
        case 0: r = has(f, OF); break;
        case 1: r = has(f, CF); break;
        case 2: r = has(f, ZF); break;
        case 3: r = has(f, CF) || has(f, ZF); break;
        case 4: r = has(f, SF); break;
        case 5: r = has(f, PF); break;
        case 6: r = has(f, SF) != has(f, OF); break;
        default: r = has(f, ZF) || (has(f, SF) != has(f, OF)); break;
    }
    return (t & 1) ? !r : r;
}

struct Row {
    std::uint32_t vip, flags, taken_vip, fall_vip;
    std::uint8_t cc;
    std::uint16_t slot;
    bool taken;
    std::uint64_t count;
};

std::vector<Row> load_rows(const std::filesystem::path& p) {
    std::ifstream f(p);
    if (!f) throw std::runtime_error("cannot open " + p.filename().string());
    std::vector<Row> rows;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#' || line.rfind("vip,", 0) == 0) continue;
        std::stringstream ss(line);
        std::string tok[8];
        for (auto& t : tok) std::getline(ss, t, ',');
        rows.push_back({static_cast<std::uint32_t>(std::stoul(tok[0], nullptr, 16)),
                        static_cast<std::uint32_t>(std::stoul(tok[3], nullptr, 16)),
                        static_cast<std::uint32_t>(std::stoul(tok[5], nullptr, 16)),
                        static_cast<std::uint32_t>(std::stoul(tok[6], nullptr, 16)),
                        static_cast<std::uint8_t>(std::stoul(tok[1], nullptr, 16)),
                        static_cast<std::uint16_t>(std::stoul(tok[2], nullptr, 16)), tok[4] == "1",
                        std::stoull(tok[7])});
    }
    return rows;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: vjcc_vmd <plutonium-bootstrapper-win32.exe> [vmd_vjcc_observed.csv]\n");
        return 2;
    }
    try {
        const pdv::ProtectedImage img = pdv::open_image(argv[1]);
        const std::filesystem::path csv = argc >= 3 ? std::filesystem::path(argv[2])
                                                    : std::filesystem::path(PDV_DATA_DIR) / "vmd_vjcc_observed.csv";
        const auto rows = load_rows(csv);
        std::printf("input sha256  %s (%s)\n", img.input_sha256.c_str(),
                    img.input_sha256 == pdv::kInputSha256 ? "r5354" : "UNKNOWN BUILD");
        std::printf("dataset       %s, %zu rows\n\n", csv.filename().string().c_str(), rows.size());

        // 1. The map against x86 Jcc semantics, all 2^5 combinations of CF PF ZF SF OF.
        int map_bad = 0;
        for (const auto& c : kConditionMap)
            for (std::uint32_t m = 0; m < 32; ++m) {
                const std::uint32_t f = (has(m, 1) ? CF : 0) | (has(m, 2) ? PF : 0) | (has(m, 4) ? ZF : 0) |
                                        (has(m, 8) ? SF : 0) | (has(m, 16) ? OF : 0);
                map_bad += c.test(f) != x86_jcc(c.x86, f);
            }
        std::printf("condition map vs x86 Jcc semantics: 16 codes x 32 flag combinations, %d disagreements\n\n",
                    map_bad);

        // 2. Differential test: run vmd_078 on a fresh context per recorded execution.
        struct Stat {
            std::uint64_t n = 0, taken = 0;
            std::set<std::uint32_t> flags;
        };
        std::map<std::uint8_t, Stat> per_code;
        std::uint64_t total = 0, pred_bad = 0, op_bad = 0, succ_bad = 0, step_bad = 0, idx_bad = 0;
        std::set<std::uint32_t> vips;
        for (const Row& r : rows) {
            VmdContext ctx;
            ctx.set_u32(kVipField, r.vip);
            const Vmd078Operand op = decode_vmd078(img, r.vip);
            if (op.flags_slot + 4 > kVmdContextSize) throw std::runtime_error("flags slot outside the context");
            ctx.set_u32(op.flags_slot, r.flags);
            const Vmd078Step s = vmd_078(ctx, img);

            total += r.count;
            vips.insert(r.vip);
            if (op.code != r.cc || op.flags_slot != r.slot) op_bad += r.count;
            if (taken_target(r.vip, op.taken_disp) != r.taken_vip || r.vip + op.fall_delta != r.fall_vip)
                succ_bad += r.count;
            if (s.taken != r.taken || ctx.b[kTakenField] != (r.taken ? 1 : 0)) pred_bad += r.count;
            if (s.next_vip != (r.taken ? r.taken_vip : r.fall_vip)) step_bad += r.count;
            // Both successor handler indices must name a table entry (an E9 thunk).
            for (std::uint16_t idx : {op.taken_index, op.fall_index}) {
                const bool ok = idx < kVmdHandlerCount &&
                                img.u8(img.u32(kVmdHandlerTable + 4u * idx) + img.pe.image_base) == 0xE9;
                if (!ok) ++idx_bad;
            }
            auto& st = per_code[r.cc];
            st.n += r.count;
            st.taken += r.taken ? r.count : 0;
            st.flags.insert(r.flags);
        }
        std::printf("recorded vmd_078 executions   %llu at %zu distinct VIPs\n", static_cast<unsigned long long>(total),
                    vips.size());
        std::printf("operand decode (code, slot)   %llu mismatches\n", static_cast<unsigned long long>(op_bad));
        std::printf("successor VIPs (both arms)    %llu mismatches\n", static_cast<unsigned long long>(succ_bad));
        std::printf("taken outcome vs handler      %llu mismatches\n", static_cast<unsigned long long>(pred_bad));
        std::printf("successor handler indices     %llu outside the 498-entry table\n\n",
                    static_cast<unsigned long long>(idx_bad));

        std::printf("code  x86   predicate          executions    taken  flag words  source\n");
        for (const auto& c : kConditionMap) {
            const auto it = per_code.find(c.code);
            if (it != per_code.end())
                std::printf("0x%02X  %-4s  %-17s  %10llu  %7llu  %10zu  trace + disassembly\n", c.code, c.x86,
                            c.predicate, static_cast<unsigned long long>(it->second.n),
                            static_cast<unsigned long long>(it->second.taken), it->second.flags.size());
            else
                std::printf("0x%02X  %-4s  %-17s  %10s  %7s  %10s  disassembly only\n", c.code, c.x86, c.predicate,
                            "-", "-", "-");
        }
        const bool ok = map_bad == 0 && op_bad == 0 && succ_bad == 0 && step_bad == 0 && pred_bad == 0 && idx_bad == 0;
        std::printf("\nresult  %s\n", ok ? "0 mismatches" : "MISMATCHES");
        return ok ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 2;
    }
}
