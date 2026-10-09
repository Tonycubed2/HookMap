#include "Disasm.h"

namespace hm
{
    static int32_t Rd32(const uint8_t* p)
    {
        int32_t v;
        std::memcpy(&v, p, 4);
        return v;
    }
    static uint64_t Rd64(const uint8_t* p)
    {
        uint64_t v;
        std::memcpy(&v, p, 8);
        return v;
    }

    Branch DecodeBranch(const uint8_t* p, size_t n, uint64_t addr)
    {
        Branch b;
        if (n < 2) return b;

        switch (p[0]) {
        case 0xE8:
            if (n >= 5) b = { BrKind::Call, 5, addr + 5 + (int64_t)Rd32(p + 1), 0 };
            return b;
        case 0xE9:
            if (n >= 5) b = { BrKind::Jmp, 5, addr + 5 + (int64_t)Rd32(p + 1), 0 };
            return b;
        case 0xEB:
            b = { BrKind::Jmp, 2, addr + 2 + (int64_t)(int8_t)p[1], 0 };
            return b;
        case 0xFF:
            if (n >= 6 && p[1] == 0x15) b = { BrKind::CallInd, 6, 0, addr + 6 + (int64_t)Rd32(p + 2) };
            else if (n >= 6 && p[1] == 0x25) b = { BrKind::JmpInd, 6, 0, addr + 6 + (int64_t)Rd32(p + 2) };
            return b;
        case 0x0F:
            if (n >= 6 && (p[1] & 0xF0) == 0x80) b = { BrKind::Jcc, 6, addr + 6 + (int64_t)Rd32(p + 2), 0 };
            return b;
        case 0x68:
            // push imm32 ; mov dword [rsp+4], imm32 ; ret
            if (n >= 14 && p[5] == 0xC7 && p[6] == 0x44 && p[7] == 0x24 && p[8] == 0x04 && p[13] == 0xC3) {
                uint64_t lo = (uint32_t)Rd32(p + 1), hi = (uint32_t)Rd32(p + 9);
                b = { BrKind::AbsJmp, 14, lo | (hi << 32), 0 };
            }
            return b;
        default:
            break;
        }

        if (p[0] >= 0x70 && p[0] <= 0x7F) {
            b = { BrKind::Jcc, 2, addr + 2 + (int64_t)(int8_t)p[1], 0 };
            return b;
        }

        // mov r64, imm64 followed by jmp/call/push+ret on the same register
        if (n >= 12 && (p[0] == 0x48 || p[0] == 0x49) && p[1] >= 0xB8 && p[1] <= 0xBF) {
            int reg = p[1] - 0xB8;
            uint64_t imm = Rd64(p + 2);
            const uint8_t* q = p + 10;
            size_t left = n - 10;
            if (p[0] == 0x48) {
                if (left >= 2 && q[0] == 0xFF && q[1] == 0xE0 + reg) return { BrKind::AbsJmp, 12, imm, 0 };
                if (left >= 2 && q[0] == 0xFF && q[1] == 0xD0 + reg) return { BrKind::AbsCall, 12, imm, 0 };
                if (left >= 2 && q[0] == 0x50 + reg && q[1] == 0xC3) return { BrKind::AbsJmp, 12, imm, 0 };
            } else {
                if (left >= 3 && q[0] == 0x41 && q[1] == 0xFF && q[2] == 0xE0 + reg) return { BrKind::AbsJmp, 13, imm, 0 };
                if (left >= 3 && q[0] == 0x41 && q[1] == 0xFF && q[2] == 0xD0 + reg) return { BrKind::AbsCall, 13, imm, 0 };
                if (left >= 3 && q[0] == 0x41 && q[1] == 0x50 + reg && q[2] == 0xC3) return { BrKind::AbsJmp, 13, imm, 0 };
            }
        }
        return b;
    }

    const char* BrKindName(BrKind k)
    {
        switch (k) {
        case BrKind::Call: return "call";
        case BrKind::Jmp: return "jmp";
        case BrKind::Jcc: return "jcc";
        case BrKind::CallInd: return "call [ptr]";
        case BrKind::JmpInd: return "jmp [ptr]";
        case BrKind::AbsJmp: return "abs jmp";
        case BrKind::AbsCall: return "abs call";
        default: return "none";
        }
    }

    size_t PaddingLen(const uint8_t* p, size_t n)
    {
        size_t i = 0;
        while (i < n) {
            if (p[i] == 0x90 || p[i] == 0xCC) {
                ++i;
                continue;
            }
            if (i + 1 < n && p[i] == 0x66 && p[i + 1] == 0x90) {
                i += 2;
                continue;
            }
            // 0F 1F /0 multi-byte NOPs (lengths 3..9 with optional 66 prefix)
            size_t pre = 0;
            while (i + pre < n && p[i + pre] == 0x66) ++pre;
            if (i + pre + 2 < n && p[i + pre] == 0x0F && p[i + pre + 1] == 0x1F) {
                uint8_t modrm = p[i + pre + 2];
                size_t len = pre + 3;
                uint8_t mod = modrm >> 6, rm = modrm & 7;
                if (mod != 3 && rm == 4) ++len;  // SIB
                if (mod == 1) len += 1;
                else if (mod == 2) len += 4;
                if (i + len > n) break;
                i += len;
                continue;
            }
            break;
        }
        return i;
    }
}
