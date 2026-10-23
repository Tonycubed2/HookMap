#pragma once
#include "Common.h"

namespace hm
{
    enum class BrKind
    {
        None,
        Call,       // E8 rel32
        Jmp,        // E9 rel32 / EB rel8
        Jcc,        // 0F 8x rel32 / 7x rel8
        CallInd,    // FF 15 [rip+disp32]
        JmpInd,     // FF 25 [rip+disp32]
        AbsJmp,     // mov rax/r11, imm64 ; jmp reg   (or push/ret forms)
        AbsCall,    // mov rax/r11, imm64 ; call reg
    };

    struct Branch
    {
        BrKind   kind = BrKind::None;
        int      len = 0;
        uint64_t target = 0;  // resolved target for direct forms
        uint64_t slot = 0;    // pointer slot address for FF 15 / FF 25
        bool IsBranch() const { return kind != BrKind::None; }
        bool IsIndirect() const { return kind == BrKind::CallInd || kind == BrKind::JmpInd; }
        bool IsJumpLike() const { return kind == BrKind::Jmp || kind == BrKind::JmpInd || kind == BrKind::AbsJmp; }
    };

    Branch DecodeBranch(const uint8_t* p, size_t avail, uint64_t addr);
    const char* BrKindName(BrKind k);

    // Length of a NOP / INT3 padding run at p (0 if p doesn't start with padding).
    size_t PaddingLen(const uint8_t* p, size_t avail);

    // ---- full x86-64 decoding (Zydis), used to show the instructions a patch touches

    // Start of the instruction that contains `rva`, found by decoding forward from `from` (a function start).
    // Returns `rva` when the bytes in between don't decode cleanly or `from` is too far back.
    uint32_t InsnBoundary(const uint8_t* image, size_t size, uint32_t from, uint32_t rva);

    // Decodes from `start` until the instructions cover [rva, rva + len). One line per instruction,
    // "+0x1234  call 0x7FF6AB001000" (targets as absolute addresses, using `base`).
    std::vector<std::string> DisasmCover(const uint8_t* image, size_t size, uint64_t base, uint32_t start, uint32_t rva,
        uint32_t len, size_t maxLines = 16);
}
