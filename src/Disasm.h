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
}
