#pragma once
#include "Common.h"

namespace hm
{
    // Steam's DRM wrapper (SteamStub variant 3.1, x64) encrypts SkyrimSE.exe's code section on disk and decrypts it
    // in memory at startup. To compare the running code against a clean copy we undo that here.
    //
    // The result is self-checked by the caller against the running process, so a wrong guess about the format
    // can only make HookMap fall back to its baseline-free scan, never produce a bogus report.
    struct SteamStubResult
    {
        bool        wrapped = false;     // a SteamStub header was found
        bool        encrypted = false;   // the code section is encrypted
        uint32_t    codeRva = 0;         // where the decrypted code belongs
        uint32_t    codeRawSize = 0;     // size of the code section in the file
        std::string note;                // human-readable status
        std::vector<std::vector<uint8_t>> plaintexts;  // candidate decryptions (stolen block + section)
    };

    SteamStubResult DecryptSteamStub(const std::vector<uint8_t>& file);
}
