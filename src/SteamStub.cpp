#include "SteamStub.h"

#include "PEImage.h"

#include <bcrypt.h>

namespace hm
{
    namespace
    {
        constexpr uint32_t kHeaderSize = 0xF0;
        constexpr uint32_t kSignature = 0xC0DEC0DF;
        constexpr uint32_t kFlagNoEncryption = 0x04;

        // SteamStub 3.1 x64 header field offsets (after XOR decoding).
        constexpr size_t kOffSignature = 4;
        constexpr size_t kOffFlags = 60;
        constexpr size_t kOffCodeVa = 72;
        constexpr size_t kOffCodeSize = 80;
        constexpr size_t kOffAesKey = 88;   // 32 bytes
        constexpr size_t kOffAesIv = 120;   // 16 bytes
        constexpr size_t kOffStolen = 136;  // 16 bytes

        uint32_t U32(const uint8_t* p)
        {
            uint32_t v;
            std::memcpy(&v, p, 4);
            return v;
        }
        uint64_t U64(const uint8_t* p)
        {
            uint64_t v;
            std::memcpy(&v, p, 8);
            return v;
        }

        // Rolling XOR: the first dword is the key; each decoded dword's ciphertext becomes the next key.
        void SteamXor(uint8_t* data, uint32_t size)
        {
            uint32_t key = U32(data);
            for (uint32_t x = 4; x + 4 <= size; x += 4) {
                uint32_t val = U32(data + x);
                uint32_t plain = val ^ key;
                std::memcpy(data + x, &plain, 4);
                key = val;
            }
        }

        bool AesDecrypt(const uint8_t key[32], const wchar_t* mode, uint8_t* iv, const uint8_t* in, size_t n, std::vector<uint8_t>& out)
        {
            BCRYPT_ALG_HANDLE alg = nullptr;
            BCRYPT_KEY_HANDLE hk = nullptr;
            bool ok = false;
            if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return false;
            if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)mode, (ULONG)((wcslen(mode) + 1) * sizeof(wchar_t)), 0) == 0 &&
                BCryptGenerateSymmetricKey(alg, &hk, nullptr, 0, (PUCHAR)key, 32, 0) == 0) {
                out.assign(n, 0);
                ULONG got = 0;
                std::vector<uint8_t> ivCopy;
                if (iv) ivCopy.assign(iv, iv + 16);
                ok = BCryptDecrypt(hk, (PUCHAR)in, (ULONG)n, nullptr, iv ? ivCopy.data() : nullptr, iv ? 16 : 0, out.data(),
                         (ULONG)n, &got, 0) == 0 &&
                     got == n;
            }
            if (hk) BCryptDestroyKey(hk);
            BCryptCloseAlgorithmProvider(alg, 0);
            return ok;
        }
    }

    SteamStubResult DecryptSteamStub(const std::vector<uint8_t>& file)
    {
        SteamStubResult r;
        if (file.size() < 0x400) return r;
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || (uint64_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > file.size()) return r;
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return r;

        uint32_t ep = nt->OptionalHeader.AddressOfEntryPoint;
        uint32_t epOff = RvaToFileOffset(file, ep);
        if (epOff < kHeaderSize) return r;

        std::vector<uint8_t> hdr(file.begin() + (epOff - kHeaderSize), file.begin() + epOff);
        SteamXor(hdr.data(), kHeaderSize);
        if (U32(hdr.data() + kOffSignature) != kSignature) {
            r.note = "no SteamStub 3.1 header at the entry point";
            return r;
        }
        r.wrapped = true;
        uint32_t flags = U32(hdr.data() + kOffFlags);
        if (flags & kFlagNoEncryption) {
            r.note = "SteamStub present, code not encrypted";
            return r;
        }
        r.encrypted = true;

        // Find the code section: prefer the header's address, fall back to the first executable section.
        uint64_t hdrCodeVa = U64(hdr.data() + kOffCodeVa);
        uint64_t hdrCodeSize = U64(hdr.data() + kOffCodeSize);
        auto sec = IMAGE_FIRST_SECTION(nt);
        const IMAGE_SECTION_HEADER* code = nullptr;
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
            if (sec[i].VirtualAddress == hdrCodeVa || sec[i].VirtualAddress == hdrCodeVa - nt->OptionalHeader.ImageBase) code = &sec[i];
        if (!code)
            for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i)
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    code = &sec[i];
                    break;
                }
        if (!code || code->PointerToRawData >= file.size()) {
            r.note = "SteamStub code section not found";
            return r;
        }
        r.codeRva = code->VirtualAddress;
        r.codeRawSize = code->SizeOfRawData;
        size_t raw = std::min<size_t>(code->SizeOfRawData, file.size() - code->PointerToRawData);
        if (hdrCodeSize && hdrCodeSize < raw) raw = (size_t)hdrCodeSize;
        raw &= ~(size_t)15;

        // Ciphertext = 16 stolen bytes (kept in the header) followed by the section data.
        std::vector<uint8_t> cipher(16 + raw);
        std::memcpy(cipher.data(), hdr.data() + kOffStolen, 16);
        std::memcpy(cipher.data() + 16, file.data() + code->PointerToRawData, raw);

        uint8_t key[32], iv[16];
        std::memcpy(key, hdr.data() + kOffAesKey, 32);
        std::memcpy(iv, hdr.data() + kOffAesIv, 16);

        // Two IV variants (the stub ECB-decrypts its IV first); only the first block differs between them.
        std::vector<uint8_t> ivEcb;
        if (AesDecrypt(key, BCRYPT_CHAIN_MODE_ECB, nullptr, iv, 16, ivEcb)) {
            std::vector<uint8_t> p;
            if (AesDecrypt(key, BCRYPT_CHAIN_MODE_CBC, ivEcb.data(), cipher.data(), cipher.size(), p)) r.plaintexts.push_back(std::move(p));
        }
        {
            std::vector<uint8_t> p;
            if (AesDecrypt(key, BCRYPT_CHAIN_MODE_CBC, iv, cipher.data(), cipher.size(), p)) r.plaintexts.push_back(std::move(p));
        }
        r.note = r.plaintexts.empty() ? "SteamStub found but AES decryption failed" : "SteamStub 3.1 decrypted";
        return r;
    }
}
