#include "PEImage.h"

namespace hm
{
    namespace
    {
        // Our own copy so we don't depend on SDK header versions.
        struct DelayDescriptor
        {
            uint32_t attributes;
            uint32_t dllNameRva;
            uint32_t moduleHandleRva;
            uint32_t iatRva;
            uint32_t intRva;
            uint32_t boundIatRva;
            uint32_t unloadIatRva;
            uint32_t timeDateStamp;
        };

        const IMAGE_NT_HEADERS64* NtHeaders(const uint8_t* data, size_t size, uint32_t* ntOff)
        {
            if (size < sizeof(IMAGE_DOS_HEADER)) return nullptr;
            auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
            uint32_t off = (uint32_t)dos->e_lfanew;
            if ((uint64_t)off + sizeof(IMAGE_NT_HEADERS64) > size) return nullptr;
            auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(data + off);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
            if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;
            if (ntOff) *ntOff = off;
            return nt;
        }
    }

    bool PEImage::Parse(const uint8_t* data, size_t size, uint64_t actualBase)
    {
        valid = false;
        data_ = data;
        size_ = size;
        base = actualBase;

        uint32_t ntOff = 0;
        auto nt = NtHeaders(data, size, &ntOff);
        if (!nt) return false;

        machine = nt->FileHeader.Machine;
        timeDateStamp = nt->FileHeader.TimeDateStamp;
        linkerMajor = nt->OptionalHeader.MajorLinkerVersion;
        linkerMinor = nt->OptionalHeader.MinorLinkerVersion;
        sizeOfImage = nt->OptionalHeader.SizeOfImage;
        preferredBase = nt->OptionalHeader.ImageBase;

        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if ((const uint8_t*)(sec + i + 1) > data + size) break;
            PESection s;
            char nm[9]{};
            std::memcpy(nm, sec[i].Name, 8);
            s.name = nm;
            s.va = sec[i].VirtualAddress;
            s.vsize = sec[i].Misc.VirtualSize;
            s.rawSize = sec[i].SizeOfRawData;
            s.chars = sec[i].Characteristics;
            sections.push_back(s);
        }

        const auto& dd = nt->OptionalHeader.DataDirectory;
        auto numDirs = nt->OptionalHeader.NumberOfRvaAndSizes;
        auto dir = [&](unsigned i) -> IMAGE_DATA_DIRECTORY {
            if (i < numDirs) return dd[i];
            return IMAGE_DATA_DIRECTORY{};
        };

        ParseImports(dir(IMAGE_DIRECTORY_ENTRY_IMPORT));
        ParseDelayImports(dir(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
        ParseExports(dir(IMAGE_DIRECTORY_ENTRY_EXPORT));
        ParseDebug(dir(IMAGE_DIRECTORY_ENTRY_DEBUG));
        ParseLoadConfig(dir(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG));
        ParseRich(ntOff);

        auto iat = dir(IMAGE_DIRECTORY_ENTRY_IAT);
        if (iat.VirtualAddress && iat.Size) {
            loaderRanges.push_back({ iat.VirtualAddress, iat.VirtualAddress + iat.Size });
            iatRanges.push_back({ iat.VirtualAddress, iat.VirtualAddress + iat.Size });
        }

        valid = true;
        return true;
    }

    std::string PEImage::ReadCStr(uint32_t rva, size_t maxLen) const
    {
        std::string s;
        for (size_t i = 0; i < maxLen; ++i) {
            uint8_t c;
            if (!Read(rva + (uint32_t)i, c) || c == 0) break;
            s += (char)c;
        }
        return s;
    }

    const PESection* PEImage::SectionAt(uint32_t rva) const
    {
        for (auto& s : sections)
            if (rva >= s.va && rva < s.va + s.Size()) return &s;
        return nullptr;
    }

    bool PEImage::IsLoaderWritten(uint32_t rva) const
    {
        for (auto& r : loaderRanges)
            if (rva >= r.first && rva < r.second) return true;
        return false;
    }

    const PEExport* PEImage::NearestExport(uint32_t rva) const
    {
        const PEExport* best = nullptr;
        for (auto& e : exports) {
            if (e.rva <= rva) best = &e;
            else break;
        }
        return best;
    }

    uint32_t PEImage::ExportRva(const std::string& name) const
    {
        for (auto& e : exports)
            if (e.name == name) return e.rva;
        return 0;
    }

    void PEImage::ParseImports(const IMAGE_DATA_DIRECTORY& dir)
    {
        if (!dir.VirtualAddress) return;
        for (uint32_t off = dir.VirtualAddress;; off += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            IMAGE_IMPORT_DESCRIPTOR d{};
            if (!Read(off, d)) break;
            if (!d.Name && !d.FirstThunk) break;
            PEImportDll dll;
            dll.dll = ReadCStr(d.Name, 260);
            uint32_t nameTable = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
            for (uint32_t i = 0; i < 65536; ++i) {
                uint64_t entry = 0;
                if (!Read(nameTable + i * 8, entry) || entry == 0) break;
                PEImportFunc f;
                f.iatRva = d.FirstThunk + i * 8;
                if (entry & IMAGE_ORDINAL_FLAG64) {
                    f.ordinal = (uint16_t)(entry & 0xFFFF);
                } else if (d.OriginalFirstThunk) {
                    f.name = ReadCStr((uint32_t)entry + 2, 256);
                }
                dll.funcs.push_back(std::move(f));
            }
            imports.push_back(std::move(dll));
            if (imports.size() > 4096) break;
        }
    }

    void PEImage::ParseDelayImports(const IMAGE_DATA_DIRECTORY& dir)
    {
        if (!dir.VirtualAddress) return;
        for (uint32_t off = dir.VirtualAddress;; off += sizeof(DelayDescriptor)) {
            DelayDescriptor d{};
            if (!Read(off, d)) break;
            if (!d.dllNameRva) break;
            bool rvaBased = (d.attributes & 1) != 0;
            auto toRva = [&](uint32_t v) -> uint32_t { return rvaBased ? v : (uint32_t)(v - (uint32_t)preferredBase); };
            PEImportDll dll;
            dll.delay = true;
            dll.dll = ReadCStr(toRva(d.dllNameRva), 260);
            uint32_t intRva = toRva(d.intRva);
            uint32_t iatRva = toRva(d.iatRva);
            uint32_t count = 0;
            for (uint32_t i = 0; i < 65536; ++i) {
                uint64_t entry = 0;
                if (!Read(intRva + i * 8, entry) || entry == 0) break;
                PEImportFunc f;
                f.iatRva = iatRva + i * 8;
                if (entry & IMAGE_ORDINAL_FLAG64) f.ordinal = (uint16_t)(entry & 0xFFFF);
                else f.name = ReadCStr(toRva((uint32_t)entry) + 2, 256);
                dll.funcs.push_back(std::move(f));
                ++count;
            }
            if (count) loaderRanges.push_back({ iatRva, iatRva + count * 8 });
            imports.push_back(std::move(dll));
            if (imports.size() > 4096) break;
        }
    }

    void PEImage::ParseExports(const IMAGE_DATA_DIRECTORY& dir)
    {
        if (!dir.VirtualAddress) return;
        IMAGE_EXPORT_DIRECTORY ed{};
        if (!Read(dir.VirtualAddress, ed)) return;
        if (ed.NumberOfNames > 200000) return;
        for (uint32_t i = 0; i < ed.NumberOfNames; ++i) {
            uint32_t nameRva = 0;
            uint16_t ordIndex = 0;
            if (!Read(ed.AddressOfNames + i * 4, nameRva)) break;
            if (!Read(ed.AddressOfNameOrdinals + i * 2, ordIndex)) break;
            uint32_t fnRva = 0;
            if (!Read(ed.AddressOfFunctions + ordIndex * 4u, fnRva)) continue;
            // forwarded exports point back inside the export directory
            if (fnRva >= dir.VirtualAddress && fnRva < dir.VirtualAddress + dir.Size) continue;
            exports.push_back({ ReadCStr(nameRva, 256), fnRva });
        }
        std::sort(exports.begin(), exports.end(), [](const PEExport& a, const PEExport& b) { return a.rva < b.rva; });
    }

    void PEImage::ParseDebug(const IMAGE_DATA_DIRECTORY& dir)
    {
        if (!dir.VirtualAddress) return;
        uint32_t n = dir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (uint32_t i = 0; i < n && i < 64; ++i) {
            IMAGE_DEBUG_DIRECTORY d{};
            if (!Read(dir.VirtualAddress + i * (uint32_t)sizeof(d), d)) break;
            if (d.Type == 16) repro = true;  // IMAGE_DEBUG_TYPE_REPRO
            if (d.Type == IMAGE_DEBUG_TYPE_CODEVIEW && d.AddressOfRawData && d.SizeOfData > 24) {
                uint32_t sig = 0;
                if (Read(d.AddressOfRawData, sig) && sig == 0x53445352)  // 'RSDS'
                    pdbPath = ReadCStr(d.AddressOfRawData + 24, 1024);
            }
        }
    }

    void PEImage::ParseLoadConfig(const IMAGE_DATA_DIRECTORY& dir)
    {
        if (!dir.VirtualAddress) return;
        uint32_t lcSize = 0;
        if (!Read(dir.VirtualAddress, lcSize)) return;
        // Offsets of pointer fields in IMAGE_LOAD_CONFIG_DIRECTORY64 that the loader fills in at runtime.
        static const uint32_t kPtrFields[] = { 112, 120, 216, 232, 280, 288, 296, 312 };
        for (uint32_t f : kPtrFields) {
            if (f + 8 > lcSize) continue;
            uint64_t va = 0;
            if (!Read(dir.VirtualAddress + f, va) || va == 0) continue;
            uint64_t rva = va - base;
            if (rva < sizeOfImage) loaderRanges.push_back({ (uint32_t)rva, (uint32_t)rva + 8 });
        }
    }

    void PEImage::ParseRich(uint32_t ntOff)
    {
        if (ntOff < 0x90 || ntOff > size_) return;
        for (uint32_t pos = 0x80; pos + 8 <= ntOff; pos += 4) {
            uint32_t v = 0;
            Read(pos, v);
            if (v != 0x68636952) continue;  // 'Rich'
            uint32_t key = 0;
            Read(pos + 4, key);
            int32_t p = (int32_t)pos - 4;
            int32_t start = -1;
            while (p >= 0x80) {
                uint32_t x = 0;
                Read((uint32_t)p, x);
                if ((x ^ key) == 0x536E6144) {  // 'DanS'
                    start = p;
                    break;
                }
                p -= 4;
            }
            if (start < 0) return;
            for (uint32_t q = (uint32_t)start + 16; q + 8 <= pos; q += 8) {
                uint32_t compId = 0, count = 0;
                Read(q, compId);
                Read(q + 4, count);
                compId ^= key;
                count ^= key;
                RichEntry e;
                e.prodId = (uint16_t)(compId >> 16);
                e.build = (uint16_t)(compId & 0xFFFF);
                e.count = count;
                rich.push_back(e);
            }
            return;
        }
    }

    bool LoadFileAsImage(const std::wstring& path, uint64_t actualBase, std::vector<uint8_t>& out, std::string& err)
    {
        std::vector<uint8_t> file;
        if (!ReadFileBytes(path, file)) {
            err = "cannot read file from disk";
            return false;
        }
        uint32_t ntOff = 0;
        auto nt = NtHeaders(file.data(), file.size(), &ntOff);
        if (!nt) {
            err = "not a 64-bit PE file";
            return false;
        }
        uint32_t soi = nt->OptionalHeader.SizeOfImage;
        if (soi == 0 || soi > (1u << 30)) {
            err = "bad SizeOfImage";
            return false;
        }
        out.assign(soi, 0);
        uint32_t hdr = std::min<uint32_t>(nt->OptionalHeader.SizeOfHeaders, (uint32_t)file.size());
        std::memcpy(out.data(), file.data(), std::min<uint32_t>(hdr, soi));

        auto sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            uint32_t va = sec[i].VirtualAddress;
            uint32_t raw = sec[i].PointerToRawData;
            uint32_t n = sec[i].SizeOfRawData;
            if (sec[i].Misc.VirtualSize) n = std::min<uint32_t>(n, (uint32_t)sec[i].Misc.VirtualSize);
            if (raw >= file.size() || va >= soi) continue;
            n = std::min<uint32_t>(n, (uint32_t)(file.size() - raw));
            n = std::min<uint32_t>(n, soi - va);
            std::memcpy(out.data() + va, file.data() + raw, n);
        }

        // Base relocations
        uint64_t delta = actualBase - nt->OptionalHeader.ImageBase;
        auto& rd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (delta && rd.VirtualAddress && rd.Size && !(nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
            uint32_t off = rd.VirtualAddress, end = rd.VirtualAddress + rd.Size;
            while (off + 8 <= end && off + 8 <= soi) {
                uint32_t pageRva = 0, blockSize = 0;
                std::memcpy(&pageRva, out.data() + off, 4);
                std::memcpy(&blockSize, out.data() + off + 4, 4);
                if (blockSize < 8) break;
                uint32_t count = (blockSize - 8) / 2;
                for (uint32_t i = 0; i < count; ++i) {
                    uint16_t e = 0;
                    if (off + 8 + i * 2 + 2 > soi) break;
                    std::memcpy(&e, out.data() + off + 8 + i * 2, 2);
                    uint32_t type = e >> 12, rva = pageRva + (e & 0xFFF);
                    if (type == IMAGE_REL_BASED_DIR64 && rva + 8 <= soi) {
                        uint64_t v;
                        std::memcpy(&v, out.data() + rva, 8);
                        v += delta;
                        std::memcpy(out.data() + rva, &v, 8);
                    } else if (type == IMAGE_REL_BASED_HIGHLOW && rva + 4 <= soi) {
                        uint32_t v;
                        std::memcpy(&v, out.data() + rva, 4);
                        v += (uint32_t)delta;
                        std::memcpy(out.data() + rva, &v, 4);
                    }
                }
                off += blockSize;
            }
        }
        // The loader rewrites ImageBase in the in-memory header; mirror that so headers compare equal.
        auto ntOut = reinterpret_cast<IMAGE_NT_HEADERS64*>(out.data() + ntOff);
        ntOut->OptionalHeader.ImageBase = actualBase;
        return true;
    }

    std::string ToolsetFromBuild(uint16_t b)
    {
        if (b == 0) return "unknown";
        if (b < 23026) return "pre-VS2015 MSVC";
        if (b < 25017) return "VS2015 (v140)";
        if (b < 27508) return "VS2017 (v141)";
        if (b < 30705) return "VS2019 (v142)";
        if (b < 35700) {
            static const struct { uint16_t build; const char* ver; } kTable[] = {
                { 35207, "17.14" }, { 34808, "17.13" }, { 34433, "17.12" }, { 34120, "17.11" }, { 33808, "17.10" },
                { 33519, "17.9" }, { 33130, "17.8" }, { 32822, "17.7" }, { 32532, "17.6" }, { 32215, "17.5" },
                { 31933, "17.4" }, { 31629, "17.3" }, { 31332, "17.2" }, { 31104, "17.1" }, { 30705, "17.0" },
            };
            for (auto& e : kTable)
                if (b >= e.build) return std::string("VS2022 ≈") + e.ver + " (v143)";
            return "VS2022 (v143)";
        }
        return "VS2026 or newer (v145+)";
    }
}
