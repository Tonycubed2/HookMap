#pragma once
#include "Common.h"

namespace hm
{
    struct PESection
    {
        std::string name;
        uint32_t    va = 0;
        uint32_t    vsize = 0;
        uint32_t    rawSize = 0;
        uint32_t    chars = 0;

        bool Exec() const { return (chars & IMAGE_SCN_MEM_EXECUTE) != 0; }
        bool Write() const { return (chars & IMAGE_SCN_MEM_WRITE) != 0; }
        bool InitData() const { return (chars & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0; }
        bool UninitData() const { return (chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0; }
        uint32_t Size() const { return vsize ? vsize : rawSize; }
    };

    struct PEImportFunc
    {
        std::string name;      // empty when imported by ordinal
        uint16_t    ordinal = 0;
        uint32_t    iatRva = 0;
    };

    struct PEImportDll
    {
        std::string               dll;
        bool                      delay = false;
        std::vector<PEImportFunc> funcs;
    };

    struct PEExport
    {
        std::string name;
        uint32_t    rva = 0;
    };

    struct RichEntry
    {
        uint16_t prodId = 0;
        uint16_t build = 0;
        uint32_t count = 0;
    };

    // A PE image laid out in memory layout (section data at its RVA).
    // Works for both an image read out of a process and a file mapped by LoadFileAsImage.
    class PEImage
    {
    public:
        bool Parse(const uint8_t* data, size_t size, uint64_t actualBase);

        bool        valid = false;
        uint64_t    base = 0;
        uint64_t    preferredBase = 0;
        uint32_t    sizeOfImage = 0;
        uint32_t    timeDateStamp = 0;
        uint8_t     linkerMajor = 0;
        uint8_t     linkerMinor = 0;
        uint16_t    machine = 0;
        bool        repro = false;
        std::string pdbPath;

        std::vector<PESection>   sections;
        std::vector<PEImportDll> imports;
        std::vector<PEExport>    exports;   // sorted by rva
        std::vector<RichEntry>   rich;

        // RVA ranges the Windows loader writes (IAT, CFG/XFG pointers...). Excluded from diffs.
        std::vector<std::pair<uint32_t, uint32_t>> loaderRanges;
        std::vector<std::pair<uint32_t, uint32_t>> iatRanges;

        const uint8_t* At(uint32_t rva, size_t n) const
        {
            if ((uint64_t)rva + n > size_) return nullptr;
            return data_ + rva;
        }
        template <class T>
        bool Read(uint32_t rva, T& out) const
        {
            auto p = At(rva, sizeof(T));
            if (!p) return false;
            std::memcpy(&out, p, sizeof(T));
            return true;
        }
        std::string ReadCStr(uint32_t rva, size_t maxLen = 512) const;

        const PESection* SectionAt(uint32_t rva) const;
        bool IsLoaderWritten(uint32_t rva) const;
        const PEExport* NearestExport(uint32_t rva) const;
        uint32_t ExportRva(const std::string& name) const;
        bool HasExport(const std::string& name) const { return ExportRva(name) != 0; }

        const uint8_t* data() const { return data_; }
        size_t size() const { return size_; }

    private:
        const uint8_t* data_ = nullptr;
        size_t         size_ = 0;

        void ParseImports(const IMAGE_DATA_DIRECTORY& dir);
        void ParseDelayImports(const IMAGE_DATA_DIRECTORY& dir);
        void ParseExports(const IMAGE_DATA_DIRECTORY& dir);
        void ParseDebug(const IMAGE_DATA_DIRECTORY& dir);
        void ParseLoadConfig(const IMAGE_DATA_DIRECTORY& dir);
        void ParseRich(uint32_t ntOffset);
    };

    // Reads a PE file from disk and lays it out the way the loader would, with base relocations applied.
    bool LoadFileAsImage(const std::wstring& path, uint64_t actualBase, std::vector<uint8_t>& out, std::string& err);
    bool LoadBytesAsImage(const std::vector<uint8_t>& file, uint64_t actualBase, std::vector<uint8_t>& out, std::string& err);

    // Function start addresses (RVAs) from the exception directory (.pdata), sorted.
    std::vector<uint32_t> FunctionStarts(const uint8_t* image, size_t size);

    // File offset of an RVA in a raw (on-disk layout) PE; 0 if not mapped.
    uint32_t RvaToFileOffset(const std::vector<uint8_t>& file, uint32_t rva);

    // MSVC toolset guess from a Rich header compiler build number.
    std::string ToolsetFromBuild(uint16_t build);
}
