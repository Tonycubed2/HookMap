#pragma once
#include "Common.h"

namespace hm
{
    // Reader for Address Library .bin databases (format 1 = SE "version-*.bin", format 2 = AE "versionlib-*.bin").
    class AddressLib
    {
    public:
        bool Load(const std::wstring& path, std::string& err);
        bool Loaded() const { return !byOffset_.empty(); }

        struct Hit
        {
            uint64_t id;
            uint64_t delta;  // rva - offset(id)
        };
        // Nearest ID at or below rva.
        std::optional<Hit> Nearest(uint64_t rva) const;
        std::optional<uint64_t> OffsetOf(uint64_t id) const;

        std::wstring path;
        int          format = 0;
        int          version[4]{};
        size_t       Count() const { return byOffset_.size(); }

    private:
        std::vector<std::pair<uint64_t, uint64_t>> byOffset_;  // (offset, id) sorted by offset
        std::unordered_map<uint64_t, uint64_t>      idToOffset_;
    };

    // Function / vtable names harvested from CommonLibSSE-NG headers (RelocationID / VariantID usages).
    class NameDb
    {
    public:
        // se = true picks the SE (1.5.x) ID column instead of the AE one.
        bool LoadCommonLib(const std::wstring& root, bool se, std::string& err);
        void ResolveVtables(const AddressLib& lib);

        std::string NameOf(uint64_t id) const;
        // Vtable containing rva (within 0x800 bytes of its start): name + slot index.
        std::optional<std::pair<std::string, uint32_t>> VtableSlot(uint64_t rva) const;

        size_t       Count() const { return names_.size(); }
        size_t       VtableCount() const { return vtables_.size(); }
        std::wstring root;

    private:
        void ParseFile(const std::string& text, const std::string& fileStem);
        void Add(uint64_t id, const std::string& name, bool declared);
        bool se_ = false;

        std::unordered_map<uint64_t, std::pair<std::string, bool>> names_;  // id -> (name, declared)
        std::vector<std::pair<uint64_t, std::string>>              vtableIds_;
        std::vector<std::pair<uint64_t, std::string>>              vtables_;  // (rva, name) sorted
    };
}
