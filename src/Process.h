#pragma once
#include "Common.h"

namespace hm
{
    struct ModuleEntry
    {
        std::wstring name;      // SkyrimSE.exe, Foo.dll
        std::wstring path;      // path as the loader recorded it (may be an MO2 virtual path)
        std::wstring physPath;  // real file backing the mapping (GetMappedFileName)
        uint64_t     base = 0;
        uint32_t     size = 0;
    };

    struct MemRegion
    {
        uint64_t base = 0;
        uint64_t size = 0;
        DWORD    protect = 0;
        std::vector<uint8_t> bytes;  // filled for regions we read
    };

    class RemoteProcess
    {
    public:
        ~RemoteProcess();

        bool Open(DWORD pid, DWORD& lastError);
        DWORD Pid() const { return pid_; }

        std::vector<ModuleEntry> Modules() const;

        bool Read(uint64_t addr, void* buf, size_t n) const;
        bool ReadQword(uint64_t addr, uint64_t& out) const { return Read(addr, &out, 8); }

        // Reads a whole module image; unreadable pages are left as zero and flagged in `readable`.
        std::vector<uint8_t> ReadImage(uint64_t base, uint32_t size, std::vector<bool>& readablePages) const;

        // Private (non-image) committed executable memory: trampolines, xbyak thunks, overlay stubs.
        std::vector<MemRegion> PrivateExecRegions(size_t maxRegionBytes) const;

        std::optional<FILETIME> CreationTime() const;

    private:
        HANDLE h_ = nullptr;
        DWORD  pid_ = 0;
    };

    struct ProcInfo
    {
        DWORD        pid;
        std::wstring exe;
    };

    std::vector<ProcInfo> FindProcesses(const std::vector<std::wstring>& exeNames);
    std::wstring DevicePathToDos(const std::wstring& devicePath);
    bool IsElevated();
}
