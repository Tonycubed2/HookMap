#include "Process.h"

namespace hm
{
    RemoteProcess::~RemoteProcess()
    {
        if (h_) CloseHandle(h_);
    }

    bool RemoteProcess::Open(DWORD pid, DWORD& lastError)
    {
        h_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h_) {
            lastError = GetLastError();
            return false;
        }
        pid_ = pid;
        BOOL wow = FALSE;
        if (IsWow64Process(h_, &wow) && wow) {
            lastError = ERROR_NOT_SUPPORTED;
            CloseHandle(h_);
            h_ = nullptr;
            return false;
        }
        return true;
    }

    std::vector<ModuleEntry> RemoteProcess::Modules() const
    {
        std::vector<ModuleEntry> out;
        std::vector<HMODULE> mods(1024);
        DWORD needed = 0;
        for (int attempt = 0; attempt < 4; ++attempt) {
            if (!EnumProcessModulesEx(h_, mods.data(), (DWORD)(mods.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL))
                return out;
            if (needed <= mods.size() * sizeof(HMODULE)) break;
            mods.resize(needed / sizeof(HMODULE) + 64);
        }
        mods.resize(needed / sizeof(HMODULE));

        wchar_t buf[MAX_PATH * 4];
        for (auto m : mods) {
            ModuleEntry e;
            MODULEINFO mi{};
            if (!GetModuleInformation(h_, m, &mi, sizeof(mi))) continue;
            e.base = (uint64_t)mi.lpBaseOfDll;
            e.size = mi.SizeOfImage;
            DWORD n = GetModuleBaseNameW(h_, m, buf, (DWORD)std::size(buf));
            e.name.assign(buf, n);
            n = GetModuleFileNameExW(h_, m, buf, (DWORD)std::size(buf));
            e.path.assign(buf, n);
            n = GetMappedFileNameW(h_, (LPVOID)e.base, buf, (DWORD)std::size(buf));
            if (n) e.physPath = DevicePathToDos(std::wstring(buf, n));
            if (e.physPath.empty()) e.physPath = e.path;
            out.push_back(std::move(e));
        }
        return out;
    }

    bool RemoteProcess::Read(uint64_t addr, void* buf, size_t n) const
    {
        SIZE_T got = 0;
        return ReadProcessMemory(h_, (LPCVOID)addr, buf, n, &got) && got == n;
    }

    static bool Readable(DWORD prot)
    {
        if (prot & (PAGE_GUARD | PAGE_NOACCESS)) return false;
        return (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                           PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    std::vector<uint8_t> RemoteProcess::ReadImage(uint64_t base, uint32_t size, std::vector<bool>& readablePages) const
    {
        std::vector<uint8_t> img(size, 0);
        readablePages.assign((size + 0xFFF) / 0x1000, false);
        uint64_t addr = base, end = base + size;
        while (addr < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(h_, (LPCVOID)addr, &mbi, sizeof(mbi))) break;
            uint64_t rBase = (uint64_t)mbi.BaseAddress;
            uint64_t rEnd = std::min<uint64_t>(rBase + mbi.RegionSize, end);
            if (rEnd <= addr) break;
            if (mbi.State == MEM_COMMIT && Readable(mbi.Protect)) {
                uint64_t from = std::max(addr, rBase);
                SIZE_T got = 0;
                if (ReadProcessMemory(h_, (LPCVOID)from, img.data() + (from - base), (SIZE_T)(rEnd - from), &got) &&
                    got == rEnd - from) {
                    for (uint64_t p = from; p < rEnd; p += 0x1000) readablePages[(p - base) / 0x1000] = true;
                } else {
                    // fall back page by page
                    for (uint64_t p = from; p < rEnd; p += 0x1000) {
                        SIZE_T n = (SIZE_T)std::min<uint64_t>(0x1000, rEnd - p);
                        if (ReadProcessMemory(h_, (LPCVOID)p, img.data() + (p - base), n, &got) && got == n)
                            readablePages[(p - base) / 0x1000] = true;
                    }
                }
            }
            addr = rEnd;
        }
        return img;
    }

    std::vector<MemRegion> RemoteProcess::PrivateExecRegions(size_t maxRegionBytes) const
    {
        std::vector<MemRegion> out;
        uint64_t addr = 0x10000;
        const uint64_t kTop = 0x7FFFFFFF0000ull;
        while (addr < kTop) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(h_, (LPCVOID)addr, &mbi, sizeof(mbi))) break;
            uint64_t rBase = (uint64_t)mbi.BaseAddress;
            uint64_t rSize = mbi.RegionSize;
            if (rSize == 0) break;
            bool exec = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && exec && !(mbi.Protect & PAGE_GUARD) &&
                rSize <= maxRegionBytes && Readable(mbi.Protect)) {
                MemRegion r;
                r.base = rBase;
                r.size = rSize;
                r.protect = mbi.Protect;
                r.bytes.resize((size_t)rSize);
                SIZE_T got = 0;
                if (ReadProcessMemory(h_, (LPCVOID)rBase, r.bytes.data(), (SIZE_T)rSize, &got) && got == rSize)
                    out.push_back(std::move(r));
            }
            addr = rBase + rSize;
        }
        return out;
    }

    std::optional<FILETIME> RemoteProcess::CreationTime() const
    {
        FILETIME c, e, k, u;
        if (GetProcessTimes(h_, &c, &e, &k, &u)) return c;
        return std::nullopt;
    }

    std::vector<ProcInfo> FindProcesses(const std::vector<std::wstring>& exeNames)
    {
        std::vector<ProcInfo> out;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return out;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                for (auto& n : exeNames)
                    if (IEquals(pe.szExeFile, n)) out.push_back({ pe.th32ProcessID, pe.szExeFile });
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return out;
    }

    std::wstring DevicePathToDos(const std::wstring& devicePath)
    {
        wchar_t drives[512];
        DWORD n = GetLogicalDriveStringsW(511, drives);
        for (wchar_t* d = drives; d < drives + n && *d; d += wcslen(d) + 1) {
            std::wstring letter(d, 2);  // "C:"
            wchar_t target[1024];
            if (!QueryDosDeviceW(letter.c_str(), target, 1024)) continue;
            std::wstring dev = target;
            if (IStartsWith(devicePath, dev) && devicePath.size() > dev.size() && devicePath[dev.size()] == L'\\')
                return letter + devicePath.substr(dev.size());
        }
        return {};
    }

    bool IsElevated()
    {
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
        TOKEN_ELEVATION el{};
        DWORD sz = 0;
        BOOL ok = GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &sz);
        CloseHandle(tok);
        return ok && el.TokenIsElevated;
    }
}
