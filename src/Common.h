#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 2
#endif

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace hm
{
    inline constexpr const char* kToolName = "HookMap";
    inline constexpr const char* kToolVersion = "1.4.1";

    std::string  W2U(const std::wstring& w);
    std::wstring U2W(const std::string& s);

    std::wstring Lower(std::wstring s);
    std::string  LowerA(std::string s);

    bool IEquals(const std::wstring& a, const std::wstring& b);
    bool IStartsWith(const std::wstring& s, const std::wstring& prefix);
    bool IContains(const std::wstring& s, const std::wstring& needle);
    size_t IFind(const std::wstring& s, const std::wstring& needle, size_t from = 0);

    bool GlobMatch(const std::wstring& pattern, const std::wstring& text);  // case-insensitive, * and ?

    std::string Hex(uint64_t v);
    std::string Hex8(uint32_t v);
    std::string HexBytes(const uint8_t* p, size_t n, size_t maxBytes = 32);
    std::string Trim(const std::string& s);

    std::wstring FileNameOf(const std::wstring& path);
    std::wstring DirOf(const std::wstring& path);
    bool FileExists(const std::wstring& path);
    bool DirExists(const std::wstring& path);
    bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out);
    bool ReadFileText(const std::wstring& path, std::string& out);
    bool WriteFileText(const std::wstring& path, const std::string& text);
    std::optional<FILETIME> FileWriteTime(const std::wstring& path);

    std::string NowLocalString();      // 2026-10-08 19:20:31
    std::string NowFileStamp();        // 2026-10-08_1920
    std::string FileTimeToLocalString(const FILETIME& ft);
    std::string UnixToUtcString(uint32_t t);

    std::wstring SelfExePath();
    std::wstring WindowsDir();
    std::wstring DocumentsDir();
    std::wstring UserName();
    std::wstring ComputerName();
    std::wstring EnvVar(const wchar_t* name);

    template <class T>
    void SortUnique(std::vector<T>& v)
    {
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }

    template <class T>
    bool SortedContains(const std::vector<T>& v, const T& x)
    {
        return std::binary_search(v.begin(), v.end(), x);
    }

    // Any value in [lo, hi) present in a sorted vector?
    inline bool SortedAnyInRange(const std::vector<uint64_t>& v, uint64_t lo, uint64_t hi)
    {
        auto it = std::lower_bound(v.begin(), v.end(), lo);
        return it != v.end() && *it < hi;
    }
}
