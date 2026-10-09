#include "Common.h"

#include <shlobj.h>

namespace hm
{
    std::string W2U(const std::wstring& w)
    {
        if (w.empty()) return {};
        int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        std::string s(n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
        return s;
    }

    std::wstring U2W(const std::string& s)
    {
        if (s.empty()) return {};
        int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
        std::wstring w(n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
        return w;
    }

    std::wstring Lower(std::wstring s)
    {
        for (auto& c : s) c = (wchar_t)towlower(c);
        return s;
    }

    std::string LowerA(std::string s)
    {
        for (auto& c : s) c = (char)tolower((unsigned char)c);
        return s;
    }

    bool IEquals(const std::wstring& a, const std::wstring& b)
    {
        return a.size() == b.size() && _wcsicmp(a.c_str(), b.c_str()) == 0;
    }

    bool IStartsWith(const std::wstring& s, const std::wstring& prefix)
    {
        return s.size() >= prefix.size() && _wcsnicmp(s.c_str(), prefix.c_str(), prefix.size()) == 0;
    }

    size_t IFind(const std::wstring& s, const std::wstring& needle, size_t from)
    {
        return Lower(s).find(Lower(needle), from);
    }

    bool IContains(const std::wstring& s, const std::wstring& needle)
    {
        return IFind(s, needle) != std::wstring::npos;
    }

    static bool GlobImpl(const wchar_t* p, const wchar_t* t)
    {
        while (*p) {
            if (*p == L'*') {
                while (*p == L'*') ++p;
                if (!*p) return true;
                for (; *t; ++t)
                    if (GlobImpl(p, t)) return true;
                return false;
            }
            if (!*t) return false;
            if (*p != L'?' && towlower(*p) != towlower(*t)) return false;
            ++p;
            ++t;
        }
        return *t == 0;
    }

    bool GlobMatch(const std::wstring& pattern, const std::wstring& text)
    {
        return GlobImpl(pattern.c_str(), text.c_str());
    }

    std::string Hex(uint64_t v)
    {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)v);
        return buf;
    }

    std::string Hex8(uint32_t v)
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "%08X", v);
        return buf;
    }

    std::string HexBytes(const uint8_t* p, size_t n, size_t maxBytes)
    {
        std::string s;
        size_t m = std::min(n, maxBytes);
        char buf[4];
        for (size_t i = 0; i < m; ++i) {
            snprintf(buf, sizeof(buf), "%02X", p[i]);
            if (i) s += ' ';
            s += buf;
        }
        if (n > m) s += " …";
        return s;
    }

    std::string Trim(const std::string& s)
    {
        size_t a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) return {};
        size_t b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    }

    std::wstring FileNameOf(const std::wstring& path)
    {
        size_t p = path.find_last_of(L"\\/");
        return p == std::wstring::npos ? path : path.substr(p + 1);
    }

    std::wstring DirOf(const std::wstring& path)
    {
        size_t p = path.find_last_of(L"\\/");
        return p == std::wstring::npos ? std::wstring() : path.substr(0, p);
    }

    bool FileExists(const std::wstring& path)
    {
        DWORD a = GetFileAttributesW(path.c_str());
        return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
    }

    bool DirExists(const std::wstring& path)
    {
        DWORD a = GetFileAttributesW(path.c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
    }

    bool ReadFileBytes(const std::wstring& path, std::vector<uint8_t>& out)
    {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz) || sz.QuadPart > (1LL << 31)) {
            CloseHandle(h);
            return false;
        }
        out.resize((size_t)sz.QuadPart);
        size_t done = 0;
        while (done < out.size()) {
            DWORD chunk = (DWORD)std::min<size_t>(out.size() - done, 1u << 24);
            DWORD got = 0;
            if (!ReadFile(h, out.data() + done, chunk, &got, nullptr) || got == 0) break;
            done += got;
        }
        CloseHandle(h);
        out.resize(done);
        return done == (size_t)sz.QuadPart;
    }

    bool ReadFileText(const std::wstring& path, std::string& out)
    {
        std::vector<uint8_t> b;
        if (!ReadFileBytes(path, b)) return false;
        out.assign(b.begin(), b.end());
        return true;
    }

    bool WriteFileText(const std::wstring& path, const std::string& text)
    {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD wrote = 0;
        BOOL ok = WriteFile(h, text.data(), (DWORD)text.size(), &wrote, nullptr);
        CloseHandle(h);
        return ok && wrote == text.size();
    }

    std::optional<FILETIME> FileWriteTime(const std::wstring& path)
    {
        WIN32_FILE_ATTRIBUTE_DATA d{};
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &d)) return std::nullopt;
        return d.ftLastWriteTime;
    }

    std::string NowLocalString()
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buf[64];
        snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }

    std::string NowFileStamp()
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buf[64];
        snprintf(buf, sizeof(buf), "%04u-%02u-%02u_%02u%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        return buf;
    }

    std::string FileTimeToLocalString(const FILETIME& ft)
    {
        FILETIME lft;
        SYSTEMTIME st;
        if (!FileTimeToLocalFileTime(&ft, &lft) || !FileTimeToSystemTime(&lft, &st)) return "?";
        char buf[64];
        snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
        return buf;
    }

    std::string UnixToUtcString(uint32_t t)
    {
        time_t tt = (time_t)t;
        struct tm g{};
        if (gmtime_s(&g, &tt) != 0) return "?";
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M UTC", &g);
        return buf;
    }

    std::wstring SelfExePath()
    {
        wchar_t buf[MAX_PATH * 4];
        DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)std::size(buf));
        return std::wstring(buf, n);
    }

    std::wstring WindowsDir()
    {
        wchar_t buf[MAX_PATH];
        UINT n = GetWindowsDirectoryW(buf, MAX_PATH);
        return std::wstring(buf, n);
    }

    std::wstring DocumentsDir()
    {
        wchar_t buf[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, buf))) return buf;
        return {};
    }

    std::wstring UserName()
    {
        wchar_t buf[256];
        DWORD n = 256;
        if (GetUserNameW(buf, &n)) return std::wstring(buf);
        return {};
    }

    std::wstring ComputerName()
    {
        wchar_t buf[256];
        DWORD n = 256;
        if (GetComputerNameW(buf, &n)) return std::wstring(buf, n);
        return {};
    }

    std::wstring EnvVar(const wchar_t* name)
    {
        wchar_t buf[4096];
        DWORD n = GetEnvironmentVariableW(name, buf, 4096);
        if (n == 0 || n >= 4096) return {};
        return std::wstring(buf, n);
    }
}
