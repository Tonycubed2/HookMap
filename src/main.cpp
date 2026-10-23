#include "Analyzer.h"
#include "Common.h"
#include "Health.h"
#include "Process.h"
#include "Report.h"

#include <shellapi.h>

using namespace hm;

namespace
{
    const char* kHelp =
        "HookMap %s - maps which DLLs hook what in a running Skyrim SE/AE, and where they collide.\n"
        "\n"
        "Usage:\n"
        "  HookMap.exe [options]                     scan the running SkyrimSE.exe or SkyrimVR.exe\n"
        "  HookMap.exe --diff OLD.json NEW.json      compare two earlier scans\n"
        "\n"
        "Options:\n"
        "  --pid N            scan this process id instead of finding the game\n"
        "  --wait             wait for the game to start, then scan\n"
        "  --addrlib PATH     Address Library .bin file, or the folder that holds it\n"
        "  --clib DIR         CommonLibSSE-NG folder for function/vtable names\n"
        "                     (default: CommonLibSSEPath_NG environment variable)\n"
        "  --clean-exe FILE   unencrypted copy of the running game exe to compare against\n"
        "                     (only needed if HookMap can't decrypt the Steam exe itself)\n"
        "  --mo2 DIR          MO2 instance folder (normally detected automatically)\n"
        "  --allowlist FILE   allowlist file (default: allowlist.txt next to HookMap.exe)\n"
        "  --out DIR          where to write the reports (default: next to HookMap.exe)\n"
        "  --share            make a shareable report (user name, PC name and personal folders removed)\n"
        "  --no-share         full report for your own use (skips the question)\n"
        "                     With neither option, HookMap asks before scanning.\n"
        "  --no-system        skip scanning Windows DLLs (ntdll, dxgi, d3d11, ...) for overlay hooks\n"
        "  --no-open          don't open the HTML report when done\n"
        "  --render FILE.json rebuild the HTML report from a saved JSON report\n"
        "  --help             this text\n"
        "\n"
        "Best results: run it with the game in a loaded save (some plugins only hook after a save loads).\n";

    bool StdinIsConsole()
    {
        DWORD mode = 0;
        return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
    }

    bool LaunchedByDoubleClick()
    {
        DWORD list[4];
        return GetConsoleProcessList(list, 4) <= 1;
    }

    void Pause(const Options& o)
    {
        if (o.pauseAtEnd || LaunchedByDoubleClick()) {
            printf("\nPress Enter to close...");
            (void)getchar();
        }
    }

    std::wstring QuoteArg(const std::wstring& a)
    {
        if (!a.empty() && a.find_first_of(L" \t\"") == std::wstring::npos) return a;
        std::wstring q = L"\"";
        for (wchar_t c : a) {
            if (c == L'"') q += L'\\';
            q += c;
        }
        return q + L"\"";
    }

    bool RelaunchElevated(const Options& o)
    {
        std::wstring params;
        for (auto& a : o.rawArgs) params += QuoteArg(a) + L" ";
        params += L"--elevated";
        std::wstring self = SelfExePath();
        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.lpVerb = L"runas";
        sei.lpFile = self.c_str();
        sei.lpParameters = params.c_str();
        sei.nShow = SW_SHOWNORMAL;
        return ShellExecuteExW(&sei) != FALSE;
    }

    std::wstring OutDir(const Options& o)
    {
        std::wstring d = o.outDir.empty() ? DirOf(SelfExePath()) : o.outDir;
        CreateDirectoryW(d.c_str(), nullptr);
        return d;
    }

    void OpenFile(const std::wstring& path)
    {
        ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    }

    int RunDiff(const Options& o)
    {
        Report a, b;
        std::string text, err;
        if (!ReadFileText(o.diffOld, text) || !FromJson(text, a, err)) {
            printf("Can't read %s: %s\n", W2U(o.diffOld).c_str(), err.empty() ? "file not readable" : err.c_str());
            return 2;
        }
        err.clear();
        if (!ReadFileText(o.diffNew, text) || !FromJson(text, b, err)) {
            printf("Can't read %s: %s\n", W2U(o.diffNew).c_str(), err.empty() ? "file not readable" : err.c_str());
            return 2;
        }
        std::string html = DiffHtml(a, b, W2U(FileNameOf(o.diffOld)), W2U(FileNameOf(o.diffNew)));
        std::wstring out = OutDir(o) + L"\\HookMap_Diff_" + U2W(NowFileStamp()) + L".html";
        if (!WriteFileText(out, html)) {
            printf("Can't write %s\n", W2U(out).c_str());
            return 3;
        }
        printf("Diff written: %s\n", W2U(out).c_str());
        if (!o.noOpen) OpenFile(out);
        return 0;
    }

    int RunRender(const std::wstring& jsonPath, const Options& o)
    {
        Report r;
        std::string text, err;
        if (!ReadFileText(jsonPath, text) || !FromJson(text, r, err)) {
            printf("Can't read %s: %s\n", W2U(jsonPath).c_str(), err.empty() ? "file not readable" : err.c_str());
            return 2;
        }
        std::wstring out = jsonPath;
        if (out.size() > 5 && IEquals(out.substr(out.size() - 5), L".json")) out.resize(out.size() - 5);
        out += L"_rendered.html";
        if (!WriteFileText(out, ToHtml(r))) {
            printf("Can't write %s\n", W2U(out).c_str());
            return 3;
        }
        printf("Report: %s\n", W2U(out).c_str());
        if (!o.noOpen) OpenFile(out);
        return 0;
    }

    int RunScan(const Options& o)
    {
        DWORD pid = o.pid;
        if (!pid) {
            const std::vector<std::wstring> kGames = { L"SkyrimSE.exe", L"SkyrimVR.exe" };
            auto found = FindProcesses(kGames);
            if (found.empty() && o.wait) {
                printf("Waiting for Skyrim (SkyrimSE.exe or SkyrimVR.exe) to start (Ctrl+C to cancel)...\n");
                while (found.empty()) {
                    Sleep(2000);
                    found = FindProcesses(kGames);
                }
                printf("Found it. Giving it 20 seconds to finish loading plugins...\n");
                Sleep(20000);
            }
            if (found.empty()) {
                printf("Skyrim (SkyrimSE.exe or SkyrimVR.exe) is not running. Start the game (ideally load a save), then run HookMap again,\n"
                       "or use --wait to have HookMap wait for it.\n");
                return 1;
            }
            if (found.size() > 1) printf("Several Skyrim processes found; scanning %s, PID %lu.\n", W2U(found.front().exe).c_str(), found.front().pid);
            pid = found.front().pid;
        }

        RemoteProcess proc;
        DWORD err = 0;
        if (!proc.Open(pid, err)) {
            if (err == ERROR_ACCESS_DENIED && !IsElevated()) {
                printf("Windows won't let HookMap read Skyrim — the game is probably running as administrator\n"
                       "(or through an elevated MO2). Relaunch HookMap as administrator? [Y/n] ");
                char line[16]{};
                if (!fgets(line, sizeof(line), stdin)) line[0] = 'y';
                if (line[0] != 'n' && line[0] != 'N') {
                    if (RelaunchElevated(o)) return 0;
                    printf("Relaunch was cancelled.\n");
                }
                return 1;
            }
            if (err == ERROR_NOT_SUPPORTED) printf("PID %lu is a 32-bit process; HookMap only reads 64-bit Skyrim SE/AE.\n", pid);
            else printf("Could not open PID %lu (Windows error %lu).\n", pid, err);
            return 1;
        }

        bool share = o.share;
        if (!o.share && !o.noShare && StdinIsConsole()) {
            printf("Make this report shareable? It removes your Windows user name, PC name and folder paths,\n"
                   "so it's safe to post or send to a mod author. [y/N] ");
            char line[16]{};
            if (fgets(line, sizeof(line), stdin)) share = (line[0] == 'y' || line[0] == 'Y');
            printf(share ? "OK, personal info will be removed.\n\n" : "OK, full report for your own use.\n\n");
        }

        printf("HookMap %s — scanning PID %lu\n", kToolVersion, pid);
        Report rep;
        std::vector<std::pair<std::wstring, std::wstring>> repl;
        Analyze(proc, o, rep, repl);
        ScanHealth(proc, rep);
        if (share) Sanitize(rep, repl);

        std::wstring base = OutDir(o) + L"\\HookMap_" + U2W(NowFileStamp()) + (share ? L"_share" : L"");
        std::wstring htmlPath = base + L".html", jsonPath = base + L".json";
        bool okH = WriteFileText(htmlPath, ToHtml(rep));
        bool okJ = WriteFileText(jsonPath, ToJson(rep));

        int c[4]{};
        for (auto& x : rep.conflicts)
            if (!x.expected) c[std::clamp(x.severity, 0, 3)]++;
        printf("\n%zu patches mapped. Conflicts: %d high, %d medium, %d low.\n", rep.patches.size(), c[kHigh], c[kMedium], c[kLow]);
        PrintHealth(rep.health);
        if (okH) printf("Report: %s\n", W2U(htmlPath).c_str());
        else printf("Could not write %s\n", W2U(htmlPath).c_str());
        if (okJ) printf("Data:   %s\n", W2U(jsonPath).c_str());
        if (okH && !o.noOpen) OpenFile(htmlPath);
        return okH ? 0 : 3;
    }
}

int wmain(int argc, wchar_t** argv)
{
    SetConsoleOutputCP(CP_UTF8);
    Options o;
    std::wstring render;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        auto next = [&](std::wstring& dst) {
            if (i + 1 < argc) dst = argv[++i];
        };
        if (a != L"--elevated") o.rawArgs.push_back(a);
        if (a == L"--help" || a == L"-h" || a == L"/?") {
            printf(kHelp, kToolVersion);
            return 0;
        } else if (a == L"--pid" && i + 1 < argc) {
            o.pid = (DWORD)wcstoul(argv[++i], nullptr, 10);
            o.rawArgs.push_back(argv[i]);
        } else if (a == L"--render" && i + 1 < argc) {
            render = argv[++i];
        } else if (a == L"--wait") o.wait = true;
        else if (a == L"--share") o.share = true;
        else if (a == L"--no-share") o.noShare = true;
        else if (a == L"--no-open") o.noOpen = true;
        else if (a == L"--no-system") o.noSystem = true;
        else if (a == L"--elevated") o.pauseAtEnd = true;
        else if (a == L"--addrlib") next(o.addrlib), o.rawArgs.push_back(o.addrlib);
        else if (a == L"--clib") next(o.clib), o.rawArgs.push_back(o.clib);
        else if (a == L"--mo2") next(o.mo2), o.rawArgs.push_back(o.mo2);
        else if (a == L"--clean-exe") next(o.cleanExe), o.rawArgs.push_back(o.cleanExe);
        else if (a == L"--out") next(o.outDir), o.rawArgs.push_back(o.outDir);
        else if (a == L"--allowlist") next(o.allowlist), o.rawArgs.push_back(o.allowlist);
        else if (a == L"--diff" && i + 2 < argc) {
            o.diffOld = argv[++i];
            o.diffNew = argv[++i];
            o.rawArgs.push_back(o.diffOld);
            o.rawArgs.push_back(o.diffNew);
        } else {
            printf("Unknown option: %s\n\n", W2U(a).c_str());
            printf(kHelp, kToolVersion);
            return 2;
        }
    }

    int rc = !render.empty() ? RunRender(render, o) : (o.diffOld.empty() ? RunScan(o) : RunDiff(o));
    Pause(o);
    return rc;
}
