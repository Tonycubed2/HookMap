#pragma once
#include "Common.h"
#include "Process.h"
#include "Report.h"

namespace hm
{
    struct Options
    {
        DWORD        pid = 0;
        bool         wait = false;
        bool         share = false;
        bool         noShare = false;
        bool         noOpen = false;
        bool         noSystem = false;
        bool         pauseAtEnd = false;
        std::wstring addrlib;    // file or folder
        std::wstring clib;       // CommonLibSSE-NG root for names
        std::wstring mo2;        // MO2 instance folder
        std::wstring outDir;
        std::wstring allowlist;
        std::wstring diffOld, diffNew;
        std::vector<std::wstring> rawArgs;
    };

    // Scans an already-opened Skyrim process and fills the report.
    // shareRepl receives the replacement pairs --share uses (game/MO2 roots, profile, user and machine names).
    void Analyze(RemoteProcess& proc, const Options& opt, Report& report,
        std::vector<std::pair<std::wstring, std::wstring>>& shareRepl);
}
