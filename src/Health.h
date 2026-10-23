#pragma once
#include "Common.h"
#include "Process.h"
#include "Report.h"

namespace hm
{
    // Process-wide limits every DLL in Skyrim shares, plus the hook-collision verdict:
    //   crt   - static-CRT DLLs vs. Fiber Local Storage slots (estimate)
    //   tls   - TlsAlloc slots used out of 1088 (exact, read from the game's PEB)
    //   near  - free address space within rel32 reach of the game exe, where trampolines must live (exact)
    //   hooks - clobbered / high / medium conflicts from the analyzer
    // Fills r.health. Call after Analyze(), before Sanitize().
    void ScanHealth(const RemoteProcess& proc, Report& r);

    // Danger-level panel for the HTML report; "" when the report has no health data (older JSON).
    std::string HealthHtml(const HealthRec& h);

    // Short console summary.
    void PrintHealth(const HealthRec& h);
}
