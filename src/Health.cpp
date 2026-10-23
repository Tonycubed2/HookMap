#include "Health.h"

#include <bit>

namespace hm
{
    namespace
    {
        constexpr uint64_t kMB = 1024ull * 1024ull;

        enum Level
        {
            kGray = -1,
            kGreen = 0,
            kYellow = 1,
            kRed = 2
        };

        const char* LevelName(int l)
        {
            switch (l) {
            case kGreen: return "green";
            case kYellow: return "yellow";
            case kRed: return "red";
            default: return "gray";
            }
        }

        int LevelFromName(const std::string& s)
        {
            if (s == "red") return kRed;
            if (s == "yellow") return kYellow;
            if (s == "green") return kGreen;
            return kGray;
        }

        const char* LevelWord(const std::string& s)
        {
            switch (LevelFromName(s)) {
            case kGreen: return "OK";
            case kYellow: return "WATCH";
            case kRed: return "DANGER";
            default: return "N/A";
            }
        }

        std::string Size(uint64_t bytes)
        {
            char b[32];
            if (bytes >= 1024 * kMB) snprintf(b, sizeof(b), "%.2f GB", bytes / double(1024 * kMB));
            else if (bytes >= kMB) snprintf(b, sizeof(b), "%.1f MB", bytes / double(kMB));
            else snprintf(b, sizeof(b), "%llu KB", (unsigned long long)(bytes / 1024));
            return b;
        }

        std::string Pct(double p)
        {
            char b[16];
            snprintf(b, sizeof(b), "%.0f%%", p);
            return b;
        }

        std::string Esc(const std::string& s)
        {
            std::string o;
            o.reserve(s.size() + 8);
            for (char c : s) {
                switch (c) {
                case '&': o += "&amp;"; break;
                case '<': o += "&lt;"; break;
                case '>': o += "&gt;"; break;
                case '"': o += "&quot;"; break;
                default: o += c;
                }
            }
            return o;
        }

        HMODULE Ntdll() { return GetModuleHandleW(L"ntdll.dll"); }

        // Windows build of this PC (HookMap runs next to the game, so it's the game's Windows too).
        uint32_t WindowsBuild(std::string& text)
        {
            using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
            auto fn = reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(Ntdll(), "RtlGetVersion")));
            OSVERSIONINFOW vi{};
            vi.dwOSVersionInfoSize = sizeof(vi);
            if (!fn || fn(&vi) != 0) {
                text = "Windows (version unknown)";
                return 0;
            }
            const char* name = "Windows";
            if (vi.dwMajorVersion == 10) name = vi.dwBuildNumber >= 22000 ? "Windows 11" : "Windows 10";
            text = std::string(name) + " build " + std::to_string(vi.dwBuildNumber);
            return vi.dwBuildNumber;
        }

        uint64_t RemotePeb(const RemoteProcess& proc)
        {
            struct Pbi
            {
                LONG      exitStatus;
                PVOID     peb;
                ULONG_PTR affinity;
                LONG      basePriority;
                ULONG_PTR pid;
                ULONG_PTR parentPid;
            } pbi{};
            using NtQipFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
            auto fn = reinterpret_cast<NtQipFn>(reinterpret_cast<void*>(GetProcAddress(Ntdll(), "NtQueryInformationProcess")));
            ULONG len = 0;
            if (!fn || fn(proc.Handle(), 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &len) < 0) return 0;
            return reinterpret_cast<uint64_t>(pbi.peb);
        }

        // Reads an RTL_BITMAP in the game and counts set bits. Validates the bitmap size so a wrong
        // PEB layout gives "unknown" instead of a wrong number.
        bool CountBitmap(const RemoteProcess& proc, uint64_t bitmapPtr, uint32_t expectBits, int& used)
        {
            struct RtlBitmap64
            {
                uint32_t size;
                uint32_t pad;
                uint64_t buffer;
            } bm{};
            if (!bitmapPtr || !proc.Read(bitmapPtr, &bm, sizeof(bm))) return false;
            if (bm.size != expectBits || !bm.buffer) return false;
            std::vector<uint32_t> words(expectBits / 32);
            if (!proc.Read(bm.buffer, words.data(), words.size() * sizeof(uint32_t))) return false;
            used = 0;
            for (uint32_t w : words) used += std::popcount(w);
            return true;
        }

        // ------------------------------------------------------------ static CRT / FLS

        GaugeRec CrtGauge(const Report& r, uint32_t build)
        {
            GaugeRec g;
            g.id = "crt";
            g.name = "Static CRT (FLS slots)";

            std::vector<std::string> statics;
            for (auto& m : r.modules)
                if (!m.windows && m.crt.rfind("/MT", 0) == 0) statics.push_back(m.name);
            std::sort(statics.begin(), statics.end(), [](const std::string& a, const std::string& b) { return LowerA(a) < LowerA(b); });

            const bool raised = build == 0 || build >= 18362;  // Windows 10 1903 raised the limit from 128 to 4080
            const int  limit = raised ? 4080 : 128;
            const int  estimate = 16 + 2 * (int)statics.size();  // Windows/game baseline + ~2 slots (UCRT + vcruntime) per static-CRT DLL
            const double pct = estimate * 100.0 / limit;

            int lvl = pct >= 90 ? kRed : pct >= 70 ? kYellow : kGreen;
            g.level = LevelName(lvl);
            g.value = std::to_string(statics.size()) + " static-CRT DLLs";
            g.detail = "Each DLL built with the static CRT (/MT) uses about 2 Fiber Local Storage slots. Estimated ~" +
                       std::to_string(estimate) + " of " + std::to_string(limit) + " used (" + Pct(pct) +
                       "). Counted from imports, so DLLs with no CRT at all are included: treat it as an upper bound.";
            if (!raised)
                g.advice = "This Windows build still has the old 128-slot limit. Updating to Windows 10 1903 or later raises it to 4080.";
            else if (lvl == kGreen)
                g.advice = "Not a practical limit on this Windows version. Shown for information.";
            else
                g.advice = "Too many static-CRT DLLs for the slot pool. Remove DLL mods you don't need, or ask authors for /MD builds.";
            g.items = std::move(statics);
            return g;
        }

        // ------------------------------------------------------------ TlsAlloc slots

        GaugeRec TlsGauge(const RemoteProcess& proc)
        {
            GaugeRec g;
            g.id = "tls";
            g.name = "TLS slots (TlsAlloc)";
            g.level = LevelName(kGray);

            constexpr uint64_t kPebTlsBitmap = 0x78;            // PEB64.TlsBitmap          (64 slots)
            constexpr uint64_t kPebTlsExpansionBitmap = 0x238;  // PEB64.TlsExpansionBitmap (1024 slots)
            constexpr int      kTotal = 64 + 1024;

            uint64_t peb = RemotePeb(proc);
            uint64_t p1 = 0, p2 = 0;
            int used1 = 0, used2 = 0;
            bool ok = peb && proc.ReadQword(peb + kPebTlsBitmap, p1) && CountBitmap(proc, p1, 64, used1);
            if (ok && proc.ReadQword(peb + kPebTlsExpansionBitmap, p2) && p2) ok = CountBitmap(proc, p2, 1024, used2);

            if (!ok) {
                g.value = "not measured";
                g.detail = "HookMap couldn't read the game's TLS table.";
                g.advice = "If the game runs as administrator, run HookMap as administrator too.";
                return g;
            }

            const int used = used1 + used2;
            const double pct = used * 100.0 / kTotal;
            int lvl = pct >= 92 ? kRed : pct >= 80 ? kYellow : kGreen;
            g.level = LevelName(lvl);
            g.value = std::to_string(used) + " of " + std::to_string(kTotal) + " used";
            g.detail = "Shared by the whole game process: Skyrim, Windows, drivers, overlays, ENB and every SKSE plugin. "
                       "When they run out, the next DLL that asks for one fails to load or misbehaves. (" + Pct(pct) + " used; "
                       "thread_local variables don't count against this.)";
            g.advice = lvl == kGreen ? "Plenty of room." :
                       lvl == kYellow ? "Getting full. Note which DLLs you add next; a failed load in skse64.log is the first sign." :
                                        "Nearly exhausted. Remove DLL mods or overlays (Steam, Discord, RivaTuner) until this drops.";
            g.items.push_back("Base slots: " + std::to_string(used1) + " of 64");
            g.items.push_back("Expansion slots: " + std::to_string(used2) + " of 1024");
            return g;
        }

        // ------------------------------------------------------------ near-exe address space

        GaugeRec NearGauge(const RemoteProcess& proc)
        {
            GaugeRec g;
            g.id = "near";
            g.name = "Near memory (trampolines)";
            g.level = LevelName(kGray);

            auto mods = proc.Modules();
            const ModuleEntry* exe = nullptr;
            for (auto& m : mods)
                if (IEquals(m.name, L"SkyrimSE.exe") || IEquals(m.name, L"SkyrimVR.exe")) {
                    exe = &m;
                    break;
                }
            if (!exe && !mods.empty()) exe = &mods.front();
            if (!exe || !exe->base) {
                g.value = "not measured";
                g.detail = "HookMap couldn't find the game exe in the process.";
                return g;
            }

            // A 5-byte jmp/call reaches +-2 GB. For a trampoline to be reachable from every call site in the exe,
            // it has to sit within [exeEnd - 2 GB, exeBase + 2 GB].
            const uint64_t reach = 0x7FFF0000ull;
            const uint64_t exeBase = exe->base, exeEnd = exe->base + exe->size;
            const uint64_t lo = std::max<uint64_t>(exeEnd > reach ? exeEnd - reach : 0, 0x10000);
            const uint64_t hi = exeBase + reach;

            uint64_t freeTotal = 0, largest = 0, largestAt = 0, execBytes = 0;
            int freeGaps = 0, execRegions = 0;
            std::map<uint64_t, std::pair<uint64_t, DWORD>> owners;  // allocation base -> bytes in window, type

            for (uint64_t a = lo; a < hi;) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQueryEx(proc.Handle(), reinterpret_cast<LPCVOID>(a), &mbi, sizeof(mbi))) break;
                const uint64_t rb = reinterpret_cast<uint64_t>(mbi.BaseAddress), re = rb + mbi.RegionSize;
                const uint64_t s = std::max(rb, lo), e = std::min(re, hi);
                if (e > s) {
                    if (mbi.State == MEM_FREE) {
                        // Allocations start on 64 KB boundaries, so only the aligned part of a gap is usable.
                        const uint64_t as = (s + 0xFFFF) & ~0xFFFFull, ae = e & ~0xFFFFull;
                        const uint64_t usable = ae > as ? ae - as : 0;
                        if (usable) {
                            freeTotal += usable;
                            ++freeGaps;
                            if (usable > largest) largest = usable, largestAt = as;
                        }
                    } else {
                        auto& o = owners[reinterpret_cast<uint64_t>(mbi.AllocationBase)];
                        o.first += e - s;
                        o.second = mbi.Type;
                        const DWORD prot = mbi.Protect & 0xFF;
                        const bool exec = prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
                        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && exec) {
                            execBytes += e - s;
                            ++execRegions;
                        }
                    }
                }
                if (re <= a) break;
                a = re;
            }

            int lvl = kGreen;
            if (largest < 8 * kMB || freeTotal < 32 * kMB) lvl = kRed;
            else if (largest < 64 * kMB || freeTotal < 256 * kMB) lvl = kYellow;

            g.level = LevelName(lvl);
            g.value = "largest free block " + Size(largest);
            g.detail = "Hook trampolines must be allocated within 2 GB of " + W2U(exe->name) + ". In that window: " + Size(freeTotal) +
                       " free in " + std::to_string(freeGaps) + " gaps; " + std::to_string(execRegions) + " trampoline-like regions using " +
                       Size(execBytes) + ". Fragmentation (the largest block) matters more than the total.";
            g.advice = lvl == kGreen ? "Plenty of room for more hooking DLLs." :
                       lvl == kYellow ? "Room is getting tight. Turn off overlays you don't use (Steam, Discord, RivaTuner, GPU overlays) before adding DLLs." :
                                        "Next plugin that needs a trampoline may fail at startup. Remove overlays and DLL mods until this turns yellow.";
            if (largest) g.items.push_back("Largest free block starts at " + Hex(largestAt));

            // Biggest occupants of the window, so the player can see what's eating it.
            std::vector<std::pair<uint64_t, std::string>> top;
            for (auto& [base, info] : owners) {
                std::string who;
                if (info.second == MEM_IMAGE) {
                    for (auto& m : mods)
                        if (m.base == base) {
                            who = W2U(m.name);
                            break;
                        }
                    if (who.empty()) who = "image at " + Hex(base);
                } else if (info.second == MEM_MAPPED) who = "mapped file at " + Hex(base);
                else who = "private memory at " + Hex(base);
                top.push_back({ info.first, who });
            }
            std::sort(top.begin(), top.end(), [](auto& a, auto& b) { return a.first > b.first; });
            for (size_t i = 0; i < top.size() && i < 10; ++i) g.items.push_back(top[i].second + " - " + Size(top[i].first));
            return g;
        }

        // ------------------------------------------------------------ hook collisions

        GaugeRec HookGauge(const Report& r)
        {
            GaugeRec g;
            g.id = "hooks";
            g.name = "Hook collisions";

            int clobbered = 0, high = 0, medium = 0;
            std::vector<const ConflictRec*> shown;
            for (auto& c : r.conflicts) {
                if (c.expected) continue;
                if (c.category == "clobber" || c.category == "overlap") ++clobbered;
                if (c.severity == kHigh) ++high;
                else if (c.severity == kMedium) ++medium;
                if (c.severity >= kMedium) shown.push_back(&c);
            }

            int lvl = (clobbered || high) ? kRed : medium ? kYellow : kGreen;
            g.level = LevelName(lvl);
            if (clobbered) g.value = std::to_string(clobbered) + " clobbered";
            else if (high) g.value = std::to_string(high) + " high";
            else if (medium) g.value = std::to_string(medium) + " medium";
            else g.value = "none serious";
            g.detail = std::to_string(clobbered) + " clobbered/overlapping hooks, " + std::to_string(high) + " high and " + std::to_string(medium) +
                       " medium conflicts (expected ones excluded). A clobbered hook means one DLL overwrote another's, so one of them isn't working.";
            g.advice = lvl == kGreen ? "No serious hook conflicts." :
                       lvl == kYellow ? "Worth a look: see Conflicts below for which DLLs share code." :
                                        "Fix these first: see Conflicts below for the DLL pairs. Usually one mod must go or load a compatible version.";
            for (size_t i = 0; i < shown.size() && i < 10; ++i)
                g.items.push_back(std::string("[") + SeverityName(shown[i]->severity) + "] " + shown[i]->title);
            if (shown.size() > 10) g.items.push_back("+" + std::to_string(shown.size() - 10) + " more in Conflicts");
            return g;
        }
    }

    void ScanHealth(const RemoteProcess& proc, Report& r)
    {
        HealthRec h;
        uint32_t build = WindowsBuild(h.windows);
        h.gauges.push_back(HookGauge(r));
        h.gauges.push_back(NearGauge(proc));
        h.gauges.push_back(TlsGauge(proc));
        h.gauges.push_back(CrtGauge(r, build));

        int worst = kGray;
        for (auto& g : h.gauges) worst = std::max(worst, LevelFromName(g.level));
        h.overall = LevelName(worst);
        h.scanned = true;
        r.health = std::move(h);
    }

    void PrintHealth(const HealthRec& h)
    {
        if (!h.scanned) return;
        printf("\nDanger level: %s\n", LevelWord(h.overall));
        for (auto& g : h.gauges) printf("  %-28s %-7s %s\n", g.name.c_str(), LevelWord(g.level), g.value.c_str());
    }

    std::string HealthHtml(const HealthRec& h)
    {
        if (!h.scanned) return "";
        std::string o =
            "<style>"
            ".hzo{margin:8px 0 4px;padding:10px 14px;border-radius:10px;font-weight:600;background:var(--infoBg);color:var(--info)}"
            ".hzo.green{background:var(--okBg);color:var(--ok)}.hzo.yellow{background:var(--medBg);color:var(--med)}.hzo.red{background:var(--hiBg);color:var(--hi)}"
            ".hzo span{font-weight:400;color:var(--mute);margin-left:8px}"
            ".hz{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin:10px 0}"
            ".hzc{background:var(--panel);border:1px solid var(--line);border-top:4px solid var(--line);border-radius:10px;padding:12px 14px}"
            ".hzc.green{border-top-color:var(--ok)}.hzc.yellow{border-top-color:var(--med)}.hzc.red{border-top-color:var(--hi)}"
            ".hzw{font-weight:700;font-size:12px;letter-spacing:.06em;color:var(--mute)}"
            ".hzc.green .hzw{color:var(--ok)}.hzc.yellow .hzw{color:var(--med)}.hzc.red .hzw{color:var(--hi)}"
            ".hzn{font-weight:600;margin-top:2px}.hzv{font-size:18px;margin:4px 0}"
            ".hzd{color:var(--mute);font-size:13px}.hza{font-size:13px;margin-top:6px}"
            ".hzc details{margin-top:8px;font-size:12.5px}.hzc ul{margin:4px 0 0;padding-left:18px;max-height:220px;overflow:auto;word-break:break-word}"
            "</style>";
        o += "<h2 id=danger>Danger levels</h2>";
        o += "<div class=\"hzo " + Esc(h.overall) + "\">Overall: " + LevelWord(h.overall) +
             "<span>the worst of the gauges below · " + Esc(h.windows) + "</span></div>";
        o += "<div class=hz>";
        for (auto& g : h.gauges) {
            o += "<div class=\"hzc " + Esc(g.level) + "\" id=\"hz-" + Esc(g.id) + "\">";
            o += std::string("<div class=hzw>") + LevelWord(g.level) + "</div>";
            o += "<div class=hzn>" + Esc(g.name) + "</div>";
            o += "<div class=hzv>" + Esc(g.value) + "</div>";
            if (!g.detail.empty()) o += "<div class=hzd>" + Esc(g.detail) + "</div>";
            if (!g.advice.empty()) o += "<div class=hza>" + Esc(g.advice) + "</div>";
            if (!g.items.empty()) {
                o += "<details><summary>Details (" + std::to_string(g.items.size()) + ")</summary><ul>";
                for (auto& it : g.items) o += "<li>" + Esc(it) + "</li>";
                o += "</ul></details>";
            }
            o += "</div>";
        }
        o += "</div>";
        return o;
    }
}
