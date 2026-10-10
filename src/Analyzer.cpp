#include "Analyzer.h"

#include "AddressLib.h"
#include "Disasm.h"
#include "PEImage.h"
#include "SteamStub.h"

#include <winver.h>

namespace hm
{
    namespace
    {
        constexpr const char* kUnattributed = "(unattributed)";
        constexpr size_t      kMaxPatchesPerModule = 5000;

        // SKSE's plugin version export (AE-style plugins).
#pragma pack(push, 4)
        struct PluginVersionData
        {
            uint32_t dataVersion;
            uint32_t pluginVersion;
            char     name[256];
            char     author[256];
            char     supportEmail[252];
            uint32_t versionIndependenceEx;
            uint32_t versionIndependence;
            uint32_t compatibleVersions[16];
            uint32_t seVersionRequired;
        };
#pragma pack(pop)
        static_assert(sizeof(PluginVersionData) == 848, "SKSE PluginVersionData layout");

        uint32_t PackVersion(unsigned a, unsigned b, unsigned c, unsigned d)
        {
            return ((a & 0xFF) << 24) | ((b & 0xFF) << 16) | ((c & 0xFFF) << 4) | (d & 0xF);
        }
        std::string UnpackVersion(uint32_t v)
        {
            char buf[64];
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", v >> 24, (v >> 16) & 0xFF, (v >> 4) & 0xFFF, v & 0xF);
            return buf;
        }

        struct FileVer
        {
            unsigned    v[4]{};
            bool        ok = false;
            std::string text, product, company;
        };

        FileVer GetFileVer(const std::wstring& path)
        {
            FileVer fv;
            DWORD h = 0;
            DWORD sz = GetFileVersionInfoSizeW(path.c_str(), &h);
            if (!sz) return fv;
            std::vector<BYTE> b(sz);
            if (!GetFileVersionInfoW(path.c_str(), 0, sz, b.data())) return fv;
            VS_FIXEDFILEINFO* ffi = nullptr;
            UINT len = 0;
            if (VerQueryValueW(b.data(), L"\\", (LPVOID*)&ffi, &len) && ffi) {
                fv.v[0] = HIWORD(ffi->dwFileVersionMS);
                fv.v[1] = LOWORD(ffi->dwFileVersionMS);
                fv.v[2] = HIWORD(ffi->dwFileVersionLS);
                fv.v[3] = LOWORD(ffi->dwFileVersionLS);
                fv.ok = true;
                char buf[64];
                snprintf(buf, sizeof(buf), "%u.%u.%u.%u", fv.v[0], fv.v[1], fv.v[2], fv.v[3]);
                fv.text = buf;
            }
            struct LangCp
            {
                WORD lang, cp;
            }* lc = nullptr;
            if (VerQueryValueW(b.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&lc, &len) && lc && len >= 4) {
                auto query = [&](const wchar_t* key) -> std::string {
                    wchar_t q[128];
                    swprintf(q, 128, L"\\StringFileInfo\\%04x%04x\\%s", lc->lang, lc->cp, key);
                    wchar_t* val = nullptr;
                    UINT vl = 0;
                    if (VerQueryValueW(b.data(), q, (LPVOID*)&val, &vl) && val && vl) return W2U(std::wstring(val, wcsnlen(val, vl)));
                    return {};
                };
                fv.product = query(L"ProductName");
                fv.company = query(L"CompanyName");
            }
            return fv;
        }

        const wchar_t* kDefaultAllowlist =
            L"# HookMap allowlist\r\n"
            L"# One module name per line. Wildcards * and ? are allowed. Text after '|' is a note shown in the report.\r\n"
            L"# Patches and conflicts that only involve allowlisted modules are marked \"expected\" and ranked lower.\r\n"
            L"# Edit freely; no rebuild needed.\r\n"
            L"\r\n"
            L"skse64_*.dll            | SKSE core: hooks the game by design\r\n"
            L"EngineFixes.dll         | SSE Engine Fixes: patches dozens of sites by design\r\n"
            L"SSEDisplayTweaks.dll    | SSE Display Tweaks: frame timing and display patches\r\n"
            L"po3_Tweaks.dll          | powerofthree's Tweaks: many small engine fixes\r\n"
            L"ScrambledBugs.dll       | Scrambled Bugs: many small engine fixes\r\n"
            L"PapyrusTweaks.dll       | Papyrus Tweaks NG: VM patches\r\n"
            L"PrivateProfileRedirector.dll | INI redirector: hooks profile APIs by design\r\n"
            L"CrashLogger.dll         | Crash Logger: installs exception handlers by design\r\n"
            L"GameOverlayRenderer64.dll | Steam overlay\r\n"
            L"DiscordHook64.dll       | Discord overlay\r\n"
            L"RTSSHooks64.dll         | RivaTuner / Afterburner overlay\r\n"
            L"graphics-hook64.dll     | OBS game capture\r\n";

        bool IsJumpKind(BrKind k) { return k == BrKind::Jmp || k == BrKind::JmpInd || k == BrKind::AbsJmp; }

        struct Mod
        {
            ModuleEntry e;
            bool        windows = false;
            bool        game = false;
            bool        read = false;
            bool        scanCode = false;
            bool        scanRdata = false;
            std::vector<uint8_t> img;
            std::vector<bool>    pages;
            PEImage     pe;
            ModuleRec   rec;
            std::vector<std::pair<uint64_t, uint64_t>> exec;
            std::vector<uint64_t> dataRefs;
            std::vector<uint64_t> orphans;
            std::vector<int>      neighbors;
            bool        neighborsBuilt = false;
            bool        registersVeh = false;
            bool        noBaseline = false;   // code compared without a clean copy (game only)
            std::vector<uint64_t> funcStarts;   // absolute addresses from .pdata

            bool PageOk(uint64_t rva) const
            {
                size_t p = (size_t)(rva / 0x1000);
                return p < pages.size() && pages[p];
            }
            bool InExec(uint64_t a) const
            {
                for (auto& r : exec)
                    if (a >= r.first && a < r.second) return true;
                return false;
            }
        };

        struct PInfo
        {
            int      patch = -1;
            int      mod = -1;
            uint64_t site = 0;
            uint64_t origTarget = 0;
            uint64_t newTarget = 0;
            bool     detour = false;
            bool     hook = false;    // redirect into another module (branch or pointer)
            bool     isVptr = false;
            bool     isIat = false;
            int      owner = -1;
            std::vector<uint64_t> hops;
            std::vector<uint64_t> thunkRefs;
            std::vector<uint8_t>  newBytes;
            bool     noBaseline = false;
        };

        struct Resolved
        {
            int         mod = -1;
            uint64_t    final = 0;
            std::vector<uint64_t> hops;
            std::vector<uint64_t> thunkRefs;
            std::string how;
        };

        class Engine
        {
        public:
            Engine(RemoteProcess& p, const Options& o, Report& r) : proc_(p), opt_(o), rep_(r) {}
            void Run(std::vector<std::pair<std::wstring, std::wstring>>& repl);

        private:
            RemoteProcess& proc_;
            const Options& opt_;
            Report&        rep_;

            std::vector<Mod> mods_;
            std::vector<std::pair<uint64_t, int>> modIndex_;
            std::vector<MemRegion> priv_;
            int gameIdx_ = -1;
            std::wstring gameDir_, winDir_;
            std::vector<std::wstring> mo2Roots_;
            std::vector<std::wstring> modsDirs_;
            AddressLib alib_;
            NameDb     names_;
            bool       haveNames_ = false;
            std::vector<std::pair<std::wstring, std::string>> allow_;
            std::vector<PInfo> pinfo_;
            std::unordered_map<uint64_t, int> resolveCache_;
            uint32_t runtimePacked_ = 0;
            std::string runtimeStr_;
            uint32_t skseCorePacked_ = 0;
            std::vector<uint8_t> gameDisk_;   // clean SkyrimSE.exe image (empty without a baseline)

            // ---- helpers
            int ModAt(uint64_t a) const;
            int PrivAt(uint64_t a) const;
            bool IsCodeAddr(uint64_t a) const;
            bool ReadQ(uint64_t a, uint64_t& out) const;
            const uint8_t* PrivBytes(uint64_t a, size_t& avail) const;
            Resolved Resolve(uint64_t addr);
            int ResolveMod(uint64_t v);
            bool Eligible(int m) const { return m >= 0 && !mods_[m].windows && !mods_[m].game; }
            std::string AddrText(uint64_t a) const;
            std::string ModName(int m) const { return m >= 0 ? W2U(mods_[m].e.name) : std::string(kUnattributed); }
            bool Allowlisted(const std::wstring& name, std::string* note) const;

            // ---- stages
            void LoadModules();
            void FindMo2Roots();
            void LoadAllowlist();
            void LoadAddressLibrary();
            void LoadNames();
            void StaticAnalyze(Mod& m);
            void BuildDataRefs();
            void ScanModule(int mi);
            void ScanCode(int mi, const std::vector<uint8_t>& disk, const PESection& sec, size_t& budget);
            bool GameBaseline(int mi, std::vector<uint8_t>& disk);
            size_t CodeDiff(const Mod& m, const std::vector<uint8_t>& disk) const;
            void ScanCodeNoBaseline(int mi, const PESection& sec, size_t& budget);
            bool IsFuncStart(int m, uint64_t a) const { return m >= 0 && SortedContains(mods_[m].funcStarts, a); }
            void AnalyzeCodeRange(int mi, const std::vector<uint8_t>& disk, uint32_t a, uint32_t b, size_t& budget);
            void ScanRdata(int mi, const std::vector<uint8_t>& disk, const PESection& sec, size_t& budget);
            void CheckIats();
            void FindOrphanStubs();
            void AttributeBytePatches();
            std::map<std::pair<int, uint64_t>, std::vector<int>> FunctionGroups();
            void InferSameFunctionOwners();
            void AnalyzeChains();
            void FindTrampolineEvidence();
            std::unordered_set<uint64_t> ReachFrom(const PInfo& pi);
            void Locate();
            void ReadSkseLog();
            void BuildConflicts();
            int  AddPatch(PatchRec rec, PInfo info);
            const std::vector<int>& Neighbors(int m);
        };

        // ------------------------------------------------------------ helpers

        int Engine::ModAt(uint64_t a) const
        {
            auto it = std::upper_bound(modIndex_.begin(), modIndex_.end(), std::make_pair(a, INT32_MAX));
            if (it == modIndex_.begin()) return -1;
            --it;
            auto& m = mods_[it->second];
            return a < m.e.base + m.e.size ? it->second : -1;
        }

        int Engine::PrivAt(uint64_t a) const
        {
            auto it = std::upper_bound(priv_.begin(), priv_.end(), a, [](uint64_t v, const MemRegion& r) { return v < r.base; });
            if (it == priv_.begin()) return -1;
            --it;
            return a < it->base + it->size ? (int)(it - priv_.begin()) : -1;
        }

        bool Engine::IsCodeAddr(uint64_t a) const
        {
            if (a < 0x10000 || (a >> 47)) return false;
            int m = ModAt(a);
            if (m >= 0) return mods_[m].read ? mods_[m].InExec(a) : true;
            return PrivAt(a) >= 0;
        }

        bool Engine::ReadQ(uint64_t a, uint64_t& out) const
        {
            int m = ModAt(a);
            if (m >= 0 && mods_[m].read) {
                uint64_t rva = a - mods_[m].e.base;
                if (rva + 8 <= mods_[m].img.size() && mods_[m].PageOk(rva)) {
                    std::memcpy(&out, mods_[m].img.data() + rva, 8);
                    return true;
                }
            }
            int r = PrivAt(a);
            if (r >= 0 && a + 8 <= priv_[r].base + priv_[r].size) {
                std::memcpy(&out, priv_[r].bytes.data() + (a - priv_[r].base), 8);
                return true;
            }
            return proc_.ReadQword(a, out);
        }

        const uint8_t* Engine::PrivBytes(uint64_t a, size_t& avail) const
        {
            int r = PrivAt(a);
            if (r < 0) return nullptr;
            avail = (size_t)(priv_[r].base + priv_[r].size - a);
            return priv_[r].bytes.data() + (a - priv_[r].base);
        }

        std::string Engine::AddrText(uint64_t a) const
        {
            int m = ModAt(a);
            if (m >= 0) return W2U(mods_[m].e.name) + "+" + Hex(a - mods_[m].e.base);
            if (PrivAt(a) >= 0) return "private " + Hex(a);
            return "unmapped " + Hex(a);
        }

        bool Engine::Allowlisted(const std::wstring& name, std::string* note) const
        {
            for (auto& [pat, n] : allow_)
                if (GlobMatch(pat, name)) {
                    if (note) *note = n;
                    return true;
                }
            return false;
        }

        Resolved Engine::Resolve(uint64_t addr)
        {
            Resolved r;
            for (int i = 0; i < 8; ++i) {
                int m = ModAt(addr);
                if (m >= 0) {
                    r.mod = m;
                    r.final = addr;
                    r.how = r.hops.empty() ? "direct" : "via trampoline";
                    return r;
                }
                size_t avail = 0;
                const uint8_t* p = PrivBytes(addr, avail);
                if (!p) {
                    r.final = addr;
                    r.how = "target is not in any module or executable memory";
                    return r;
                }
                r.hops.push_back(addr);
                Branch b = DecodeBranch(p, std::min<size_t>(avail, 32), addr);
                if (IsJumpKind(b.kind)) {
                    uint64_t t = b.target;
                    if (b.IsIndirect() && !ReadQ(b.slot, t)) break;
                    addr = t;
                    continue;
                }
                // A real thunk (xbyak/hand-written code). Collect what it references and vote on an owner.
                size_t n = std::min<size_t>(avail, 512);
                std::map<int, int> votes;
                for (size_t k = 0; k + 5 <= n; ++k) {
                    uint64_t t = 0;
                    if (p[k] == 0xE8 || p[k] == 0xE9) {
                        int32_t rel;
                        std::memcpy(&rel, p + k + 1, 4);
                        t = addr + k + 5 + (int64_t)rel;
                        if (IsCodeAddr(t)) r.thunkRefs.push_back(t);
                    }
                    if (k + 6 <= n && p[k] == 0xFF && (p[k + 1] == 0x15 || p[k + 1] == 0x25)) {
                        int32_t rel;
                        std::memcpy(&rel, p + k + 2, 4);
                        uint64_t slot = addr + k + 6 + (int64_t)rel, v = 0;
                        if (ReadQ(slot, v) && IsCodeAddr(v)) r.thunkRefs.push_back(v);
                    }
                    if (k + 8 <= n) {
                        uint64_t v;
                        std::memcpy(&v, p + k, 8);
                        if (IsCodeAddr(v)) r.thunkRefs.push_back(v);
                    }
                }
                SortUnique(r.thunkRefs);
                for (auto t : r.thunkRefs) {
                    int tm = ModAt(t);
                    if (tm < 0) {
                        // a stub in private memory: one level of jump following
                        size_t av2 = 0;
                        if (const uint8_t* q = PrivBytes(t, av2)) {
                            Branch b2 = DecodeBranch(q, std::min<size_t>(av2, 32), t);
                            uint64_t t2 = b2.target;
                            if (IsJumpKind(b2.kind) && (!b2.IsIndirect() || ReadQ(b2.slot, t2))) tm = ModAt(t2);
                        }
                    }
                    if (Eligible(tm)) votes[tm]++;
                }
                int best = -1, bestN = 0;
                for (auto& [m2, c] : votes)
                    if (c > bestN) best = m2, bestN = c;
                r.mod = best;
                r.final = addr;
                r.how = best >= 0 ? "via thunk (inferred)" : "thunk with no identifiable owner";
                return r;
            }
            r.final = addr;
            if (r.how.empty()) r.how = "jump chain too long";
            return r;
        }

        int Engine::ResolveMod(uint64_t v)
        {
            auto it = resolveCache_.find(v);
            if (it != resolveCache_.end()) return it->second;
            int m = Resolve(v).mod;
            resolveCache_[v] = m;
            return m;
        }

        const std::vector<int>& Engine::Neighbors(int mi)
        {
            Mod& m = mods_[mi];
            if (m.neighborsBuilt) return m.neighbors;
            std::set<int> s;
            for (auto v : m.dataRefs) {
                int n = ResolveMod(v);
                if (n != mi && Eligible(n)) s.insert(n);
            }
            m.neighbors.assign(s.begin(), s.end());
            m.neighborsBuilt = true;
            return m.neighbors;
        }

        int Engine::AddPatch(PatchRec rec, PInfo info)
        {
            rec.id = (int)rep_.patches.size();
            info.patch = rec.id;
            rep_.patches.push_back(std::move(rec));
            pinfo_.push_back(std::move(info));
            return (int)rep_.patches.size() - 1;
        }

        // ------------------------------------------------------------ stages

        void Engine::LoadModules()
        {
            winDir_ = WindowsDir();
            auto entries = proc_.Modules();
            for (auto& e : entries) {
                Mod m;
                m.e = e;
                m.windows = IStartsWith(e.physPath, winDir_ + L"\\");
                m.game = IEquals(e.name, L"SkyrimSE.exe");
                mods_.push_back(std::move(m));
            }
            for (int i = 0; i < (int)mods_.size(); ++i) {
                modIndex_.push_back({ mods_[i].e.base, i });
                if (mods_[i].game) gameIdx_ = i;
            }
            std::sort(modIndex_.begin(), modIndex_.end());
            if (gameIdx_ >= 0) gameDir_ = DirOf(mods_[gameIdx_].e.physPath);

            static const wchar_t* kSystemScan[] = { L"ntdll.dll", L"kernelbase.dll", L"kernel32.dll", L"user32.dll",
                L"dxgi.dll", L"d3d11.dll", L"dinput8.dll", L"xinput1_3.dll", L"xinput1_4.dll", L"xinput9_1_0.dll" };
            static const wchar_t* kSystemRdata[] = { L"dxgi.dll", L"d3d11.dll", L"dinput8.dll" };

            size_t total = 0, done = 0;
            for (auto& m : mods_) {
                bool sys = false, sysR = false;
                for (auto n : kSystemScan) sys |= IEquals(m.e.name, n);
                for (auto n : kSystemRdata) sysR |= IEquals(m.e.name, n);
                if (m.windows) {
                    m.scanCode = sys && !opt_.noSystem;
                    m.scanRdata = sysR && !opt_.noSystem;
                } else {
                    m.scanCode = true;
                    m.scanRdata = m.game;
                }
                m.read = !m.windows || m.scanCode;
                if (m.read) ++total;
            }
            for (auto& m : mods_) {
                if (!m.read) continue;
                ++done;
                printf("\r  reading module images %zu/%zu", done, total);
                m.img = proc_.ReadImage(m.e.base, m.e.size, m.pages);
                if (!m.pe.Parse(m.img.data(), m.img.size(), m.e.base)) {
                    m.read = false;
                    m.scanCode = m.scanRdata = false;
                    m.rec.scanNote = "PE headers unreadable in memory";
                    continue;
                }
                for (auto& s : m.pe.sections)
                    if (s.Exec()) m.exec.push_back({ m.e.base + s.va, m.e.base + s.va + s.Size() });
                if (!m.windows)
                    for (auto rva : FunctionStarts(m.img.data(), m.img.size())) m.funcStarts.push_back(m.e.base + rva);
            }
            printf("\n");
        }

        void Engine::FindMo2Roots()
        {
            std::set<std::wstring> roots;
            auto add = [&](const std::wstring& r) {
                if (!r.empty() && DirExists(r)) roots.insert(Lower(r));
            };
            for (auto& m : mods_) {
                size_t p = IFind(m.e.physPath, L"\\mods\\");
                if (p != std::wstring::npos) add(m.e.physPath.substr(0, p));
                p = IFind(m.e.physPath, L"\\overwrite\\");
                if (p != std::wstring::npos) add(m.e.physPath.substr(0, p));
            }
            if (!opt_.mo2.empty()) add(opt_.mo2);
            for (auto& pi : FindProcesses({ L"ModOrganizer.exe" })) {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.pid);
                if (!h) continue;
                wchar_t buf[MAX_PATH * 2];
                DWORD n = (DWORD)std::size(buf);
                if (QueryFullProcessImageNameW(h, 0, buf, &n)) add(DirOf(std::wstring(buf, n)));
                CloseHandle(h);
            }
            mo2Roots_.assign(roots.begin(), roots.end());

            // Mods folders: <root>\mods for each MO2 root, plus the parent of every "<mod>\SKSE\Plugins\x.dll" that
            // loads from outside the game folder. The second covers MO2 instances with a custom mod_directory.
            std::set<std::wstring> modsDirs;
            for (auto& r : mo2Roots_)
                if (DirExists(r + L"\\mods")) modsDirs.insert(Lower(r + L"\\mods"));
            for (auto& m : mods_) {
                if (m.windows) continue;
                size_t p = IFind(m.e.physPath, L"\\SKSE\\Plugins\\");
                if (p == std::wstring::npos) continue;
                std::wstring modDir = m.e.physPath.substr(0, p);
                if (!gameDir_.empty() && IEquals(modDir, gameDir_ + L"\\Data")) continue;
                std::wstring parent = DirOf(modDir);
                if (IEquals(FileNameOf(modDir), L"overwrite")) continue;
                if (!parent.empty() && DirExists(parent)) modsDirs.insert(Lower(parent));
            }
            modsDirs_.assign(modsDirs.begin(), modsDirs.end());

            if (mo2Roots_.empty() && modsDirs_.empty()) rep_.mo2 = "not detected (no module loads from an MO2 mods folder)";
            else {
                rep_.mo2.clear();
                for (auto& r : mo2Roots_) rep_.mo2 += (rep_.mo2.empty() ? "" : "; ") + W2U(r);
                for (auto& d : modsDirs_) rep_.mo2 += (rep_.mo2.empty() ? "mods: " : "; mods: ") + W2U(d);
            }
        }

        void Engine::LoadAllowlist()
        {
            std::wstring path = opt_.allowlist.empty() ? DirOf(SelfExePath()) + L"\\allowlist.txt" : opt_.allowlist;
            std::string text;
            if (!ReadFileText(path, text)) {
                text = W2U(kDefaultAllowlist);
                if (opt_.allowlist.empty() && WriteFileText(path, text))
                    rep_.notes.push_back("Created a default allowlist.txt next to HookMap.exe; edit it to tune what counts as expected.");
            }
            size_t pos = 0;
            while (pos < text.size()) {
                size_t nl = text.find('\n', pos);
                std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
                pos = nl == std::string::npos ? text.size() : nl + 1;
                line = Trim(line);
                if (line.empty() || line[0] == '#') continue;
                std::string note;
                if (auto bar = line.find('|'); bar != std::string::npos) {
                    note = Trim(line.substr(bar + 1));
                    line = Trim(line.substr(0, bar));
                }
                if (!line.empty()) allow_.push_back({ U2W(line), note });
            }
        }

        void Engine::LoadAddressLibrary()
        {
            if (gameIdx_ < 0) return;
            FileVer fv = GetFileVer(mods_[gameIdx_].e.physPath);
            if (!fv.ok) {
                rep_.addrLib = "game version unreadable; Address Library not loaded";
                return;
            }
            runtimePacked_ = PackVersion(fv.v[0], fv.v[1], fv.v[2], fv.v[3]);
            runtimeStr_ = fv.text;
            rep_.gameVersion = fv.text;
            bool ae = fv.v[0] > 1 || (fv.v[0] == 1 && fv.v[1] >= 6);
            wchar_t fname[128];
            swprintf(fname, 128, ae ? L"versionlib-%u-%u-%u-%u.bin" : L"version-%u-%u-%u-%u.bin", fv.v[0], fv.v[1], fv.v[2], fv.v[3]);

            std::vector<std::wstring> cands;
            if (!opt_.addrlib.empty()) {
                if (DirExists(opt_.addrlib)) cands.push_back(opt_.addrlib + L"\\" + fname);
                else cands.push_back(opt_.addrlib);
            }
            cands.push_back(gameDir_ + L"\\Data\\SKSE\\Plugins\\" + fname);
            for (auto& root : mo2Roots_) cands.push_back(root + L"\\overwrite\\SKSE\\Plugins\\" + fname);
            for (auto& dir : modsDirs_) {
                std::error_code ec;
                for (auto it = std::filesystem::directory_iterator(dir, ec); !ec && it != std::filesystem::directory_iterator();
                     it.increment(ec))
                    if (it->is_directory(ec)) cands.push_back((it->path() / L"SKSE" / L"Plugins" / fname).wstring());
            }
            for (auto& c : cands) {
                if (!FileExists(c)) continue;
                std::string err;
                if (alib_.Load(c, err)) {
                    rep_.addrLib = W2U(c) + " (" + std::to_string(alib_.Count()) + " IDs)";
                    return;
                }
                rep_.notes.push_back("Address Library file " + W2U(c) + " failed to load: " + err);
            }
            rep_.addrLib = "not found (" + W2U(fname) + "); patch locations shown as raw offsets. Use --addrlib to point at it.";
        }

        void Engine::LoadNames()
        {
            std::wstring root = opt_.clib;
            if (root.empty()) root = EnvVar(L"CommonLibSSEPath_NG");
            if (root.empty()) root = EnvVar(L"CommonLibSSEPath");
            if (root.empty()) {
                rep_.names = "no CommonLib folder (set CommonLibSSEPath_NG or use --clib) — functions shown by ID only";
                return;
            }
            std::string err;
            bool se = runtimePacked_ && runtimePacked_ < PackVersion(1, 6, 0, 0);
            if (!names_.LoadCommonLib(root, se, err)) {
                rep_.names = "CommonLib names unavailable: " + err;
                return;
            }
            haveNames_ = true;
            if (alib_.Loaded()) names_.ResolveVtables(alib_);
            rep_.names = W2U(root) + " (" + std::to_string(names_.Count()) + " names, " + std::to_string(names_.VtableCount()) +
                         " vtables)";
        }

        std::string Categorize(const Mod& m, const std::wstring& gameDir)
        {
            if (m.windows) return "Windows";
            if (m.game) return "Game";
            if (IStartsWith(m.e.name, L"skse64_")) return "SKSE core";
            if (m.read && (m.pe.HasExport("SKSEPlugin_Load") || m.pe.HasExport("SKSEPlugin_Version"))) return "SKSE plugin";
            static const wchar_t* kOverlay[] = { L"GameOverlayRenderer64.dll", L"DiscordHook64.dll", L"RTSSHooks64.dll",
                L"graphics-hook64.dll", L"nvspcap64.dll", L"SpecialK64.dll", L"fraps64.dll", L"owclient.dll", L"*overlay*64*.dll" };
            for (auto p : kOverlay)
                if (GlobMatch(p, m.e.name)) return "Overlay";
            static const wchar_t* kProxy[] = { L"d3d11.dll", L"dxgi.dll", L"d3d9.dll", L"d3d10.dll", L"d3d10core.dll",
                L"d3d12.dll", L"dinput8.dll", L"version.dll", L"winmm.dll", L"dsound.dll", L"xinput1_3.dll", L"xinput1_4.dll",
                L"xinput9_1_0.dll", L"*reshade*", L"enb*.dll", L"*dxvk*", L"d3dcompiler_46e.dll" };
            for (auto p : kProxy)
                if (GlobMatch(p, m.e.name)) return "Graphics / proxy";
            if (IEquals(DirOf(m.e.physPath), gameDir)) return "Game runtime";
            return "Other injected";
        }

        std::string SourceOf(const Mod& m, const std::wstring& gameDir, const std::vector<std::wstring>& modsDirs)
        {
            const auto& p = m.e.physPath;
            for (auto& d : modsDirs)
                if (IStartsWith(p, d + L"\\")) {
                    std::wstring rest = p.substr(d.size() + 1);
                    return "MO2 mod: " + W2U(rest.substr(0, rest.find(L'\\')));
                }
            size_t i = IFind(p, L"\\mods\\");
            if (i != std::wstring::npos) {
                std::wstring rest = p.substr(i + 6);
                return "MO2 mod: " + W2U(rest.substr(0, rest.find(L'\\')));
            }
            if (IContains(p, L"\\overwrite\\")) return "MO2 Overwrite";
            if (!gameDir.empty() && IStartsWith(p, gameDir + L"\\Data\\")) return "Game Data folder";
            if (!gameDir.empty() && IStartsWith(p, gameDir + L"\\")) return "Game folder";
            if (m.windows) return "Windows";
            return "External: " + W2U(DirOf(p));
        }

        void Engine::StaticAnalyze(Mod& m)
        {
            auto& r = m.rec;
            const auto& pe = m.pe;
            std::wstring diskPath = FileExists(m.e.physPath) ? m.e.physPath : m.e.path;
            FileVer fv = GetFileVer(diskPath);
            r.fileVersion = fv.text;
            r.productName = fv.product;
            r.company = fv.company;

            char buf[64];
            snprintf(buf, sizeof(buf), "%u.%02u", pe.linkerMajor, pe.linkerMinor);
            r.linker = buf;
            uint16_t maxBuild = 0;
            for (auto& e : pe.rich)
                if (e.build >= 20000 && e.build > maxBuild) maxBuild = e.build;
            r.toolset = maxBuild ? ToolsetFromBuild(maxBuild) + " — build " + std::to_string(maxBuild) + " (Rich header)"
                                 : (pe.rich.empty() ? "unknown (no Rich header — not MSVC, or stripped)" : "unknown");
            r.built = pe.repro ? "reproducible build (timestamp field is a hash, no date)" : UnixToUtcString(pe.timeDateStamp);
            r.pdb = pe.pdbPath;

            // CRT linkage
            bool dynCrt = false, oldCrt = false, msvcrt = false;
            std::set<std::string> imported;
            for (auto& d : pe.imports) {
                std::string l = LowerA(d.dll);
                if (l.rfind("vcruntime", 0) == 0 || l.rfind("msvcp1", 0) == 0 || l.rfind("api-ms-win-crt", 0) == 0 ||
                    l == "ucrtbase.dll")
                    dynCrt = true;
                else if (l.rfind("msvcr", 0) == 0) oldCrt = true;
                else if (l == "msvcrt.dll") msvcrt = true;
                for (auto& f : d.funcs)
                    if (!f.name.empty()) imported.insert(f.name);
            }
            if (dynCrt) r.crt = "/MD — dynamic CRT (VC++ redistributable)";
            else if (oldCrt) r.crt = "dynamic CRT (old msvcrXX)";
            else if (msvcrt) r.crt = "msvcrt.dll (MinGW or legacy toolchain)";
            else r.crt = "/MT — static CRT (inferred: no CRT DLL imported)";

            // String evidence from read-only data
            bool ng = false, vr = false, clib = false, verlib = false, seVer = false, vrCsv = false;
            std::string evidence;
            std::set<std::string> feats;
            std::set<std::string> dynApis;
            for (auto& s : pe.sections) {
                if (s.Exec() || s.Write() || !s.InitData()) continue;
                if (s.name == ".rsrc" || s.name == ".reloc" || s.name == ".pdata") continue;
                uint32_t a = s.va, n = std::min<uint32_t>(s.Size(), (uint32_t)m.img.size() - std::min<uint32_t>(s.va, (uint32_t)m.img.size()));
                if (!n) continue;
                std::string low(reinterpret_cast<const char*>(m.img.data() + a), n);
                for (auto& c : low) c = (char)tolower((unsigned char)c);
                auto has = [&](const char* k) { return low.find(k) != std::string::npos; };
                auto snip = [&](const char* k) {
                    size_t p = low.find(k);
                    if (p == std::string::npos || !evidence.empty()) return;
                    size_t b = p, e = p;
                    auto pr = [&](size_t i) { unsigned char c = m.img[a + i]; return c >= 0x20 && c < 0x7F; };
                    while (b > 0 && pr(b - 1) && p - b < 160) --b;
                    while (e < n && pr(e) && e - p < 160) ++e;
                    evidence = std::string(reinterpret_cast<const char*>(m.img.data() + a + b), e - b);
                };
                if (has("commonlibsse-ng") || has("commonlibsse_ng") || has("commonlibng") || has("commonlibsse-ng-fork")) {
                    ng = true;
                    snip("commonlib");
                }
                if (has("commonlibvr")) {
                    vr = true;
                    snip("commonlibvr");
                }
                if (has("commonlibsse") || has("commonlib\\") || has("commonlib/")) {
                    clib = true;
                    snip("commonlib");
                }
                if (has("versionlib-")) verlib = true;
                if (has("plugins/version-") || has("plugins\\version-")) seVer = true;
                if (has("version-{}.csv") || (has(".csv") && has("plugins/version-"))) vrCsv = true;
                if (has("spdlog")) feats.insert("spdlog");
                if (has("xbyak")) feats.insert("Xbyak (runtime code generation)");
                if (has("safetyhook")) feats.insert("SafetyHook");
                if (has("minhook") || has("mh_createhook")) feats.insert("MinHook");
                if (has("polyhook")) feats.insert("PolyHook");
                if (has("detourattach") || has("detourtransactionbegin")) feats.insert("Microsoft Detours");
                if (has("addvectoredexceptionhandler")) dynApis.insert("AddVectoredExceptionHandler");
                if (has("addvectoredcontinuehandler")) dynApis.insert("AddVectoredContinueHandler");
                if (has("rtladdvectoredexceptionhandler")) dynApis.insert("RtlAddVectoredExceptionHandler");
                if (has("setunhandledexceptionfilter")) dynApis.insert("SetUnhandledExceptionFilter");
            }
            r.features.assign(feats.begin(), feats.end());

            r.skseVersionExport = pe.HasExport("SKSEPlugin_Version");
            r.skseQueryExport = pe.HasExport("SKSEPlugin_Query");
            r.skseLoadExport = pe.HasExport("SKSEPlugin_Load");
            bool isPlugin = r.skseLoadExport || r.skseVersionExport;

            if (ng) {
                r.clibFlavor = "CommonLibSSE-NG";
                r.clibConfidence = "detected";
            } else if (vr) {
                r.clibFlavor = "CommonLibVR";
                r.clibConfidence = "detected";
            } else if (verlib && seVer) {
                r.clibFlavor = vrCsv ? "CommonLibSSE-NG (SE/AE/VR runtime support)" : "CommonLibSSE-NG (SE + AE runtime support)";
                r.clibConfidence = "inferred";
                if (evidence.empty()) evidence = "loads both Address Library formats (version-*.bin and versionlib-*.bin)";
            } else if (clib) {
                r.clibFlavor = verlib ? "CommonLibSSE (AE build)" : "CommonLibSSE";
                r.clibConfidence = "detected";
            } else if (isPlugin && verlib) {
                r.clibFlavor = "AE-only CommonLibSSE or SKSE SDK + Address Library";
                r.clibConfidence = "inferred";
                evidence = "references versionlib-*.bin only";
            } else if (isPlugin) {
                r.clibFlavor = "no CommonLib detected (plain SKSE SDK or another framework)";
                r.clibConfidence = "inferred";
            }
            if (isPlugin && r.skseVersionExport && r.skseQueryExport && r.clibConfidence != "detected") {
                if (r.clibFlavor.empty() || r.clibFlavor.rfind("no CommonLib", 0) == 0) {
                    r.clibFlavor = "CommonLibSSE-NG style (exports both SKSEPlugin_Version and SKSEPlugin_Query)";
                    r.clibConfidence = "inferred";
                }
            }
            r.clibEvidence = evidence;

            // Exception handlers
            static const char* kVeh[] = { "AddVectoredExceptionHandler", "AddVectoredContinueHandler",
                "RtlAddVectoredExceptionHandler", "RtlAddVectoredContinueHandler" };
            for (auto api : kVeh)
                if (imported.count(api)) {
                    r.exceptionApis.push_back(std::string(api) + " (imported)");
                    m.registersVeh = true;
                } else if (dynApis.count(api)) {
                    r.exceptionApis.push_back(std::string(api) + " (looked up at runtime)");
                    m.registersVeh = true;
                }
            if (!imported.count("SetUnhandledExceptionFilter") && dynApis.count("SetUnhandledExceptionFilter"))
                r.exceptionApis.push_back("SetUnhandledExceptionFilter (looked up at runtime)");

            // SKSE version data & compatibility
            if (r.skseVersionExport) {
                PluginVersionData vd{};
                uint32_t rva = pe.ExportRva("SKSEPlugin_Version");
                if (pe.Read(rva, vd) && vd.dataVersion >= 1) {
                    vd.name[255] = vd.author[255] = 0;
                    r.pluginName = vd.name;
                    r.pluginAuthor = vd.author;
                    r.pluginVersion = UnpackVersion(vd.pluginVersion);
                    std::vector<std::string> how;
                    bool independent = false;
                    if (vd.versionIndependence & 1) how.push_back("Address Library (post-AE)"), independent = true;
                    if (vd.versionIndependence & 2) how.push_back("signature scanning"), independent = true;
                    if (vd.versionIndependence & 4) how.push_back("post-1.6.629 struct layouts");
                    if (vd.versionIndependenceEx & 1) how.push_back("no game struct use");
                    std::vector<std::string> listed;
                    bool matches = false;
                    for (auto cv : vd.compatibleVersions) {
                        if (!cv) break;
                        listed.push_back(UnpackVersion(cv));
                        if (cv == runtimePacked_) matches = true;
                    }
                    std::string s;
                    for (auto& h : how) s += (s.empty() ? "" : ", ") + h;
                    if (independent) {
                        r.compat = "version-independent via " + s;
                        r.compatStatus = "ok";
                    } else if (matches) {
                        r.compat = "built for this exact runtime (" + runtimeStr_ + ")";
                        r.compatStatus = "ok";
                    } else {
                        std::string l;
                        for (auto& x : listed) l += (l.empty() ? "" : ", ") + x;
                        r.compat = "declares " + (l.empty() ? std::string("no runtimes") : l) + " — running " + runtimeStr_;
                        r.compatStatus = "bad";
                    }
                    if (vd.seVersionRequired && skseCorePacked_ && vd.seVersionRequired > skseCorePacked_) {
                        r.compat += "; needs SKSE " + UnpackVersion(vd.seVersionRequired) + " but " +
                                    UnpackVersion(skseCorePacked_) + " is loaded";
                        r.compatStatus = "bad";
                    }
                } else {
                    r.compat = "SKSEPlugin_Version export present but unreadable";
                    r.compatStatus = "warn";
                }
            } else if (r.skseLoadExport && r.skseQueryExport) {
                r.compat = "SE-era plugin (SKSEPlugin_Query only) — AE builds of SKSE normally refuse these";
                r.compatStatus = (runtimePacked_ >= PackVersion(1, 6, 0, 0)) ? "bad" : "ok";
            }

            // SE runtime (1.5.x): SKSE calls SKSEPlugin_Query, and the plugin checks the game version there itself.
            // SKSEPlugin_Version data is for AE's SKSE and doesn't apply.
            if (runtimePacked_ && runtimePacked_ < PackVersion(1, 6, 0, 0) && (r.skseLoadExport || r.skseVersionExport)) {
                if (r.skseQueryExport) {
                    r.compat = "SE plugin interface (SKSEPlugin_Query) — the plugin checks the game version itself when SKSE "
                               "loads it";
                    r.compatStatus = "ok";
                } else {
                    r.compat = "AE-only plugin (no SKSEPlugin_Query) — SE's SKSE doesn't load these, so something else did";
                    r.compatStatus = "warn";
                }
            }
            // skse64_1_5_97.dll / skse64_1_6_1170.dll (not skse64_steam_loader.dll)
            if (IStartsWith(m.e.name, L"skse64_") && m.e.name.size() > 7 && iswdigit(m.e.name[7]) && !runtimeStr_.empty()) {
                std::string expect = "skse64_" + std::to_string(runtimePacked_ >> 24) + "_" +
                                     std::to_string((runtimePacked_ >> 16) & 0xFF) + "_" +
                                     std::to_string((runtimePacked_ >> 4) & 0xFFF) + ".dll";
                if (LowerA(W2U(m.e.name)) == expect) {
                    r.compat = "matches the running game";
                    r.compatStatus = "ok";
                } else {
                    r.compat = "SKSE core built for a different runtime than " + runtimeStr_;
                    r.compatStatus = "bad";
                }
            }
        }

        void Engine::BuildDataRefs()
        {
            for (int i = 0; i < (int)mods_.size(); ++i) {
                Mod& m = mods_[i];
                if (!m.read || m.windows || m.game) continue;
                for (auto& s : m.pe.sections) {
                    if (s.Exec() || !s.Write()) continue;
                    uint32_t end = std::min<uint32_t>(s.va + s.Size(), (uint32_t)m.img.size());
                    for (uint32_t off = (s.va + 7) & ~7u; off + 8 <= end; off += 8) {
                        if ((off & 0xFFF) == 0 && !m.PageOk(off)) {
                            off += 0xFF8;
                            continue;
                        }
                        uint64_t v;
                        std::memcpy(&v, m.img.data() + off, 8);
                        if (v < 0x10000 || (v >> 47)) continue;
                        if (m.InExec(v)) continue;
                        if (IsCodeAddr(v)) m.dataRefs.push_back(v);
                    }
                }
                SortUnique(m.dataRefs);
            }
        }

        void Engine::ScanModule(int mi)
        {
            Mod& m = mods_[mi];
            if (!m.read || (!m.scanCode && !m.scanRdata)) return;
            std::vector<uint8_t> disk;
            std::string err;
            if (m.game) {
                if (!GameBaseline(mi, disk)) return;
                if (!m.noBaseline) gameDisk_ = disk;
            } else if (!LoadFileAsImage(m.e.physPath, m.e.base, disk, err)) {
                m.rec.scanNote = "not scanned: " + err + " (" + W2U(m.e.physPath) + ")";
                return;
            }
            size_t budget = kMaxPatchesPerModule;
            for (auto& s : m.pe.sections) {
                if (m.scanCode && s.Exec()) {
                    if (m.noBaseline) ScanCodeNoBaseline(mi, s, budget);
                    else ScanCode(mi, disk, s, budget);
                }
                if (m.scanRdata && !s.Exec() && !s.Write() && s.InitData() && s.name != ".rsrc" && s.name != ".reloc" &&
                    s.name != ".pdata")
                    ScanRdata(mi, disk, s, budget);
            }
            if (budget == 0) m.rec.scanNote += (m.rec.scanNote.empty() ? "" : "; ") + std::string("patch list truncated at 5000");
        }

        // Bytes of executable code that differ between the running module and a baseline image.
        size_t Engine::CodeDiff(const Mod& m, const std::vector<uint8_t>& disk) const
        {
            size_t diff = 0;
            for (auto& s : m.pe.sections) {
                if (!s.Exec()) continue;
                uint32_t b = (uint32_t)std::min<size_t>({ (size_t)s.va + s.Size(), m.img.size(), disk.size() });
                for (uint32_t pg = s.va; pg < b; pg = (pg | 0xFFF) + 1) {
                    if (!m.PageOk(pg)) continue;
                    uint32_t e = std::min<uint32_t>((pg | 0xFFF) + 1, b);
                    if (std::memcmp(m.img.data() + pg, disk.data() + pg, e - pg) == 0) continue;
                    for (uint32_t k = pg; k < e; ++k) diff += m.img[k] != disk[k];
                }
            }
            return diff;
        }

        // Builds the clean image SkyrimSE.exe is compared against: --clean-exe, the exe on disk, or the exe on disk
        // with Steam's DRM encryption undone. Falls back to baseline-free code scanning when none matches.
        bool Engine::GameBaseline(int mi, std::vector<uint8_t>& disk)
        {
            Mod& m = mods_[mi];
            size_t codeSize = 0;
            for (auto& s : m.pe.sections)
                if (s.Exec()) codeSize += s.Size();
            const size_t limit = std::max<size_t>(65536, codeSize / 50);
            std::string err;

            if (!opt_.cleanExe.empty()) {
                if (LoadFileAsImage(opt_.cleanExe, m.e.base, disk, err) && CodeDiff(m, disk) <= limit) {
                    rep_.baseline = "clean exe given with --clean-exe (" + W2U(FileNameOf(opt_.cleanExe)) + ")";
                    return true;
                }
                rep_.notes.push_back("--clean-exe file doesn't match the running game" + (err.empty() ? "" : " (" + err + ")") +
                                     "; ignoring it.");
            }

            std::vector<uint8_t> file;
            if (!ReadFileBytes(m.e.physPath, file) || !LoadBytesAsImage(file, m.e.base, disk, err)) {
                m.rec.scanNote = "not scanned: cannot read " + W2U(m.e.physPath);
                return false;
            }
            size_t diff = CodeDiff(m, disk);
            if (diff <= limit) {
                rep_.baseline = "SkyrimSE.exe on disk (not DRM-encrypted)";
                return true;
            }

            printf("  SkyrimSE.exe is encrypted on disk, decrypting for comparison...\n");
            SteamStubResult ss = DecryptSteamStub(file);
            size_t best = diff;
            std::vector<uint8_t> bestImg;
            if (!ss.plaintexts.empty()) {
                uint32_t rawOff = RvaToFileOffset(file, ss.codeRva);
                for (auto& pt : ss.plaintexts)
                    for (size_t skip : { (size_t)0, (size_t)16 }) {
                        if (!rawOff || pt.size() <= skip) continue;
                        std::vector<uint8_t> f2 = file;
                        size_t n = std::min({ pt.size() - skip, f2.size() - rawOff, (size_t)ss.codeRawSize });
                        std::memcpy(f2.data() + rawOff, pt.data() + skip, n);
                        std::vector<uint8_t> img;
                        if (!LoadBytesAsImage(f2, m.e.base, img, err)) continue;
                        size_t d = CodeDiff(m, img);
                        if (d < best) {
                            best = d;
                            bestImg = std::move(img);
                        }
                    }
            }
            if (!bestImg.empty() && best <= limit) {
                disk = std::move(bestImg);
                rep_.baseline = "SkyrimSE.exe on disk, Steam DRM decrypted in memory";
                return true;
            }

            m.noBaseline = true;
            rep_.baseline = "none — code hooks found by checking where calls and jumps lead (" +
                            (ss.wrapped ? std::string("Steam DRM found, but couldn't decrypt it to a copy that matches")
                                        : std::string("exe on disk doesn't match the running game")) +
                            ")";
            rep_.notes.push_back(
                "No clean copy of SkyrimSE.exe matched the running game, so hooks in game code were found by looking for calls and "
                "jumps that lead into DLLs. Byte patches in game code can't be seen in this mode, and chain/overwrite analysis "
                "isn't available for code hooks. Run HookMap with --clean-exe pointing at an unencrypted copy of this exact "
                "SkyrimSE.exe for a full scan.");
            return true;
        }

        // Without a baseline: a direct call/jump from game code to a function start in a DLL, or to a trampoline stub
        // or thunk that leads to one, is never part of the original exe.
        void Engine::ScanCodeNoBaseline(int mi, const PESection& sec, size_t& budget)
        {
            Mod& m = mods_[mi];
            const auto& mem = m.img;
            uint32_t a = sec.va;
            uint32_t b = (uint32_t)std::min<size_t>((size_t)sec.va + sec.Size(), mem.size());
            const uint64_t lo = m.e.base, hi = m.e.base + m.e.size;
            auto nearSite = [&](uint64_t site, const std::vector<uint64_t>& refs) {
                for (auto r : refs) {
                    if (r >= site - 0x400 && r <= site + 0x400) return true;
                    if (r >= lo && r < hi && IsFuncStart(mi, r)) return true;
                }
                return false;
            };
            auto blobStart = [&](uint64_t t) {
                size_t av = 0;
                int r = PrivAt(t);
                if (r < 0) return false;
                if (t == priv_[r].base) return true;
                const uint8_t* p = PrivBytes(t - 1, av);
                if (p && (p[0] == 0xC3 || p[0] == 0xCC)) return true;
                if (t - 14 >= priv_[r].base) {
                    p = PrivBytes(t - 14, av);
                    if (p && p[0] == 0xFF && p[1] == 0x25 && !p[2] && !p[3] && !p[4] && !p[5]) return true;
                }
                if (t - 5 >= priv_[r].base) {
                    p = PrivBytes(t - 5, av);
                    if (p && p[0] == 0xE9) return true;
                }
                return false;
            };

            for (uint32_t i = a; i + 5 <= b && budget;) {
                if (!m.PageOk(i)) {
                    i = (i | 0xFFF) + 1;
                    continue;
                }
                uint8_t op = mem[i];
                if (op != 0xE8 && op != 0xE9 && op != 0xFF && op != 0x48 && op != 0x49) {
                    ++i;
                    continue;
                }
                uint64_t site = m.e.base + i;
                Branch br = DecodeBranch(mem.data() + i, std::min<size_t>(32, mem.size() - i), site);
                uint64_t t = br.target;
                if (br.kind == BrKind::JmpInd) {
                    // only the inline absolute form: jmp [rip+0] ; dq target
                    if (br.slot != site + 6) br.kind = BrKind::None;
                    else {
                        std::memcpy(&t, mem.data() + i + 6, 8);
                        br.len = 14;
                    }
                }
                bool candidate = (br.kind == BrKind::Call || br.kind == BrKind::Jmp || br.kind == BrKind::JmpInd ||
                                     br.kind == BrKind::AbsJmp || br.kind == BrKind::AbsCall) &&
                                 br.len >= 5 && (t < lo || t >= hi);
                if (!candidate) {
                    ++i;
                    continue;
                }

                int tm = ModAt(t);
                int owner = -1;
                std::string how;
                Resolved res;
                if (Eligible(tm) && IsFuncStart(tm, t)) {
                    owner = tm;
                    how = "direct";
                } else if (tm < 0 && PrivAt(t) >= 0) {
                    res = Resolve(t);
                    if (Eligible(res.mod)) {
                        bool viaJump = res.how == "via trampoline";
                        if (viaJump && IsFuncStart(res.mod, res.final)) owner = res.mod, how = res.how;
                        else if (!viaJump && blobStart(t) && nearSite(site, res.thunkRefs)) owner = res.mod, how = res.how;
                    }
                }
                if (owner < 0) {
                    ++i;
                    continue;
                }

                uint32_t len = (uint32_t)br.len;
                size_t pad = i + len < b ? std::min<size_t>(PaddingLen(mem.data() + i + len, mem.size() - i - len), b - i - len) : 0;
                PatchRec rec;
                PInfo info;
                rec.inModule = W2U(m.e.name);
                rec.rva = i;
                rec.len = len + (uint32_t)pad;
                rec.kind = br.kind == BrKind::JmpInd ? "abs jmp" : BrKindName(br.kind);
                rec.kindNote = "found without a clean exe";
                rec.origBytes = "(no clean copy)";
                rec.newBytes = HexBytes(mem.data() + i, rec.len);
                rec.target = AddrText(res.final ? res.final : t);
                rec.owner = W2U(mods_[owner].e.name);
                rec.ownerHow = how;
                info.mod = mi;
                info.site = site;
                info.newTarget = t;
                info.owner = owner;
                info.hook = true;
                info.noBaseline = true;
                info.hops = res.hops;
                info.thunkRefs = res.thunkRefs;
                AddPatch(std::move(rec), std::move(info));
                --budget;
                i += len + (uint32_t)pad;
            }
        }

        void Engine::ScanCode(int mi, const std::vector<uint8_t>& disk, const PESection& sec, size_t& budget)
        {
            Mod& m = mods_[mi];
            const auto& mem = m.img;
            uint32_t a = sec.va;
            uint32_t b = (uint32_t)std::min<size_t>({ (size_t)sec.va + sec.Size(), mem.size(), disk.size() });
            if (a >= b) return;

            std::vector<std::pair<uint32_t, uint32_t>> ranges;
            size_t diffBytes = 0;
            uint32_t i = a;
            while (i < b) {
                if (!m.PageOk(i)) {
                    i = (i | 0xFFF) + 1;
                    continue;
                }
                uint32_t pageEnd = std::min<uint32_t>((i | 0xFFF) + 1, b);
                if ((i & 0xFFF) == 0 && std::memcmp(mem.data() + i, disk.data() + i, pageEnd - i) == 0) {
                    i = pageEnd;
                    continue;
                }
                uint32_t k = i;
                while (k < pageEnd && mem[k] == disk[k]) ++k;
                if (k == pageEnd) {
                    i = pageEnd;
                    continue;
                }
                i = k;
                if (m.pe.IsLoaderWritten(i)) {
                    ++i;
                    continue;
                }
                uint32_t start = i, last = i;
                uint32_t j = i + 1;
                while (j < b && j - last <= 3) {
                    if (!m.PageOk(j)) break;
                    if (mem[j] != disk[j] && !m.pe.IsLoaderWritten(j)) last = j;
                    ++j;
                }
                ranges.push_back({ start, last + 1 });
                diffBytes += last + 1 - start;
                i = last + 1;
            }
            size_t secSize = b - a;
            if (diffBytes > std::max<size_t>(65536, secSize / 10)) {
                std::string what = m.game ? "the on-disk SkyrimSE.exe does not match the running code (packed or DRM-wrapped exe?)"
                                          : "self-modifying or packed module";
                m.rec.scanNote += (m.rec.scanNote.empty() ? "" : "; ") + std::string("code section ") + sec.name + " skipped: " +
                                  std::to_string(diffBytes) + " bytes differ — " + what;
                if (m.game) rep_.notes.push_back("Game code scan skipped: " + what + ". Hooks in SkyrimSE.exe cannot be mapped.");
                return;
            }
            for (auto& r : ranges) {
                if (budget == 0) return;
                AnalyzeCodeRange(mi, disk, r.first, r.second, budget);
            }
        }

        void Engine::AnalyzeCodeRange(int mi, const std::vector<uint8_t>& disk, uint32_t a, uint32_t b, size_t& budget)
        {
            Mod& m = mods_[mi];
            const auto& mem = m.img;
            uint32_t cursor = a;
            bool first = true;
            while (cursor < b && budget) {
                Branch br;
                uint32_t pos = cursor;
                // The changed bytes may start mid-instruction (a retargeted E8 keeps its opcode byte), so look back up to
                // 4 bytes and pick the branch that best explains the whole change: one that covers the changed range,
                // is a full-size branch, and sits where the original file also had a branch of the same size.
                int bestScore = -1;
                for (uint32_t k = 0; k <= (first ? 4u : 0u) && k <= cursor; ++k) {
                    uint32_t p = cursor - k;
                    if (k && std::memcmp(mem.data() + p, disk.data() + p, k) != 0) break;
                    size_t avail = std::min<size_t>(32, mem.size() - p);
                    Branch t = DecodeBranch(mem.data() + p, avail, m.e.base + p);
                    if (!t.IsBranch() || p + (uint32_t)t.len <= cursor) continue;
                    Branch o = DecodeBranch(disk.data() + p, std::min<size_t>(32, disk.size() - p), m.e.base + p);
                    int score = (p + (uint32_t)t.len >= b ? 4 : 0) + (t.len >= 5 ? 2 : 0) + (o.IsBranch() && o.len == t.len ? 2 : 0);
                    if (score > bestScore) {
                        bestScore = score;
                        br = t;
                        pos = p;
                    }
                }
                first = false;

                PatchRec rec;
                PInfo info;
                rec.inModule = W2U(m.e.name);
                info.mod = mi;

                if (br.IsBranch()) {
                    uint64_t site = m.e.base + pos;
                    uint32_t len = (uint32_t)br.len;
                    uint32_t after = pos + len;
                    size_t pad = after < b ? std::min<size_t>(PaddingLen(mem.data() + after, mem.size() - after), b - after) : 0;
                    rec.rva = pos;
                    rec.len = len + (uint32_t)pad;
                    rec.kind = BrKindName(br.kind);
                    if (pad) rec.kindNote = "+" + std::to_string(pad) + " bytes padding";
                    rec.origBytes = HexBytes(disk.data() + pos, rec.len);
                    rec.newBytes = HexBytes(mem.data() + pos, rec.len);
                    info.site = site;

                    uint64_t target = br.target;
                    if (br.IsIndirect() && !ReadQ(br.slot, target)) target = 0;
                    info.newTarget = target;

                    Branch ob = DecodeBranch(disk.data() + pos, std::min<size_t>(32, disk.size() - pos), site);
                    if (ob.IsBranch()) {
                        uint64_t ot = ob.target;
                        if (ob.IsIndirect() && !ReadQ(ob.slot, ot)) ot = 0;
                        info.origTarget = ot;
                    } else {
                        info.detour = true;
                    }

                    int tm = ModAt(target);
                    bool local = tm == mi && (target > site ? target - site : site - target) < 0x20000 &&
                                 (br.kind == BrKind::Jmp || br.kind == BrKind::Jcc);
                    if (local) {
                        rec.kind = "flow";
                        if (ob.kind == BrKind::Jcc && br.kind == BrKind::Jmp) rec.kindNote = "conditional jump forced (jcc → jmp)";
                        else if (ob.IsBranch()) rec.kindNote = "branch retargeted inside the function";
                        else rec.kindNote = "jump inserted inside the function";
                        rec.target = AddrText(target);
                        rec.owner = kUnattributed;
                        rec.ownerHow = "unknown";
                        info.newBytes.assign(mem.begin() + pos, mem.begin() + pos + rec.len);
                    } else {
                        Resolved res = Resolve(target);
                        info.owner = res.mod;
                        info.hops = res.hops;
                        info.thunkRefs = res.thunkRefs;
                        info.hook = res.mod >= 0 && res.mod != mi;
                        rec.target = AddrText(res.final ? res.final : target);
                        if (res.mod == mi) {
                            rec.owner = kUnattributed;
                            rec.ownerHow = "redirects to other code in the same module";
                            info.owner = -1;
                        } else {
                            rec.owner = res.mod >= 0 ? W2U(mods_[res.mod].e.name) : kUnattributed;
                            rec.ownerHow = res.how;
                        }
                        if (info.detour && rec.kind != "flow") rec.kindNote += std::string(rec.kindNote.empty() ? "" : "; ") +
                                                                               "detour over original instructions";
                    }
                    AddPatch(std::move(rec), std::move(info));
                    --budget;
                    cursor = after + (uint32_t)pad;
                    continue;
                }

                // plain byte patch
                rec.rva = cursor;
                rec.len = b - cursor;
                rec.kind = "bytes";
                rec.origBytes = HexBytes(disk.data() + cursor, rec.len);
                rec.newBytes = HexBytes(mem.data() + cursor, rec.len);
                const uint8_t* p = mem.data() + cursor;
                bool allNop = true, allCC = true;
                for (uint32_t k = 0; k < rec.len; ++k) {
                    allNop &= p[k] == 0x90;
                    allCC &= p[k] == 0xCC;
                }
                if (allNop) rec.kindNote = "NOP-out (code removed)";
                else if (allCC) rec.kindNote = "INT3 fill";
                else if (p[0] == 0xC3 && disk[cursor] != 0xC3) rec.kindNote = "early return (function disabled)";
                else if (rec.len >= 3 && p[0] == 0xB0 && p[2] == 0xC3) rec.kindNote = "forced return value (mov al, imm; ret)";
                else if (rec.len >= 3 && p[0] == 0x33 && p[1] == 0xC0 && p[2] == 0xC3) rec.kindNote = "returns 0 (xor eax, eax; ret)";
                rec.owner = kUnattributed;
                rec.ownerHow = "unknown";
                info.site = m.e.base + cursor;
                info.newBytes.assign(mem.begin() + cursor, mem.begin() + b);
                AddPatch(std::move(rec), std::move(info));
                --budget;
                break;
            }
        }

        void Engine::ScanRdata(int mi, const std::vector<uint8_t>& disk, const PESection& sec, size_t& budget)
        {
            Mod& m = mods_[mi];
            const auto& mem = m.img;
            uint32_t a = (sec.va + 7) & ~7u;
            uint32_t b = (uint32_t)std::min<size_t>({ (size_t)sec.va + sec.Size(), mem.size(), disk.size() });
            uint32_t dataStart = 0, dataEnd = 0;
            auto flushData = [&]() {
                if (dataEnd <= dataStart || budget == 0) {
                    dataStart = dataEnd = 0;
                    return;
                }
                PatchRec rec;
                PInfo info;
                rec.inModule = W2U(m.e.name);
                rec.rva = dataStart;
                rec.len = dataEnd - dataStart;
                rec.kind = "data";
                rec.kindNote = "read-only data changed (" + sec.name + ")";
                rec.origBytes = HexBytes(disk.data() + dataStart, rec.len);
                rec.newBytes = HexBytes(mem.data() + dataStart, rec.len);
                rec.owner = kUnattributed;
                rec.ownerHow = "unknown";
                info.mod = mi;
                info.site = m.e.base + dataStart;
                info.newBytes.assign(mem.begin() + dataStart, mem.begin() + dataEnd);
                AddPatch(std::move(rec), std::move(info));
                --budget;
                dataStart = dataEnd = 0;
            };

            for (uint32_t off = a; off + 8 <= b && budget; off += 8) {
                if ((off & 0xFFF) == 0) {
                    if (!m.PageOk(off)) {
                        flushData();
                        off += 0xFF8;
                        continue;
                    }
                    uint32_t pe = std::min<uint32_t>(off + 0x1000, b);
                    if (std::memcmp(mem.data() + off, disk.data() + off, pe - off) == 0) {
                        flushData();
                        off += 0xFF8;
                        continue;
                    }
                }
                if (std::memcmp(mem.data() + off, disk.data() + off, 8) == 0 || m.pe.IsLoaderWritten(off)) {
                    flushData();
                    continue;
                }
                uint64_t nv, ov;
                std::memcpy(&nv, mem.data() + off, 8);
                std::memcpy(&ov, disk.data() + off, 8);
                if (IsCodeAddr(nv) && IsCodeAddr(ov)) {
                    flushData();
                    PatchRec rec;
                    PInfo info;
                    rec.inModule = W2U(m.e.name);
                    rec.rva = off;
                    rec.len = 8;
                    rec.kind = "vptr";
                    rec.kindNote = "virtual function / function pointer replaced";
                    rec.origBytes = AddrText(ov);
                    rec.newBytes = AddrText(nv);
                    Resolved res = Resolve(nv);
                    rec.target = AddrText(res.final ? res.final : nv);
                    rec.owner = res.mod >= 0 && res.mod != mi ? W2U(mods_[res.mod].e.name) : kUnattributed;
                    rec.ownerHow = res.how;
                    info.mod = mi;
                    info.site = m.e.base + off;
                    info.origTarget = ov;
                    info.newTarget = nv;
                    info.isVptr = true;
                    info.owner = res.mod != mi ? res.mod : -1;
                    info.hook = info.owner >= 0;
                    info.hops = res.hops;
                    info.thunkRefs = res.thunkRefs;
                    AddPatch(std::move(rec), std::move(info));
                    --budget;
                    continue;
                }
                if (dataEnd == off) dataEnd = off + 8;
                else {
                    flushData();
                    dataStart = off;
                    dataEnd = off + 8;
                }
            }
            flushData();
        }

        void Engine::CheckIats()
        {
            for (int mi = 0; mi < (int)mods_.size(); ++mi) {
                Mod& m = mods_[mi];
                if (!m.read || m.windows) continue;
                for (auto& d : m.pe.imports) {
                    std::wstring dllW = U2W(d.dll);
                    for (auto& f : d.funcs) {
                        uint64_t v = 0;
                        if (f.iatRva + 8 > m.img.size() || !m.PageOk(f.iatRva)) continue;
                        std::memcpy(&v, m.img.data() + f.iatRva, 8);
                        if (v == 0) continue;
                        int tm = ModAt(v);
                        if (tm == mi) continue;                       // unresolved delay-load thunk
                        if (tm >= 0 && mods_[tm].windows) continue;   // normal or forwarded system import
                        if (tm >= 0 && IEquals(mods_[tm].e.name, dllW)) continue;
                        if (d.delay && tm < 0 && PrivAt(v) < 0) continue;
                        Resolved res = Resolve(v);
                        PatchRec rec;
                        PInfo info;
                        rec.inModule = W2U(m.e.name);
                        rec.rva = f.iatRva;
                        rec.len = 8;
                        rec.kind = "iat";
                        rec.kindNote = std::string("import hooked") + (d.delay ? " (delay-load)" : "");
                        rec.location = d.dll + "!" + (f.name.empty() ? "#" + std::to_string(f.ordinal) : f.name);
                        rec.origBytes = "import from " + d.dll;
                        rec.newBytes = AddrText(v);
                        rec.target = AddrText(res.final ? res.final : v);
                        rec.owner = res.mod >= 0 ? W2U(mods_[res.mod].e.name) : kUnattributed;
                        rec.ownerHow = res.how;
                        rec.chainStatus = "n/a";
                        info.mod = mi;
                        info.site = m.e.base + f.iatRva;
                        info.newTarget = v;
                        info.isIat = true;
                        info.owner = res.mod;
                        info.hook = res.mod >= 0;
                        info.hops = res.hops;
                        AddPatch(std::move(rec), std::move(info));
                    }
                }
            }
        }

        void Engine::FindOrphanStubs()
        {
            struct Stub
            {
                uint64_t addr;
                int      mod;
            };
            std::vector<Stub> stubs;
            for (auto& r : priv_) {
                const auto& by = r.bytes;
                for (size_t i = 0; i + 14 <= by.size(); ++i) {
                    if (by[i] != 0xFF || by[i + 1] != 0x25 || by[i + 2] || by[i + 3] || by[i + 4] || by[i + 5]) continue;
                    uint64_t v;
                    std::memcpy(&v, by.data() + i + 6, 8);
                    int mi = ModAt(v);
                    if (!Eligible(mi) || !mods_[mi].InExec(v)) continue;
                    stubs.push_back({ r.base + i, mi });
                    i += 13;
                }
            }
            if (stubs.empty()) return;
            std::sort(stubs.begin(), stubs.end(), [](const Stub& a, const Stub& b) { return a.addr < b.addr; });
            std::vector<uint64_t> addrs;
            for (auto& s : stubs) addrs.push_back(s.addr);
            std::vector<bool> refd(stubs.size(), false);
            auto mark = [&](uint64_t v) {
                auto it = std::lower_bound(addrs.begin(), addrs.end(), v);
                if (it != addrs.end() && *it == v) refd[it - addrs.begin()] = true;
            };
            for (auto& m : mods_)
                for (auto v : m.dataRefs) mark(v);
            if (gameIdx_ >= 0) {
                Mod& g = mods_[gameIdx_];
                for (auto& s : g.pe.sections) {
                    if (s.Exec() || !s.Write()) continue;
                    uint32_t end = std::min<uint32_t>(s.va + s.Size(), (uint32_t)g.img.size());
                    for (uint32_t off = (s.va + 7) & ~7u; off + 8 <= end; off += 8) {
                        uint64_t v;
                        std::memcpy(&v, g.img.data() + off, 8);
                        if (v >= addrs.front() && v <= addrs.back()) mark(v);
                    }
                }
            }
            for (auto& r : priv_) {
                const auto& by = r.bytes;
                for (size_t i = 0; i + 8 <= by.size(); ++i) {
                    uint64_t v;
                    std::memcpy(&v, by.data() + i, 8);
                    if (v >= addrs.front() && v <= addrs.back()) mark(v);
                    if (by[i] == 0xE8 || by[i] == 0xE9) {
                        int32_t rel;
                        std::memcpy(&rel, by.data() + i + 1, 4);
                        mark(r.base + i + 5 + (int64_t)rel);
                    }
                }
            }
            for (auto& pi : pinfo_) {
                mark(pi.newTarget);
                for (auto h : pi.hops) mark(h);
            }
            for (size_t i = 0; i < stubs.size(); ++i)
                if (!refd[i]) mods_[stubs[i].mod].orphans.push_back(stubs[i].addr);
            for (auto& m : mods_) m.rec.orphanStubs = (int)m.orphans.size();
        }

        void Engine::AttributeBytePatches()
        {
            // index unattributed byte/data patches by their first 6 bytes
            std::unordered_map<uint64_t, std::vector<int>> byKey;
            std::vector<bool> first2(65536, false);
            for (int i = 0; i < (int)pinfo_.size(); ++i) {
                auto& pi = pinfo_[i];
                auto& pr = rep_.patches[pi.patch];
                if (pr.owner != kUnattributed || pi.newBytes.size() < 4) continue;
                bool uniform = std::all_of(pi.newBytes.begin(), pi.newBytes.end(), [&](uint8_t c) { return c == pi.newBytes[0]; });
                if (uniform) continue;
                size_t kl = std::min<size_t>(6, pi.newBytes.size());
                if (kl < 4) continue;
                uint64_t key = 0;
                std::memcpy(&key, pi.newBytes.data(), kl);
                key |= (uint64_t)kl << 56;
                byKey[key].push_back(i);
                first2[pi.newBytes[0] | (pi.newBytes[1] << 8)] = true;
            }
            if (byKey.empty()) return;
            std::vector<std::set<int>> found(pinfo_.size());
            for (int mi = 0; mi < (int)mods_.size(); ++mi) {
                Mod& m = mods_[mi];
                if (!m.read || m.windows || m.game) continue;
                for (auto& s : m.pe.sections) {
                    if (s.Exec() || !s.InitData() || s.name == ".rsrc" || s.name == ".reloc" || s.name == ".pdata") continue;
                    uint32_t end = std::min<uint32_t>(s.va + s.Size(), (uint32_t)m.img.size());
                    const uint8_t* d = m.img.data();
                    for (uint32_t i = s.va; i + 4 <= end; ++i) {
                        if (!first2[d[i] | (d[i + 1] << 8)]) continue;
                        for (size_t kl = 4; kl <= 6; ++kl) {
                            if (i + kl > end) break;
                            uint64_t key = 0;
                            std::memcpy(&key, d + i, kl);
                            key |= (uint64_t)kl << 56;
                            auto it = byKey.find(key);
                            if (it == byKey.end()) continue;
                            for (int pidx : it->second) {
                                auto& nb = pinfo_[pidx].newBytes;
                                if (i + nb.size() <= end && std::memcmp(d + i, nb.data(), nb.size()) == 0) found[pidx].insert(mi);
                            }
                        }
                    }
                }
            }
            for (size_t i = 0; i < pinfo_.size(); ++i) {
                if (found[i].empty()) continue;
                auto& pr = rep_.patches[pinfo_[i].patch];
                if (found[i].size() == 1) {
                    int mi = *found[i].begin();
                    pr.owner = W2U(mods_[mi].e.name);
                    pr.ownerHow = "byte pattern found in this DLL (inferred)";
                    pinfo_[i].owner = mi;
                } else {
                    for (int mi : found[i]) pr.otherRefs.push_back(W2U(mods_[mi].e.name));
                    pr.ownerHow = "byte pattern found in several DLLs";
                }
            }
        }

        // Code patches grouped by (scanned module, containing function). Values are indexes into pinfo_.
        std::map<std::pair<int, uint64_t>, std::vector<int>> Engine::FunctionGroups()
        {
            std::map<std::pair<int, uint64_t>, std::vector<int>> groups;
            for (int i = 0; i < (int)pinfo_.size(); ++i) {
                auto& pi = pinfo_[i];
                auto& pr = rep_.patches[pi.patch];
                if (pi.isIat || pi.isVptr || pr.kind == "data") continue;
                Mod& m = mods_[pi.mod];
                uint64_t key = pr.rva >> 12;
                if (m.game && alib_.Loaded()) {
                    if (auto h = alib_.Nearest(pr.rva); h && h->delta < 0x4000) key = (1ull << 63) | h->id;
                } else if (m.read) {
                    if (auto e = m.pe.NearestExport((uint32_t)pr.rva); e && pr.rva - e->rva < 0x4000) key = (1ull << 62) | e->rva;
                }
                groups[{ pi.mod, key }].push_back(i);
            }
            return groups;
        }

        // A NOP fill or forced jump next to a DLL's hook in the same function is almost always that DLL's doing.
        void Engine::InferSameFunctionOwners()
        {
            for (auto& [k, list] : FunctionGroups()) {
                std::set<int> owners;
                for (int i : list)
                    if (pinfo_[i].owner >= 0) owners.insert(pinfo_[i].owner);
                if (owners.size() != 1) continue;
                int o = *owners.begin();
                for (int i : list) {
                    auto& pr = rep_.patches[pinfo_[i].patch];
                    if (pinfo_[i].owner >= 0 || pr.owner != kUnattributed) continue;
                    pinfo_[i].owner = o;
                    pr.owner = W2U(mods_[o].e.name);
                    pr.ownerHow = "same function as this DLL's other patch (inferred)";
                }
            }
        }

        void Engine::AnalyzeChains()
        {
            // origTargets each module legitimately stores because it owns a patch with that original
            std::map<int, std::set<uint64_t>> ownedOrig;
            for (auto& pi : pinfo_)
                if (pi.owner >= 0 && pi.origTarget) ownedOrig[pi.owner].insert(pi.origTarget);

            for (auto& pi : pinfo_) {
                auto& pr = rep_.patches[pi.patch];
                if (pi.isIat) continue;
                if (pi.noBaseline) {
                    pr.chainStatus = "unknown — no clean copy of SkyrimSE.exe to compare against";
                    continue;
                }
                if (!pi.hook || pi.owner < 0 || !Eligible(pi.owner)) {
                    if (pr.chainStatus.empty()) pr.chainStatus = pi.hook ? "n/a" : "";
                    continue;
                }
                const int O = pi.owner;
                const uint64_t S = pi.site, T = pi.origTarget;
                auto isOrig = [&](const std::vector<uint64_t>& refs) {
                    if (T && SortedContains(refs, T)) return true;
                    if (pi.detour && SortedAnyInRange(refs, S + 1, S + 40)) return true;
                    return false;
                };

                std::vector<int> path;
                std::string status;
                if (isOrig(pi.thunkRefs)) {
                    path = { O };
                    status = "calls original (seen in hook thunk)";
                } else if (isOrig(mods_[O].dataRefs)) {
                    path = { O };
                    status = "calls original";
                } else {
                    // BFS through "module holds a pointer into another module's code" edges
                    std::map<int, int> parent;
                    std::vector<int> frontier = { O };
                    parent[O] = -1;
                    std::set<int> extraO;
                    for (auto v : pi.thunkRefs) {
                        int n = ResolveMod(v);
                        if (n != O && Eligible(n)) extraO.insert(n);
                    }
                    int found = -1;
                    for (int depth = 0; depth < 4 && found < 0 && !frontier.empty(); ++depth) {
                        std::vector<int> next;
                        for (int cur : frontier) {
                            std::vector<int> nb = Neighbors(cur);
                            if (cur == O) nb.insert(nb.end(), extraO.begin(), extraO.end());
                            for (int n : nb) {
                                if (parent.count(n)) continue;
                                parent[n] = cur;
                                if (isOrig(mods_[n].dataRefs)) {
                                    found = n;
                                    break;
                                }
                                next.push_back(n);
                            }
                            if (found >= 0) break;
                        }
                        frontier = std::move(next);
                    }
                    if (found >= 0) {
                        for (int c = found; c != -1; c = parent[c]) path.push_back(c);
                        std::reverse(path.begin(), path.end());
                        status = "chained";
                    }
                }

                // Other modules that merely hold the original target. That alone says nothing about this site
                // (any DLL that calls the function holds it), so it is only listed, never treated as a victim.
                // Victims come from FindTrampolineEvidence, which needs a stub tied to this exact site.
                for (int mi = 0; mi < (int)mods_.size(); ++mi) {
                    if (!Eligible(mi) || mi == O || std::find(path.begin(), path.end(), mi) != path.end()) continue;
                    if (!mods_[mi].read || !isOrig(mods_[mi].dataRefs)) continue;
                    if (T && ownedOrig.count(mi) && ownedOrig[mi].count(T)) continue;  // explained by its own patch
                    pr.otherRefs.push_back(W2U(mods_[mi].e.name));
                }
                for (int c : path) pr.chain.push_back(W2U(mods_[c].e.name));
                if (status.empty()) status = "no call-through found (replacement hook, or original kept somewhere HookMap can't see)";
                pr.chainStatus = status;
            }
        }

        // Private-memory code (trampolines, stubs, thunks) reachable from a patched site, following
        // site -> stub/thunk -> DLL -> trampolines that DLL stores -> next DLL -> ...  This is how hook chains link up.
        std::unordered_set<uint64_t> Engine::ReachFrom(const PInfo& pi)
        {
            std::unordered_set<uint64_t> seen;
            std::set<int> modsSeen;
            std::vector<uint64_t> work;
            if (pi.newTarget) work.push_back(pi.newTarget);
            work.insert(work.end(), pi.hops.begin(), pi.hops.end());
            work.insert(work.end(), pi.thunkRefs.begin(), pi.thunkRefs.end());
            auto visitMod = [&](int m) {
                if (!Eligible(m) || !modsSeen.insert(m).second || modsSeen.size() > 64) return;
                for (auto v : mods_[m].dataRefs)
                    if (PrivAt(v) >= 0) work.push_back(v);
            };
            if (pi.owner >= 0) visitMod(pi.owner);
            while (!work.empty() && seen.size() < 200000) {
                uint64_t a = work.back();
                work.pop_back();
                int m = ModAt(a);
                if (m >= 0) {
                    visitMod(m);
                    continue;
                }
                if (PrivAt(a) < 0 || !seen.insert(a).second) continue;
                Resolved r = Resolve(a);
                for (auto h : r.hops) seen.insert(h);
                if (r.mod >= 0) visitMod(r.mod);
                if (r.final && ModAt(r.final) < 0 && PrivAt(r.final) >= 0) work.push_back(r.final);
                for (auto t : r.thunkRefs) work.push_back(t);
            }
            return seen;
        }

        // Rule 1: a DLL is only called the victim of a patch when its trampoline for that exact site is found.
        // A trampoline holds the site's original instruction(s) (verbatim, or a relocated copy of a stolen call) and
        // jumps back to the end of the stolen range. If the DLL still stores the trampoline's address but no current
        // hook reaches it, the site was overwritten after that DLL hooked it. If the stolen range only partly lines up
        // with the current patch, the newer patch overlaps (ate) the earlier hook.
        void Engine::FindTrampolineEvidence()
        {
            if (gameDisk_.empty() || gameIdx_ < 0) return;
            Mod& g = mods_[gameIdx_];
            const uint64_t gb = g.e.base;

            struct Range
            {
                uint32_t lo, hi;
                int      pinfo;
            };
            std::vector<Range> ranges;
            for (int i = 0; i < (int)pinfo_.size(); ++i) {
                auto& pi = pinfo_[i];
                auto& pr = rep_.patches[pi.patch];
                if (pi.mod != gameIdx_ || pi.isVptr || pi.isIat || pr.kind == "data") continue;
                ranges.push_back({ (uint32_t)pr.rva, (uint32_t)(pr.rva + pr.len), i });
            }
            if (ranges.empty()) return;

            // Every address a current hook reaches.
            std::unordered_set<uint64_t> reached;
            for (auto& pi : pinfo_) {
                if (pi.newTarget) reached.insert(pi.newTarget);
                for (auto h : pi.hops) reached.insert(h);
                for (auto t : pi.thunkRefs) reached.insert(t);
            }

            struct Hit
            {
                uint64_t    stub = 0, jmpAt = 0, cont = 0;
                uint32_t    siteRva = 0, len = 0;
                uint32_t    minLen = 0;  // verbatim matches: any length from minLen..len fits, the stored address decides
                std::string matched;
            };
            std::vector<Hit> hits;
            const uint8_t* disk = gameDisk_.data();

            for (auto& r : priv_) {
                const auto& by = r.bytes;
                for (size_t k = 0; k + 5 <= by.size(); ++k) {
                    uint8_t op = by[k];
                    if (op != 0xE9 && op != 0xFF && op != 0x48 && op != 0x49 && op != 0x68) continue;
                    uint64_t J = r.base + k;
                    Branch b = DecodeBranch(by.data() + k, std::min<size_t>(32, by.size() - k), J);
                    if (!IsJumpKind(b.kind)) continue;
                    uint64_t C = b.target;
                    if (b.IsIndirect() && !ReadQ(b.slot, C)) continue;
                    if (C <= gb || C >= gb + g.e.size || !g.InExec(C)) continue;
                    uint32_t crva = (uint32_t)(C - gb);
                    if (crva > gameDisk_.size()) continue;

                    Hit h;
                    bool ok = false;
                    // Original bytes copied verbatim right before the jump back. Padding before a trampoline can
                    // match padding before the function, so every length that matches is kept as a candidate.
                    for (uint32_t L = 32; L >= 5 && !ok; --L) {
                        if (k < L || crva < L) continue;
                        if (std::memcmp(by.data() + k - L, disk + crva - L, L) != 0) continue;
                        h.stub = J - L;
                        h.siteRva = crva - L;
                        h.len = L;
                        h.minLen = 5;
                        ok = true;
                    }
                    // A stolen call (E8 rel32) relocated into the trampoline, optionally followed by verbatim bytes.
                    for (uint32_t L = 5; L <= 32 && !ok; ++L) {
                        if (crva < L) break;
                        uint32_t s = crva - L, tail = L - 5;
                        if (disk[s] != 0xE8 || k < tail) continue;
                        if (tail && std::memcmp(by.data() + k - tail, disk + s + 5, tail) != 0) continue;
                        int32_t rel;
                        std::memcpy(&rel, disk + s + 1, 4);
                        uint64_t T = gb + s + 5 + (int64_t)rel;
                        size_t end = k - tail;
                        for (size_t back = 5; back <= 24 && back <= end && !ok; ++back) {
                            size_t p = end - back;
                            Branch cb = DecodeBranch(by.data() + p, std::min<size_t>(32, by.size() - p), r.base + p);
                            size_t clen = (size_t)cb.len;
                            // call [rip+2] ; jmp +8 ; dq target
                            if (cb.kind == BrKind::CallInd && p + 8 <= by.size() && by[p + 6] == 0xEB && by[p + 7] == 0x08 &&
                                cb.slot == r.base + p + 8)
                                clen = 16;
                            if (clen != back) continue;
                            if (cb.kind != BrKind::Call && cb.kind != BrKind::CallInd && cb.kind != BrKind::AbsCall) continue;
                            uint64_t ct = cb.target;
                            if (cb.IsIndirect() && !ReadQ(cb.slot, ct)) continue;
                            if (ct != T) continue;
                            h.stub = r.base + p;
                            h.siteRva = s;
                            h.len = L;
                            h.minLen = L;
                            h.matched = "relocated copy of call " + AddrText(T) + " (original E8 " + HexBytes(disk + s + 1, 4) + ")" +
                                        (tail ? " + " + HexBytes(disk + s + 5, tail) : "");
                            ok = true;
                        }
                    }
                    if (!ok) continue;
                    h.jmpAt = J;
                    h.cont = C;
                    hits.push_back(std::move(h));
                }
            }

            std::sort(ranges.begin(), ranges.end(), [](const Range& a, const Range& b) { return a.lo < b.lo; });
            std::set<uint64_t> used;
            const bool dbg = !EnvVar(L"HOOKMAP_DEBUG").empty();
            auto holdersOf = [&](uint64_t a) {
                std::vector<int> v;
                for (int mi = 0; mi < (int)mods_.size(); ++mi)
                    if (Eligible(mi) && mods_[mi].read && SortedContains(mods_[mi].dataRefs, a)) v.push_back(mi);
                return v;
            };
            for (auto& h : hits) {
                // Anchor the trampoline start to an address some DLL actually stores (or a current hook reaches).
                std::vector<int> holders;
                bool anchored = false;
                for (uint32_t L = h.minLen; L <= h.len && !anchored; ++L) {
                    uint64_t a = h.jmpAt - L;
                    auto hv = holdersOf(a);
                    if (hv.empty() && !reached.count(a)) continue;
                    holders = std::move(hv);
                    h.stub = a;
                    h.siteRva = (uint32_t)(h.cont - gb) - L;
                    h.len = L;
                    anchored = true;
                }
                if (!anchored) continue;  // nobody stores or reaches it: can't say whose it is
                if (h.matched.empty()) h.matched = HexBytes(disk + h.siteRva, h.len, 40);
                if (dbg)
                    printf("[dbg] stub %llx site %x len %u cont %llx holders=%zu\n", (unsigned long long)h.stub, h.siteRva, h.len,
                        (unsigned long long)h.cont, holders.size());
                if (!used.insert(h.stub).second) continue;  // one stub explains one site

                const Range* hitRange = nullptr;
                for (auto& rg : ranges)
                    if (rg.lo < h.siteRva + h.len && h.siteRva < rg.hi) {
                        if (!hitRange || rg.lo == h.siteRva) hitRange = &rg;
                    }
                if (!hitRange) continue;  // nothing is patched there now (hook was removed)
                PInfo& pi = pinfo_[hitRange->pinfo];
                PatchRec& pr = rep_.patches[pi.patch];
                bool sameSite = hitRange->lo == h.siteRva;

                // Still reached from this site: it's how the current hook (or a hook it chains to) runs the original.
                bool local = ReachFrom(pi).count(h.stub) > 0;
                bool heldByPath = false;
                for (int x : holders) {
                    if (x == pi.owner) heldByPath = true;
                    for (auto& c : pr.chain)
                        if (c == W2U(mods_[x].e.name)) heldByPath = true;
                }
                if (local || heldByPath) {
                    if (sameSite && pr.chainStatus.rfind("no call-through found", 0) == 0) {
                        bool own = holders.empty() || (holders.size() == 1 && holders[0] == pi.owner);
                        if (own) {
                            pr.chainStatus = "calls original (through its trampoline)";
                        } else {
                            pr.chainStatus = "chained";
                            pr.chain.clear();
                            if (pi.owner >= 0) pr.chain.push_back(W2U(mods_[pi.owner].e.name));
                            for (int x : holders)
                                if (x != pi.owner) pr.chain.push_back(W2U(mods_[x].e.name));
                        }
                    }
                    continue;
                }
                if (holders.empty() || reached.count(h.stub)) continue;  // reached from elsewhere, or nobody to name

                bool overlap = !sameSite;
                std::string names;
                for (int x : holders) {
                    std::string n = W2U(mods_[x].e.name);
                    if (std::find(pr.victims.begin(), pr.victims.end(), n) == pr.victims.end()) pr.victims.push_back(n);
                    names += (names.empty() ? "" : ", ") + n;
                }
                auto add = [](std::string& f, const std::string& v) { f += (f.empty() ? "" : "; ") + v; };
                add(pr.stubAt, names + " trampoline at " + Hex(h.stub) + " (private memory), for site SkyrimSE.exe+" + Hex(h.siteRva));
                add(pr.stubMatched, h.matched);
                add(pr.stubReturns, "jumps back to SkyrimSE.exe+" + Hex(h.cont - gb) + " (jump at " + Hex(h.jmpAt) + ")");
                if (pr.evidenceKind.empty() || overlap) pr.evidenceKind = overlap ? "overlap" : "clobber";
                pr.chainStatus = overlap ? "overlaps " + names + "'s earlier hook at SkyrimSE.exe+" + Hex(h.siteRva)
                                         : "overwrote " + names + "'s hook (its trampoline is no longer reached)";
            }
        }

        void Engine::Locate()
        {
            for (auto& pi : pinfo_) {
                auto& pr = rep_.patches[pi.patch];
                if (!pr.location.empty()) continue;
                Mod& m = mods_[pi.mod];
                if (m.game) {
                    std::string loc;
                    if (pi.isVptr && haveNames_) {
                        if (auto vt = names_.VtableSlot(pr.rva))
                            loc = vt->first + " slot " + std::to_string(vt->second) + " (+" + Hex(vt->second * 8) + ")";
                    }
                    if (alib_.Loaded()) {
                        if (auto h = alib_.Nearest(pr.rva); h && h->delta < 0x8000) {
                            std::string idTxt = "ID " + std::to_string(h->id) + (h->delta ? " +" + Hex(h->delta) : "");
                            std::string nm = haveNames_ ? names_.NameOf(h->id) : std::string();
                            if (loc.empty()) loc = idTxt + (nm.empty() ? "" : " — " + nm);
                            else loc += " · " + idTxt;
                        }
                    }
                    if (loc.empty()) loc = "SkyrimSE.exe+" + Hex(pr.rva);
                    pr.location = loc;
                } else if (m.read) {
                    if (auto e = m.pe.NearestExport((uint32_t)pr.rva); e && pr.rva - e->rva < 0x4000)
                        pr.location = e->name + (pr.rva != e->rva ? "+" + Hex(pr.rva - e->rva) : "");
                    else pr.location = W2U(m.e.name) + "+" + Hex(pr.rva);
                }
            }
        }

        void Engine::ReadSkseLog()
        {
            std::wstring docs = DocumentsDir();
            std::wstring best;
            FILETIME bestT{};
            for (auto sub : { L"Skyrim Special Edition", L"Skyrim Special Edition GOG" }) {
                std::wstring p = docs + L"\\My Games\\" + sub + L"\\SKSE\\skse64.log";
                if (auto t = FileWriteTime(p)) {
                    if (best.empty() || CompareFileTime(&*t, &bestT) > 0) {
                        best = p;
                        bestT = *t;
                    }
                }
            }
            if (best.empty()) {
                rep_.skseLogFile = "skse64.log not found";
                return;
            }
            rep_.skseLogFile = W2U(best);
            if (auto ct = proc_.CreationTime(); ct && CompareFileTime(&bestT, &*ct) < 0) {
                rep_.skseLogFile += " (older than the running game — ignored)";
                return;
            }
            std::string text;
            if (!ReadFileText(best, text)) return;
            std::map<std::string, std::string> status;  // lower name -> status
            size_t pos = 0;
            while (pos < text.size()) {
                size_t nl = text.find('\n', pos);
                std::string line = Trim(text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
                pos = nl == std::string::npos ? text.size() : nl + 1;
                std::string low = LowerA(line);
                size_t dll = low.find(".dll");
                if (dll == std::string::npos || low.rfind("checking plugin", 0) == 0) continue;
                if (low.rfind("plugin ", 0) != 0 && low.rfind("couldn't load plugin", 0) != 0) continue;
                size_t slash = line.find_last_of("\\/", dll);
                std::string name = LowerA(line.substr(slash == std::string::npos ? 0 : slash + 1, dll + 4 - (slash == std::string::npos ? 0 : slash + 1)));
                if (low.find("loaded correctly") != std::string::npos) status[name] = "loaded correctly";
                else if (auto d = low.find("disabled"); d != std::string::npos) status[name] = line.substr(d);
                else if (low.rfind("couldn't load", 0) == 0) status[name] = "couldn't load" + line.substr(dll + 4);
                else if (low.find("reported as incompatible") != std::string::npos) status[name] = "reported as incompatible";
            }
            std::set<std::string> loaded;
            for (auto& m : mods_) {
                std::string ln = LowerA(W2U(m.e.name));
                loaded.insert(ln);
                if (auto it = status.find(ln); it != status.end()) m.rec.skseLog = it->second;
            }
            for (auto& [name, st] : status) {
                if (st == "loaded correctly" || loaded.count(name)) continue;
                ConflictRec c;
                c.severity = kMedium;
                c.category = "skse-log";
                c.title = "SKSE did not load " + name;
                c.detail = "skse64.log: " + st;
                c.modules = { name };
                c.key = "skse-log|" + name;
                rep_.conflicts.push_back(std::move(c));
            }
        }

        void Engine::BuildConflicts()
        {
            auto& out = rep_.conflicts;
            auto modsText = [](const std::vector<std::string>& v) {
                std::string s;
                for (auto& x : v) s += (s.empty() ? "" : ", ") + x;
                return s;
            };

            auto verb = [](const std::vector<std::string>& v) { return v.size() > 1 ? std::string("hold") : std::string("holds"); };
            auto strongOwner = [](const PatchRec& pr) { return pr.ownerHow == "direct" || pr.ownerHow == "via trampoline"; };
            auto siteText = [](const PatchRec& pr) {
                std::string w = pr.location;
                if (auto plus = w.find(" +"); plus != std::string::npos && w.rfind("ID ", 0) == 0) {
                    auto dash = w.find(" — ");
                    w = w.substr(0, plus) + (dash != std::string::npos ? w.substr(dash) : "");
                }
                return w;
            };

            // 1. clobbers and overlaps — only with a trampoline tied to the site (rule 1); chained shared sites
            for (auto& pi : pinfo_) {
                auto& pr = rep_.patches[pi.patch];
                if (!pr.victims.empty() && !pr.stubAt.empty()) {
                    ConflictRec c;
                    bool overlap = pr.evidenceKind == "overlap";
                    c.severity = strongOwner(pr) ? kHigh : kMedium;
                    c.category = overlap ? "overlap" : "clobber";
                    if (overlap) {
                        c.title = pr.owner + "'s patch at " + pr.location + " overlaps " + modsText(pr.victims) + "'s earlier hook";
                        c.detail = "The " + std::to_string(pr.len) + "-byte " + pr.kind + " at " + pr.inModule + "+" + Hex(pr.rva) +
                                   " (owner " + pr.owner + ", " + pr.ownerHow + ") covers bytes that " + modsText(pr.victims) +
                                   " had already hooked, without starting at the same instruction, so the two can't chain. Evidence: " +
                                   pr.stubAt + "; it holds the original bytes " + pr.stubMatched + " and " + pr.stubReturns +
                                   ". Nothing reaches that trampoline any more, so " + modsText(pr.victims) + "'s hook there never runs.";
                    } else {
                        c.title = pr.owner + " overwrote " + modsText(pr.victims) + "'s hook at " + pr.location;
                        c.detail = "The " + pr.kind + " at " + pr.inModule + "+" + Hex(pr.rva) + " now goes to " + pr.owner + " (" +
                                   pr.ownerHow + "). Evidence: " + pr.stubAt + "; it holds this site's original bytes " + pr.stubMatched +
                                   " and " + pr.stubReturns + ". " + modsText(pr.victims) + " still " + verb(pr.victims) +
                                   " that trampoline's address but no hook reaches it any more, so " + modsText(pr.victims) +
                                   "'s hook here never runs. Fix: change load order, or ask the author of " + pr.owner +
                                   " to call through the previous target instead of the original.";
                    }
                    if (!strongOwner(pr))
                        c.detail += " Severity lowered: the current owner (" + pr.owner + ") is inferred, not read directly.";
                    c.modules = { pr.owner };
                    c.modules.insert(c.modules.end(), pr.victims.begin(), pr.victims.end());
                    c.patches = { pr.id };
                    c.key = c.category + "|" + pr.inModule + "|" + Hex(pr.rva) + "|" + modsText(c.modules);
                    out.push_back(std::move(c));
                }
                if (pr.chain.size() >= 2) {
                    ConflictRec c;
                    c.severity = kLow;
                    c.category = "shared-site";
                    c.title = "Shared hook at " + pr.location + ": " + modsText(pr.chain);
                    c.detail = "Several DLLs hook the same spot and each appears to call through to the next (" +
                               modsText(pr.chain) + " → original). Usually fine; the order is decided by load order.";
                    c.modules = pr.chain;
                    c.patches = { pr.id };
                    c.key = "shared|" + pr.inModule + "|" + Hex(pr.rva);
                    out.push_back(std::move(c));
                }
            }

            // 1b. overlapping patch records (two recorded patches whose byte ranges overlap)
            {
                std::map<int, std::vector<int>> byMod;
                for (auto& pi : pinfo_) {
                    auto& pr = rep_.patches[pi.patch];
                    if (pi.isIat || pi.isVptr || pr.kind == "data") continue;
                    byMod[pi.mod].push_back(pi.patch);
                }
                for (auto& [mi, list] : byMod) {
                    std::sort(list.begin(), list.end(), [&](int x, int y) { return rep_.patches[x].rva < rep_.patches[y].rva; });
                    for (size_t i = 1; i < list.size(); ++i) {
                        auto& p = rep_.patches[list[i - 1]];
                        auto& q = rep_.patches[list[i]];
                        uint64_t pEnd = p.rva + p.len;
                        if (q.rva < pEnd && q.rva != p.rva) {
                            ConflictRec c;
                            c.severity = (strongOwner(p) && strongOwner(q)) ? kHigh : kMedium;
                            c.category = "overlap";
                            c.title = "Overlapping patches at " + p.location + ": " + p.owner + " and " + q.owner;
                            c.detail = p.inModule + "+" + Hex(p.rva) + " (" + std::to_string(p.len) + " bytes, " + p.owner + ") and +" +
                                       Hex(q.rva) + " (" + std::to_string(q.len) + " bytes, " + q.owner +
                                       ") share bytes but start at different instructions, so they can't chain.";
                            c.modules = { p.owner, q.owner };
                            c.patches = { p.id, q.id };
                            c.key = "overlap2|" + p.inModule + "|" + Hex(p.rva) + "|" + Hex(q.rva);
                            out.push_back(std::move(c));
                        } else if (q.rva >= pEnd && q.rva - pEnd < 16 && p.owner != q.owner &&
                                   (p.owner != kUnattributed || q.owner != kUnattributed)) {
                            ConflictRec c;
                            c.severity = kMedium;
                            c.category = "near";
                            uint64_t gap = q.rva - pEnd;
                            std::string gapText = gap == 0 ? std::string("right next to each other")
                                                           : std::to_string(gap) + (gap == 1 ? " byte apart" : " bytes apart");
                            c.title = "Patches " + gapText + " at " + siteText(p) + ": " + p.owner + " and " + q.owner;
                            c.detail = p.inModule + "+" + Hex(p.rva) + " (" + std::to_string(p.len) + " bytes, " + p.owner + ") " +
                                       (gap == 0 ? std::string("ends exactly where +") + Hex(q.rva) + " (" + q.owner + ") starts"
                                                 : "ends " + gapText.substr(0, gapText.size() - 6) + " before +" + Hex(q.rva) + " (" +
                                                       q.owner + ")") +
                                       ". They don't share bytes, but a later update that hooks a slightly longer range would collide.";
                            c.modules = { p.owner, q.owner };
                            c.patches = { p.id, q.id };
                            c.key = "near|" + p.inModule + "|" + Hex(p.rva) + "|" + Hex(q.rva);
                            out.push_back(std::move(c));
                        }
                    }
                }
            }

            // 1c. hooks that call a game function another DLL has detoured: both run (one Info note per function)
            if (gameIdx_ >= 0) {
                const uint64_t gb = mods_[gameIdx_].e.base;
                std::map<uint64_t, int> detourAt;  // entry rva -> patch index
                for (auto& pi : pinfo_) {
                    auto& pr = rep_.patches[pi.patch];
                    if (pi.mod != gameIdx_ || pi.isVptr || pi.isIat || pi.owner < 0) continue;
                    if (pr.kind == "jmp" || pr.kind == "abs jmp" || pr.kind == "jmp [ptr]") detourAt[pr.rva] = pi.patch;
                }
                std::map<uint64_t, std::vector<int>> callers;
                for (auto& pi : pinfo_) {
                    auto& pr = rep_.patches[pi.patch];
                    if (!pi.origTarget || pi.origTarget < gb || pi.origTarget >= gb + mods_[gameIdx_].e.size) continue;
                    if (pr.chainStatus.rfind("calls original", 0) != 0 && pr.chainStatus != "chained") continue;
                    auto it = detourAt.find(pi.origTarget - gb);
                    if (it == detourAt.end() || rep_.patches[it->second].owner == pr.owner) continue;
                    callers[pi.origTarget - gb].push_back(pi.patch);
                }
                for (auto& [rva, list] : callers) {
                    auto& d = rep_.patches[detourAt[rva]];
                    std::set<std::string> owners;
                    for (int p : list) owners.insert(rep_.patches[p].owner);
                    std::vector<std::string> ow(owners.begin(), owners.end());
                    ConflictRec c;
                    c.severity = kInfo;
                    c.category = "entry-detour";
                    std::string nm = siteText(d);
                    std::string at = "SkyrimSE.exe+" + Hex(rva);
                    c.title = std::to_string(list.size()) + " hook(s) by " + modsText(ow) + " call " + at +
                              (nm != at ? " (" + nm + ")" : std::string()) + ", which is detoured by " + d.owner + ", so " + d.owner +
                              " still runs";
                    c.detail = "Calling the function's entry runs " + d.owner + "'s detour first. Nothing is skipped.";
                    c.modules = ow;
                    c.modules.push_back(d.owner);
                    c.patches = list;
                    c.patches.push_back(d.id);
                    c.key = "entry|" + Hex(rva);
                    out.push_back(std::move(c));
                }
            }

            // 2. same function patched by different owners — context, not a collision
            for (auto& [k, idxs] : FunctionGroups()) {
                std::vector<int> list;
                for (int i : idxs) list.push_back(pinfo_[i].patch);
                std::set<std::string> owners;
                bool anyUnknown = false;
                for (int p : list) {
                    auto& o = rep_.patches[p].owner;
                    if (o == kUnattributed) anyUnknown = true;
                    else owners.insert(o);
                }
                if (owners.size() < 2) continue;
                auto& p0 = rep_.patches[list.front()];
                ConflictRec c;
                c.severity = kInfo;
                c.category = "same-function";
                c.modules.assign(owners.begin(), owners.end());
                if (anyUnknown) c.modules.push_back(kUnattributed);
                c.title = "Busy function: " + siteText(p0) + " in " + p0.inModule + " — " + std::to_string(list.size()) +
                          " patches from " + std::to_string(c.modules.size()) + " DLLs";
                c.detail = "These patches are at different places in the same function and don't share any bytes. "
                           "That's a crowded function, not a collision. Patches that actually overlap or sit within a few bytes "
                           "of each other are listed separately.";
                c.patches = list;
                c.key = "samefn|" + p0.inModule + "|" + siteText(p0) + "|" + modsText(c.modules);
                out.push_back(std::move(c));
            }

            // 3. cross-module patches (a DLL patching another non-game, non-Windows DLL)
            std::map<std::pair<int, std::string>, std::vector<int>> cross;
            for (auto& pi : pinfo_) {
                auto& pr = rep_.patches[pi.patch];
                Mod& m = mods_[pi.mod];
                if (m.game || m.windows || pi.isIat) continue;
                cross[{ pi.mod, pr.owner }].push_back(pi.patch);
            }
            static const std::set<std::string> kCodeKinds = { "bytes", "flow", "call", "jmp", "jcc", "abs jmp", "abs call" };
            for (auto& [k, list] : cross) {
                ConflictRec c;
                c.severity = kMedium;
                c.category = "cross-module";
                std::string target = W2U(mods_[k.first].e.name);
                bool codeBytes = false;
                for (int p : list) codeBytes |= kCodeKinds.count(rep_.patches[p].kind) > 0;
                c.title = (k.second == kUnattributed ? std::string("Unattributed patches inside ") : k.second + " patches code inside ") +
                          target + " (" + std::to_string(list.size()) + ")";
                c.detail = "Code inside " + target + " differs from its file on disk." +
                           (codeBytes ? " If " + target + " is updated, these patches can land on the wrong bytes and crash."
                                      : std::string(" These are pointer/import redirects that are re-made each time the game loads, "
                                                    "so they don't depend on " + target + "'s exact code."));
                if (!codeBytes) c.severity = kLow;
                c.modules = { target };
                if (k.second != kUnattributed) c.modules.push_back(k.second);
                c.patches = list;
                c.key = "cross|" + target + "|" + k.second;
                out.push_back(std::move(c));
            }

            // 4. IAT hooks
            std::map<std::string, std::vector<int>> iat;
            for (auto& pi : pinfo_)
                if (pi.isIat) iat[rep_.patches[pi.patch].owner + "|" + rep_.patches[pi.patch].inModule].push_back(pi.patch);
            for (auto& [k, list] : iat) {
                auto& p0 = rep_.patches[list.front()];
                ConflictRec c;
                c.severity = kLow;
                c.category = "iat";
                c.title = p0.owner + " hooks " + std::to_string(list.size()) + " import(s) of " + p0.inModule;
                std::string fns;
                for (size_t i = 0; i < list.size() && i < 8; ++i) fns += (i ? ", " : "") + rep_.patches[list[i]].location;
                if (list.size() > 8) fns += ", …";
                c.detail = "Import table entries redirected: " + fns + ".";
                c.modules = { p0.owner, p0.inModule };
                c.patches = list;
                c.key = "iat|" + k;
                out.push_back(std::move(c));
            }

            // 5. exception handler stacking — importing the API is not proof a handler is registered
            static const std::set<std::wstring> kNotGuards = { L"bink2w64.dll", L"usvfs_x64.dll" };
            std::vector<std::string> veh;
            for (auto& m : mods_)
                if (m.registersVeh && !m.windows && !kNotGuards.count(Lower(m.e.name))) veh.push_back(W2U(m.e.name));
            if (veh.size() >= 2) {
                ConflictRec c;
                c.severity = kMedium;
                c.category = "veh";
                c.title = std::to_string(veh.size()) + " DLLs import a vectored-exception API (not proof a handler is registered)";
                c.detail = "Each of these can register a handler that sees (and can swallow or \"fix\") a crash before the others "
                           "and before Crash Logger. Stacked guards can turn a clean crash into a freeze or a later, "
                           "unrelated-looking crash. Whether each one actually registers a handler, and in what order, can't be "
                           "read from outside the process: " + modsText(veh) + ".";
                c.modules = veh;
                c.key = "veh|" + modsText(veh);
                out.push_back(std::move(c));
            }

            // 6. compatibility
            for (auto& m : mods_) {
                if (m.rec.compatStatus != "bad") continue;
                ConflictRec c;
                c.severity = kHigh;
                c.category = "compat";
                c.title = W2U(m.e.name) + ": built for a different game/SKSE version";
                c.detail = m.rec.compat;
                c.modules = { W2U(m.e.name) };
                c.key = "compat|" + W2U(m.e.name);
                out.push_back(std::move(c));
            }

            // 7. orphaned stubs not already explained by a clobber
            std::set<std::string> inClobber;
            for (auto& c : out)
                if (c.category == "clobber" || c.category == "overlap")
                    for (auto& m : c.modules) inClobber.insert(m);
            for (auto& m : mods_) {
                if (m.orphans.empty() || inClobber.count(W2U(m.e.name))) continue;
                ConflictRec c;
                c.severity = kLow;
                c.category = "orphan";
                c.title = W2U(m.e.name) + " has " + std::to_string(m.orphans.size()) + " jump stub(s) nothing points to";
                c.detail = "Small jump stubs that lead into " + W2U(m.e.name) +
                           " exist, but no patched site, stored pointer or thunk references them. Often a hook the DLL "
                           "installed and later removed, or spare trampoline space. They aren't tied to any particular site, "
                           "so this says nothing about other DLLs.";
                c.modules = { W2U(m.e.name) };
                c.key = "orphan|" + W2U(m.e.name);
                out.push_back(std::move(c));
            }

            // 8. scan notes
            for (auto& m : mods_) {
                if (m.rec.scanNote.empty() || m.windows) continue;
                ConflictRec c;
                c.severity = kInfo;
                c.category = "scan";
                c.title = W2U(m.e.name) + ": " + m.rec.scanNote;
                c.modules = { W2U(m.e.name) };
                c.key = "scan|" + W2U(m.e.name);
                out.push_back(std::move(c));
            }

            // 9. unattributed patches in the game, summarized
            {
                std::map<std::string, std::vector<int>> un;
                for (auto& pi : pinfo_) {
                    auto& pr = rep_.patches[pi.patch];
                    if (pr.owner == kUnattributed && mods_[pi.mod].game) un[pr.kind].push_back(pr.id);
                }
                for (auto& [kind, list] : un) {
                    ConflictRec c;
                    c.severity = kInfo;
                    c.category = "unattributed";
                    c.title = std::to_string(list.size()) + " " + kind + " patch(es) in SkyrimSE.exe with no identifiable owner";
                    c.detail = "Usually small fixes (NOP-outs, forced jumps, changed constants) written by fix-it DLLs. "
                               "Their bytes didn't match any DLL's data, so the writer can't be named.";
                    c.patches = list;
                    c.key = "unattributed|" + kind;
                    out.push_back(std::move(c));
                }
            }

            // expected / allowlist demotion
            for (auto& c : out) {
                bool all = !c.modules.empty();
                for (auto& m : c.modules)
                    if (m == kUnattributed || !Allowlisted(U2W(m), nullptr)) all = false;
                if (all) {
                    c.expected = true;
                    if (c.severity > kInfo) c.severity -= 1;
                }
            }
            std::stable_sort(out.begin(), out.end(), [](const ConflictRec& a, const ConflictRec& b) {
                if (a.expected != b.expected) return !a.expected;
                if (a.severity != b.severity) return a.severity > b.severity;
                return a.modules.size() > b.modules.size();
            });
        }

        // ------------------------------------------------------------ run

        void Engine::Run(std::vector<std::pair<std::wstring, std::wstring>>& repl)
        {
            rep_.generated = NowLocalString();
            printf("Reading process...\n");
            LoadModules();
            if (gameIdx_ < 0) {
                rep_.notes.push_back("SkyrimSE.exe module not found in the process.");
                return;
            }
            rep_.gameExe = W2U(mods_[gameIdx_].e.physPath);
            {
                std::string started;
                if (auto ct = proc_.CreationTime()) started = ", started " + FileTimeToLocalString(*ct);
                rep_.processInfo = "SkyrimSE.exe, PID " + std::to_string(proc_.Pid()) + started;
            }
            FindMo2Roots();
            LoadAllowlist();
            printf("Loading Address Library and names...\n");
            LoadAddressLibrary();
            LoadNames();

            for (auto& m : mods_)
                if (IStartsWith(m.e.name, L"skse64_") && m.e.name.size() > 7 && iswdigit(m.e.name[7])) {
                    FileVer fv = GetFileVer(m.e.physPath);
                    // SKSE stamps its DLL as 0.major.minor.beta (2.2.6 -> 0.2.2.6); plugins request 2.2.x.
                    if (fv.ok)
                        skseCorePacked_ = fv.v[0] == 0 ? PackVersion(fv.v[1], fv.v[2], fv.v[3], 0)
                                                       : PackVersion(fv.v[0], fv.v[1], fv.v[2], fv.v[3]);
                }

            printf("Analyzing DLLs...\n");
            for (auto& m : mods_) {
                auto& r = m.rec;
                r.name = W2U(m.e.name);
                r.path = W2U(m.e.path);
                r.physPath = W2U(m.e.physPath);
                r.base = Hex(m.e.base);
                r.size = m.e.size;
                r.windows = m.windows;
                r.category = Categorize(m, gameDir_);
                r.source = SourceOf(m, gameDir_, modsDirs_);
                r.allowlisted = Allowlisted(m.e.name, &r.allowNote);
                if (m.read && !m.windows) StaticAnalyze(m);
            }

            printf("Reading trampolines and thunks...\n");
            priv_ = proc_.PrivateExecRegions(64ull << 20);
            std::sort(priv_.begin(), priv_.end(), [](const MemRegion& a, const MemRegion& b) { return a.base < b.base; });
            BuildDataRefs();

            size_t n = 0, total = 0;
            for (auto& m : mods_) total += (m.read && (m.scanCode || m.scanRdata)) ? 1 : 0;
            for (int i = 0; i < (int)mods_.size(); ++i) {
                if (!mods_[i].read || (!mods_[i].scanCode && !mods_[i].scanRdata)) continue;
                printf("\r  comparing against disk %zu/%zu", ++n, total);
                ScanModule(i);
            }
            printf("\n");
            CheckIats();
            printf("Attributing patches...\n");
            FindOrphanStubs();
            AttributeBytePatches();
            InferSameFunctionOwners();
            AnalyzeChains();
            FindTrampolineEvidence();
            Locate();

            for (auto& pi : pinfo_) {
                if (pi.owner >= 0) mods_[pi.owner].rec.patchesOwned++;
                mods_[pi.mod].rec.patchesInside++;
            }

            ReadSkseLog();
            BuildConflicts();

            rep_.notes.push_back("Exception handler registration order can't be read from outside the process; the census shows "
                                 "which DLLs can register handlers, not the order they run in.");
            rep_.notes.push_back("SetUnhandledExceptionFilter is imported by nearly every MSVC binary through the CRT, so it is "
                                 "only listed when a DLL looks it up by name at runtime.");
            rep_.notes.push_back("Writable game data (.data) is not compared; patches made there are invisible to this scan.");
            rep_.notes.push_back("Owner attribution marked \"inferred\" is a best guess (thunk voting or byte-pattern match).");
            rep_.notes.push_back("An \"overwrote\" verdict is only given when the earlier hook's trampoline was found: it holds the "
                                 "site's original bytes, jumps back to the site, and nothing reaches it any more. A DLL that merely "
                                 "holds the original address is listed under \"also references original\" and is never called a victim.");
            if (!priv_.empty())
                rep_.notes.push_back(std::to_string(priv_.size()) + " executable private memory regions (trampolines/thunks) examined.");

            for (auto& m : mods_) rep_.modules.push_back(m.rec);

            // --share replacements: longest/specific first
            for (auto& r : mo2Roots_) repl.push_back({ r, L"<MO2>" });
            if (!gameDir_.empty()) repl.push_back({ gameDir_, L"<Game>" });
            std::wstring profile = EnvVar(L"USERPROFILE");
            if (!profile.empty()) repl.push_back({ profile, L"%USERPROFILE%" });
            std::wstring user = UserName();
            if (user.size() >= 3) repl.push_back({ user, L"<user>" });
            std::wstring pc = ComputerName();
            if (pc.size() >= 3) repl.push_back({ pc, L"<pc>" });
        }
    }

    void Analyze(RemoteProcess& proc, const Options& opt, Report& report,
        std::vector<std::pair<std::wstring, std::wstring>>& shareRepl)
    {
        Engine e(proc, opt, report);
        e.Run(shareRepl);
    }
}
