#include "Analyzer.h"

#include "AddressLib.h"
#include "Disasm.h"
#include "PEImage.h"

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
            void AnalyzeCodeRange(int mi, const std::vector<uint8_t>& disk, uint32_t a, uint32_t b, size_t& budget);
            void ScanRdata(int mi, const std::vector<uint8_t>& disk, const PESection& sec, size_t& budget);
            void CheckIats();
            void FindOrphanStubs();
            void AttributeBytePatches();
            std::map<std::pair<int, uint64_t>, std::vector<int>> FunctionGroups();
            void InferSameFunctionOwners();
            void AnalyzeChains();
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
            if (!names_.LoadCommonLib(root, err)) {
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
            if (IStartsWith(m.e.name, L"skse64_") && !runtimeStr_.empty()) {
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
            if (!LoadFileAsImage(m.e.physPath, m.e.base, disk, err)) {
                m.rec.scanNote = "not scanned: " + err + " (" + W2U(m.e.physPath) + ")";
                return;
            }
            size_t budget = kMaxPatchesPerModule;
            for (auto& s : m.pe.sections) {
                if (m.scanCode && s.Exec()) ScanCode(mi, disk, s, budget);
                if (m.scanRdata && !s.Exec() && !s.Write() && s.InitData() && s.name != ".rsrc" && s.name != ".reloc" &&
                    s.name != ".pdata")
                    ScanRdata(mi, disk, s, budget);
            }
            if (budget == 0) m.rec.scanNote += (m.rec.scanNote.empty() ? "" : "; ") + std::string("patch list truncated at 5000");
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
                for (uint32_t k = 0; k <= (first ? 4u : 0u) && k <= cursor; ++k) {
                    uint32_t p = cursor - k;
                    if (k && std::memcmp(mem.data() + p, disk.data() + p, k) != 0) break;
                    size_t avail = std::min<size_t>(32, mem.size() - p);
                    Branch t = DecodeBranch(mem.data() + p, avail, m.e.base + p);
                    if (t.IsBranch() && p + (uint32_t)t.len > cursor) {
                        br = t;
                        pos = p;
                        break;
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

                // Other modules that hold the original pointer but are not on the call-through path.
                std::vector<int> storers;
                for (int mi = 0; mi < (int)mods_.size(); ++mi) {
                    if (!Eligible(mi) || mi == O || std::find(path.begin(), path.end(), mi) != path.end()) continue;
                    if (!mods_[mi].read || !isOrig(mods_[mi].dataRefs)) continue;
                    if (T && ownedOrig.count(mi) && ownedOrig[mi].count(T)) continue;  // explained by its own patch
                    storers.push_back(mi);
                }
                std::vector<int> victims;
                for (int x : storers)
                    if (pi.isVptr || !mods_[x].orphans.empty() || pi.detour) victims.push_back(x);

                for (int x : storers)
                    if (std::find(victims.begin(), victims.end(), x) == victims.end()) pr.otherRefs.push_back(W2U(mods_[x].e.name));
                for (int x : victims) pr.victims.push_back(W2U(mods_[x].e.name));
                for (int c : path) pr.chain.push_back(W2U(mods_[c].e.name));

                if (status.empty()) {
                    if (!victims.empty()) status = pi.isVptr ? "possibly clobbered" : "likely clobbered";
                    else status = "no call-through found (replacement hook, or original kept somewhere HookMap can't see)";
                } else if (!victims.empty()) {
                    // The owner reaches the original itself, so whatever was hooked here before it is skipped.
                    status = std::string(pi.isVptr ? "possibly clobbered — " : "likely clobbered — ") + status +
                             " directly, skipping the earlier hook";
                }
                pr.chainStatus = status;
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

            // 1. clobbers and chained shared sites
            for (auto& pi : pinfo_) {
                auto& pr = rep_.patches[pi.patch];
                if (!pr.victims.empty()) {
                    ConflictRec c;
                    bool likely = pr.chainStatus.rfind("likely", 0) == 0;
                    bool direct = pr.chainStatus.find("calls original") != std::string::npos;
                    c.severity = likely ? kHigh : kMedium;
                    c.category = "clobber";
                    c.title = pr.owner + (likely ? " overwrote " : " may have overwritten ") + modsText(pr.victims) +
                              "'s hook at " + pr.location;
                    c.detail = "The " + pr.kind + " at " + pr.inModule + "+" + Hex(pr.rva) + " now goes to " + pr.owner +
                               (direct ? ", which calls the original game code itself. " : ". ") + modsText(pr.victims) +
                               " also holds this site's original target" +
                               (pi.isVptr ? "" : " and has a hook stub that nothing points to any more") +
                               ", which is what a hook that was installed first and then overwritten looks like. "
                               "If so, its hook here never runs. Fix: load order, or ask the author of " + pr.owner +
                               " to call through the previous target instead of the original.";
                    c.modules = { pr.owner };
                    c.modules.insert(c.modules.end(), pr.victims.begin(), pr.victims.end());
                    c.patches = { pr.id };
                    c.key = "clobber|" + pr.inModule + "|" + Hex(pr.rva) + "|" + modsText(c.modules);
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

            // 2. same function patched by different owners
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
                std::string where = p0.location;
                if (auto plus = where.find(" +"); plus != std::string::npos && where.rfind("ID ", 0) == 0) {
                    auto dash = where.find(" — ");
                    where = where.substr(0, plus) + (dash != std::string::npos ? where.substr(dash) : "");
                }
                ConflictRec c;
                c.severity = owners.size() >= 2 ? kMedium : kLow;
                c.category = "same-function";
                c.modules.assign(owners.begin(), owners.end());
                if (anyUnknown) c.modules.push_back(kUnattributed);
                bool windowsTarget = mods_[k.first].windows;
                c.title = (windowsTarget ? "Competing hooks on " + p0.inModule + " " : "Same function patched by several DLLs: ") +
                          where + " — " + modsText(c.modules);
                c.detail = std::to_string(list.size()) + " separate patches inside one function of " + p0.inModule +
                           ". They don't touch the same bytes, but they change the same code path, so the result depends on "
                           "how the patches interact.";
                c.patches = list;
                c.key = "samefn|" + p0.inModule + "|" + where + "|" + modsText(c.modules);
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
            for (auto& [k, list] : cross) {
                ConflictRec c;
                c.severity = kMedium;
                c.category = "cross-module";
                std::string target = W2U(mods_[k.first].e.name);
                c.title = (k.second == kUnattributed ? std::string("Unattributed patches inside ") : k.second + " patches code inside ") +
                          target + " (" + std::to_string(list.size()) + ")";
                c.detail = "Code inside " + target +
                           " differs from its file on disk. If " + target +
                           " is updated, these patches can land on the wrong bytes and crash.";
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

            // 5. exception handler stacking
            std::vector<std::string> veh;
            for (auto& m : mods_)
                if (m.registersVeh && !m.windows) veh.push_back(W2U(m.e.name));
            if (veh.size() >= 2) {
                ConflictRec c;
                c.severity = kMedium;
                c.category = "veh";
                c.title = std::to_string(veh.size()) + " DLLs install vectored exception handlers";
                c.detail = "Each of these can see (and swallow or \"fix\") a crash before the others and before Crash Logger. "
                           "Stacked guards can turn a clean crash into a freeze or a later, unrelated-looking crash. "
                           "Registration order can't be read from outside the process; handlers added with First=1 run first, "
                           "otherwise roughly in DLL load order: " + modsText(veh) + ".";
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
                if (c.category == "clobber")
                    for (auto& m : c.modules) inClobber.insert(m);
            for (auto& m : mods_) {
                if (m.orphans.empty() || inClobber.count(W2U(m.e.name))) continue;
                ConflictRec c;
                c.severity = kLow;
                c.category = "orphan";
                c.title = W2U(m.e.name) + " has " + std::to_string(m.orphans.size()) + " hook stub(s) nothing points to";
                c.detail = "Trampoline stubs that jump into " + W2U(m.e.name) +
                           " exist, but no patched site, stored pointer or thunk references them. Either the DLL removed "
                           "its own hook, or another DLL overwrote the site without keeping the old target.";
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
                if (IStartsWith(m.e.name, L"skse64_")) {
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
            rep_.notes.push_back("Owner attribution marked \"inferred\" is a best guess (thunk voting or byte-pattern match). "
                                 "\"Clobbered\" verdicts are evidence-based guesses; confirm by removing one DLL and rescanning.");
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
