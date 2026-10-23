#include "Report.h"

#include "Health.h"
#include "Json.h"

namespace hm
{
    const char* SeverityName(int s)
    {
        switch (s) {
        case kHigh: return "High";
        case kMedium: return "Medium";
        case kLow: return "Low";
        default: return "Info";
        }
    }

    std::string PatchRec::Key() const
    {
        return inModule + "|" + Hex(rva) + "|" + kind + "|" + owner;
    }

    // ================================================================ JSON

    namespace
    {
        class JW
        {
        public:
            std::string out;
            void Open(char c) { out += c, first_.push_back(true); }
            void Close(char c) { out += c, first_.pop_back(); }
            void Key(const char* k)
            {
                Sep();
                out += json::Quote(k) + ":";
            }
            void Sep()
            {
                if (!first_.empty()) {
                    if (!first_.back()) out += ",";
                    first_.back() = false;
                }
            }
            void S(const char* k, const std::string& v) { Key(k), out += json::Quote(v); }
            void N(const char* k, double v)
            {
                Key(k);
                char buf[64];
                snprintf(buf, sizeof(buf), "%.17g", v);
                out += buf;
            }
            void B(const char* k, bool v) { Key(k), out += v ? "true" : "false"; }
            void L(const char* k, const std::vector<std::string>& v)
            {
                Key(k);
                out += "[";
                for (size_t i = 0; i < v.size(); ++i) out += (i ? "," : "") + json::Quote(v[i]);
                out += "]";
            }
            void IL(const char* k, const std::vector<int>& v)
            {
                Key(k);
                out += "[";
                for (size_t i = 0; i < v.size(); ++i) out += (i ? "," : "") + std::to_string(v[i]);
                out += "]";
            }

        private:
            std::vector<bool> first_;
        };
    }

    std::string ToJson(const Report& r)
    {
        JW w;
        w.Open('{');
        w.S("tool", r.tool);
        w.S("toolVersion", r.toolVersion);
        w.S("generated", r.generated);
        w.S("gameVersion", r.gameVersion);
        w.S("gameExe", r.gameExe);
        w.S("processInfo", r.processInfo);
        w.S("addrLib", r.addrLib);
        w.S("names", r.names);
        w.S("mo2", r.mo2);
        w.S("skseLogFile", r.skseLogFile);
        w.S("baseline", r.baseline);
        w.B("shared", r.shared);
        w.L("notes", r.notes);

        w.Key("modules");
        w.Open('[');
        for (auto& m : r.modules) {
            w.Sep();
            w.out += "\n";
            w.Open('{');
            w.S("name", m.name);
            w.S("path", m.path);
            w.S("physPath", m.physPath);
            w.S("source", m.source);
            w.S("category", m.category);
            w.S("base", m.base);
            w.N("size", m.size);
            w.B("windows", m.windows);
            w.B("allowlisted", m.allowlisted);
            w.S("allowNote", m.allowNote);
            w.S("fileVersion", m.fileVersion);
            w.S("productName", m.productName);
            w.S("company", m.company);
            w.S("linker", m.linker);
            w.S("toolset", m.toolset);
            w.S("crt", m.crt);
            w.S("built", m.built);
            w.S("pdb", m.pdb);
            w.S("clibFlavor", m.clibFlavor);
            w.S("clibConfidence", m.clibConfidence);
            w.S("clibEvidence", m.clibEvidence);
            w.L("features", m.features);
            w.B("skseVersionExport", m.skseVersionExport);
            w.B("skseQueryExport", m.skseQueryExport);
            w.B("skseLoadExport", m.skseLoadExport);
            w.S("pluginName", m.pluginName);
            w.S("pluginAuthor", m.pluginAuthor);
            w.S("pluginVersion", m.pluginVersion);
            w.S("compat", m.compat);
            w.S("compatStatus", m.compatStatus);
            w.L("exceptionApis", m.exceptionApis);
            w.S("skseLog", m.skseLog);
            w.S("scanNote", m.scanNote);
            w.N("patchesOwned", m.patchesOwned);
            w.N("patchesInside", m.patchesInside);
            w.N("orphanStubs", m.orphanStubs);
            w.Close('}');
        }
        w.Close(']');

        w.Key("patches");
        w.Open('[');
        for (auto& p : r.patches) {
            w.Sep();
            w.out += "\n";
            w.Open('{');
            w.N("id", p.id);
            w.S("inModule", p.inModule);
            w.S("rva", Hex(p.rva));
            w.N("len", p.len);
            w.S("kind", p.kind);
            w.S("kindNote", p.kindNote);
            w.S("origBytes", p.origBytes);
            w.S("newBytes", p.newBytes);
            w.S("target", p.target);
            w.S("owner", p.owner);
            w.S("ownerHow", p.ownerHow);
            w.L("chain", p.chain);
            w.S("chainStatus", p.chainStatus);
            w.L("victims", p.victims);
            w.L("otherRefs", p.otherRefs);
            w.S("stubAt", p.stubAt);
            w.S("stubMatched", p.stubMatched);
            w.S("stubReturns", p.stubReturns);
            w.S("evidenceKind", p.evidenceKind);
            w.S("location", p.location);
            w.Close('}');
        }
        w.Close(']');

        w.Key("conflicts");
        w.Open('[');
        for (auto& c : r.conflicts) {
            w.Sep();
            w.out += "\n";
            w.Open('{');
            w.N("severity", c.severity);
            w.B("expected", c.expected);
            w.S("category", c.category);
            w.S("title", c.title);
            w.S("detail", c.detail);
            w.L("modules", c.modules);
            w.IL("patches", c.patches);
            w.S("key", c.key);
            w.Close('}');
        }
        w.Close(']');

        w.Key("health");
        w.Open('{');
        w.B("scanned", r.health.scanned);
        w.S("overall", r.health.overall);
        w.S("windows", r.health.windows);
        w.Key("gauges");
        w.Open('[');
        for (auto& g : r.health.gauges) {
            w.Sep();
            w.out += "\n";
            w.Open('{');
            w.S("id", g.id);
            w.S("name", g.name);
            w.S("level", g.level);
            w.S("value", g.value);
            w.S("detail", g.detail);
            w.S("advice", g.advice);
            w.L("items", g.items);
            w.Close('}');
        }
        w.Close(']');
        w.Close('}');

        w.Close('}');
        w.out += "\n";
        return w.out;
    }

    bool FromJson(const std::string& text, Report& r, std::string& err)
    {
        json::Value v;
        if (!json::Parse(text, v, err)) return false;
        if (v.type != json::Value::kObject || v.GetStr("tool") != kToolName) {
            err = "not a HookMap JSON report";
            return false;
        }
        r.tool = v.GetStr("tool");
        r.toolVersion = v.GetStr("toolVersion");
        r.generated = v.GetStr("generated");
        r.gameVersion = v.GetStr("gameVersion");
        r.gameExe = v.GetStr("gameExe");
        r.processInfo = v.GetStr("processInfo");
        r.addrLib = v.GetStr("addrLib");
        r.names = v.GetStr("names");
        r.mo2 = v.GetStr("mo2");
        r.skseLogFile = v.GetStr("skseLogFile");
        r.baseline = v.GetStr("baseline");
        r.shared = v.GetBool("shared");
        r.notes = v.GetStrList("notes");
        if (auto a = v.Get("modules"); a && a->type == json::Value::kArray)
            for (auto& o : a->arr) {
                ModuleRec m;
                m.name = o.GetStr("name");
                m.path = o.GetStr("path");
                m.physPath = o.GetStr("physPath");
                m.source = o.GetStr("source");
                m.category = o.GetStr("category");
                m.base = o.GetStr("base");
                m.size = (uint32_t)o.GetNum("size");
                m.windows = o.GetBool("windows");
                m.allowlisted = o.GetBool("allowlisted");
                m.allowNote = o.GetStr("allowNote");
                m.fileVersion = o.GetStr("fileVersion");
                m.productName = o.GetStr("productName");
                m.company = o.GetStr("company");
                m.linker = o.GetStr("linker");
                m.toolset = o.GetStr("toolset");
                m.crt = o.GetStr("crt");
                m.built = o.GetStr("built");
                m.pdb = o.GetStr("pdb");
                m.clibFlavor = o.GetStr("clibFlavor");
                m.clibConfidence = o.GetStr("clibConfidence");
                m.clibEvidence = o.GetStr("clibEvidence");
                m.features = o.GetStrList("features");
                m.skseVersionExport = o.GetBool("skseVersionExport");
                m.skseQueryExport = o.GetBool("skseQueryExport");
                m.skseLoadExport = o.GetBool("skseLoadExport");
                m.pluginName = o.GetStr("pluginName");
                m.pluginAuthor = o.GetStr("pluginAuthor");
                m.pluginVersion = o.GetStr("pluginVersion");
                m.compat = o.GetStr("compat");
                m.compatStatus = o.GetStr("compatStatus");
                m.exceptionApis = o.GetStrList("exceptionApis");
                m.skseLog = o.GetStr("skseLog");
                m.scanNote = o.GetStr("scanNote");
                m.patchesOwned = (int)o.GetNum("patchesOwned");
                m.patchesInside = (int)o.GetNum("patchesInside");
                m.orphanStubs = (int)o.GetNum("orphanStubs");
                r.modules.push_back(std::move(m));
            }
        if (auto a = v.Get("patches"); a && a->type == json::Value::kArray)
            for (auto& o : a->arr) {
                PatchRec p;
                p.id = (int)o.GetNum("id");
                p.inModule = o.GetStr("inModule");
                p.rva = strtoull(o.GetStr("rva").c_str(), nullptr, 16);
                p.len = (uint32_t)o.GetNum("len");
                p.kind = o.GetStr("kind");
                p.kindNote = o.GetStr("kindNote");
                p.origBytes = o.GetStr("origBytes");
                p.newBytes = o.GetStr("newBytes");
                p.target = o.GetStr("target");
                p.owner = o.GetStr("owner");
                p.ownerHow = o.GetStr("ownerHow");
                p.chain = o.GetStrList("chain");
                p.chainStatus = o.GetStr("chainStatus");
                p.victims = o.GetStrList("victims");
                p.otherRefs = o.GetStrList("otherRefs");
                p.stubAt = o.GetStr("stubAt");
                p.stubMatched = o.GetStr("stubMatched");
                p.stubReturns = o.GetStr("stubReturns");
                p.evidenceKind = o.GetStr("evidenceKind");
                p.location = o.GetStr("location");
                r.patches.push_back(std::move(p));
            }
        if (auto a = v.Get("conflicts"); a && a->type == json::Value::kArray)
            for (auto& o : a->arr) {
                ConflictRec c;
                c.severity = (int)o.GetNum("severity");
                c.expected = o.GetBool("expected");
                c.category = o.GetStr("category");
                c.title = o.GetStr("title");
                c.detail = o.GetStr("detail");
                c.modules = o.GetStrList("modules");
                if (auto pl = o.Get("patches"); pl && pl->type == json::Value::kArray)
                    for (auto& e : pl->arr)
                        if (e.type == json::Value::kNumber) c.patches.push_back((int)e.num);
                c.key = o.GetStr("key");
                r.conflicts.push_back(std::move(c));
            }
        if (auto hv = v.Get("health"); hv && hv->type == json::Value::kObject) {
            r.health.scanned = hv->GetBool("scanned");
            r.health.overall = hv->GetStr("overall");
            r.health.windows = hv->GetStr("windows");
            if (auto a = hv->Get("gauges"); a && a->type == json::Value::kArray)
                for (auto& o : a->arr) {
                    GaugeRec g;
                    g.id = o.GetStr("id");
                    g.name = o.GetStr("name");
                    g.level = o.GetStr("level");
                    g.value = o.GetStr("value");
                    g.detail = o.GetStr("detail");
                    g.advice = o.GetStr("advice");
                    g.items = o.GetStrList("items");
                    r.health.gauges.push_back(std::move(g));
                }
        }
        return true;
    }

    // ================================================================ Sanitize

    namespace
    {
        void ReplaceI(std::string& s, const std::vector<std::pair<std::wstring, std::wstring>>& repl)
        {
            if (s.empty()) return;
            std::wstring w = U2W(s);
            bool changed = false;
            for (auto& [from, to] : repl) {
                if (from.empty()) continue;
                std::wstring lf = Lower(from);
                for (size_t p = Lower(w).find(lf); p != std::wstring::npos; p = Lower(w).find(lf, p + to.size())) {
                    w.replace(p, from.size(), to);
                    changed = true;
                }
            }
            if (changed) s = W2U(w);
        }
        void ReplaceI(std::vector<std::string>& v, const std::vector<std::pair<std::wstring, std::wstring>>& repl)
        {
            for (auto& s : v) ReplaceI(s, repl);
        }
    }

    void Sanitize(Report& r, const std::vector<std::pair<std::wstring, std::wstring>>& repl)
    {
        r.shared = true;
        for (auto* s : { &r.gameExe, &r.processInfo, &r.addrLib, &r.names, &r.mo2, &r.skseLogFile, &r.baseline }) ReplaceI(*s, repl);
        ReplaceI(r.notes, repl);
        for (auto& m : r.modules)
            for (auto* s : { &m.path, &m.physPath, &m.source, &m.pdb, &m.clibEvidence, &m.scanNote, &m.compat, &m.skseLog })
                ReplaceI(*s, repl);
        for (auto& c : r.conflicts)
            for (auto* s : { &c.title, &c.detail }) ReplaceI(*s, repl);
    }

    // ================================================================ HTML

    namespace
    {
        std::string E(const std::string& s)
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

        std::string Anchor(const std::string& name)
        {
            std::string a = "m-";
            for (char c : LowerA(name)) a += isalnum((unsigned char)c) ? c : '-';
            return a;
        }

        std::string ModLink(const std::string& name)
        {
            if (name.empty() || name[0] == '(') return "<span class=mute>" + E(name) + "</span>";
            return "<a class=mod href=\"#" + Anchor(name) + "\">" + E(name) + "</a>";
        }

        const char* SevClass(int s)
        {
            switch (s) {
            case kHigh: return "hi";
            case kMedium: return "med";
            case kLow: return "low";
            default: return "info";
            }
        }

        const char* kCss = R"CSS(
:root{--bg:#f5f6f8;--panel:#ffffff;--ink:#1a1d21;--mute:#5d6670;--line:#e2e5e9;--accent:#2b63d9;
--hi:#b42318;--hiBg:#fdeceb;--med:#a15c00;--medBg:#fff3df;--low:#1f5fa8;--lowBg:#e7f0fb;--info:#5d6670;--infoBg:#eef0f2;
--ok:#18794e;--okBg:#e3f5ec;--mono:ui-monospace,SFMono-Regular,Consolas,"Cascadia Mono",monospace}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--panel:#1b1e23;--ink:#e6e8eb;--mute:#9aa3ad;--line:#2c3138;--accent:#7aa7ff;
--hi:#ff8a80;--hiBg:#3a1d1b;--med:#ffc061;--medBg:#38290f;--low:#8cbcff;--lowBg:#16283f;--info:#9aa3ad;--infoBg:#23272d;--ok:#6fdc9c;--okBg:#163024}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:24px 16px 80px}
h1{font-size:26px;margin:0 0 2px;letter-spacing:-.01em}
h2{font-size:18px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.mute{color:var(--mute)}.mono{font-family:var(--mono);font-size:12.5px}
.sub{color:var(--mute);margin-bottom:16px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.meta dt{color:var(--mute)}.meta dd{margin:0;word-break:break-word}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.stat b{display:block;font-size:24px;line-height:1.2}.stat span{color:var(--mute);font-size:12.5px}
.stat.hi b{color:var(--hi)}.stat.med b{color:var(--med)}.stat.low b{color:var(--low)}
.bar{position:sticky;top:0;z-index:5;background:var(--bg);padding:10px 0;display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;border-bottom:1px solid var(--line)}
.bar input[type=search]{flex:1 1 260px;min-width:0;padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);font:inherit}
.bar nav{display:flex;flex-wrap:wrap;gap:4px 12px;font-size:13px}
.chip{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.chip.hi{background:var(--hiBg);color:var(--hi)}.chip.med{background:var(--medBg);color:var(--med)}
.chip.low{background:var(--lowBg);color:var(--low)}.chip.info{background:var(--infoBg);color:var(--info)}
.chip.ok{background:var(--okBg);color:var(--ok)}.chip.exp{background:var(--infoBg);color:var(--mute);font-weight:500}
.cf{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:8px;padding:10px 14px;margin:8px 0}
.cf.hi{border-left-color:var(--hi)}.cf.med{border-left-color:var(--med)}.cf.low{border-left-color:var(--low)}
.cf .t{font-weight:600}.cf .d{color:var(--mute);margin-top:4px}.cf .r{margin-top:6px;font-size:13px}
.cf .r a.p{font-family:var(--mono);font-size:12px;margin-right:6px}
body.hideexp .exp-row{display:none}
.tw{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line)}
th{position:sticky;top:0;background:var(--panel);color:var(--mute);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
tr:last-child td{border-bottom:0}
tr.bad td:first-child{box-shadow:inset 3px 0 0 var(--hi)}
tr:target td{background:var(--lowBg)}
details.grp,details.mrec{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:8px 0}
details.grp>summary,details.mrec>summary{cursor:pointer;padding:10px 14px;list-style:none;display:flex;flex-wrap:wrap;gap:6px 14px;align-items:baseline}
details.grp>summary::-webkit-details-marker,details.mrec>summary::-webkit-details-marker{display:none}
details>summary{cursor:pointer;list-style:none}details>summary::-webkit-details-marker{display:none}
details>summary::before{content:"▸";color:var(--mute);margin-right:2px}details[open]>summary::before{content:"▾"}
details.grp .tw{border:0;border-top:1px solid var(--line);border-radius:0 0 10px 10px}
details.mrec:target{outline:2px solid var(--accent)}
.mrec .body{border-top:1px solid var(--line);padding:10px 14px}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:3px 16px;font-size:13px}
.kv dt{color:var(--mute)}.kv dd{margin:0;word-break:break-word}
.name{font-weight:600}
.bytes{font-family:var(--mono);font-size:11.5px;color:var(--mute);word-break:break-all;max-width:340px}
.bytes b{color:var(--ink);font-weight:500}
.hid{display:none!important}
ul.notes{margin:6px 0;padding-left:20px;color:var(--mute)}
.empty{color:var(--mute);background:var(--panel);border:1px dashed var(--line);border-radius:8px;padding:14px}
@media (max-width:640px){.meta,.kv{grid-template-columns:1fr}.meta dt,.kv dt{margin-top:6px}}
)CSS";

        const char* kJs = R"JS(
(function(){
 var q=document.getElementById('q');
 function apply(){var t=(q.value||'').toLowerCase();
  document.querySelectorAll('.f').forEach(function(e){e.classList.toggle('hid',!!t&&e.textContent.toLowerCase().indexOf(t)<0);});
  document.querySelectorAll('details.grp').forEach(function(g){var rows=g.querySelectorAll('tr.f');var vis=false;
   rows.forEach(function(r){if(!r.classList.contains('hid'))vis=true;});
   g.classList.toggle('hid',!!t&&!vis);if(t&&vis)g.open=true;});}
 if(q)q.addEventListener('input',apply);
 var he=document.getElementById('he');if(he)he.addEventListener('change',function(){document.body.classList.toggle('hideexp',he.checked);});
 function reveal(){var id=location.hash.slice(1);if(!id)return;var el=document.getElementById(id);if(!el)return;
  for(var p=el;p;p=p.parentElement){if(p.tagName==='DETAILS')p.open=true;}
  el.scrollIntoView({block:'center'});}
 window.addEventListener('hashchange',reveal);reveal();
})();
)JS";

        std::string Head(const std::string& title)
        {
            return "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">"
                   "<title>" + E(title) + "</title><style>" + kCss + "</style></head><body><div class=wrap>";
        }

        std::string Foot() { return std::string("</div><script>") + kJs + "</script></body></html>"; }

        std::string CompatChip(const ModuleRec& m)
        {
            if (m.compatStatus == "ok") return "<span class=\"chip ok\">compatible</span>";
            if (m.compatStatus == "bad") return "<span class=\"chip hi\">version mismatch</span>";
            if (m.compatStatus == "warn") return "<span class=\"chip med\">check</span>";
            return "";
        }

        std::string ListText(const std::vector<std::string>& v)
        {
            std::string s;
            for (auto& x : v) s += (s.empty() ? "" : ", ") + x;
            return s;
        }
    }

    std::string ToHtml(const Report& r)
    {
        std::string h = Head("HookMap — " + r.generated);
        int counts[4]{};
        int plugins = 0, visibleMods = 0;
        for (auto& c : r.conflicts)
            if (!c.expected) counts[std::clamp(c.severity, 0, 3)]++;
        for (auto& m : r.modules) {
            if (m.category == "SKSE plugin") ++plugins;
            if (!m.windows) ++visibleMods;
        }

        h += "<h1>HookMap</h1><div class=sub>Hook and conflict report · " + E(r.generated) + (r.shared ? " · shareable copy (personal paths removed)" : "") + "</div>";
        h += "<dl class=meta>";
        auto meta = [&](const char* k, const std::string& v) {
            if (!v.empty()) h += "<dt>" + std::string(k) + "</dt><dd>" + E(v) + "</dd>";
        };
        meta("Game", r.gameVersion + (r.gameExe.empty() ? "" : " — " + r.gameExe));
        meta("Process", r.processInfo);
        meta("Game code compared against", r.baseline);
        meta("Address Library", r.addrLib);
        meta("Function names", r.names);
        meta("MO2", r.mo2);
        meta("SKSE log", r.skseLogFile);
        meta("Tool", r.tool + " " + r.toolVersion);
        h += "</dl>";

        h += "<div class=stats>";
        auto stat = [&](const char* cls, int n, const char* label) {
            h += std::string("<div class=\"stat ") + cls + "\"><b>" + std::to_string(n) + "</b><span>" + label + "</span></div>";
        };
        stat("", visibleMods, "non-Windows modules");
        stat("", plugins, "SKSE plugins");
        stat("", (int)r.patches.size(), "patches found");
        stat("hi", counts[kHigh], "high");
        stat("med", counts[kMedium], "medium");
        stat("low", counts[kLow], "low");
        h += "</div>";

        h += "<div class=bar><input id=q type=search placeholder=\"Filter everything — a DLL name, an ID, a function…\" aria-label=Filter>"
             "<label><input id=he type=checkbox> hide expected</label>"
             "<nav>" + std::string(r.health.scanned ? "<a href=\"#danger\">Danger levels</a>" : "") + "<a href=\"#conflicts\">Conflicts</a><a href=\"#hooks\">Hook map</a><a href=\"#veh\">Exception handlers</a>"
             "<a href=\"#modules\">Modules</a><a href=\"#info\">Scan info</a></nav></div>";

        // ---------------- danger levels
        h += HealthHtml(r.health);

        // ---------------- conflicts
        h += "<h2 id=conflicts>Conflicts, ranked</h2>";
        if (r.conflicts.empty()) h += "<div class=empty>No conflicts found.</div>";
        for (auto& c : r.conflicts) {
            h += std::string("<div class=\"cf f ") + SevClass(c.severity) + (c.expected ? " exp-row" : "") + "\">";
            h += std::string("<span class=\"chip ") + SevClass(c.severity) + "\">" + SeverityName(c.severity) + "</span> ";
            if (c.expected) h += "<span class=\"chip exp\">expected</span> ";
            h += "<span class=t>" + E(c.title) + "</span>";
            if (!c.detail.empty()) h += "<div class=d>" + E(c.detail) + "</div>";
            if (!c.modules.empty() || !c.patches.empty()) {
                h += "<div class=r>";
                if (!c.modules.empty()) {
                    h += "<span class=mute>DLLs:</span> ";
                    for (size_t i = 0; i < c.modules.size(); ++i) h += (i ? ", " : "") + ModLink(c.modules[i]);
                }
                if (!c.patches.empty()) {
                    h += " &nbsp;<span class=mute>Patches:</span> ";
                    for (size_t i = 0; i < c.patches.size() && i < 24; ++i)
                        h += "<a class=p href=\"#p-" + std::to_string(c.patches[i]) + "\">#" + std::to_string(c.patches[i]) + "</a>";
                    if (c.patches.size() > 24) h += "<span class=mute>+" + std::to_string(c.patches.size() - 24) + " more</span>";
                }
                h += "</div>";
            }
            h += "</div>";
        }

        // ---------------- hook map
        h += "<h2 id=hooks>Hook map</h2>";
        std::map<std::string, std::vector<const PatchRec*>> byMod;
        std::vector<std::string> order;
        for (auto& p : r.patches) {
            if (!byMod.count(p.inModule)) order.push_back(p.inModule);
            byMod[p.inModule].push_back(&p);
        }
        std::string gameMod = "SkyrimSE.exe";
        if (auto sl = r.gameExe.find_last_of("\\/"); !r.gameExe.empty()) gameMod = r.gameExe.substr(sl == std::string::npos ? 0 : sl + 1);
        std::stable_sort(order.begin(), order.end(), [&](const std::string& a, const std::string& b) {
            if ((a == gameMod) != (b == gameMod)) return a == gameMod;
            return byMod[a].size() > byMod[b].size();
        });
        if (order.empty()) h += "<div class=empty>No patched code found. Make sure the game is past the main menu or in a loaded save.</div>";
        for (auto& mod : order) {
            auto& list = byMod[mod];
            std::map<std::string, int> owners;
            for (auto p : list) owners[p->owner]++;
            h += std::string("<details class=grp") + (mod == gameMod ? " open" : "") + "><summary><span class=name>" + E(mod) +
                 "</span><span class=mute>" + std::to_string(list.size()) + " patch(es) · " + std::to_string(owners.size()) +
                 " owner(s)</span></summary><div class=tw><table><thead><tr><th>#</th><th>Location</th><th>Kind</th><th>Owner</th>"
                 "<th>Chain</th><th>Bytes (original → now)</th></tr></thead><tbody>";
            auto row = [&](const PatchRec* p) {
                bool bad = !p->victims.empty();
                std::string t = std::string("<tr class=\"f") + (bad ? " bad" : "") + "\" id=\"p-" + std::to_string(p->id) + "\">";
                t += "<td class=mono>" + std::to_string(p->id) + "</td>";
                t += "<td><div>" + E(p->location) + "</div><div class=\"mono mute\">+" + E(Hex(p->rva)) + "</div></td>";
                t += "<td>" + E(p->kind) + (p->kindNote.empty() ? "" : "<div class=mute>" + E(p->kindNote) + "</div>") + "</td>";
                t += "<td>" + ModLink(p->owner) + "<div class=mute>" + E(p->ownerHow) + "</div>" +
                     (p->target.empty() ? "" : "<div class=\"mono mute\">→ " + E(p->target) + "</div>") + "</td>";
                t += "<td>";
                if (!p->chainStatus.empty()) t += E(p->chainStatus);
                if (p->chain.size() >= 2) t += "<div class=mute>" + E(ListText(p->chain)) + " → original</div>";
                if (!p->victims.empty()) {
                    t += std::string("<div><span class=\"chip hi\">") + (p->evidenceKind == "overlap" ? "overlaps" : "overwrote") +
                         "</span> " + E(ListText(p->victims)) + "</div>";
                    if (!p->stubAt.empty())
                        t += "<div class=mute>Evidence: " + E(p->stubAt) + " · holds " + E(p->stubMatched) + " · " + E(p->stubReturns) +
                             "</div>";
                }
                if (!p->otherRefs.empty())
                    t += "<div class=mute>also references original (not evidence of a conflict): " + E(ListText(p->otherRefs)) + "</div>";
                t += "</td>";
                t += "<td><div class=bytes>" + E(p->origBytes) + "<br>→ <b>" + E(p->newBytes) + "</b></div></td>";
                t += "</tr>";
                return t;
            };

            // Collapse vtable slots that share one original function and one owner into a single row.
            std::map<std::pair<std::string, std::string>, std::vector<const PatchRec*>> vgroups;
            for (auto p : list)
                if (p->kind == "vptr") vgroups[{ p->owner, p->origBytes }].push_back(p);
            std::set<const PatchRec*> grouped;
            for (auto& [key, g] : vgroups)
                if (g.size() >= 3)
                    for (auto p : g) grouped.insert(p);
            std::set<std::pair<std::string, std::string>> emitted;
            for (auto p : list) {
                if (!grouped.count(p)) {
                    h += row(p);
                    continue;
                }
                auto key = std::make_pair(p->owner, p->origBytes);
                if (!emitted.insert(key).second) continue;
                auto& g = vgroups[key];
                std::set<std::string> slots;
                for (auto q : g) {
                    auto pos = q->location.find(" slot ");
                    if (pos == std::string::npos) {
                        slots.insert("?");
                        continue;
                    }
                    auto end = q->location.find(' ', pos + 6);
                    slots.insert(q->location.substr(pos + 6, end == std::string::npos ? std::string::npos : end - pos - 6));
                }
                std::string slotText = slots.size() == 1 && *slots.begin() != "?" ? "slot " + *slots.begin() : "several slots";
                h += "<tr class=f><td colspan=6><details><summary><b>" + std::to_string(g.size()) + " vtables, " + E(slotText) +
                     "</b> — was " + E(key.second) + ", now " + ModLink(key.first) + " <span class=mute>(" + E(g.front()->chainStatus) +
                     ")</span></summary><div class=tw><table><tbody>";
                for (auto q : g) h += row(q);
                h += "</tbody></table></div></details></td></tr>";
            }
            h += "</tbody></table></div></details>";
        }

        // ---------------- exception handlers
        h += "<h2 id=veh>Exception handlers</h2>";
        {
            std::string rows;
            for (auto& m : r.modules)
                if (!m.exceptionApis.empty())
                {
                    std::string ln = LowerA(m.name);
                    bool lib = ln == "bink2w64.dll" || ln == "usvfs_x64.dll";
                    rows += "<tr class=f><td>" + ModLink(m.name) + "</td><td>" + E(m.category) + "</td><td>" +
                            E(ListText(m.exceptionApis)) + "</td><td>" +
                            (lib ? std::string("<span class=\"chip exp\">library, not a crash guard</span>")
                                 : (m.allowlisted ? std::string("<span class=\"chip exp\">allowlisted</span>") : std::string())) +
                            "</td></tr>";
                }
            if (rows.empty()) h += "<div class=empty>No DLL imports a vectored-exception API.</div>";
            else
                h += "<p class=mute>These DLLs import a vectored-exception API, so they can register a handler that sees a crash "
                     "before Crash Logger does. Importing the API is not proof a handler is registered, and the order can't be read "
                     "from outside the process.</p><div class=tw><table><thead><tr><th>DLL</th>"
                     "<th>Type</th><th>APIs</th><th></th></tr></thead><tbody>" + rows + "</tbody></table></div>";
        }

        // ---------------- modules
        h += "<h2 id=modules>Modules</h2>";
        std::vector<const ModuleRec*> mods;
        for (auto& m : r.modules)
            if (!m.windows) mods.push_back(&m);
        std::stable_sort(mods.begin(), mods.end(), [](const ModuleRec* a, const ModuleRec* b) {
            if (a->patchesOwned != b->patchesOwned) return a->patchesOwned > b->patchesOwned;
            return LowerA(a->name) < LowerA(b->name);
        });
        for (auto m : mods) {
            h += "<details class=\"mrec f\" id=\"" + Anchor(m->name) + "\"><summary><span class=name>" + E(m->name) + "</span>";
            h += "<span class=\"chip info\">" + E(m->category) + "</span>";
            if (m->allowlisted) h += "<span class=\"chip exp\">allowlisted</span>";
            h += CompatChip(*m);
            if (m->orphanStubs) h += "<span class=\"chip med\">" + std::to_string(m->orphanStubs) + " orphan stub(s)</span>";
            h += "<span class=mute>" + E(m->source) + "</span>";
            h += "<span class=mute>owns " + std::to_string(m->patchesOwned) + " patch(es)</span></summary><div class=body><dl class=kv>";
            auto kv = [&](const char* k, const std::string& v) {
                if (!v.empty()) h += "<dt>" + std::string(k) + "</dt><dd>" + E(v) + "</dd>";
            };
            kv("Plugin name", m->pluginName);
            kv("Plugin version", m->pluginVersion);
            kv("Author", m->pluginAuthor);
            kv("File version", m->fileVersion);
            kv("Product", m->productName);
            kv("Company", m->company);
            kv("Runtime compatibility", m->compat);
            kv("SKSE log", m->skseLog);
            kv("CommonLib", m->clibFlavor.empty() ? "" : m->clibFlavor + " (" + m->clibConfidence + ")");
            kv("CommonLib evidence", m->clibEvidence);
            kv("Compiler", m->toolset);
            kv("Linker version", m->linker);
            kv("CRT", m->crt);
            kv("Built", m->built);
            kv("Libraries", ListText(m->features));
            std::string exports;
            if (m->skseLoadExport) exports += "SKSEPlugin_Load ";
            if (m->skseQueryExport) exports += "SKSEPlugin_Query ";
            if (m->skseVersionExport) exports += "SKSEPlugin_Version";
            kv("SKSE exports", Trim(exports));
            kv("Exception APIs", ListText(m->exceptionApis));
            kv("Patches inside this DLL", m->patchesInside ? std::to_string(m->patchesInside) : "");
            kv("Allowlist note", m->allowNote);
            kv("Scan note", m->scanNote);
            kv("Loaded from", m->physPath);
            if (m->path != m->physPath) kv("Path seen by game", m->path);
            kv("PDB", m->pdb);
            kv("Base", m->base + " (" + std::to_string(m->size / 1024) + " KB)");
            h += "</dl></div></details>";
        }

        // ---------------- info
        h += "<h2 id=info>Scan info</h2><ul class=notes>";
        for (auto& n : r.notes) h += "<li>" + E(n) + "</li>";
        h += "</ul><p class=mute>Windows system DLLs are listed only where they were patched.</p>"
             "<p class=mute><b>Severity</b><br>"
             "High = a previous hook's stolen bytes were found in a stub nothing calls anymore<br>"
             "Medium = overlapping or near-overlapping patches, or several VEH-capable crash plugins<br>"
             "Low = chained shared site, usually fine<br>"
             "Info = same function, unattributed bytes, imports, weak pointer matches</p>";
        h += Foot();
        return h;
    }

    // ================================================================ Diff

    std::string DiffHtml(const Report& a, const Report& b, const std::string& an, const std::string& bn)
    {
        std::string h = Head("HookMap diff");
        h += "<h1>HookMap diff</h1><div class=sub>What changed between two scans</div><dl class=meta>";
        h += "<dt>Before</dt><dd>" + E(an) + " — " + E(a.generated) + " · game " + E(a.gameVersion) + "</dd>";
        h += "<dt>After</dt><dd>" + E(bn) + " — " + E(b.generated) + " · game " + E(b.gameVersion) + "</dd></dl>";

        // modules
        std::map<std::string, const ModuleRec*> ma, mb;
        for (auto& m : a.modules)
            if (!m.windows) ma[LowerA(m.name)] = &m;
        for (auto& m : b.modules)
            if (!m.windows) mb[LowerA(m.name)] = &m;
        std::vector<std::string> added, removed, changed;
        for (auto& [k, m] : mb)
            if (!ma.count(k)) added.push_back(m->name);
        for (auto& [k, m] : ma)
            if (!mb.count(k)) removed.push_back(m->name);
        for (auto& [k, m] : mb) {
            auto it = ma.find(k);
            if (it == ma.end()) continue;
            auto o = it->second;
            std::string d;
            if (o->fileVersion != m->fileVersion) d += "file " + o->fileVersion + " → " + m->fileVersion + "; ";
            if (o->pluginVersion != m->pluginVersion) d += "plugin " + o->pluginVersion + " → " + m->pluginVersion + "; ";
            if (o->built != m->built) d += "rebuilt; ";
            if (o->patchesOwned != m->patchesOwned)
                d += "owns " + std::to_string(o->patchesOwned) + " → " + std::to_string(m->patchesOwned) + " patches; ";
            if (o->compatStatus != m->compatStatus) d += "compat " + o->compatStatus + " → " + m->compatStatus + "; ";
            if (!d.empty()) changed.push_back(m->name + ": " + d.substr(0, d.size() - 2));
        }

        // conflicts and patches by key
        std::map<std::string, const ConflictRec*> ca, cb;
        for (auto& c : a.conflicts) ca[c.key] = &c;
        for (auto& c : b.conflicts) cb[c.key] = &c;
        std::map<std::string, const PatchRec*> pa, pb;
        for (auto& p : a.patches) pa[p.Key()] = &p;
        for (auto& p : b.patches) pb[p.Key()] = &p;

        int newC = 0, goneC = 0, newP = 0, goneP = 0;
        for (auto& [k, c] : cb) newC += !ca.count(k);
        for (auto& [k, c] : ca) goneC += !cb.count(k);
        for (auto& [k, p] : pb) newP += !pa.count(k);
        for (auto& [k, p] : pa) goneP += !pb.count(k);

        h += "<div class=stats>";
        auto stat = [&](const char* cls, int n, const char* label) {
            h += std::string("<div class=\"stat ") + cls + "\"><b>" + std::to_string(n) + "</b><span>" + label + "</span></div>";
        };
        stat("", (int)added.size(), "DLLs added");
        stat("", (int)removed.size(), "DLLs removed");
        stat("", (int)changed.size(), "DLLs changed");
        stat("hi", newC, "new conflicts");
        stat("low", goneC, "resolved conflicts");
        stat("", newP - goneP, "net patch change");
        h += "</div><div class=bar><input id=q type=search placeholder=\"Filter…\" aria-label=Filter></div>";

        auto list = [&](const char* title, const std::vector<std::string>& v) {
            h += std::string("<h2>") + title + "</h2>";
            if (v.empty()) {
                h += "<div class=empty>None.</div>";
                return;
            }
            h += "<div class=tw><table><tbody>";
            for (auto& x : v) h += "<tr class=f><td>" + E(x) + "</td></tr>";
            h += "</tbody></table></div>";
        };
        auto conflicts = [&](const char* title, const std::map<std::string, const ConflictRec*>& from,
                             const std::map<std::string, const ConflictRec*>& other) {
            h += std::string("<h2>") + title + "</h2>";
            bool any = false;
            for (auto& [k, c] : from) {
                if (other.count(k)) continue;
                any = true;
                h += std::string("<div class=\"cf f ") + SevClass(c->severity) + "\"><span class=\"chip " + SevClass(c->severity) + "\">" +
                     SeverityName(c->severity) + "</span> " + (c->expected ? "<span class=\"chip exp\">expected</span> " : "") +
                     "<span class=t>" + E(c->title) + "</span>" + (c->detail.empty() ? "" : "<div class=d>" + E(c->detail) + "</div>") +
                     "</div>";
            }
            if (!any) h += "<div class=empty>None.</div>";
        };
        conflicts("New conflicts", cb, ca);
        conflicts("Resolved conflicts", ca, cb);
        list("DLLs added", added);
        list("DLLs removed", removed);
        list("DLLs changed", changed);

        auto patches = [&](const char* title, const std::map<std::string, const PatchRec*>& from,
                           const std::map<std::string, const PatchRec*>& other) {
            h += std::string("<h2>") + title + "</h2>";
            std::string rows;
            int n = 0;
            for (auto& [k, p] : from) {
                if (other.count(k)) continue;
                if (++n > 2000) break;
                rows += "<tr class=f><td>" + E(p->inModule) + "</td><td>" + E(p->location) + "<div class=\"mono mute\">+" + E(Hex(p->rva)) +
                        "</div></td><td>" + E(p->kind) + "</td><td>" + E(p->owner) + "</td></tr>";
            }
            if (rows.empty()) h += "<div class=empty>None.</div>";
            else
                h += "<div class=tw><table><thead><tr><th>In</th><th>Location</th><th>Kind</th><th>Owner</th></tr></thead><tbody>" + rows +
                     "</tbody></table></div>";
        };
        patches("Patches added", pb, pa);
        patches("Patches removed", pa, pb);
        h += Foot();
        return h;
    }
}
