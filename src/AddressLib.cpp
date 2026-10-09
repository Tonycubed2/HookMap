#include "AddressLib.h"

namespace hm
{
    // ---------------------------------------------------------------- Address Library

    namespace
    {
        struct Reader
        {
            const uint8_t* p;
            size_t         n;
            size_t         pos = 0;
            bool           ok = true;
            template <class T>
            T Get()
            {
                T v{};
                if (pos + sizeof(T) > n) {
                    ok = false;
                    return v;
                }
                std::memcpy(&v, p + pos, sizeof(T));
                pos += sizeof(T);
                return v;
            }
        };
    }

    bool AddressLib::Load(const std::wstring& file, std::string& err)
    {
        std::vector<uint8_t> buf;
        if (!ReadFileBytes(file, buf)) {
            err = "cannot read " + W2U(file);
            return false;
        }
        Reader r{ buf.data(), buf.size() };
        format = r.Get<int32_t>();
        if (format != 1 && format != 2) {
            err = "unsupported Address Library format " + std::to_string(format);
            return false;
        }
        for (int i = 0; i < 4; ++i) version[i] = r.Get<int32_t>();
        int32_t nameLen = r.Get<int32_t>();
        if (nameLen < 0 || nameLen > 0x10000) {
            err = "corrupt header";
            return false;
        }
        r.pos += (size_t)nameLen;
        int32_t ptrSize = r.Get<int32_t>();
        int32_t count = r.Get<int32_t>();
        if (!r.ok || ptrSize <= 0 || count <= 0 || count > 10000000) {
            err = "corrupt header";
            return false;
        }

        byOffset_.clear();
        byOffset_.reserve((size_t)count);
        uint64_t id = 0, offset = 0, prevId = 0, prevOffset = 0;
        for (int32_t i = 0; i < count && r.ok; ++i) {
            uint8_t type = r.Get<uint8_t>();
            uint8_t lo = type & 0xF, hi = type >> 4;
            switch (lo) {
            case 0: id = r.Get<uint64_t>(); break;
            case 1: id = prevId + 1; break;
            case 2: id = prevId + r.Get<uint8_t>(); break;
            case 3: id = prevId - r.Get<uint8_t>(); break;
            case 4: id = prevId + r.Get<uint16_t>(); break;
            case 5: id = prevId - r.Get<uint16_t>(); break;
            case 6: id = r.Get<uint16_t>(); break;
            case 7: id = r.Get<uint32_t>(); break;
            default: err = "corrupt entry"; return false;
            }
            uint64_t tmp = (hi & 8) ? (prevOffset / (uint64_t)ptrSize) : prevOffset;
            switch (hi & 7) {
            case 0: offset = r.Get<uint64_t>(); break;
            case 1: offset = tmp + 1; break;
            case 2: offset = tmp + r.Get<uint8_t>(); break;
            case 3: offset = tmp - r.Get<uint8_t>(); break;
            case 4: offset = tmp + r.Get<uint16_t>(); break;
            case 5: offset = tmp - r.Get<uint16_t>(); break;
            case 6: offset = r.Get<uint16_t>(); break;
            case 7: offset = r.Get<uint32_t>(); break;
            }
            if (hi & 8) offset *= (uint64_t)ptrSize;
            byOffset_.push_back({ offset, id });
            idToOffset_[id] = offset;
            prevOffset = offset;
            prevId = id;
        }
        if (!r.ok) {
            err = "truncated file";
            byOffset_.clear();
            idToOffset_.clear();
            return false;
        }
        std::sort(byOffset_.begin(), byOffset_.end());
        path = file;
        return true;
    }

    std::optional<AddressLib::Hit> AddressLib::Nearest(uint64_t rva) const
    {
        auto it = std::upper_bound(byOffset_.begin(), byOffset_.end(), std::make_pair(rva, UINT64_MAX));
        if (it == byOffset_.begin()) return std::nullopt;
        --it;
        return Hit{ it->second, rva - it->first };
    }

    std::optional<uint64_t> AddressLib::OffsetOf(uint64_t id) const
    {
        auto it = idToOffset_.find(id);
        if (it == idToOffset_.end()) return std::nullopt;
        return it->second;
    }

    // ---------------------------------------------------------------- CommonLib name harvesting

    namespace
    {
        bool IsIdStart(char c) { return isalpha((unsigned char)c) || c == '_'; }
        bool IsIdChar(char c) { return isalnum((unsigned char)c) || c == '_'; }

        std::string ReadIdent(const std::string& s, size_t& i)
        {
            size_t a = i;
            while (i < s.size() && IsIdChar(s[i])) ++i;
            return s.substr(a, i - a);
        }

        void SkipWs(const std::string& s, size_t& i)
        {
            while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        }

        bool ReadNumber(const std::string& s, size_t& i, uint64_t& v)
        {
            SkipWs(s, i);
            if (i >= s.size() || !isdigit((unsigned char)s[i])) return false;
            v = 0;
            if (s[i] == '0' && i + 1 < s.size() && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
                i += 2;
                while (i < s.size() && isxdigit((unsigned char)s[i])) {
                    v = v * 16 + (uint64_t)(isdigit((unsigned char)s[i]) ? s[i] - '0' : (tolower(s[i]) - 'a' + 10));
                    ++i;
                }
            } else {
                while (i < s.size() && isdigit((unsigned char)s[i])) v = v * 10 + (uint64_t)(s[i++] - '0');
            }
            return true;
        }

        const std::set<std::string>& NotFunctions()
        {
            static const std::set<std::string> k = { "if", "for", "while", "switch", "return", "sizeof", "alignof",
                "decltype", "static_assert", "catch", "noexcept", "requires", "constexpr", "RELOCATION_ID",
                "RelocationID", "VariantID", "Relocation", "ID", "assert", "static_cast", "reinterpret_cast",
                "const_cast", "dynamic_cast", "defined", "Offset", "func", "else", "do", "case", "new", "delete",
                "throw", "using", "typedef", "template", "alignas", "operator" };
            return k;
        }

        struct Scope
        {
            std::string name;
            bool        isFunc = false;
        };
    }

    void NameDb::Add(uint64_t aeId, const std::string& name, bool declared)
    {
        if (aeId == 0 || name.empty()) return;
        auto it = names_.find(aeId);
        if (it == names_.end() || (!it->second.second && declared) ||
            (it->second.second == declared && name.size() < it->second.first.size()))
            names_[aeId] = { name, declared };
    }

    void NameDb::ParseFile(const std::string& text, const std::string& fileStem)
    {
        std::vector<Scope> stack;
        std::string pendingScope, pendingFunc;
        size_t start = 0;
        while (start <= text.size()) {
            size_t nl = text.find('\n', start);
            std::string line = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
            start = (nl == std::string::npos) ? text.size() + 1 : nl + 1;

            if (auto c = line.find("//"); c != std::string::npos) line.resize(c);
            std::string t = Trim(line);
            if (t.empty() || t[0] == '#') continue;

            // --- scope keywords
            {
                size_t i = 0;
                std::string prev;
                while (i < t.size()) {
                    if (IsIdStart(t[i])) {
                        std::string tok = ReadIdent(t, i);
                        if (tok == "namespace" || ((tok == "class" || tok == "struct") && prev != "friend")) {
                            SkipWs(t, i);
                            size_t j = i;
                            std::string nm;
                            while (j < t.size() && (IsIdChar(t[j]) || t[j] == ':')) nm += t[j++];
                            // skip attributes/macros like "class RE_API Foo" by taking the last identifier before ':' or '{'
                            size_t k = j;
                            SkipWs(t, k);
                            while (k < t.size() && IsIdStart(t[k])) {
                                std::string more = ReadIdent(t, k);
                                if (more == "final") break;
                                nm = more;
                                SkipWs(t, k);
                            }
                            bool forward = t.find(';') != std::string::npos && t.find('{') == std::string::npos;
                            if (!nm.empty() && !forward) pendingScope = nm;
                            i = j;
                        }
                        prev = tok;
                    } else {
                        ++i;
                    }
                }
            }

            // --- function definition candidates
            if (t.back() != ';' && t.find('(') != std::string::npos) {
                size_t paren = t.find('(');
                size_t e = paren;
                while (e > 0 && (t[e - 1] == ' ' || t[e - 1] == '\t')) --e;
                size_t b = e;
                while (b > 0 && (IsIdChar(t[b - 1]) || t[b - 1] == ':' || t[b - 1] == '~')) --b;
                std::string fn = t.substr(b, e - b);
                while (!fn.empty() && fn[0] == ':') fn.erase(0, 1);
                std::string last = fn.substr(fn.rfind(':') == std::string::npos ? 0 : fn.rfind(':') + 1);
                bool assign = t.substr(0, b).find('=') != std::string::npos;
                if (!fn.empty() && !assign && !NotFunctions().count(last) && IsIdStart(last.empty() ? '0' : last[0]))
                    pendingFunc = fn;
            }

            // --- IDs on this line
            {
                static const char* kKeys[] = { "RelocationID", "RELOCATION_ID", "VariantID" };
                int vtIndex = 0;
                std::string vtName;
                if (auto v = t.find("VTABLE_"); v != std::string::npos) {
                    size_t i = v;
                    vtName = ReadIdent(t, i);
                }
                // Gather matches in position order
                std::vector<std::pair<size_t, size_t>> hits;  // (pos, keyLen)
                for (auto key : kKeys) {
                    size_t kl = strlen(key);
                    for (size_t p = t.find(key); p != std::string::npos; p = t.find(key, p + kl)) {
                        if (p > 0 && IsIdChar(t[p - 1])) continue;
                        if (p + kl >= t.size()) continue;
                        char nx = t[p + kl];
                        if (nx != ' ' && nx != '\t' && nx != '(' && nx != '{') continue;
                        hits.push_back({ p, kl });
                    }
                }
                std::sort(hits.begin(), hits.end());
                for (auto& [pos, kl] : hits) {
                    size_t i = pos + kl;
                    SkipWs(t, i);
                    std::string declName;
                    if (i < t.size() && IsIdStart(t[i])) {
                        declName = ReadIdent(t, i);
                        SkipWs(t, i);
                    }
                    if (i >= t.size() || (t[i] != '(' && t[i] != '{')) continue;
                    ++i;
                    uint64_t se = 0, ae = 0;
                    if (!ReadNumber(t, i, se)) continue;
                    SkipWs(t, i);
                    if (i >= t.size() || t[i] != ',') continue;
                    ++i;
                    if (!ReadNumber(t, i, ae)) continue;

                    // scope path
                    std::string path;
                    std::string func;
                    for (auto& s : stack) {
                        if (s.isFunc) {
                            func = s.name;
                            continue;
                        }
                        if (s.name.empty() || s.name == "RE" || s.name == "Offset" || s.name == "RE::Offset") continue;
                        if (!path.empty()) path += "::";
                        path += s.name;
                    }

                    if (!vtName.empty()) {
                        std::string nm = vtName + "[" + std::to_string(vtIndex++) + "]";
                        Add(ae, nm, true);
                        vtableIds_.push_back({ ae, nm });
                    } else if (!declName.empty()) {
                        Add(ae, path.empty() ? declName : path + "::" + declName, true);
                    } else {
                        std::string nm = func.empty() ? (pendingFunc.empty() ? fileStem : pendingFunc) : func;
                        if (!path.empty() && nm.find("::") == std::string::npos) nm = path + "::" + nm;
                        Add(ae, nm, false);
                    }
                }
            }

            // --- braces
            for (char c : t) {
                if (c == '{') {
                    Scope s;
                    if (!pendingScope.empty()) s.name = pendingScope;
                    else if (!pendingFunc.empty()) {
                        s.name = pendingFunc;
                        s.isFunc = true;
                    }
                    pendingScope.clear();
                    pendingFunc.clear();
                    stack.push_back(s);
                } else if (c == '}') {
                    if (!stack.empty()) stack.pop_back();
                }
            }
            if (t.back() == ';') pendingFunc.clear();
        }
    }

    bool NameDb::LoadCommonLib(const std::wstring& dir, std::string& err)
    {
        namespace fs = std::filesystem;
        std::vector<fs::path> roots = { fs::path(dir) / L"include" / L"RE", fs::path(dir) / L"src" / L"RE",
            fs::path(dir) / L"include" / L"REL", fs::path(dir) / L"include" / L"SKSE" };
        size_t files = 0;
        for (auto& r : roots) {
            std::error_code ec;
            if (!fs::exists(r, ec)) continue;
            for (auto it = fs::recursive_directory_iterator(r, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) break;
                if (!it->is_regular_file(ec)) continue;
                auto ext = Lower(it->path().extension().wstring());
                if (ext != L".h" && ext != L".hpp" && ext != L".cpp" && ext != L".inl") continue;
                std::string text;
                if (!ReadFileText(it->path().wstring(), text)) continue;
                if (text.find("ID") == std::string::npos) continue;
                ParseFile(text, W2U(it->path().stem().wstring()));
                ++files;
            }
        }
        if (files == 0) {
            err = "no CommonLib sources found under " + W2U(dir);
            return false;
        }
        root = dir;
        return true;
    }

    void NameDb::ResolveVtables(const AddressLib& lib)
    {
        vtables_.clear();
        for (auto& [id, nm] : vtableIds_)
            if (auto off = lib.OffsetOf(id)) vtables_.push_back({ *off, nm });
        std::sort(vtables_.begin(), vtables_.end());
    }

    std::string NameDb::NameOf(uint64_t aeId) const
    {
        auto it = names_.find(aeId);
        return it == names_.end() ? std::string() : it->second.first;
    }

    std::optional<std::pair<std::string, uint32_t>> NameDb::VtableSlot(uint64_t rva) const
    {
        auto it = std::upper_bound(vtables_.begin(), vtables_.end(), std::make_pair(rva, std::string("\xff")));
        if (it == vtables_.begin()) return std::nullopt;
        --it;
        if (rva - it->first >= 0x800) return std::nullopt;
        return std::make_pair(it->second, (uint32_t)((rva - it->first) / 8));
    }
}
