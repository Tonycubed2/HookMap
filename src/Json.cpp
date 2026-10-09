#include "Json.h"

#include <cstdio>
#include <cstdlib>

namespace hm::json
{
    namespace
    {
        struct P
        {
            const std::string& s;
            size_t             i = 0;
            std::string        err;

            void Ws()
            {
                while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
            }
            bool Fail(const char* m)
            {
                if (err.empty()) err = std::string(m) + " at offset " + std::to_string(i);
                return false;
            }
            static void PutUtf8(std::string& o, unsigned cp)
            {
                if (cp < 0x80) o += (char)cp;
                else if (cp < 0x800) {
                    o += (char)(0xC0 | (cp >> 6));
                    o += (char)(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000) {
                    o += (char)(0xE0 | (cp >> 12));
                    o += (char)(0x80 | ((cp >> 6) & 0x3F));
                    o += (char)(0x80 | (cp & 0x3F));
                } else {
                    o += (char)(0xF0 | (cp >> 18));
                    o += (char)(0x80 | ((cp >> 12) & 0x3F));
                    o += (char)(0x80 | ((cp >> 6) & 0x3F));
                    o += (char)(0x80 | (cp & 0x3F));
                }
            }
            bool Hex4(unsigned& v)
            {
                if (i + 4 > s.size()) return false;
                v = 0;
                for (int k = 0; k < 4; ++k) {
                    char c = s[i++];
                    v <<= 4;
                    if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
                    else return false;
                }
                return true;
            }
            bool Str(std::string& o)
            {
                if (s[i] != '"') return Fail("expected string");
                ++i;
                while (i < s.size()) {
                    char c = s[i++];
                    if (c == '"') return true;
                    if (c != '\\') {
                        o += c;
                        continue;
                    }
                    if (i >= s.size()) break;
                    char e = s[i++];
                    switch (e) {
                    case '"': o += '"'; break;
                    case '\\': o += '\\'; break;
                    case '/': o += '/'; break;
                    case 'b': o += '\b'; break;
                    case 'f': o += '\f'; break;
                    case 'n': o += '\n'; break;
                    case 'r': o += '\r'; break;
                    case 't': o += '\t'; break;
                    case 'u': {
                        unsigned cp;
                        if (!Hex4(cp)) return Fail("bad \\u escape");
                        if (cp >= 0xD800 && cp < 0xDC00 && i + 6 <= s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                            i += 2;
                            unsigned lo;
                            if (!Hex4(lo)) return Fail("bad surrogate");
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        }
                        PutUtf8(o, cp);
                        break;
                    }
                    default: return Fail("bad escape");
                    }
                }
                return Fail("unterminated string");
            }
            bool Val(Value& v, int depth)
            {
                if (depth > 64) return Fail("nesting too deep");
                Ws();
                if (i >= s.size()) return Fail("unexpected end");
                char c = s[i];
                if (c == '{') {
                    v.type = Value::kObject;
                    ++i;
                    Ws();
                    if (i < s.size() && s[i] == '}') {
                        ++i;
                        return true;
                    }
                    while (true) {
                        Ws();
                        std::string k;
                        if (i >= s.size() || !Str(k)) return Fail("expected key");
                        Ws();
                        if (i >= s.size() || s[i] != ':') return Fail("expected ':'");
                        ++i;
                        Value child;
                        if (!Val(child, depth + 1)) return false;
                        v.obj.push_back({ std::move(k), std::move(child) });
                        Ws();
                        if (i < s.size() && s[i] == ',') {
                            ++i;
                            continue;
                        }
                        if (i < s.size() && s[i] == '}') {
                            ++i;
                            return true;
                        }
                        return Fail("expected ',' or '}'");
                    }
                }
                if (c == '[') {
                    v.type = Value::kArray;
                    ++i;
                    Ws();
                    if (i < s.size() && s[i] == ']') {
                        ++i;
                        return true;
                    }
                    while (true) {
                        Value child;
                        if (!Val(child, depth + 1)) return false;
                        v.arr.push_back(std::move(child));
                        Ws();
                        if (i < s.size() && s[i] == ',') {
                            ++i;
                            continue;
                        }
                        if (i < s.size() && s[i] == ']') {
                            ++i;
                            return true;
                        }
                        return Fail("expected ',' or ']'");
                    }
                }
                if (c == '"') {
                    v.type = Value::kString;
                    return Str(v.str);
                }
                if (s.compare(i, 4, "true") == 0) {
                    v.type = Value::kBool;
                    v.b = true;
                    i += 4;
                    return true;
                }
                if (s.compare(i, 5, "false") == 0) {
                    v.type = Value::kBool;
                    i += 5;
                    return true;
                }
                if (s.compare(i, 4, "null") == 0) {
                    i += 4;
                    return true;
                }
                if (c == '-' || (c >= '0' && c <= '9')) {
                    const char* b = s.c_str() + i;
                    char* e = nullptr;
                    v.type = Value::kNumber;
                    v.num = strtod(b, &e);
                    if (e == b) return Fail("bad number");
                    i += (size_t)(e - b);
                    return true;
                }
                return Fail("unexpected character");
            }
        };
    }

    bool Parse(const std::string& text, Value& out, std::string& err)
    {
        P p{ text };
        if (text.size() >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF)
            p.i = 3;
        if (!p.Val(out, 0)) {
            err = p.err;
            return false;
        }
        return true;
    }

    std::string Quote(const std::string& s)
    {
        std::string o = "\"";
        for (unsigned char c : s) {
            switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    o += buf;
                } else {
                    o += (char)c;
                }
            }
        }
        return o + "\"";
    }
}
