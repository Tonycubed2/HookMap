#pragma once
#include <map>
#include <string>
#include <vector>

namespace hm::json
{
    // Minimal JSON value + parser, enough to read HookMap's own reports back for --diff.
    struct Value
    {
        enum Type { kNull, kBool, kNumber, kString, kArray, kObject } type = kNull;
        bool        b = false;
        double      num = 0;
        std::string str;
        std::vector<Value> arr;
        std::vector<std::pair<std::string, Value>> obj;

        const Value* Get(const std::string& key) const
        {
            for (auto& kv : obj)
                if (kv.first == key) return &kv.second;
            return nullptr;
        }
        std::string GetStr(const std::string& key) const
        {
            auto v = Get(key);
            return v && v->type == kString ? v->str : std::string();
        }
        double GetNum(const std::string& key) const
        {
            auto v = Get(key);
            return v && v->type == kNumber ? v->num : 0.0;
        }
        bool GetBool(const std::string& key) const
        {
            auto v = Get(key);
            return v && v->type == kBool && v->b;
        }
        std::vector<std::string> GetStrList(const std::string& key) const
        {
            std::vector<std::string> out;
            if (auto v = Get(key); v && v->type == kArray)
                for (auto& e : v->arr)
                    if (e.type == kString) out.push_back(e.str);
            return out;
        }
    };

    bool Parse(const std::string& text, Value& out, std::string& err);
    std::string Quote(const std::string& s);
}
