#pragma once
#include "Common.h"

namespace hm
{
    // Everything in the report is UTF-8 so it round-trips through JSON for --diff.

    enum Severity
    {
        kInfo = 0,
        kLow = 1,
        kMedium = 2,
        kHigh = 3
    };
    const char* SeverityName(int s);

    struct ModuleRec
    {
        std::string name, path, physPath, source, category;
        std::string base;  // hex
        uint32_t    size = 0;
        bool        windows = false;
        bool        allowlisted = false;
        std::string allowNote;

        std::string fileVersion, productName, company;
        std::string linker, toolset, crt, built, pdb;
        std::string clibFlavor, clibConfidence, clibEvidence;
        std::vector<std::string> features;

        bool        skseVersionExport = false, skseQueryExport = false, skseLoadExport = false;
        std::string pluginName, pluginAuthor, pluginVersion;
        std::string compat, compatStatus;  // ok / warn / bad / ""

        std::vector<std::string> exceptionApis;
        std::string skseLog;
        std::string scanNote;
        int patchesOwned = 0;
        int patchesInside = 0;
        int orphanStubs = 0;
    };

    struct PatchRec
    {
        int         id = 0;
        std::string inModule;
        uint64_t    rva = 0;
        uint32_t    len = 0;
        std::string kind;       // call, jmp, vptr, iat, bytes, ...
        std::string kindNote;   // e.g. "jcc -> jmp", "+3 pad"
        std::string origBytes, newBytes;
        std::string target;     // "Foo.dll+0x1234" / "private 0x..." / ""
        std::string owner;      // module name, "" when unknown
        std::string ownerHow;   // direct / via trampoline / via thunk (inferred) / byte pattern (inferred) / unknown
        std::vector<std::string> chain;
        std::string chainStatus;
        std::vector<std::string> victims;
        std::vector<std::string> otherRefs;
        std::string location;   // ID / name / vtable slot / export
        std::string Key() const;
    };

    struct ConflictRec
    {
        int         severity = kInfo;
        bool        expected = false;
        std::string category;   // clobber, shared-site, same-function, cross-module, veh, compat, iat, skse-log, orphan
        std::string title;
        std::string detail;
        std::vector<std::string> modules;
        std::vector<int>         patches;
        std::string key;
    };

    struct Report
    {
        std::string tool = kToolName, toolVersion = kToolVersion;
        std::string generated, gameVersion, gameExe, processInfo;
        std::string addrLib, names, mo2, skseLogFile, baseline;
        bool        shared = false;
        std::vector<std::string> notes;
        std::vector<ModuleRec>   modules;
        std::vector<PatchRec>    patches;
        std::vector<ConflictRec> conflicts;
    };

    // Output
    std::string ToJson(const Report& r);
    bool FromJson(const std::string& text, Report& r, std::string& err);
    std::string ToHtml(const Report& r);
    std::string DiffHtml(const Report& before, const Report& after, const std::string& beforeName, const std::string& afterName);

    // --share: scrub user names / machine name / personal folder prefixes from every string.
    void Sanitize(Report& r, const std::vector<std::pair<std::wstring, std::wstring>>& replacements);
}
