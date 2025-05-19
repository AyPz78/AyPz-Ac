#pragma once
#include "../../includes.h"

class dbg
{
    private :
    std::vector<std::string> suspicious_strings = {
    "cheatengine", "injector", "aimbot", "esp", "hacks", "bypass", "x64dbg"
    };

    std::vector<std::string> suspicious_dlls = {
        "dbghelp.dll",
        "dbgeng.dll",
        "dbgclr.dll",
        "dbgcore.dll",
        "dbgview.exe",
        "windbg.exe",
        "x64dbg.exe",
        "ollydbg.exe"
    };

	public:
	dbg() = default;
	bool dtc_peb();
	bool rwx_check();
	bool suspicious_dll();
	bool detect_plaintext_strings();
};
inline dbg* dbg_tool;


