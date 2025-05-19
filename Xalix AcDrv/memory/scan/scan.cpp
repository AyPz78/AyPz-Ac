#include "scan.h"


PBYTE scan::PatternScanEx(PVOID Module, DWORD Size, LPCSTR Pattern, LPCSTR Mask)
{

	auto CheckMask = [](PBYTE Buffer, LPCSTR Pattern, LPCSTR Mask) -> BOOL
		{
			for (auto x = Buffer; *Mask; Pattern++, Mask++, x++)
			{
				auto Addr = *(BYTE*)(Pattern);
				if (Addr != *x && *Mask != '?')
					return FALSE;
			}

			return TRUE;
		};

	auto StrLen = [](const char* String) -> size_t
		{
			UINT32 Length = 0;

			while (*String)
			{
				Length++;
				String++;
			}

			return (Length);
		};

	for (auto x = 0; x < Size - StrLen(Mask); x++) {

		auto Addr = (PBYTE)Module + x;
		if (CheckMask(Addr, Pattern, Mask))
		{
			return Addr;
		}
	}

	return NULL;

}

PBYTE scan::PatternScan(PVOID Module, LPCSTR Pattern, LPCSTR Mask)
{

	PIMAGE_NT_HEADERS Nt = (PIMAGE_NT_HEADERS)((PBYTE)Module + *(LONG*)((PBYTE)Module + 0x3C));

	auto Section = IMAGE_FIRST_SECTION(Nt);

	auto MemCmp = [](const void* s1, const void* s2, size_t n) -> int
		{
			if (n != 0) {
				const unsigned char* p1 = (const unsigned char*)s1, * p2 = (const unsigned char*)s2;
				do {
					if (*p1++ != *p2++)
						return (*--p1 - *--p2);
				} while (--n != 0);
			}
			return 0;
		};

	for (auto x = 0; x < Nt->FileHeader.NumberOfSections; x++, Section++)
	{
		if (!MemCmp(Section->Name, SK(".text"), 5) || !MemCmp(Section->Name, SK("PAGE"), 4))
		{
			auto Addr = PatternScanEx((PBYTE)Module + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			return Addr;
		}
	}

	return NULL;

}

void scan::ParseIdaSig(const char* idaSig, PUCHAR pattern, PUCHAR mask, size_t& outLen)
{
    auto in_range = [](char x, char a, char b) {
        return x >= a && x <= b;
        };

    auto get_bits = [in_range](char x) -> int {
        if (in_range(x, '0', '9')) return x - '0';
        if (in_range(x, 'A', 'F')) return x - 'A' + 0xA;
        if (in_range(x, 'a', 'f')) return x - 'a' + 0xA;
        return -1;
        };

    auto get_byte = [get_bits](const char* str) -> int {
        int high = get_bits(str[0]);
        int low = get_bits(str[1]);
        if (high < 0 || low < 0) return -1;
        return (high << 4) | low;
        };

    outLen = 0;

    while (*idaSig)
    {
        if (*idaSig == ' ') {
            idaSig++;
            continue;
        }

        if (*idaSig == '?') {
            pattern[outLen] = 0x00;
            mask[outLen] = 0;
            idaSig++;
            if (*idaSig == '?') idaSig++; // double ??
        }
        else {
            int byte = get_byte(idaSig);
            if (byte < 0)
                break; // stop if pattern malformé

            pattern[outLen] = (UCHAR)byte;
            mask[outLen] = 1;
            idaSig += 2;
        }

        outLen++;
    }
}

PBYTE scan::PatternScanIDA(PVOID Base, DWORD Size, const char* idaSig)
{
    UCHAR pattern[256]{};
    UCHAR mask[256]{};
    size_t patternLength = 0;
    ParseIdaSig(idaSig, pattern, mask, patternLength);

    PUCHAR mem = (PUCHAR)Base;

    for (DWORD i = 0; i <= Size - patternLength; ++i)
    {
        BOOLEAN found = TRUE;
        for (DWORD j = 0; j < patternLength; ++j)
        {
            if (mask[j] && mem[i + j] != pattern[j])
            {
                found = FALSE;
                break;
            }
        }

        if (found)
            return mem + i;
    }

    return nullptr;
}

PBYTE scan::FindPattern(PVOID ModuleBase, const char* idaSig)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return nullptr;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return nullptr;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4))
        {
            PBYTE addr = PatternScanIDA((PUCHAR)ModuleBase + section->VirtualAddress, section->Misc.VirtualSize, idaSig);
            if (addr)
                return addr;
        }
    }

    return nullptr;
}