#include "crc.h"
//for the moment just .text section
// You can have false flag sometimes because of mutation encryption etc etc
bool crc::check_text_integrity(const wchar_t* moduleName)
{
    HMODULE hModule = GetModuleHandleW(moduleName);
    if (!hModule)
        return false;
    auto base = reinterpret_cast<std::uint8_t*>(hModule);
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (std::strncmp((char*)section->Name, ".text", 5) == 0)
        {
            std::uint8_t* sectionStart = base + section->VirtualAddress;
            DWORD sectionSize = section->Misc.VirtualSize;

            std::vector<std::uint8_t> currentData(sectionSize);
            memcpy(currentData.data(), sectionStart, sectionSize);

            wchar_t fullPath[MAX_PATH];
            GetModuleFileNameW(hModule, fullPath, MAX_PATH);
            HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hFile == INVALID_HANDLE_VALUE)
                return false;

            HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!hMapping)
            {
                CloseHandle(hFile);
                return false;
            }

            std::uint8_t* fileData = reinterpret_cast<std::uint8_t*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
            if (!fileData)
            {
                CloseHandle(hMapping);
                CloseHandle(hFile);
                return false;
            }

            IMAGE_DOS_HEADER* fileDos = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData);
            IMAGE_NT_HEADERS* fileNt = reinterpret_cast<IMAGE_NT_HEADERS*>(fileData + fileDos->e_lfanew);
            IMAGE_SECTION_HEADER* fileSection = IMAGE_FIRST_SECTION(fileNt);

            for (int j = 0; j < fileNt->FileHeader.NumberOfSections; ++j, ++fileSection)
            {
                if (std::strncmp((char*)fileSection->Name, ".text", 5) == 0)
                {
                    std::uint8_t* fileTextStart = fileData + fileSection->PointerToRawData;
                    DWORD fileTextSize = fileSection->SizeOfRawData;

                    if (fileTextSize > sectionSize)
                        fileTextSize = sectionSize;

                    if (memcmp(fileTextStart, sectionStart, fileTextSize) != 0)
                    {
                        std::cout << "[!] .text section has been modified!\n";
                        UnmapViewOfFile(fileData);
                        CloseHandle(hMapping);
                        CloseHandle(hFile);
                        return true;
                    }
                    break;
                }
            }

            UnmapViewOfFile(fileData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            break;
        }
    }

    return false;
}

bool crc::is_function_hooked(uintptr_t modulebase, uintptr_t function)
{
    
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(modulebase);
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(modulebase + dosHeader->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section)
    {
        if (std::strncmp((char*)section->Name, ".text", 5) == 0)
        {
            uintptr_t sectionStart = modulebase + section->VirtualAddress;
            uintptr_t sectionEnd = sectionStart + section->Misc.VirtualSize;
            if (function >= sectionStart && function < sectionEnd)
            {
                
                BYTE original[16];
                SIZE_T bytesRead;
                if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)function, original, sizeof(original), &bytesRead))
                    return true;

                if (original[0] == 0xE9 || original[0] == 0xEA ||
                    (original[0] == 0xFF && (original[1] & 0xF0) == 0x20) ||
                    (original[0] == 0x48 && original[1] == 0xB8 && original[10] == 0xFF && original[11] == 0xE0))
                    return true;

                return false;
            }
        }
    }

    return true;
}

