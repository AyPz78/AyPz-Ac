#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>

inline uintptr_t virtualaddy;
inline uintptr_t cr3;

#define CODE_RW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2345, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_BA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3456, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_GET_GUARDED_REGION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4567, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_SYS_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4568, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_GET_DIR_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x5678, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MOUSE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN,  0x010, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_PROTECT_PID CTL_CODE(FILE_DEVICE_UNKNOWN,  0x023, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define getpeb CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1648, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define CODE_SECURITY 0x9af2b37


typedef struct _rw {
    INT32 security;
    INT32 process_id;
    ULONGLONG address;
    ULONGLONG buffer;
    ULONGLONG size;
    BOOLEAN write;
} rw, * prw;

typedef struct _ba {
    const char* module_name;
    INT32 security;
    INT32 process_id;
    ULONGLONG* address;

} ba, * pba;
typedef struct _peb {
    INT32 security;
    INT32 proc_id;
    ULONGLONG* address;
} peb, * ppeb;
typedef struct _ga {
    INT32 security;
    ULONGLONG* address;
} ga, * pga;

typedef struct _MEMORY_OPERATION_DATA {
    uint32_t        pid;
    ULONGLONG* cr3;
} MEMORY_OPERATION_DATA, * PMEMORY_OPERATION_DATA;

struct ProcessProtectArgs {
    size_t pid;
};

typedef struct _MODULE {
    const char* module_name;
    INT32 security;
    ULONGLONG* address;
} MODULE, * PMODULE;

namespace mem {
    inline HANDLE driver_handle;
    inline  INT32 process_id;

    inline  bool find_driver() {
  
        driver_handle = CreateFileW((L"\\\\.\\xalixac"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        if (!driver_handle || (driver_handle == INVALID_HANDLE_VALUE))
            return false;

        return true;
      
    }

    inline  void read_physical(PVOID address, PVOID buffer, DWORD size) {
        _rw arguments = { 0 };

        arguments.security = CODE_SECURITY;
        arguments.address = (ULONGLONG)address;
        arguments.buffer = (ULONGLONG)buffer;
        arguments.size = size;
        arguments.process_id = process_id;
        arguments.write = FALSE;

        DeviceIoControl(driver_handle, CODE_RW, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
    }

    inline   void write_physical(PVOID address, PVOID buffer, DWORD size) {
        _rw arguments = { 0 };

        arguments.security = CODE_SECURITY;
        arguments.address = (ULONGLONG)address;
        arguments.buffer = (ULONGLONG)buffer;
        arguments.size = size;
        arguments.process_id = process_id;
        arguments.write = TRUE;

        DeviceIoControl(driver_handle, CODE_RW, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
    }

    inline  uintptr_t fetch_cr3() {
        uintptr_t cr3 = NULL;
        _MEMORY_OPERATION_DATA arguments = { 0 };

        arguments.pid = process_id;
        arguments.cr3 = (ULONGLONG*)&cr3;

        DeviceIoControl(driver_handle, CODE_GET_DIR_BASE, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

        return cr3;
    }


    inline    uintptr_t find_image(const char* module) {
        uintptr_t image_address = { NULL };
        _ba arguments = { NULL };

        arguments.security = CODE_SECURITY;
        arguments.process_id = process_id;
        arguments.module_name = module;
        arguments.address = (ULONGLONG*)&image_address;

        DeviceIoControl(driver_handle, CODE_BA, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

        return image_address;
    }

    inline    PVOID get_peb() {
        PVOID peb_address = NULL;
        peb arguments = { 0 };
        arguments.security = CODE_SECURITY;
        arguments.proc_id = process_id;
        arguments.address = (ULONGLONG*)&peb_address;

        DeviceIoControl(driver_handle, getpeb, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

        return peb_address;
    }
    inline void readsize(const std::uintptr_t address, void* buffer, std::size_t size)
    {
        _rw arguments = { 0 };

        arguments.security = CODE_SECURITY;
        arguments.address = address;
        arguments.buffer = reinterpret_cast<std::uintptr_t>(buffer);  // Pas besoin de cast ici
        arguments.size = size;
        arguments.process_id = process_id;
        arguments.write = FALSE;
        DeviceIoControl(driver_handle, CODE_RW, &arguments, sizeof(arguments), nullptr, 0, nullptr, nullptr);
    }

    inline void protect_process(int pid)
    {
		ProcessProtectArgs args;
		args.pid = pid;
		DeviceIoControl(driver_handle, CODE_PROTECT_PID, &args, sizeof(args), nullptr, NULL, NULL, NULL);
    }
    inline uintptr_t GetSystemModuleBase(const char* module_name)
    {
		uintptr_t system_module_base =  NULL ;
		MODULE arguments = { 0 };
		arguments.security = CODE_SECURITY;
        arguments.module_name = module_name;
		arguments.address = (ULONGLONG*)&system_module_base;
		DeviceIoControl(driver_handle, CODE_SYS_MODULE, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
		return system_module_base;
    }

    inline   INT32 find_process(LPCTSTR process_name) {
        PROCESSENTRY32 pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pt.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pt)) {
            do {
                if (!lstrcmpi(pt.szExeFile, process_name)) {
                    CloseHandle(hsnap);
                    process_id = pt.th32ProcessID;
                    return pt.th32ProcessID;
                }
            } while (Process32Next(hsnap, &pt));
        }
        CloseHandle(hsnap);

        return { NULL };
    }
}

class Driver
{
public:

    template <typename T>
    T rpm(uint64_t address) {
        T buffer{ };
        mem::read_physical((PVOID)address, &buffer, sizeof(T));
        return buffer;
    }

    template <typename T>
    T wpm(uint64_t address, T buffer) {

        mem::write_physical((PVOID)address, &buffer, sizeof(T));
        return buffer;
    }

    std::string read_string(uint64_t address) {
        std::string buffer;
        char ch;
        while (true) {
            ch = rpm<char>(address++);
            if (ch == '\0') break;
            buffer += ch;
        }
        return buffer;
    }

    const char* read_string_def(uint64_t address)
    {
        char buffer[1000];
        mem::readsize(address, &buffer, sizeof(buffer));
        return buffer;
    }

    const char* read_string_to_memory(uint64_t address)
    {
        if (uint64_t ptr = rpm<uint64_t>(address))
            return read_string_def(ptr);

        return "";
    }
    uintptr_t __fastcall ReadChain(uintptr_t base, const std::vector<uintptr_t>& offsets) {

        uintptr_t result = driver.rpm<uintptr_t>(base + offsets.at(0));
        for (int i = 1; i < offsets.size(); i++) {
            result = rpm<uintptr_t>(result + offsets.at(i));
        }
        return result;

    }


    template <typename t>
    t read_chain(uintptr_t address, std::vector<uintptr_t> chain)
    {
        uintptr_t cur_read = address;

        for (int i = 0; i < chain.size() - 1; ++i)
            cur_read = rpm<uintptr_t>(cur_read + chain[i]);

        return rpm<t>(cur_read + chain[chain.size() - 1]);
    }
    std::string read_ascii(const std::uintptr_t address, std::size_t size)
    {
        std::unique_ptr<char[]> buffer(new char[size]);
        mem::readsize(address, buffer.get(), size);
        return std::string(buffer.get());
    }

    std::wstring read_unicode(const std::uintptr_t address, std::size_t size)
    {
        const auto buffer = std::make_unique<wchar_t[]>(size);
        mem::readsize(address, buffer.get(), size * 2);
        return std::wstring(buffer.get());
    }


}inline driver;

