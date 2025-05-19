#pragma once
#include "../../includes.h"

typedef struct _peb {
    INT32 security;
    INT32 proc_id;
    ULONGLONG* address;
} peb, * ppeb;

typedef struct _BA {

    INT32 security;
    INT32 process_id;
    const char* module_name;
    ULONGLONG* address;
} BA, * PBA;
typedef struct _ba {
    const char* module_name;
    INT32 security;
    INT32 process_id;
    ULONGLONG* address;

} ba, * pba;

typedef struct _MODULE {
	const char* module_name;
	INT32 security;
	ULONGLONG* address;
} MODULE, * PMODULE;

class module
{
    public:
    NTSTATUS GetPeb(ppeb request, PVOID* peb_address);
    void* GetProcessModuleBase(PEPROCESS process, UNICODE_STRING module_name);
    NTSTATUS FindBaseAddress(pba x);
    unsigned long long GetSystemModuleBase(PMODULE request, uint64_t* module_address);
    unsigned long long Internal_GetSystemModuleBase(const char* request);
    SIZE_T Internal_GetSystemModuleSize(const char* module_name);

};
inline module* module_instance;

