#pragma once
#include <ntifs.h>
#include <windef.h>
#include <ntimage.h>
#include <cstdint>
#include <intrin.h>

#include "encryptions/spoof.h"

#include "struct/defines.h"

#include "memory/dirbase/cr3.h"
#include "memory/cpy/cpy_tool.h"
#include "memory/module/module.h"
#include "memory/scan/scan.h"

#include "features/callback/callback.h"

inline UNICODE_STRING name, link;
typedef struct _SYSTEM_BIGPOOL_ENTRY {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged : 1;
    ULONG_PTR SizeInBytes;
    UCHAR Tag[4];
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11,
    SystemBigPoolInformation = 0x42,
} SYSTEM_INFORMATION_CLASS;

extern "C" POBJECT_TYPE* IoDriverObjectType;
inline POBJECT_TYPE* IoDriverObjectType;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
extern "C" PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

inline PVOID(*DynamicMmCopyMemory)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T) = NULL;
inline PVOID(*DynamicMmMapIoSpaceEx)(PHYSICAL_ADDRESS, SIZE_T, ULONG) = NULL;
inline VOID(*DynamicMmUnmapIoSpace)(PVOID, SIZE_T) = NULL;


#define CODE_RW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2345, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_BA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3456, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_GET_GUARDED_REGION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4567, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_SYS_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x4568, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_GET_DIR_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x5678, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_MOUSE_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN,  0x010, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_PROTECT_PID CTL_CODE(FILE_DEVICE_UNKNOWN,  0x023, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define getpeb CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1648, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CODE_SECURITY 0x9af2b37

#define win_1803 17134
#define win_1809 17763
#define win_1903 18362
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180
#define win_21H2 22000
#define win_22H2 22621
#define win_23H2 22631
#define win_23H2 25290

#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;



typedef struct _GA {
    INT32 security;
    ULONGLONG* address;
} GA, * PGA;

typedef struct _MEMORY_OPERATION_DATA {
    uint32_t pid;
    uintptr_t cr3;
} MEMORY_OPERATION_DATA, * PMEMORY_OPERATION_DATA;