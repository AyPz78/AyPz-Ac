#pragma once
#include "../../includes.h"
typedef struct _RW {
    INT32 security;
    INT32 process_id;
    ULONGLONG address;
    ULONGLONG buffer;
    ULONGLONG size;
    BOOLEAN write;
} RW, * PRW;

class cpy_tool
{
public:
  
    NTSTATUS read_write(PRW x);
    NTSTATUS read(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read);
    NTSTATUS write(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read);
    UINT64 translate_linear(UINT64 directoryTableBase, UINT64 virtualAddress);
	
};
inline cpy_tool* cpy_tool_instance;
