#include "cpy_tool.h"


ULONG64 find_min(INT32 g, SIZE_T f) {
    INT32 h = (INT32)f;
    ULONG64 result = 0;

    result = (((g) < (h)) ? (g) : (h));

    return result;
}

NTSTATUS cpy_tool::read(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
    if (!target_address)
        return STATUS_UNSUCCESSFUL;

    MM_COPY_ADDRESS address_to_read = { 0 };
    address_to_read.PhysicalAddress.QuadPart = (uint64_t)target_address;

    void* nonpaged_buffer = ExAllocatePoolWithTag(NonPagedPool, size, 'tran');
    if (!nonpaged_buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = MmCopyMemory(nonpaged_buffer, address_to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);

    if (NT_SUCCESS(status))
    {
        RtlCopyMemory(buffer, nonpaged_buffer, size);
        *bytes_read = size;
    }
    ExFreePoolWithTag(nonpaged_buffer, 'tran');
    return status;
}

NTSTATUS cpy_tool::write(PVOID target_address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
    SPOOF_FUNC;
    if (!target_address)
        return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS AddrToWrite = { 0 };
    AddrToWrite.QuadPart = LONGLONG(target_address);

    PVOID pmapped_mem = DynamicMmMapIoSpaceEx(AddrToWrite, size, PAGE_READWRITE);

    if (!pmapped_mem)
        return STATUS_UNSUCCESSFUL;

    memcpy(pmapped_mem, buffer, size);

    *bytes_read = size;
    DynamicMmUnmapIoSpace(pmapped_mem, size);
    return STATUS_SUCCESS;
}


NTSTATUS cpy_tool::read_write(PRW x) {
    if (x->security != CODE_SECURITY)
        return STATUS_UNSUCCESSFUL;

    if (!x->process_id)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS process = NULL;
    PsLookupProcessByProcessId((HANDLE)x->process_id, &process);
    if (!process)
        return STATUS_UNSUCCESSFUL;

	//get the directory table base
	ULONG_PTR dirBase = (ULONG_PTR)cr3_instance->GetProcessCr3(process);
    ULONGLONG process_base = dirBase;
    if (!process_base)
        return STATUS_UNSUCCESSFUL;
    ObDereferenceObject(process);

    SIZE_T this_offset = NULL;
    SIZE_T total_size = x->size;

    INT64 physical_address = translate_linear(process_base, (ULONG64)x->address + this_offset);
    if (!physical_address)
        return STATUS_UNSUCCESSFUL;

    ULONG64 final_size = find_min(PAGE_SIZE - (physical_address & 0xFFF), total_size);
    if (!final_size)  return STATUS_UNSUCCESSFUL;
    SIZE_T bytes_trough = NULL;

    if (x->write) {
        write(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
    }
    else {
        read(PVOID(physical_address), (PVOID)((ULONG64)x->buffer + this_offset), final_size, &bytes_trough);
    }

    return STATUS_SUCCESS;
}


UINT64 cpy_tool::translate_linear(UINT64 directoryTableBase, UINT64 virtualAddress) {
    directoryTableBase &= ~0xf;

    UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
    UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
    UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
    UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
    UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

    SIZE_T readsize = 0;
    UINT64 pdpe = 0;
    read(PVOID(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
    if (~pdpe & 1)
        return 0;

    UINT64 pde = 0;
    read(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
    if (~pde & 1)
        return 0;

    if (pde & 0x80)
        return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

    UINT64 pteAddr = 0;
    read(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
    if (~pteAddr & 1)
        return 0;

    if (pteAddr & 0x80)
        return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

    virtualAddress = 0;
    read(PVOID((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
    virtualAddress &= PMASK;

    if (!virtualAddress)
        return 0;

    return virtualAddress + pageOffset;
}
