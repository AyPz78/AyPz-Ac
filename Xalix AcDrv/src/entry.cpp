#include "../includes.h"


void HideDriver(PDRIVER_OBJECT DriverObject) {
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) {
        return;
    }
    RemoveEntryList(&entry->InLoadOrderLinks);
    RemoveEntryList(&entry->InMemoryOrderLinks);
    RemoveEntryList(&entry->InInitializationOrderLinks);
    InitializeListHead(&entry->InLoadOrderLinks);
    InitializeListHead(&entry->InMemoryOrderLinks);
    InitializeListHead(&entry->InInitializationOrderLinks);
}


NTSTATUS load_dynamic_functions() {
    UNICODE_STRING funcName;

    RtlInitUnicodeString(&funcName, SK(L"MmCopyMemory"));
    DynamicMmCopyMemory = (PVOID(*)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T))MmGetSystemRoutineAddress(&funcName);
    if (!DynamicMmCopyMemory) return STATUS_UNSUCCESSFUL;

    RtlInitUnicodeString(&funcName, SK(L"MmMapIoSpaceEx"));
    DynamicMmMapIoSpaceEx = (PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, ULONG))MmGetSystemRoutineAddress(&funcName);
    if (!DynamicMmMapIoSpaceEx) return STATUS_UNSUCCESSFUL;

    RtlInitUnicodeString(&funcName, SK(L"MmUnmapIoSpace"));
    DynamicMmUnmapIoSpace = (VOID(*)(PVOID, SIZE_T))MmGetSystemRoutineAddress(&funcName);
    if (!DynamicMmUnmapIoSpace) return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}
void unload_drv(PDRIVER_OBJECT drv_obj) {
    NTSTATUS status = { };

    status = IoDeleteSymbolicLink(&link);

    if (!NT_SUCCESS(status))
        return;

    IoDeleteDevice(drv_obj->DeviceObject);
}
NTSTATUS NTAPI IopInvalidDeviceRequest(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS dispatch_handler(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        break;
    case IRP_MJ_CLOSE:
        break;
    default:
        break;
    }

    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}




NTSTATUS io_controller(PDEVICE_OBJECT device_obj, PIRP irp) {
    SPOOF_FUNC;
    UNREFERENCED_PARAMETER(device_obj);

    NTSTATUS status = { };
    ULONG bytes = { };
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

    if (code == CODE_RW) {
        if (size == sizeof(RW)) {
            PRW req = (PRW)(irp->AssociatedIrp.SystemBuffer);

            status = cpy_tool_instance->read_write(req);
            bytes = sizeof(RW);
        }
        else
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            bytes = 0;
        }
    }
    else if (code == CODE_BA) {
        if (size == sizeof(_ba)) {
            pba req = (pba)(irp->AssociatedIrp.SystemBuffer);

            status = module_instance->FindBaseAddress(req);
            bytes = sizeof(_ba);
        }
        else
        {
            status = STATUS_INFO_LENGTH_MISMATCH;
            bytes = 0;
        }
    }
  
    else if (code == getpeb) {
        if (size == sizeof(peb)) {
            ppeb req = (ppeb)(irp->AssociatedIrp.SystemBuffer);

            PVOID peb_address = NULL;
            status = module_instance->GetPeb(req, &peb_address);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(req->address, &peb_address, sizeof(peb_address));
                bytes = sizeof(peb);
            }
            else {
                bytes = 0;
            }
        }
        else {
            status = STATUS_INFO_LENGTH_MISMATCH;
            bytes = 0;
        }
    }
    else if (code == CODE_GET_DIR_BASE) {
        PMEMORY_OPERATION_DATA req = (PMEMORY_OPERATION_DATA)(irp->AssociatedIrp.SystemBuffer);
        PEPROCESS process = NULL;
        PsLookupProcessByProcessId((HANDLE)req->pid, &process);
        if (!process)
            return STATUS_UNSUCCESSFUL;
        status = (uint64_t)cr3_instance->GetProcessCr3(process);
    }
    else if (code == CODE_SYS_MODULE)
    {
		if (size == sizeof(MODULE)) {
			PMODULE req = (PMODULE)(irp->AssociatedIrp.SystemBuffer);
			uint64_t module_address = 0;
			status = module_instance->GetSystemModuleBase(req, &module_address);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(req->address, &module_address, sizeof(module_address));
                bytes = sizeof(MODULE);
            }
            else {
                bytes = 0;
            }
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}

	}
	else if (code == CODE_PROTECT_PID) {
		if (size == sizeof(ProcessProtectArgs)) {
            auto args = static_cast<ProcessProtectArgs*>(irp->AssociatedIrp.SystemBuffer);
            status = callback_instance->protect_process(*args);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}


    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}


NTSTATUS initialize_driver(_In_ PDRIVER_OBJECT drv_obj, _In_ PUNICODE_STRING path) {
    UNREFERENCED_PARAMETER(path);

    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT device_obj = NULL;

    UNICODE_STRING name, link;
    RtlInitUnicodeString(&name, SK(L"\\Device\\xalixac"));
    RtlInitUnicodeString(&link, SK(L"\\DosDevices\\xalixac"));


    status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    HideDriver(drv_obj); 

    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device_obj);
        return status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        drv_obj->MajorFunction[i] = IopInvalidDeviceRequest;
    }

    drv_obj->MajorFunction[IRP_MJ_CREATE] = dispatch_handler;
    drv_obj->MajorFunction[IRP_MJ_CLOSE] = dispatch_handler;
    drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = io_controller;
    drv_obj->DriverUnload = unload_drv;

    device_obj->Flags |= DO_BUFFERED_IO;
    device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

    status = load_dynamic_functions();
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&link);
        IoDeleteDevice(device_obj);
        return status;
    }

    drv_obj->DriverSection = NULL;

    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);

    return IoCreateDriver(NULL, initialize_driver);
}