#include "callback.h"

OB_PREOP_CALLBACK_STATUS callback::PreOperationCallback(pcallback request, PVOID RegistrationContext,POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType == *PsProcessType) {
        PEPROCESS target = (PEPROCESS)OperationInformation->Object;
        HANDLE pid = PsGetProcessId(target);

		HANDLE g_ProtectedPid = (HANDLE)request->pid;
        if (pid == g_ProtectedPid) {
            ACCESS_MASK* access = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
            *access &= ~PROCESS_ALL_ACCESS;
        }
    }

    return OB_PREOP_SUCCESS;
}



NTSTATUS callback::protect_process(const ProcessProtectArgs& args) {
	if (nullptr == g_protected_processes) {
		auto entry = (ProtectProcessEntry*)ExAllocatePoolWithTag(PagedPool, sizeof ProtectProcessEntry, 0x1337);
		entry->args = args;
		g_protected_processes = &entry->next;
		return STATUS_SUCCESS;
	}
	else {
		auto entry = (ProtectProcessEntry*)ExAllocatePoolWithTag(PagedPool, sizeof ProtectProcessEntry, 0x1337);
		entry->args = args;
		PushEntryList(g_protected_processes, &entry->next);
		return STATUS_SUCCESS;
	}
}

OB_PREOP_CALLBACK_STATUS protect_processes_callback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION PreInfo) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (PreInfo->ObjectType == *PsProcessType && PreInfo->Object != PsGetCurrentProcess()) {
		auto current_entry = g_protected_processes;
		while (nullptr != current_entry) {
			auto pid = reinterpret_cast<size_t>(PsGetProcessId((PEPROCESS)PreInfo->Object));

			if (pid == CONTAINING_RECORD(current_entry, ProtectProcessEntry, next)->args.pid) {
				if (OB_OPERATION_HANDLE_CREATE == PreInfo->Operation) {
					if (PreInfo->KernelHandle != TRUE) {
						ACCESS_MASK bits_to_clear = PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD |
							PROCESS_DUP_HANDLE | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SUSPEND_RESUME |
							PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
						PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~bits_to_clear;
					}
				}
			}

			current_entry = current_entry->Next;
		}

	}
	else if (PreInfo->ObjectType == *PsThreadType) {
		HANDLE target_process_id = PsGetThreadProcessId((PETHREAD)PreInfo->Object);
		if (target_process_id != PsGetCurrentProcessId()) {
			goto exit;
		}
		auto current_entry = g_protected_processes;
		while (nullptr != current_entry) {
			if ((size_t)target_process_id == CONTAINING_RECORD(current_entry, ProtectProcessEntry, next)->args.pid) {
				if (OB_OPERATION_HANDLE_CREATE == PreInfo->Operation) {
					if (PreInfo->KernelHandle != TRUE) {
						ACCESS_MASK bits_to_clear = THREAD_DIRECT_IMPERSONATION | THREAD_IMPERSONATE |
							THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION | THREAD_SET_THREAD_TOKEN |
							THREAD_SUSPEND_RESUME | THREAD_TERMINATE;
						PreInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~bits_to_clear;
					}
				}
			}

			current_entry = current_entry->Next;
		}
	}

exit:
	return OB_PREOP_SUCCESS;
}

NTSTATUS callback::register_protectors() {
	OB_CALLBACK_REGISTRATION  ob_callback_registration;

	OB_OPERATION_REGISTRATION operation_registration[2] = {};
	operation_registration[0].ObjectType = PsProcessType;
	operation_registration[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	operation_registration[0].PreOperation = protect_processes_callback;
	operation_registration[0].PostOperation = nullptr;

	operation_registration[1].ObjectType = PsThreadType;
	operation_registration[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	operation_registration[1].PreOperation = protect_processes_callback;
	operation_registration[1].PostOperation = nullptr;

	UNICODE_STRING altitude = {};
	RtlInitUnicodeString(&altitude, L"99999999");
	ob_callback_registration.Version = OB_FLT_REGISTRATION_VERSION;
	ob_callback_registration.OperationRegistrationCount = 2;
	ob_callback_registration.Altitude = altitude;
	ob_callback_registration.RegistrationContext = nullptr;
	ob_callback_registration.OperationRegistration = operation_registration;

	return ObRegisterCallbacks(&ob_callback_registration, &g_registration_handle);
}