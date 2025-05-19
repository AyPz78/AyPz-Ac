#include "cr3.h"

INT32 get_winver() { // as explnained befour this is to get ur winver
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);
	switch (ver.dwBuildNumber)
	{
	case win_1803:
		return 0x0278;
		break;
	case win_1809:
		return 0x0278;
		break;
	case win_1903:
		return 0x0280;
		break;
	case win_1909:
		return 0x0280;
		break;
	case win_2004:
		return 0x0388;
		break;
	case win_20H2:
		return 0x0388;
		break;
	case win_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

PVOID cr3::GetProcessCr3(const PEPROCESS hprocess)
{
	PUCHAR process = (PUCHAR)hprocess;				
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
	if (process_dirbase == 0) {
		INT32 UserDirOffset = get_winver();
	
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return (PVOID)process_userdirbase;
	}


	return (PVOID)process_dirbase;
}