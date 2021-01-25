#include "sedebugprivilege.h"

	bool add_sedebug(void) {
		// Get a privilege value.
		// API - https://msdn.microsoft.com/en-us/library/windows/desktop/aa379180(v=vs.85).aspx
		// Privs - https://msdn.microsoft.com/en-us/library/windows/desktop/bb530716(v=vs.85).aspx
		LUID privilegeluid;
		if (!LookupPrivilegeValue(
			NULL,
			_T("SeDebugPrivilege"),
			&privilegeluid))
		{
			_tprintf(_T("LookupPrivilegeValue() failed."));
			return FALSE;
		}

		// Construct TOKEN_PRIVILEGES for SeDebugPrivilege.
		// https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
		TOKEN_PRIVILEGES tokenprivs;
		tokenprivs.PrivilegeCount = 1; // Only one privilege changed.
		tokenprivs.Privileges[0].Luid = privilegeluid; // Specify the privilege to be modified i.e. SeDebugPrivilege
		tokenprivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // Let's enable this privilege.

		// Get current process handle - https://msdn.microsoft.com/en-us/library/windows/desktop/ms683179(v=vs.85).aspx
		// Get process token - https://msdn.microsoft.com/en-us/library/windows/desktop/aa379295(v=vs.85).aspx
		// Token access rights - https://msdn.microsoft.com/en-us/library/windows/desktop/aa374905(v=vs.85).aspx

		// Get process token to current process.
		HANDLE currentProcessHandle = GetCurrentProcess();
		HANDLE processtoken;
		if (!OpenProcessToken(
			currentProcessHandle,
			TOKEN_ADJUST_PRIVILEGES,
			&processtoken
		))
		{
			_tprintf(_T("OpenProcessToken() failed.\n"));
			return FALSE;
		}

		// Add SeDebugPrivilege to a process token.
		if (!AdjustTokenPrivileges(
			processtoken,
			false,
			&tokenprivs,
			0,
			NULL,
			NULL))
		{
			_tprintf(_T("AdjustTokenPrivileges failed.\n"));
			return FALSE;
		}

		return TRUE;
	}