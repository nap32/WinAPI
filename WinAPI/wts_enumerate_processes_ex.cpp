#include "wts_enumerate_process_ex.h"

extern bool add_sedebug(void);

int main() {
	// Add debugging privs.
	if (!add_sedebug()) {
		_tprintf(_T("Failed to add SeDebug.\n"));
	}

	// WTSEnumerateProcessesEx https://msdn.microsoft.com/en-us/library/windows/desktop/ee621013(v=vs.85).aspx
	// WTS_PROCESS_INFO_EX:  https://msdn.microsoft.com/en-us/library/windows/desktop/ee621026(v=vs.85).aspx
	// The caller must be a member of the Administrators group to enumerate processes that are running under another user session.

	DWORD level = 1; // WTS_PROCESS_INFO_EX flag.
	PWTS_PROCESS_INFO_EX processListing = NULL;
	DWORD processCount = 0;

	if (!WTSEnumerateProcessesEx(
		WTS_CURRENT_SERVER_HANDLE,
		&level,
		WTS_ANY_SESSION,
		(LPTSTR*)&processListing,
		&processCount))
	{

		_tprintf(_T("WTSEnumerateProcessesEx failed.\n"));
	}

	// Parse the process information
	_tprintf(_T("Processes Found: %d\n\n"), processCount);
	LPTSTR stringSID = NULL;
	PWTS_PROCESS_INFO_EX originalPtr = processListing;

	_tprintf(_T("#\tPID\tHandles\tThreads\tProcess Name\nSID\tUser\n\n"));

	for (DWORD counter = 1; counter <= processCount; counter++) {
		_tprintf(_T("%d\t"), counter);
		_tprintf(_T("%d\t"), processListing->ProcessId);
		_tprintf(_T("%d\t"), processListing->HandleCount);
		_tprintf(_T("%d\t"), processListing->NumberOfThreads);
		_tprintf(_T("%s\n"), processListing->pProcessName);

		// SID enumeration.
		if (!ConvertSidToStringSid(processListing->pUserSid, &stringSID)) {
			_tprintf(_T("-\t"));
		}
		else {
			_tprintf(_T("%s\t"), stringSID);
			LocalFree((HLOCAL)stringSID);
		}

		// SID->Account Name Enumeration
		// LookupAccountSid https://msdn.microsoft.com/en-us/library/windows/desktop/aa379166(v=vs.85).aspx
		TCHAR accountName[MAX_ACCOUNTNAME_LEN];
		DWORD bufferLen = MAX_ACCOUNTNAME_LEN;
		TCHAR domainName[MAX_DOMAINNAME_LEN];
		DWORD domainNameBufferLen = MAX_DOMAINNAME_LEN;
		SID_NAME_USE peUse;
		//Print account Name.
		if (!LookupAccountSid(
			NULL,
			processListing->pUserSid,
			accountName,
			&bufferLen,
			domainName,
			&domainNameBufferLen,
			&peUse ))
		{
			_tprintf(_T("\n"));
		}else{
			_tprintf(_T("%s\\%s\n\n"), domainName, accountName);
		}

		processListing++;
	}

	// Free the memory!
	// WTSFreeMemoryEx https://msdn.microsoft.com/en-us/library/ee621015(v=vs.85).aspx 

	if (!WTSFreeMemoryEx(WTSTypeProcessInfoLevel1, originalPtr, processCount)) {

		_tprintf(_T("WTSFreeMemoryEx failed.\n"));
	}
	processListing = NULL;

	_tprintf(_T("\n\nDone.\n"));

	getchar();
	return	0;

}