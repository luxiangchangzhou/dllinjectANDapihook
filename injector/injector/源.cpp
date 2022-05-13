#include <Windows.h>
#include <stdio.h>
#include <StrSafe.h>
#include <tchar.h>
#include <TlHelp32.h>

#include <wingdi.h>

#include "MinHook.h"

#pragma comment(lib,"libMinHook.x64.lib")


#ifdef UNICODE
#define InjectLib InjectLibW
#define EjectLib  EjectLibW
#else
#define InjectLib InjectLibA
#define EjectLib  EjectLibA
#endif   // !UNICODE

BOOL WINAPI InjectLibW(DWORD dwProcessId, PCWSTR pszLibFile);
BOOL WINAPI InjectLibA(DWORD dwProcessId, PCSTR pszLibFile);
BOOL WINAPI EjectLibW(DWORD dwProcessId, PCWSTR pszLibFile);
BOOL WINAPI EjectLibA(DWORD dwProcessId, PCSTR pszLibFile);

void chMB(PCSTR szMsg);


///////////////////////////////////////////////////////////////////////////////


#include <iostream>

using namespace std;

BOOL EnableDebugPrivilege(BOOL fEnable)
{
	//����Ȩ�޿����øý����ܹ���ȡ�������̵���Ϣ��
	BOOL fOk = FALSE;    // Assume function fails
	HANDLE hToken;

	// ��ȡ��ǰ���̵����ƣ�
	//���������һ�������ǵ�ǰ���̾�����ڶ��������ǣ����̶Ի�õ����ƣ�����Щ����
	//Ȩ�ޡ�
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
		&hToken)) {

		//��ʼ���ǰ���Ƶĵ���Ȩ�ޡ�
		TOKEN_PRIVILEGES tp;//�ṹ�壬��ʾ����Ȩ��
							/*
							typedef struct _TOKEN_PRIVILEGES {
							DWORD               PrivilegeCount;
							//����ṹ�壬�м���Ȩ�ޣ�Ҳ���ǵڶ�����Ա����Privaileges���飬�м���Ԫ�ء�
							LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
							} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

							typedef struct _LUID_AND_ATTRIBUTES {
							LUID  Luid;//����Ψһ��ʶ�����������ظ���һ�����顣���������GUID��һ������
							DWORD Attributes;//Ȩ�����ԡ�
							} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;


							*/
		tp.PrivilegeCount = 1;//��ʱ����ֻ��������Ȩ�ޣ�������1
							  //����һ�����������ҵ���Ȩ�޵�LUID�������һ��������NULL����ʾ��ȡ����
							  //��ĳ��Ȩ�޵�LUID
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		//�����LookupPrivilegeValue��������ȡ����ϵͳ�ĵ���Ȩ�޵�LUID��

		//����һ�仰����tp.Privileges[0].Attributes�����У������ǿ������Ȩ�ޣ�����
		//�ر����Ȩ�ޡ�
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		//��Attributes=SE_PRIVILEGE_ENABLEʱ������Ȩ��
		//��Attributes=0ʱ���ر�Ȩ�ޡ�
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		//AdjustTokenPrivileges������߹ر�tp�и�����Ȩ�ޡ�
		fOk = (GetLastError() == ERROR_SUCCESS);//ȷʵ�����Ƿ�ɹ���
		CloseHandle(hToken);
	}
	return(fOk);
}

/*
void * orign_func_createmutexw = CreateMutexW;

HANDLE WINAPI LXCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName)
{
	MessageBoxA(0, 0, 0, MB_OK);
	printf("hook CreateMutexW...........................\n");
	return ((HANDLE(*)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR))orign_func_createmutexw)(lpMutexAttributes, bInitialOwner, lpName);
}
*/


int main()
{
	
	//EnableDebugPrivilege(TRUE);

	/*
	MH_STATUS ret = MH_Initialize();
	ret = MH_CreateHookApi(
		L"Kernel32.dll", "CreateMutexW", LXCreateMutexW, &orign_func_createmutexw);
	ret = MH_EnableHook(CreateMutexW);
	CreateMutexW(0, 0, 0);
	ret = MH_RemoveHook(CreateMutexW);
	CreateMutexW(0, 0, 0);
	ret = MH_Uninitialize();
	*/
	DWORD dwProcessId = 20452;
	//cout << "enter process id" << endl;

	//cin >> dwProcessId;
	
	//����Ҫ����Զ���߳���LoadLibraryW�ģ����Ա�����ȫ·��
	TCHAR szLibFile[MAX_PATH];
	GetModuleFileName(NULL, szLibFile, _countof(szLibFile));
	PTSTR pFilename = _tcsrchr(szLibFile, TEXT('\\')) + 1;

	_tcscpy_s(pFilename, _countof(szLibFile) - (pFilename - szLibFile),
		TEXT("HookAPIWithMinHook.dll"));//��׼���õ�DLL�����ں�injectorͬ��Ŀ¼��

	if (InjectLib(dwProcessId, szLibFile)) {
		chMB("DLL Injection successful.");
	}
	else
	{
		chMB("DLL Injection failed.");
		return 0;
	}
		

	//��ʽж��DLL
	if (EjectLib(dwProcessId, szLibFile))
	{
		chMB("Ejection successful.");
	}
	else
	{
		chMB("Ejection failed.");
		return 0;
	}
	

	return 0;
}

void chMB(PCSTR szMsg) {
	char szTitle[MAX_PATH];
	GetModuleFileNameA(NULL, szTitle, _countof(szTitle));
	MessageBoxA(GetActiveWindow(), szMsg, szTitle, MB_OK);
}





BOOL WINAPI InjectLibW(DWORD dwProcessId, PCWSTR pszLibFile) {

	BOOL bOk = FALSE; // Assume that the function fails
	HANDLE hProcess = NULL, hThread = NULL;
	PWSTR pszLibFileRemote = NULL;

	__try {
		// Get a handle for the target process.
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION |   // Required by Alpha
			PROCESS_CREATE_THREAD |   // For CreateRemoteThread
			PROCESS_VM_OPERATION |   // For VirtualAllocEx/VirtualFreeEx
			PROCESS_VM_WRITE,             // For WriteProcessMemory
			FALSE, dwProcessId);
		if (hProcess == NULL) __leave;

		// Calculate the number of bytes needed for the DLL's pathname
		int cch = 1 + lstrlenW(pszLibFile);
		int cb = cch * sizeof(wchar_t);

		// Allocate space in the remote process for the pathname
		pszLibFileRemote = (PWSTR)
			VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL) __leave;

		// Copy the DLL's pathname to the remote process' address space
		if (!WriteProcessMemory(hProcess, pszLibFileRemote,
			(PVOID)pszLibFile, cb, NULL)) __leave;

		// Get the real address of LoadLibraryW in Kernel32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
		if (pfnThreadRtn == NULL) __leave;

		// Create a remote thread that calls LoadLibraryW(DLLPathname)
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, pszLibFileRemote, 0, NULL);

		int i = GetLastError();

		if (hThread == NULL) __leave;

		// Wait for the remote thread to terminate
		WaitForSingleObject(hThread, INFINITE);

		bOk = TRUE; // Everything executed successfully
	}
	__finally { // Now, we can clean everything up

				// Free the remote memory that contained the DLL's pathname
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return(bOk);
}


///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI InjectLibA(DWORD dwProcessId, PCSTR pszLibFile) {

	// Allocate a (stack) buffer for the Unicode version of the pathname
	SIZE_T cchSize = lstrlenA(pszLibFile) + 1;
	PWSTR pszLibFileW = (PWSTR)
		_alloca(cchSize * sizeof(wchar_t));

	// Convert the ANSI pathname to its Unicode equivalent
	StringCchPrintfW(pszLibFileW, cchSize, L"%S", pszLibFile);

	// Call the Unicode version of the function to actually do the work.
	return(InjectLibW(dwProcessId, pszLibFileW));
}


///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI EjectLibW(DWORD dwProcessId, PCWSTR pszLibFile) {

	//luxiang add
	//������ĵ������������ͨ������Զ���̣߳���Զ���߳�ִ��FreeLibrary����DLL��Ŀ����̵ĵ�ַ�ռ��Ƴ�
	//���׵���Ŀ����̷��ʷǷ��ڴ棬������Ŀ����̱���
	//����ͨ��һ����ƣ�ȷ��Ŀ����̽����ָ��API������֮����ִ��ж��DLL��

	//description: 





	BOOL bOk = FALSE; // Assume that the function fails
	HANDLE hthSnapshot = NULL;
	HANDLE hProcess = NULL, hThread = NULL;

	__try {
		// Grab a new snapshot of the process
		hthSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hthSnapshot == INVALID_HANDLE_VALUE) __leave;

		// Get the HMODULE of the desired library
		MODULEENTRY32W me = { sizeof(me) };
		BOOL bFound = FALSE;
		BOOL bMoreMods = Module32FirstW(hthSnapshot, &me);
		for (; bMoreMods; bMoreMods = Module32NextW(hthSnapshot, &me)) {
			bFound = (_wcsicmp(me.szModule, pszLibFile) == 0) ||
				(_wcsicmp(me.szExePath, pszLibFile) == 0);
			if (bFound) break;
		}
		if (!bFound) __leave;

		// Get a handle for the target process.
		hProcess = OpenProcess(
			PROCESS_QUERY_INFORMATION |
			PROCESS_CREATE_THREAD |
			PROCESS_VM_OPERATION,  // For CreateRemoteThread
			FALSE, dwProcessId);
		if (hProcess == NULL) __leave;

		// Get the real address of FreeLibrary in Kernel32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "FreeLibrary");
		if (pfnThreadRtn == NULL) __leave;

		// Create a remote thread that calls FreeLibrary()
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, me.modBaseAddr, 0, NULL);
		if (hThread == NULL) __leave;

		// Wait for the remote thread to terminate
		WaitForSingleObject(hThread, INFINITE);

		bOk = TRUE; // Everything executed successfully
	}
	__finally { // Now we can clean everything up

		if (hthSnapshot != NULL)
			CloseHandle(hthSnapshot);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return(bOk);
}


///////////////////////////////////////////////////////////////////////////////


BOOL WINAPI EjectLibA(DWORD dwProcessId, PCSTR pszLibFile) {

	// Allocate a (stack) buffer for the Unicode version of the pathname
	SIZE_T cchSize = lstrlenA(pszLibFile) + 1;
	PWSTR pszLibFileW = (PWSTR)
		_alloca(cchSize * sizeof(wchar_t));

	// Convert the ANSI pathname to its Unicode equivalent
	StringCchPrintfW(pszLibFileW, cchSize, L"%S", pszLibFile);

	// Call the Unicode version of the function to actually do the work.
	return(EjectLibW(dwProcessId, pszLibFileW));
}

///////////////////////////////////////////////////////////////////////////////