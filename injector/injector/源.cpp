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
	//调试权限可以让该进程能够读取其他进程的信息。
	BOOL fOk = FALSE;    // Assume function fails
	HANDLE hToken;

	// 获取当前进程的令牌！
	//这个函数第一个参数是当前进程句柄，第二个参数是：进程对获得的令牌，有那些操作
	//权限。
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES,
		&hToken)) {

		//开始激活当前令牌的调试权限。
		TOKEN_PRIVILEGES tp;//结构体，表示令牌权限
							/*
							typedef struct _TOKEN_PRIVILEGES {
							DWORD               PrivilegeCount;
							//这个结构体，有几个权限，也就是第二个成员变量Privaileges数组，有几个元素。
							LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
							} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

							typedef struct _LUID_AND_ATTRIBUTES {
							LUID  Luid;//本地唯一标识符。不肯能重复的一个数组。这个东西和GUID是一个东西
							DWORD Attributes;//权限属性。
							} LUID_AND_ATTRIBUTES, *PLUID_AND_ATTRIBUTES;


							*/
		tp.PrivilegeCount = 1;//此时我们只启动调试权限，所以是1
							  //下面一个函数，查找调试权限的LUID，如果第一个参数是NULL，表示获取本地
							  //的某个权限的LUID
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		//上面的LookupPrivilegeValue函数，获取本地系统的调试权限的LUID。

		//下面一句话，在tp.Privileges[0].Attributes属性中，设置是开启这个权限，还是
		//关闭这个权限。
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		//当Attributes=SE_PRIVILEGE_ENABLE时，激活权限
		//当Attributes=0时，关闭权限。
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		//AdjustTokenPrivileges激活或者关闭tp中给定的权限。
		fOk = (GetLastError() == ERROR_SUCCESS);//确实激活是否成功。
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
	
	//这是要传给远程线程中LoadLibraryW的，所以必须是全路径
	TCHAR szLibFile[MAX_PATH];
	GetModuleFileName(NULL, szLibFile, _countof(szLibFile));
	PTSTR pFilename = _tcsrchr(szLibFile, TEXT('\\')) + 1;

	_tcscpy_s(pFilename, _countof(szLibFile) - (pFilename - szLibFile),
		TEXT("HookAPIWithMinHook.dll"));//将准备好的DLL，放在和injector同级目录下

	if (InjectLib(dwProcessId, szLibFile)) {
		chMB("DLL Injection successful.");
	}
	else
	{
		chMB("DLL Injection failed.");
		return 0;
	}
		

	//正式卸载DLL
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
	//很随意的调用这个函数，通过创建远程线程，让远程线程执行FreeLibrary，将DLL从目标进程的地址空间移除
	//容易导致目标进程访问非法内存，以至于目标进程崩溃
	//这里通过一个设计，确保目标进程解除对指定API的拦截之后，再执行卸载DLL的

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