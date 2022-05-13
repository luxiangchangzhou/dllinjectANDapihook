// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "Toolhelp.h"
#include <ImageHlp.h>

#include <gl\GL.h>
#pragma comment(lib, "Opengl32")

#include "APIHook.h"

#pragma comment(lib, "ImageHlp")

// By default, the module containing the CAPIHook() is not hooked
//BOOL ExcludeAPIHookMod = TRUE;


//void ReplaceIATEntryInAllMods(PCSTR pszCalleeModName,PROC pfnCurrent, PROC pfnNew);




BOOL WINAPI LXGetMessageW(_Out_ LPMSG lpMsg,_In_opt_ HWND hWnd,_In_ UINT wMsgFilterMin,_In_ UINT wMsgFilterMax)
{
	MSG msg;
	BOOL ret = GetMessageW(&msg, hWnd, wMsgFilterMin, wMsgFilterMax);
	memcpy(lpMsg, &msg, sizeof(MSG));
	
	HDC hdc = GetDC(0);
	char s[100] = { 0 };
	sprintf(s, "%d", (int)msg.message);
	TextOutA(hdc, 100, 100, s, 10);

	ReleaseDC(0,hdc);


	return ret;
}

//CAPIHook g_GetMessageW("User32.dll", "GetMessageW",(PROC)LXGetMessageW);

BOOL LXwglSwapBuffers(HDC unnamedParam1)
{

	HDC hdc = GetDC(0);
	char s[100] = { 0 };
	sprintf(s, "%d", (int)unnamedParam1);
	TextOutA(hdc, 100, 100, s, 10);
	
	return SwapBuffers(unnamedParam1);
}

//CAPIHook g_wglSwapBuffers("Opengl32.dll", "wglSwapBuffers", (PROC)LXwglSwapBuffers);




BOOL LXwglSwapLayerBuffers(
	HDC  unnamedParam1,
	UINT unnamedParam2
)
{

	HDC hdc = GetDC(0);
	char s[100] = { 0 };
	sprintf(s, "%d", (int)unnamedParam1);
	TextOutA(hdc, 100, 100, s, 10);

	return wglSwapLayerBuffers(unnamedParam1,unnamedParam2);
}
CAPIHook g_wglSwapBuffers("Opengl32.dll", "wglSwapLayerBuffers", (PROC)LXwglSwapLayerBuffers);




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	//由LoadLibraryW触发
	case DLL_PROCESS_ATTACH:
		{
			//PROC pfnOrig = GetProcAddress(GetModuleHandle(L"User32.dll"), "GetMessageW");
			//char s[100] = { 0 };
			//sprintf(s, "%d", (int)pfnOrig);
			//MessageBoxA(0, s, s, MB_OK);
			//先hook GetMessageW  User32.dll
			//ReplaceIATEntryInAllMods("User32.dll", pfnOrig, (PROC)LXGetMessageW);
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	//模块卸载的时候，再把导入段换回来
	case DLL_PROCESS_DETACH:
		{
			//PROC pfnOrig = GetProcAddress(GetModuleHandle(L"User32.dll"), "GetMessageW");
			//char s[100] = { 0 };
			//sprintf(s, "%d", (int)pfnOrig);
			//MessageBoxA(0, s, s, MB_OK);
			// Unhook this function from all modules
			//ReplaceIATEntryInAllMods("User32.dll", (PROC)LXGetMessageW, pfnOrig);

		}
		break;
	}
	return TRUE;
}

/*

// Returns the HMODULE that contains the specified memory address
static HMODULE ModuleFromAddress(PVOID pv) {

	MEMORY_BASIC_INFORMATION mbi;
	return((VirtualQuery(pv, &mbi, sizeof(mbi)) != 0)
		? (HMODULE)mbi.AllocationBase : NULL);
}




// Handle unexpected exceptions if the module is unloaded
LONG WINAPI InvalidReadExceptionFilter(PEXCEPTION_POINTERS pep) {

	// handle all unexpected exceptions because we simply don't patch
	// any module in that case
	LONG lDisposition = EXCEPTION_EXECUTE_HANDLER;

	// Note: pep->ExceptionRecord->ExceptionCode has 0xc0000005 as a value

	return(lDisposition);
}


void ReplaceIATEntryInOneMod(PCSTR pszCalleeModName,
	PROC pfnCurrent, PROC pfnNew, HMODULE hmodCaller) {

	// Get the address of the module's import section
	ULONG ulSize;

	// An exception was triggered by Explorer (when browsing the content of 
	// a folder) into imagehlp.dll. It looks like one module was unloaded...
	// Maybe some threading problem: the list of modules from Toolhelp might 
	// not be accurate if FreeLibrary is called during the enumeration.
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
	__try {
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
			hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
	}
	__except (InvalidReadExceptionFilter(GetExceptionInformation())) {
		// Nothing to do in here, thread continues to run normally
		// with NULL for pImportDesc 
	}

	if (pImportDesc == NULL)
		return;  // This module has no import section or is no longer loaded


				 // Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++) {
		PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);
		if (lstrcmpiA(pszModName, pszCalleeModName) == 0) {

			// Get caller's import address table (IAT) for the callee's functions
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
				((PBYTE)hmodCaller + pImportDesc->FirstThunk);

			// Replace current function address with new function address
			for (; pThunk->u1.Function; pThunk++) {

				// Get the address of the function address
				PROC* ppfn = (PROC*)&pThunk->u1.Function;

				// Is this the function we're looking for?
				BOOL bFound = (*ppfn == pfnCurrent);
				if (bFound) {
					if (!WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
						sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError())) {
						DWORD dwOldProtect;
						if (VirtualProtect(ppfn, sizeof(pfnNew), PAGE_WRITECOPY,
							&dwOldProtect)) {

							WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew,
								sizeof(pfnNew), NULL);
							VirtualProtect(ppfn, sizeof(pfnNew), dwOldProtect,
								&dwOldProtect);
						}
					}
					return;  // We did it, get out
				}
			}
		}  // Each import section is parsed until the right entry is found and patched
	}
}

void ReplaceIATEntryInAllMods(PCSTR pszCalleeModName,
	PROC pfnCurrent, PROC pfnNew) {

	HMODULE hmodThisMod = ExcludeAPIHookMod
		? ModuleFromAddress(ReplaceIATEntryInAllMods) : NULL;

	// Get the list of modules in this process
	CToolhelp th(TH32CS_SNAPMODULE, GetCurrentProcessId());

	MODULEENTRY32 me = { sizeof(me) };
	for (BOOL bOk = th.ModuleFirst(&me); bOk; bOk = th.ModuleNext(&me)) {

		// NOTE: We don't hook functions in our own module
		if (me.hModule != hmodThisMod) {

			// Hook this function in this module
			ReplaceIATEntryInOneMod(
				pszCalleeModName, pfnCurrent, pfnNew, me.hModule);
		}
	}
}

*/


