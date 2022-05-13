#include <windows.h>
#include <stdio.h>
#include "MinHook.h"

#include <gl\GL.h>
#pragma comment(lib,"opengl32.lib")

#pragma comment(lib,"libMinHook.x64.lib")//这东西是个静态库，本文件输出的是一个DLL



void * orign_func = SwapBuffers;

BOOL should_unload_dll = FALSE;


BOOL LXSwapBuffers(HDC unnamedParam1)
{


	static int flg = 0;
	static unsigned char * pixels_data = new unsigned char[3000 * 3000 * 3];
	//使用内核对象，对性能影响很大
	//HANDLE hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, L"lxEject");
	flg++;
	//opengl每画三帧，调用GDI重画一次
	if (flg%3 == 0)
	{
		//flg++;
		GLint viewport[4];//视⼝
		glGetIntegerv(GL_VIEWPORT, viewport);


		HDC hdc = GetDC(0);
		char s[100] = { 0 };
		sprintf(s, "%d   %d   %d   %d", viewport[0], viewport[1], viewport[2], viewport[3]);
		TextOutA(hdc, 100, 100, s, 100);
		ReleaseDC(0, hdc);

		glReadPixels(viewport[0], viewport[1], viewport[2], viewport[3], GL_BGR_EXT, GL_UNSIGNED_BYTE, pixels_data);


		BITMAPINFO bmi;
		::ZeroMemory(&bmi, sizeof(BITMAPINFO));
		bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bmi.bmiHeader.biWidth = viewport[2];
		bmi.bmiHeader.biHeight = viewport[3];
		bmi.bmiHeader.biPlanes = 1;
		bmi.bmiHeader.biBitCount = 24; // 恢复tcpsocket时改成32！
		bmi.bmiHeader.biCompression = BI_RGB;
		bmi.bmiHeader.biSizeImage = viewport[2] * viewport[3] * 3; // 恢复tcpsocket时改成4！

		//HDC desktop_dc = GetDC(0);
		StretchDIBits(unnamedParam1, 0, 0, bmi.bmiHeader.biWidth,
			bmi.bmiHeader.biHeight, 0, 0, bmi.bmiHeader.biWidth,
			bmi.bmiHeader.biHeight, pixels_data, (BITMAPINFO*)&bmi.bmiHeader,
			DIB_RGB_COLORS, SRCCOPY);
		//ReleaseDC(0, desktop_dc);

		/*
		FILE * fp = fopen("C:\\Users\\luxiang\\Desktop\\1.luxiang", "wb");
		fwrite(pixels_data, viewport[2] * viewport[3] * 4, 1, fp);
		fclose(fp);
		*/
		//glClearColor(0.2f, 0.3f, 0.3f, 1.0f);
		//glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);



	}

	if (should_unload_dll == TRUE)
	{
		MH_RemoveHook(SwapBuffers);
		MH_Uninitialize();
		delete [] pixels_data;
		should_unload_dll = FALSE;
		return SwapBuffers(unnamedParam1);
	}
	
	return ((BOOL(*)(HDC))(orign_func))(unnamedParam1);
}


BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	switch (ul_reason_for_call)
	{
		//由LoadLibraryW触发
	case DLL_PROCESS_ATTACH:
	{

		MH_STATUS ret = MH_Initialize();

		ret = MH_CreateHookApi(
			L"Gdi32.dll", "SwapBuffers", LXSwapBuffers, &orign_func);

		ret = MH_EnableHook(SwapBuffers);

		
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
		should_unload_dll = TRUE;
		int i = 0;
		for (; should_unload_dll==TRUE;i++)
		{
			if (i > 8)
			{
				MH_RemoveHook(SwapBuffers);
				MH_Uninitialize();
				break;
			}
			Sleep(100);
		}
		Sleep(100);//保险起见，这个sleep是必要的
		//CreateMutexW
		

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