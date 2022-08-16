// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "gui.h"

static constexpr const char* OVERLAY_WINDOW_CLASS_NAME = "LachClass";
static constexpr const char* OVERLAY_WINDOW_NAME = "pvzGUI";

DWORD WINAPI HackThread(HMODULE hModule)
{
	g_Menu.InitilizeWindow(hModule, OVERLAY_WINDOW_CLASS_NAME, OVERLAY_WINDOW_NAME);
	Menu::HandleMessages();

	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		HANDLE handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, 0);
		if (handle)
			CloseHandle(handle);
		break;
	}
	}
	return TRUE;
}