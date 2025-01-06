#include "stdafx.h"

ULONG _G_TlsIndex;

LRESULT CALLBACK CBTProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HCBT_CREATEWND)
	{
		CBT_CREATEWND* pccw = reinterpret_cast<CBT_CREATEWND*>(lParam);

		if (pccw->lpcs->lpszClass == WC_DIALOG)
		{
			if (HICON hIcon = (HICON)TlsGetValue(_G_TlsIndex))
			{
				SendMessageW((HWND)wParam, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
			}
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}

ULONG WINAPI DemoThread(HANDLE )
{
	WCHAR FileName[0x100];
	if (GetModuleFileNameW((HMODULE)&__ImageBase, FileName, _countof(FileName)))
	{
		MSGBOXPARAMSW mbp = {
			sizeof(mbp),
			0,
			(HINSTANCE)&__ImageBase,
			FileName,
			L"POC",
			MB_USERICON | MB_OK,
			MAKEINTRESOURCE(1)
		};

		HHOOK hhk = 0;
		HICON hIcon = 0;

		if (0 <= LoadIconWithScaleDown(0, IDI_INFORMATION,
			GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &hIcon))
		{
			TlsSetValue(_G_TlsIndex, hIcon);
			hhk = SetWindowsHookExW(WH_CBT, CBTProc, 0, GetCurrentThreadId());
		}

		MessageBoxIndirect(&mbp);

		if (hhk) UnhookWindowsHookEx(hhk);

		TlsSetValue(_G_TlsIndex, 0);
		if (hIcon) DestroyIcon(hIcon);
	}

	FreeLibraryAndExitThread((HMODULE)&__ImageBase, 0);
}

BOOLEAN WINAPI DllMain(HMODULE hmod, DWORD dwReason, HANDLE hThread)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hmod);
		_G_TlsIndex = TlsAlloc();
		if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (PCWSTR)hmod, &hmod))
		{
			if (hThread = CreateThread(0, 0, DemoThread, 0, 0, 0))
			{
				CloseHandle(hThread);
				break;
			}
			FreeLibrary(hmod);
		}
		return FALSE;
	case DLL_PROCESS_DETACH:
		TlsFree(_G_TlsIndex);
		break;
	}

	return TRUE;
}