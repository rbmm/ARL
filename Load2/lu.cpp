#include "stdafx.h"

#include "resource.h"
#include "msgbox.h"

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))

NTSTATUS NTAPI LoadLibraryFromMem(_In_ PVOID pvImage, _In_opt_ SIZE_T Size, _Out_opt_ void** ppv);

HRESULT OnBrowse(_In_ HWND hwndDlg, _Out_ PWSTR* ppszFilePath)
{
	IFileDialog* pFileOpen;

	HRESULT hr = CoCreateInstance(__uuidof(FileOpenDialog), NULL, CLSCTX_ALL, IID_PPV_ARGS(&pFileOpen));

	if (SUCCEEDED(hr))
	{
		pFileOpen->SetOptions(FOS_NOVALIDATE | FOS_NOTESTFILECREATE |
			FOS_NODEREFERENCELINKS | FOS_DONTADDTORECENT | FOS_FORCESHOWHIDDEN);

		static const COMDLG_FILTERSPEC rgSpec[] =
		{
			{ L"DLL files", L"*.DLL" }, { L"ALL files", L"*"}
		};

		if (0 <= (hr = pFileOpen->SetFileTypes(_countof(rgSpec), rgSpec)) &&
			0 <= (hr = pFileOpen->SetFileTypeIndex(1)) &&
			0 <= (hr = pFileOpen->Show(hwndDlg)))
		{
			IShellItem* pItem;
			hr = pFileOpen->GetResult(&pItem);

			if (SUCCEEDED(hr))
			{
				hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, ppszFilePath);
				pItem->Release();
			}
		}
		pFileOpen->Release();
	}

	return hr;
}

HRESULT OnBrowse(HWND hwndDlg, UINT nIDDlgItem)
{
	PWSTR pszFilePath;
	HRESULT hr = OnBrowse(hwndDlg, &pszFilePath);

	if (S_OK == hr)
	{
		SetDlgItemTextW(hwndDlg, nIDDlgItem, pszFilePath);
		CoTaskMemFree(pszFilePath);
	}

	return hr;
}

NTSTATUS Map(PCWSTR FileName, _Out_ void** BaseAddress, _Out_ PSIZE_T ViewSize)
{
	WCHAR buf[MAX_PATH] = L"\\??\\";
	if (SearchPathW(0, FileName, L".dll", _countof(buf) - 4, buf + 4, 0))
	{
		HANDLE hFile, hSection;
		IO_STATUS_BLOCK iosb;
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		RtlInitUnicodeString(&ObjectName, buf);

		NTSTATUS status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
			FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

		if (0 <= status)
		{
			status = NtCreateSection(&hSection, SECTION_MAP_READ, 0, 0, PAGE_READONLY, SEC_COMMIT, hFile);
			NtClose(hFile);

			if (0 <= status)
			{
				*BaseAddress = 0;
				*ViewSize = 0;
				status = ZwMapViewOfSection(hSection, NtCurrentProcess(), BaseAddress, 0, 0, 0, ViewSize, ViewUnmap, MEM_TOP_DOWN, PAGE_READONLY);
				NtClose(hSection);
			}
		}

		return status;
	}

	return GetLastErrorEx();
}

VOID load(HWND hwnd)
{
	if (ULONG len = GetWindowTextLengthW(hwnd))
	{
		NTSTATUS status = STATUS_NO_MEMORY;
		void* hmod = 0;

		if (PWSTR psz = new WCHAR[++len])
		{
			if (GetWindowTextW(hwnd, psz, len))
			{
				PVOID pv;
				SIZE_T ViewSize;
				if (0 <= (status = Map(psz, &pv, &ViewSize)))
				{
					status = LoadLibraryFromMem(pv, ViewSize, &hmod);
					ZwUnmapViewOfSection(NtCurrentProcess(), pv);
				}
				else
				{
					status = GetLastErrorEx();
				}
			}
			delete[] psz;
		}

		if (status)
		{
			ShowErrorBox(hwnd, status, 0);
		}
		else
		{
			PLDR_DATA_TABLE_ENTRY ldte;
			if (0 <= LdrFindEntryForAddress(hmod, &ldte))
			{
				WCHAR sz[64];
				swprintf_s(sz, _countof(sz), L"base=%p size=%x", hmod, ldte->SizeOfImage);
				CustomMessageBox(hwnd, ldte->FullDllName.Buffer, sz, MB_ICONINFORMATION);
			}

			LdrUnloadDll(hmod);
		}
	}
}

void OnInitDialog(HWND hwnd)
{
	HICON hi;
	if (0 <= LoadIconWithScaleDown((HINSTANCE) & __ImageBase, MAKEINTRESOURCEW(1),
		GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &hi))
	{
		SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hi);
	}
}

INT_PTR CALLBACK DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
			load(GetDlgItem(hwnd, IDC_EDIT1));
			break;
		case IDCANCEL:
			EndDialog(hwnd, lParam);
			break;
		case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
			OnBrowse(hwnd, IDC_EDIT1);
			break;
		}
		break;
	case WM_INITDIALOG:
		OnInitDialog(hwnd);
		break;
	}
	return 0;
}

void ep(void*)
{
	if (0 <= CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE))
	{
		DialogBoxParamW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0, DlgProc, 0);
		CoUninitialize();
	}

	ExitProcess(0);
}
