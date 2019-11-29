/*******************************************************************************
 *
 *                                   GRADIANT
 *
 *     Galician Research And Development center In AdvaNced Telecommunication
 *
 *
 * Copyright (c) 2019 by Gradiant. All rights reserved.
 * Licensed under the Mozilla Public License v2.0 (the "LICENSE").
 * https://github.com/Gradiant/BlackICE_Connect/LICENSE
 *******************************************************************************/


#include <Windows.h>
#include <KSP.h>
#include <stdio.h>   
#include <stdlib.h> 

WCHAR szItemPass[MAXPINLEN * 2];

BOOL CALLBACK GoToProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
			if (!GetDlgItemText(hwndDlg, IDC_EDIT1, szItemPass, MAXPINLEN))
			{
				*szItemPass = 0;
			}
			EndDialog(hwndDlg, wParam);
			PostQuitMessage(wParam);
			return TRUE;
		case IDCANCEL:
			EndDialog(hwndDlg, wParam);
			PostQuitMessage(wParam);
			return TRUE;
		default:
			return FALSE;
		}
	case WM_CLOSE:
		if (MessageBox(hwndDlg, L"Are you sure you want to exit?", L"Authentication", MB_OKCANCEL | MB_ICONQUESTION ) == IDOK)
		{
			DestroyWindow(hwndDlg);
			PostQuitMessage(IDCLOSE);
		}
		return TRUE;
	default:
		return FALSE;
	}
	return FALSE;
}

SECURITY_STATUS AuthDisplay(HINSTANCE hinst, char** pin)
{
	HWND hwndGoto = NULL;  // Window handle of dialog boxIDD_DIALOG1
	HWND hwndTextBox = NULL; // Handle of the password edit text box
	if (hinst == NULL) {
		hinst = GetModuleHandle(NULL);
	}
	hwndGoto = CreateDialog(hinst, MAKEINTRESOURCE(IDD_DIALOG1), NULL, (DLGPROC)GoToProc);
	hwndTextBox = GetDlgItem(hwndGoto, IDC_EDIT1);
	SendMessage(hwndGoto, WM_NEXTDLGCTL, (WPARAM)hwndTextBox, TRUE);
	ShowWindow(hwndGoto, SW_SHOW);
	BOOL bRet;
	MSG msg;
	while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0)
	{
		if (bRet == -1)
		{
			return NTE_INTERNAL_ERROR;
		}
		else if (!IsWindow(hwndGoto) || !IsDialogMessage(hwndGoto, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	switch (msg.wParam) {
	case IDOK:
		wcstombs(pin, szItemPass, wcslen(szItemPass));
		ZeroMemory(szItemPass, MAXPINLEN * 2);
		return ERROR_SUCCESS;
		break;
	case IDCLOSE:
	case IDCANCEL:
		return NTE_INCORRECT_PASSWORD;
		break;
	default:
		return NTE_INTERNAL_ERROR;
	}
}