---
layout: article
title: "[Rev]Windows Hooking(3)"
key: 20190227
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Windows Hooking(3)

<!--more-->

이번 예제는 계산기이다. 계산기에 계산결과를 한글로 출력하도록 특정 api를 후킹한다

바로 이전에는 디버기 상태로 만들어 후킹하는 방식이였다면 이번엔 **DLL 인젝션을 이용하여 IAT를 후킹**하는 방식이다.

단점이라고 한다면 대상 프로세스에 IAT가 없다면 사용할 수 없다. 사실 프로텍터 등을 이용해 IAT를 숨기기 때문에 실제 적용 가능할지는 의문이다.

사실 처음에 가장 어려운게 내가 원하는 API가 무엇인지 찾는게 어렵다. 다 외울수도 없고... 어떤 기능을하고 내가 원하는 기능을 가지고 있는지 등등... 검색과 경험만이 살 길 이다..

## [+] Example

### Process

계산기('calc.exe')를 PEview로 열어 `.text` 섹션의 IAT를 확인한다.

RVA 0x1110 쯤에 보면 `SetWindowTextW` API 함수가 존재하고 0x1140에 보면 `SetDlgItemTextW`API 함수가 있는 것을 확인 할 수 있다.

2개 API 모두 텍스트를 써주는 역할을 한다. 그렇다면 무엇을 후킹하면 원하는대로 계산기에 글자 입력이 가능할까..

그냥 책대로 하는 방법도 있겠지만 직접 증명하며 찾아본다. 먼저 `SetWindowTextW` 인지 확인해보자

디버거를 이용해 `Search for All intermodular calls`를 이용해 호출되는 함수들을 확인한다. 그리고 증명을 할 `SetWindowTextW`를 찾아 BP를 건다.

쭉 진행해서 계산기를 켠 다음 숫자를 입력하면 해당 함수에서 멈추는 것을 확인할 수 있으며 호출하기 전 `ESP+4` 위치에 텍스트가 들어가는 것을 볼 수 있다. 
이를 변조해보면 원하던 함수임을 알 수 있다. 

그렇다고 넘어가지말고 `SetDlgItemTextW` 함수도 해보자~ 확인해보면 원하는 것 처럼 숫자를 입력할 때 멈추지 않는다. Clear를 클릭하면 멈추는 것을 알 수 있다.

자 그럼 찾은 `SetWindowTextW` 함수의 원형은 다음과 같다.(여기서 ~A, ~W는 아스키와 유니코드를 의미한다.)

```c
BOOL SetWindowTextW(
  HWND   hWnd,
  LPCSTR lpString
);
```

윈도우나 컨트롤의 핸들을 이용하여 텍스트를 써넣는다. 이제 이 함수를 후킹하여 우리가 의도한대로 동작하게 해본다.

프로세스 호출되는 API들의 주소가 저장되는 곳이 IAT(Import Address Table)이다.

```sh
01001110 > .  0E96D077      DD      USER32.SetWindowTextW	#0x77D0960E가 SetWindowTextW 시작이다.
01001114 > .  12B1D077      DD      USER32.SetFocus
01001118 > .  3099D077      DD      USER32.SetCursor
... #2 IAT

01002621  |.  FF7424 10     PUSH    DWORD PTR SS:[ESP+10]            ; /Text
01002625  |.  8BF8          MOV     EDI, EAX                         ; |
01002627  |.  56            PUSH    ESI                              ; |hWnd
01002628  |.  FF15 10110001 CALL    DWORD PTR DS:[<&USER32.SetWindow>; \SetWindowTextW
#CALL    DWORD PTR DS:[1001110] IAT 참조
... #1 Call SetWindowTextW()

77D0960E >/$  8BFF          MOV     EDI, EDI
77D09610  |.  55            PUSH    EBP
77D09611  |.  8BEC          MOV     EBP, ESP
77D09613  |.  8B4D 08       MOV     ECX, DWORD PTR SS:[EBP+8]
77D09616  |.  56            PUSH    ESI
77D09617  |.  E8 C4EEFEFF   CALL    USER32.77CF84E0
77D0961C  |.  8BF0          MOV     ESI, EAX
77D0961E  |.  85F6          TEST    ESI, ESI
77D09620  |.  74 22         JE      SHORT USER32.77D09644
77D09622  |.  56            PUSH    ESI                              ; /Arg1
77D09623  |.  E8 EFF7FFFF   CALL    USER32.77D08E17                  ; \USER32.77D08E17
77D09628  |.  85C0          TEST    EAX, EAX
77D0962A  |.  6A 00         PUSH    0
77D0962C  |.  FF75 0C       PUSH    DWORD PTR SS:[EBP+C]
77D0962F  |.  6A 00         PUSH    0
77D09631  |.  6A 0C         PUSH    0C
77D09633  |.  56            PUSH    ESI
77D09634  |.  74 13         JE      SHORT USER32.77D09649
77D09636  |.  E8 78FBFFFF   CALL    USER32.77D091B3
77D0963B  |>  33C9          XOR     ECX, ECX
77D0963D  |.  85C0          TEST    EAX, EAX
77D0963F  |.  0F9DC1        SETGE   CL
77D09642  |.  8BC1          MOV     EAX, ECX
77D09644  |>  5E            POP     ESI
77D09645  |.  5D            POP     EBP
77D09646  |.  C2 0800       RETN    8
77D09649  |>  E8 8C060000   CALL    USER32.77D09CDA
77D0964E  \.^ EB EB         JMP     SHORT USER32.77D0963B
# in SetWindowTextW 

```

주석 내용대로 돌아간다. IAT를 참조하여 해당 함수를 호출하는건데 현재 위의 코드로 봤을 때는 `CALL 0x77D0960E` 랑 차이가 없다는 것을 알 수 있다.

자 그럼 실제 DLL 인젝션을 통해 후킹을 하는 원리는 다음과 같이 이루어 진다.

1. IAT 값을 변조하여 `SetWindowTextW` 함수의 시작 주소를 후킹 함수로 변조
2. 값을 한글(유니코드)로 변조한 후, 기존의 `SetWindowTextW` 함수를 호출한다~

후킹 함수가 있는 dll을 삽입하고 IAT의 4바이트 주소만 바꿔주면 끝이다.

### Analysis

제공하는 예제 `hookiat.dll` 의 소스코드는 다음과 같다.

```c
// include
#include "stdio.h"
#include "wchar.h"
#include "windows.h"


// typedef
typedef BOOL (WINAPI *PFSETWINDOWTEXTW)(HWND hWnd, LPWSTR lpString);


// globals
FARPROC g_pOrgFunc = NULL;


// 사용자 후킹 함수
BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
    wchar_t* pNum = L"영일이삼사오육칠팔구";
    wchar_t temp[2] = {0,};
    int i = 0, nLen = 0, nIndex = 0;

    nLen = wcslen(lpString);
    for(i = 0; i < nLen; i++)
    {
        // '수'문자를 '한글'문자로 변환
        //   lpString 은 wide-character (2 byte) 문자열
        if( L'0' <= lpString[i] && lpString[i] <= L'9' )
        {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp);
            lpString[i] = pNum[nIndex];
        }
    }

    // user32!SetWindowTextW() API 호출
    //   (위에서 lpString 버퍼 내용을 변경하였음)
    return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}


// hook_iat
//   현재 프로세스의 IAT 를 검색해서
//   pfnOrg 값을 pfnNew 값으로 변경시킴
BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc; 
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

    // hMod, pAddr = ImageBase of calc.exe
    //             = VA to MZ signature (IMAGE_DOS_HEADER)
	hMod = GetModuleHandle(NULL);
	pAddr = (PBYTE)hMod;

    // pAddr = VA to PE signature (IMAGE_NT_HEADERS)
	pAddr += *((DWORD*)&pAddr[0x3C]);

    // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
	dwRVA = *((DWORD*)&pAddr[0x80]);

    // pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod+dwRVA);

	for( ; pImportDesc->Name; pImportDesc++ )
	{
        // szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if( !_stricmp(szLibName, szDllName) )
		{
            // pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
            //        = VA to IAT(Import Address Table)
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + 
                                         pImportDesc->FirstThunk);

            // pThunk->u1.Function = VA to API
			for( ; pThunk->u1.Function; pThunk++ )
			{
				if( pThunk->u1.Function == (DWORD)pfnOrg )
				{
                    // 메모리 속성을 E/R/W 로 변경
					VirtualProtect((LPVOID)&pThunk->u1.Function, 
                                   4, 
                                   PAGE_EXECUTE_READWRITE, 
                                   &dwOldProtect);

                    // IAT 값을 변경
                    pThunk->u1.Function = (DWORD)pfnNew;
					
                    // 메모리 속성 복원
                    VirtualProtect((LPVOID)&pThunk->u1.Function, 
                                   4, 
                                   dwOldProtect, 
                                   &dwOldProtect);						

					return TRUE;
				}
			}
		}
	}

	return FALSE;
}



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch( fdwReason )
	{
		case DLL_PROCESS_ATTACH : 
            // original API 주소 저장
           	g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"), 
                                        "SetWindowTextW");

            // # hook
            //   user32!SetWindowTextW() 를 hookiat!MySetWindowText() 로 후킹
			hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);
			break;

		case DLL_PROCESS_DETACH :
            // # unhook
            //   calc.exe 의 IAT 를 원래대로 복원
            hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);
			break;
	}

	return TRUE;
}
```

이제 한땀한땀 분석을 해본다.

#### DllMain()

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch( fdwReason )
	{
		case DLL_PROCESS_ATTACH : 
            // original API 주소 저장
           	g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"), 
                                        "SetWindowTextW");

            // # hook
            //   user32!SetWindowTextW() 를 hookiat!MySetWindowText() 로 후킹
			hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);
			break;

		case DLL_PROCESS_DETACH :
            // # unhook
            //   calc.exe 의 IAT 를 원래대로 복원
            hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);
			break;
	}
	return TRUE;
}
```

case 문을 이용하여 프로세스의 메모리 공간에 맵핑 될 때(`DLL_PROCESS_ATTACH`)는 `g_pOrgFunc` 변수에 `GetProcAddress` 함수를 이용하여 원래의 `user32.SetWindowTextW` 의 주소를 저장하고 `hook_iat` 함수를 호출한다. 종료 될 때는 언훅을 통해 원래의 IAT로 복원하는 작업을 하게 된다.

#### MySetWindowTextW()

```c
BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
    wchar_t* pNum = L"영일이삼사오육칠팔구";
    wchar_t temp[2] = {0,};
    int i = 0, nLen = 0, nIndex = 0;

    nLen = wcslen(lpString);
    for(i = 0; i < nLen; i++)
    {
        // '수'문자를 '한글'문자로 변환
        //   lpString 은 wide-character (2 byte) 문자열
        if( L'0' <= lpString[i] && lpString[i] <= L'9' )
        {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp);
            lpString[i] = pNum[nIndex];
        }
    }
    // user32!SetWindowTextW() API 호출
    //   (위에서 lpString 버퍼 내용을 변경하였음)
    return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}
```

실제 데이터를 변조하는 함수이다.

```c
    for(i = 0; i < nLen; i++)
    {
        // '수'문자를 '한글'문자로 변환
        //   lpString 은 wide-character (2 byte) 문자열
        if( L'0' <= lpString[i] && lpString[i] <= L'9' )
        {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp);
            lpString[i] = pNum[nIndex];
        }
    }
```

반복문을 확인하면 입력된 값에 대한 길이만큼 반복하고 `_wtoi` 함수를 이용하여 int형으로 변환한다. 그 값을 배열의 인덱스 값으로 하여 한글과 매칭되도록 짜여진 코드다.

```c
return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
```

변환을 마치고 원래의 `user32.SetWindowTextW` 함수로 변조한 값을 전달하여 써지게 하는 원리이다.

마지막은 핵심 함수인 `hook_iat()`이다.

#### hook_iat()

```c
BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
	HMODULE hMod;
	LPCSTR szLibName;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc; 
	PIMAGE_THUNK_DATA pThunk;
	DWORD dwOldProtect, dwRVA;
	PBYTE pAddr;

    // hMod, pAddr = ImageBase of calc.exe
    //             = VA to MZ signature (IMAGE_DOS_HEADER)
	hMod = GetModuleHandle(NULL);
	pAddr = (PBYTE)hMod;

    // pAddr = VA to PE signature (IMAGE_NT_HEADERS)
	pAddr += *((DWORD*)&pAddr[0x3C]);

    // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
	dwRVA = *((DWORD*)&pAddr[0x80]);

    // pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod+dwRVA);

	for( ; pImportDesc->Name; pImportDesc++ )
	{
        // szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
		szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
		if( !_stricmp(szLibName, szDllName) )
		{
            // pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
            //        = VA to IAT(Import Address Table)
			pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + 
                                         pImportDesc->FirstThunk);

            // pThunk->u1.Function = VA to API
			for( ; pThunk->u1.Function; pThunk++ )
			{
				if( pThunk->u1.Function == (DWORD)pfnOrg )
				{
                    // 메모리 속성을 E/R/W 로 변경
					VirtualProtect((LPVOID)&pThunk->u1.Function, 
                                   4, 
                                   PAGE_EXECUTE_READWRITE, 
                                   &dwOldProtect);

                    // IAT 값을 변경
                    pThunk->u1.Function = (DWORD)pfnNew;
					
                    // 메모리 속성 복원
                    VirtualProtect((LPVOID)&pThunk->u1.Function, 
                                   4, 
                                   dwOldProtect, 
                                   &dwOldProtect);						

					return TRUE;
				}
			}
		}
	}
	return FALSE;
}
```

빡세서 30분만쉬고옴...

