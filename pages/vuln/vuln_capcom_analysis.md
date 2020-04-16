---
title: Capcom Driver Analysis
keywords: documentation, Vulnerability
date: 2020-04-14
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "Capcom 커널 드라이버 분석"
sidebar: vuln_sidebar
permalink: vuln_capcom_analysis.html
folder: vuln
---

## [0x00] Overview

해당 드라이버는 캡콤 사의 게임을 플레이 시 설치되는 드라이버입니다. 간단히 설명하자면 해당 드라이버에서 임의 코드 실행이 가능한 부분이 존재하며 이는 `IOCTL Code`에 의해 제어됩니다. 이 취약한 함수는 `DeviceIoControl` 함수의 `InBuffer` 파라미터 함수의 주소로 처리하여 해당 메모리의 코드를 실행합니다. 정말 뜬금없지만 아마 개발자가 사용하려고 만들어놓은 것으로 예상됩니다.



## [0x01] Analysis

해당 드라이버를 `IDA`로 확인해보면 굉장히 크기가 작은 드라이버임을 알 수 있습니다. `DriverEntry`를 포함하여 8개의 함수로 이루어져 있습니다.

```
sub_103AC	.text	00000000000103AC	000000D0	00000048	00000000	R	.	.	.	.	.	.
sub_1047C	.text	000000000001047C	00000065	00000038	00000000	R	.	.	.	.	.	.
sub_104E4	.text	00000000000104E4	0000003D	00000028	00000000	R	.	.	.	.	.	.
sub_10524	.text	0000000000010524	0000006B	00000048	00000008	R	.	.	.	.	.	.
sub_10590	.text	0000000000010590	000000AC	00000038	00000000	R	.	.	.	.	.	.
DriverEntry	.text	000000000001063C	0000011B	00000078	00000018	R	.	.	.	.	T	.
sub_10788	.text	0000000000010788	00000011	00000000	00000000	R	.	.	.	.	.	.
sub_107A0	.text	00000000000107A0	00000008	00000000	00000000	R	.	.	.	.	.	.
```

문자열 또한 매우 적은 문자열들이 포함되어 있습니다.

```
.text:0000000000010758	0000001A	C (16 bits) - UTF-16LE	\\DosDevices\\
.text:0000000000010774	00000012	C (16 bits) - UTF-16LE	\\Device\\
.info:0000000000010988	00000006	C (16 bits)	KsT
.info:00000000000109AA	00000008	C (32 bits)	s
INIT:0000000000010B86	0000000D	C	ntoskrnl.exe
GAP:0000000000010CCA	0000000D	C	Western Cape1
GAP:0000000000010CE0	0000000D	C	\vDurbanville1
GAP:0000000000010CF7	00000007	C	Thawte1
GAP:0000000000010D08	00000015	C	Thawte Certification1
GAP:0000000000010D27	00000017	C	Thawte Timestamping CA0
GAP:0000000000010D40	0000000E	C	\r121221000000Z
GAP:0000000000010D4F	00000014	C	\r201230235959Z0^1\v0\t
GAP:0000000000010D77	00000018	C	Symantec Corporation100.
GAP:0000000000010D95	00000029	C	'Symantec Time Stamping Services CA - G20
GAP:0000000000010E33	00000005	C	r\x1B&Mq
GAP:0000000000010ECB	00000005	C	]jxdE
GAP:0000000000010F15	00000005	C	&0$0\"
GAP:0000000000010F26	00000017	C	http://ocsp.thawte.com0
GAP:0000000000010F58	00000005	C	80604
GAP:0000000000010F62	00000030	C	.http://crl.thawte.com/ThawteTimestampingCA.crl0
GAP:0000000000010FD0	00000012	C	TimeStamp-2048-10\r
```



### [-] DriverEntry

먼저 드라이버의 진입점부터 살펴보겠습니다.

```
.text:000000000001063C ; NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
.text:000000000001063C                 public DriverEntry
.text:000000000001063C DriverEntry     proc near               ; DATA XREF: HEADER:00000000000100E8↑o
.text:000000000001063C                                         ; .pdata:0000000000010930↓o ...
.text:000000000001063C
.text:000000000001063C DeviceCharacteristics= dword ptr -58h
.text:000000000001063C Exclusive       = byte ptr -50h
.text:000000000001063C DeviceObject    = qword ptr -48h
.text:000000000001063C DestinationString= UNICODE_STRING ptr -38h
.text:000000000001063C SymbolicLinkName= UNICODE_STRING ptr -28h
.text:000000000001063C arg_10          = qword ptr  18h
.text:000000000001063C
.text:000000000001063C                 push    rbx
.text:000000000001063E                 push    rdi
.text:000000000001063F                 sub     rsp, 68h
.text:0000000000010643                 mov     rbx, rcx
.text:0000000000010646                 lea     rdi, __ImageBase
.text:000000000001064D                 lea     r11, unk_10880
.text:0000000000010654                 xor     ecx, ecx
.text:0000000000010656
.text:0000000000010656 loc_10656:                              ; CODE XREF: DriverEntry+2E↓j
.text:0000000000010656                 movzx   eax, word ptr [rcx+rdi+774h]
.text:000000000001065E                 mov     [rcx+r11], ax
.text:0000000000010663                 add     rcx, 2
.text:0000000000010667                 test    ax, ax
.text:000000000001066A                 jnz     short loc_10656
.text:000000000001066C                 lea     rdx, unk_10980
.text:0000000000010673                 mov     rcx, r11
.text:0000000000010676                 call    sub_103AC
.text:000000000001067B                 lea     rcx, [rsp+78h+DestinationString] ; DestinationString
.text:0000000000010680                 mov     rdx, r11        ; SourceString
.text:0000000000010683                 call    cs:RtlInitUnicodeString
.text:0000000000010689                 lea     r11, [rsp+78h+arg_10]
.text:0000000000010691                 lea     r8, [rsp+78h+DestinationString] ; DeviceName
.text:0000000000010696                 mov     [rsp+78h+DeviceObject], r11 ; DeviceObject
.text:000000000001069B                 mov     r9d, 0AA01h     ; DeviceType
.text:00000000000106A1                 xor     edx, edx        ; DeviceExtensionSize
.text:00000000000106A3                 mov     rcx, rbx        ; DriverObject
.text:00000000000106A6                 mov     [rsp+78h+Exclusive], 0 ; Exclusive
.text:00000000000106AB                 mov     [rsp+78h+DeviceCharacteristics], 0 ; DeviceCharacteristics
.text:00000000000106B3                 call    cs:IoCreateDevice
.text:00000000000106B9                 test    eax, eax
.text:00000000000106BB                 js      loc_10750
.text:00000000000106C1                 xor     ecx, ecx
.text:00000000000106C3                 lea     r11, unk_10840
.text:00000000000106CA
.text:00000000000106CA loc_106CA:                              ; CODE XREF: DriverEntry+A2↓j
.text:00000000000106CA                 movzx   eax, word ptr [rcx+rdi+758h]
.text:00000000000106D2                 mov     [rcx+r11], ax
.text:00000000000106D7                 add     rcx, 2
.text:00000000000106DB                 test    ax, ax
.text:00000000000106DE                 jnz     short loc_106CA
.text:00000000000106E0                 lea     rdx, unk_10980
.text:00000000000106E7                 mov     rcx, r11
.text:00000000000106EA                 call    sub_103AC
.text:00000000000106EF                 lea     rcx, [rsp+78h+SymbolicLinkName] ; DestinationString
.text:00000000000106F4                 mov     rdx, r11        ; SourceString
.text:00000000000106F7                 call    cs:RtlInitUnicodeString
.text:00000000000106FD                 lea     rdx, [rsp+78h+DestinationString] ; DeviceName
.text:0000000000010702                 lea     rcx, [rsp+78h+SymbolicLinkName] ; SymbolicLinkName
.text:0000000000010707                 call    cs:IoCreateSymbolicLink
.text:000000000001070D                 test    eax, eax
.text:000000000001070F                 mov     edi, eax
.text:0000000000010711                 jns     short loc_10723
.text:0000000000010713                 mov     rcx, [rsp+78h+arg_10] ; DeviceObject
.text:000000000001071B                 call    cs:IoDeleteDevice
.text:0000000000010721                 jmp     short loc_1074E
.text:0000000000010723 ; ---------------------------------------------------------------------------
.text:0000000000010723
.text:0000000000010723 loc_10723:                              ; CODE XREF: DriverEntry+D5↑j
.text:0000000000010723                 lea     rax, sub_104E4
.text:000000000001072A                 mov     [rbx+80h], rax
.text:0000000000010731                 mov     [rbx+70h], rax
.text:0000000000010735                 lea     rax, sub_10590
.text:000000000001073C                 mov     [rbx+0E0h], rax
.text:0000000000010743                 lea     rax, sub_1047C
.text:000000000001074A                 mov     [rbx+68h], rax
.text:000000000001074E
.text:000000000001074E loc_1074E:                              ; CODE XREF: DriverEntry+E5↑j
.text:000000000001074E                 mov     eax, edi
.text:0000000000010750
.text:0000000000010750 loc_10750:                              ; CODE XREF: DriverEntry+7F↑j
.text:0000000000010750                 add     rsp, 68h
.text:0000000000010754                 pop     rdi
.text:0000000000010755                 pop     rbx
.text:0000000000010756                 retn
.text:0000000000010756 DriverEntry     endp
```

좀 더 보기 편하도록 의사코드로 확인해보겠습니다.

```c++
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  pDriver = DriverObject;
  v3 = 0i64;
  do
  {
    v4 = _ImageBase[v3 + 0x3BA];
    *(&unk_10880 + v3 * 2) = v4;
    ++v3;
  }
  while ( v4 );
  sub_103AC(&unk_10880, &unk_10980);
  RtlInitUnicodeString(&DestinationString, v5);
  result = IoCreateDevice(pDriver, 0, &DestinationString, 0xAA01u, 0, 0, &DeviceObject);
  if ( result >= 0 )
  {
    v7 = 0i64;
    do
    {
      v8 = _ImageBase[v7 + 0x3AC];
      *(&unk_10840 + v7 * 2) = v8;
      ++v7;
    }
    while ( v8 );
    sub_103AC(&unk_10840, &unk_10980);
    RtlInitUnicodeString(&SymbolicLinkName, v9);
    v10 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
    if ( v10 >= 0 )
    {
      pDriver->MajorFunction[2] = &sub_104E4;   // IRP_MJ_CLOSE
      pDriver->MajorFunction[0] = &sub_104E4;   // IRP_MJ_CREATE
      pDriver->MajorFunction[14] = sub_10590;   // IRP_MJ_DEVICE_CONTROL
      pDriver->DriverUnload = DriverUnload;
    }
    else
    {
      IoDeleteDevice(DeviceObject);
    }
    result = v10;
  }
  return result;
}
```

디버깅을 통해 좀 더 명확하게 어떤 동작을 하는지 살펴보겠습니다. 먼저 `DriverEntry`에서 부터 `sub_103AC` 함수 위치까지 살펴보겠습니다.

```
.text:000000000001063C arg_10          = qword ptr  18h
.text:000000000001063C
.text:000000000001063C                 push    rbx
.text:000000000001063E                 push    rdi
.text:000000000001063F                 sub     rsp, 68h
.text:0000000000010643                 mov     rbx, rcx
.text:0000000000010646                 lea     rdi, __ImageBase
.text:000000000001064D                 lea     r11, unk_10880
.text:0000000000010654                 xor     ecx, ecx
.text:0000000000010656
.text:0000000000010656 loc_10656:                              ; CODE XREF: DriverEntry+2E↓j
.text:0000000000010656                 movzx   eax, word ptr [rcx+rdi+774h]
.text:000000000001065E                 mov     [rcx+r11], ax
.text:0000000000010663                 add     rcx, 2
.text:0000000000010667                 test    ax, ax
.text:000000000001066A                 jnz     short loc_10656
.text:000000000001066C                 lea     rdx, unk_10980
.text:0000000000010673                 mov     rcx, r11
.text:0000000000010676                 call    sub_103AC
```

`rdi`에 `ImageBase`를 복사하고 `r11`에 `ImageBase+0x880` 값을 저장합니다. 그리고 반복문이 시작됩니다.
`ImageBase`로 부터 `0x774` 만큼 떨어진 위치에 있는 값을 2바이트씩 `unk_10880` 위치에 복사합니다.

해당 위치를 확인해보면 `UNICODE` 로 이루어진 `\Device\` 라는 문자열입니다. 이는 `IoCreateDevice` 함수를 호출하기 위한 Prefix라고 볼 수 있습니다. 그리고 이렇게 복사한 `unk_10880` 문자열과 `unk_10980` 을 `sub_103AC` 함수에 인자로 전달합니다.



### [-] Device Initialization

먼저 `sub_103AC` 함수를 확인하기 전, 두 번째 파라미터의 값을 확인해보면 아래와 같습니다.

```
3: kd> db Capcom+980
fffff805`03c30980  87 00 ea 00 fd 00 9a 00-4b 00 73 00 54 00 a4 00  ........K.s.T...
fffff805`03c30990  5c 00 8f 00 00 00 00 00-00 00 00 00 00 00 00 00  \...............
```

2바이트씩 떨어진 데이터와 첫 번째 파라미터 `\Device\`를 보았을 때, 암호화 되어있는 값으로 예상할 수 있습니다. `IoCreateDevice`에 전달하는 디바이스 명을 숨기기 위한 루틴으로 예상됩니다.

```c++
_WORD *__fastcall sub_103AC(_WORD *DeviceString, char *UnknownString)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  v2 = DeviceString;
  v3 = v17 - UnknownString;
  do
  {
    v4 = *UnknownString;
    *&UnknownString[v3] = *UnknownString;
    UnknownString += 2;
  }
  while ( v4 );
  v5 = 0;
  v6 = v17;
  v7 = 0x5555;
  if ( v17[0] )
  {
    while ( 1 )
    {
      v7 = v5 + 4 * v7;
      v8 = *v6 >> 6;
      if ( v8 - 1 > 2 )
        break;
      v9 = 0;
      v10 = ((v7 ^ *v6) - v5 - v8) & 0x3F;
      if ( v10 >= 0xAu )
      {
        if ( v10 >= 0x24u )
          goto LABEL_10;
        v9 = v10 + 0x37;
      }
      else
      {
        v9 = v10 + 0x30;
      }
      if ( v10 >= 0x24u )
      {
LABEL_10:
        if ( v10 < 0x3Eu )
          v9 = v10 + 0x3D;
      }
      if ( v10 == 0x3E )
        v9 = 0x2E;
      if ( v9 )
      {
        *v6 = v9;
        ++v6;
        ++v5;
        if ( *v6 )
          continue;
      }
      break;
    }
  }
  v11 = v2;
  v12 = 0xFFFFFFFFFFFFFFFFi64;
  do
  {
    if ( !v12 )
      break;
    v13 = *v11 == 0;
    ++v11;
    --v12;
  }
  while ( !v13 );
  v14 = 0i64;
  do
  {
    v15 = v17[v14];
    ++v14;
    v11[v14 - 2] = v15;
  }
  while ( v15 );
  return v2;
}
```

해당 함수를 진행한 뒤 첫 번째 파라미터인 `DeviceString(unk_10880)`을 확인하면 예상대로 디바이스 명이 만들어지는 것을 확인할 수 있습니다.

```
3: kd> du Capcom+880
fffff805`03c30880  "\Device\Htsysm72FB"
```

이를 이용하여 `IoCreateDevice` 함수로 유저모드와 소통할 수 있는 디바이스를 생성했습니다. 당연히 다음 동작은 `IoCreateSymbolicLink` 함수로 링크를 생성하는 것입니다.

{% include note.html content="해당 부분에서 이해가 되지 않는 경우에는 DeviceIoControl을 이용한 유저모드 애플리케이션과 커널 드라이버와 통신하는 내용에 대한 선행학습이 필요합니다." %}

디바이스 생성 후에 위와 같은 로직이 존재하며 이 때 prefix로 사용되는 경로는 `\DosDevice\` 입니다.

```
3: kd> u @rip l1
Capcom+0x6ea:
fffff805`03c306ea e8bdfcffff      call    Capcom+0x3ac (fffff805`03c303ac)
3: kd> du fffff80503c30840
fffff805`03c30840  "\DosDevices\"
3: kd> p
Capcom+0x6ef:
fffff805`03c306ef 488d4c2450      lea     rcx,[rsp+50h]
3: kd> du fffff80503c30840
fffff805`03c30840  "\DosDevices\Htsysm72FB"
```

`IoCreateSymbolicLink` 를 이용하여 심볼릭 링크를 생성합니다. 올바르게 디바이스와 링크가 생성이 되면 `MajorFunction` 초기화를 진행합니다.

`IRP_MJ_CLOSE`, `IRP_MJ_CREATE`, `IRP_DEVICE_CONTROL` 순으로 초기화를 진행하는 것을 확인할 수 있습니다. 위의 분석 내용을 토대로 의사코드를 정리하면 아래와 같이 정리할 수 있습니다.

```c++
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  pDriver = DriverObject;
  i = 0i64;
  do
  {
    v4 = _ImageBase[i + 0x3BA];
    *(&DeviceString + i * 2) = v4;
    ++i;
  }
  while ( v4 );
  DecryptString(&DeviceString, &EncryptString);
  RtlInitUnicodeString(&DestinationString, String);
  result = IoCreateDevice(pDriver, 0, &DestinationString, 0xAA01u, 0, 0, &DeviceObject);
  if ( result >= 0 )
  {
    j = 0i64;
    do
    {
      v8 = _ImageBase[j + 0x3AC];
      *(&LinkNameString + j * 2) = v8;
      ++j;
    }
    while ( v8 );
    DecryptString(&LinkNameString, &EncryptString);
    RtlInitUnicodeString(&SymbolicLinkName, String_1);
    Success = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
    if ( Success >= 0 )
    {
      pDriver->MajorFunction[2] = &sub_104E4;   // IRP_MJ_CLOSE
      pDriver->MajorFunction[0] = &sub_104E4;   // IRP_MJ_CREATE
      pDriver->MajorFunction[14] = sub_10590;   // IRP_MJ_DEVICE_CONTROL
      pDriver->DriverUnload = DriverUnload;
    }
    else
    {
      IoDeleteDevice(DeviceObject);
    }
    result = Success;
  }
  return result;
}
```



### [-] IRP Dispatch Routine

드라이버 진입점에서 확인했듯이 총 2개의 디스패치 루틴이 존재합니다. `IRP_MJ_CREATE`와 `CLOSE`는 동일한 `sub_104E4` 함수이며 `IRP_MJ_DEVICE_CONTROL`의 경우에는 `sub_10590` 함수로 등록되어 있습니다.

분석에 앞서 중간 정리를 하겠습니다.

- Device name : "\Device\Htsysm72FB"
- Symbolic link : "\DosDevices\Htsysm72FB"
- Device type : 0xAA01
- DEVICE_CONTROL Dispatch routine : sub_10590 

`sub_10590` 함수의 의사코드를 확인해보았습니다.

```c++
__int64 __fastcall sub_10590(__int64 a1, struct _IRP *a2)
{
  v2 = a2->Tail.Overlay.CurrentStackLocation;
  v3 = a2->AssociatedIrp.MasterIrp;
  v4 = 0;
  a2->IoStatus.Status = 0;
  a2->IoStatus.Information = 0i64;
  v5 = v2->Parameters.Create.Options;
  v6 = v2->Parameters.Read.Length;
  v7 = a2;
  v8 = v2->Parameters.Read.ByteOffset.LowPart;
  if ( v2->MajorFunction == 0xE )
  {
    v9 = 0;
    v10 = 0;
    if ( v8 == 0xAA012044 )
    {
      v10 = 4;
      v9 = 4;
    }
    else if ( v8 == 0xAA013044 )
    {
      v9 = 8;
      v10 = 4;
    }
    if ( v5 != v9 || v6 != v10 )
    {
      v7->IoStatus.Status = 0xC000000D;
      goto LABEL_16;
    }
    if ( v8 == 0xAA012044 )
    {
      v11 = *&v3->Type;
    }
    else
    {
      if ( v8 != 0xAA013044 )
      {
LABEL_14:
        *&v3->Type = v4;
        v7->IoStatus.Information = v10;
        goto LABEL_16;
      }
      v11 = *&v3->Type;
    }
    v4 = sub_10524(v11);
    goto LABEL_14;
  }
  v7->IoStatus.Status = 0xC0000002;
LABEL_16:
  IofCompleteRequest(v7, 0);
  return v7->IoStatus.Status;
}
```

해당 디스패치 루틴을 분석하기 위해 유저모드 애플리케이션을 작성하였습니다. `IRP_MJ_DEVICE_CONTROL` 을 활성화하기 위해서는 `DeviceIoControl` 함수를 이용해야 합니다.

```c++
#include <stdio.h>
#include <Windows.h>

int main()
{
	const wchar_t* deviceName = L"\\\\.\\Htsysm72FB";
	HANDLE driver = CreateFile(deviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);


	if (driver == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Unable to access device driver\n");
	}

	else {
		fprintf(stdout, "Device Handle : %p\n", driver);
		PBYTE inBuffer = (PBYTE)VirtualAlloc(0, 48, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		DWORD bytesReturned = 0;
		DWORD ioctlOutput = 0;


		if (DeviceIoControl(driver, 0x41414141, &inBuffer, 8, &ioctlOutput, 4, &bytesReturned, NULL))
		{
			fprintf(stdout, "Call DeviceIoControl\n");
		}
		else 
		{
			fprintf(stderr, "Call DeviceIoControl Failed\n");
		}
		CloseHandle(driver);
	}
}
```

`DeviceIoControl` 함수를 사용할 때 `dwControlCode`를 `0x41414141`으로 전달하였습니다. 이는 분석 시 용이하기 위해 사용한 임의의 값입니다.

{% include warning.html content="I/O Control Code를 정의할 때 Microsoft에서 정한 룰이 존재합니다.아래 링크에서 확인할 수 있습니다." %}

 <a href="https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes">제어 코드 정의</a> 

드라이버를 로드하고 해당 디스패치 루틴에 브레이크 포인트를 설치합니다. 그리고 위의 유저모드 애플리케이션을 컴파일한 후 실행하면 설치한 브레이크 포인트에서 멈추는 것을 확인할 수 있습니다.

```
0: kd> u @rip l20
Capcom+0x590:
fffff805`03c30590 4853            push    rbx
fffff805`03c30592 56              push    rsi
fffff805`03c30593 57              push    rdi
fffff805`03c30594 4883ec20        sub     rsp,20h
fffff805`03c30598 488b82b8000000  mov     rax,qword ptr [rdx+0B8h]
fffff805`03c3059f 488b7a18        mov     rdi,qword ptr [rdx+18h]
fffff805`03c305a3 33c9            xor     ecx,ecx
fffff805`03c305a5 894a30          mov     dword ptr [rdx+30h],ecx
fffff805`03c305a8 48894a38        mov     qword ptr [rdx+38h],rcx
fffff805`03c305ac 80380e          cmp     byte ptr [rax],0Eh
fffff805`03c305af 448b4810        mov     r9d,dword ptr [rax+10h]
fffff805`03c305b3 448b4008        mov     r8d,dword ptr [rax+8]
fffff805`03c305b7 488bda          mov     rbx,rdx
fffff805`03c305ba 8b5018          mov     edx,dword ptr [rax+18h]
fffff805`03c305bd 7409            je      Capcom+0x5c8 (fffff805`03c305c8)
fffff805`03c305bf c74330020000c0  mov     dword ptr [rbx+30h],0C0000002h
fffff805`03c305c6 eb5e            jmp     Capcom+0x626 (fffff805`03c30626)
fffff805`03c305c8 41bb442001aa    mov     r11d,0AA012044h
fffff805`03c305ce 8bc1            mov     eax,ecx
fffff805`03c305d0 8bf1            mov     esi,ecx
fffff805`03c305d2 413bd3          cmp     edx,r11d
fffff805`03c305d5 41ba443001aa    mov     r10d,0AA013044h
fffff805`03c305db 740f            je      Capcom+0x5ec (fffff805`03c305ec)
fffff805`03c305dd 413bd2          cmp     edx,r10d
fffff805`03c305e0 7511            jne     Capcom+0x5f3 (fffff805`03c305f3)
fffff805`03c305e2 b808000000      mov     eax,8
fffff805`03c305e7 8d70fc          lea     esi,[rax-4]
fffff805`03c305ea eb07            jmp     Capcom+0x5f3 (fffff805`03c305f3)
fffff805`03c305ec be04000000      mov     esi,4
fffff805`03c305f1 8bc6            mov     eax,esi
fffff805`03c305f3 443bc8          cmp     r9d,eax
fffff805`03c305f6 7527            jne     Capcom+0x61f (fffff805`03c3061f)
```



### [-] Conditional branching due to I/O control code

디스패치 루틴에 진입하게 되면 `IRP`에 대한 정리를 시작 합니다.

```
fffff805`03c30590 4853            push    rbx
fffff805`03c30592 56              push    rsi
fffff805`03c30593 57              push    rdi
fffff805`03c30594 4883ec20        sub     rsp,20h
fffff805`03c30598 488b82b8000000  mov     rax,qword ptr [rdx+0B8h]
fffff805`03c3059f 488b7a18        mov     rdi,qword ptr [rdx+18h]
fffff805`03c305a3 33c9            xor     ecx,ecx
fffff805`03c305a5 894a30          mov     dword ptr [rdx+30h],ecx
fffff805`03c305a8 48894a38        mov     qword ptr [rdx+38h],rcx
fffff805`03c305ac 80380e          cmp     byte ptr [rax],0Eh
fffff805`03c305af 448b4810        mov     r9d,dword ptr [rax+10h]
fffff805`03c305b3 448b4008        mov     r8d,dword ptr [rax+8]
fffff805`03c305b7 488bda          mov     rbx,rdx
fffff805`03c305ba 8b5018          mov     edx,dword ptr [rax+18h] ds:002b:ffffc60f`9bbff8f8=41414141
fffff805`03c305bd 7409            je      Capcom+0x5c8 (fffff805`03c305c8)
```

위에서 몇 가지 중요 요소만 분석해보면, `mov rax, [rdx+0B8h]` 명령을 통해 rax에 어떤 값을 가져오고 `0x0E`와 비교를 진행하게 되는데 이는 `MajorFunction`의  `IRP_MJ_DEVICE_CONTROL`이 맞는지 확인하는 것으로 보입니다. 그리고 `mov edx, [rax+18h]` 명령에서는 유저모드 애플리케이션에서 전달한 IOCTL 코드를 가져옵니다.

```
3: kd> u @rip l1
Capcom+0x5ba:
fffff805`03c305ba 8b5018          mov     edx,dword ptr [rax+18h]
3: kd> db @rax+18
ffffc60f`9bbff8f8  41 41 41 41 00 00 00 00-00 00 00 00 00 00 00 00  AAAA............
ffffc60f`9bbff908  b0 b6 e1 9c 0f c6 ff ff-00 6a c1 9e 0f c6 ff ff  .........j......
```

다음 명령으로 진행하게 되면 아래와 같은 명령들을 확인할 수 있습니다.

```
Capcom+0x5c8:
fffff805`03c305c8 41bb442001aa    mov     r11d,0AA012044h
fffff805`03c305ce 8bc1            mov     eax,ecx
fffff805`03c305d0 8bf1            mov     esi,ecx
fffff805`03c305d2 413bd3          cmp     edx,r11d
fffff805`03c305d5 41ba443001aa    mov     r10d,0AA013044h
fffff805`03c305db 740f            je      Capcom+0x5ec (fffff805`03c305ec)
```

r11 위치에 4바이트 만큼 `0xAA012044` 을 복사하고 이를 임의의 제어 코드 값인 `0x41414141` 값과 비교합니다. 이는 `0xAA012044`는 IOCTL 코드를 의미하며 전달하는 IOCTL 코드에 따라 디스패치 루틴에서 다른 동작을 한다는 것을 예상할 수 있습니다.

해당 드라이버에는 두 개의 IOCTL 코드가 존재합니다(`0xAA012044, 0xAA013044`). 유저모드 애플리케이션에서 IOCTL 코드를 이에 맞게 수정하여 다시 한번 디스패치 루틴을 확인해보면 `0xAA012044`의 경우 `inBufferSize`와 `OutBufferSize`가 4일 때, `0xAA013044`의 경우 각각 8과 4일 때 특정 함수를 호출합니다.

이 함수는 `sub_10524` 함수로 어떤 값을 전달합니다. 해당 함수를 확인해보면 굉장히 이상한 코드를 마주할 수 있습니다.



### [-] Suspicious Function

해당 함수를 호출하면서 BSOD를 마주할 수 있습니다. 아래와 같이 잘못된 메모리 값을 참조하기 때문입니다.

```
3: kd> .cxr 0xffffe885a93f9d00
rax=00000000e71f0008 rbx=ffff8883e9461060 rcx=00000000e71f0008
rdx=00000000aa012044 rsi=0000000000000004 rdi=ffff8883ee1ded40
rip=fffff8050a4a0537 rsp=ffffe885a93fa6f0 rbp=0000000000000002
 r8=0000000000000004  r9=0000000000000004 r10=00000000aa013044
r11=00000000aa012044 r12=0000000000000000 r13=0000000000000000
r14=ffff8883ee56f100 r15=ffff8883ec1b9bc0
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050286
Capcom+0x537:
fffff805`0a4a0537 483948f8        cmp     qword ptr [rax-8],rcx ds:002b:00000000`e71f0000=????????????????
```

미리 이유에 대해 말한다면 Capcom 드라이버에 존재하는 2개의 IOCTL 코드는 운영체제 기반을 의미합니다. x64와 x86에 따른 동작입니다. 이는 해당 함수로 전달되는 값의 바이트 수를 세어보면 눈치 챌 수 있습니다. 현재 블루 스크린이 발생 당시의 컨텍스트를 확인하면 `rax`와  `rcx` 레지스터에 4바이트 값이 존재합니다. 

좀더 상세하게 유저모드 애플리케이션에서부터 해당 위치까지 확인해보겠습니다. 유저모드 애플리케이션에서 `DeviceIoControl` 호출 명령 위치에 브레이크 포인트를 설치하고 파라미터들을 확인합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/capcom/capcom_00.png?raw=true">

```
3: kd> r @rcx
rcx=000000008ea70008
```

먼저 그림에서 `inBuffer` 파라미터의 값이 `sub_10524` 함수의 파라미터인 것을 확인할 수 있습니다. 설명한 것과 같이 `0xAA012044`는 x86 시스템을 의미하기에 4바이트만 전달되어 앞에 `0x00000151`이 잘려 전달되었습니다. 이로써 블루스크린의 이유가 명확해졌습니다.

그렇다면 바로 `0xAA013044` 코드로 바꿔 시도하여 확인하여도 같은 위치에서 블루스크린은 발생합니다. 이 이유는 블루 드라이버의 코드에서 발견할 수 있습니다.

```
fffff803`521e0537 483948f8        cmp     qword ptr [rax-8],rcx
fffff803`521e053b 7404            je      Capcom+0x541 (fffff803`521e0541)
fffff803`521e053d 33c0            xor     eax,eax
fffff803`521e053f eb49            jmp     Capcom+0x58a (fffff803`521e058a)
fffff803`521e0541 488b442450      mov     rax,qword ptr [rsp+50h]
```

이번엔 정확히 x64로 맞췄기 때문에 블루 스크린이 발생하지 않을 것이라 예상했습니다. 다만 위의 명령에서 다시 한번 BSOD를 만나게 됩니다.

그 이유는 `inBuffer`의 시작 위치입니다. 할당된 `inBuffer`가 0x12345670에 할당되었다면 -8 의 위치는 0x12345668이 됩니다. 하지만 우연히 해당 위치에 어떤 메모리가 할당되어 있지 않다면 존재하지 않는 영역을 참조하게 됩니다.

여기서 매우 중요한 정리를 해보겠습니다.

1. `[inBuffer-8]` 주소가 유효해야 합니다.
2. `[inBuffer-8]`의 값과 전달된 파라미터(rcx)의 값이 동일해야 합니다.(그렇지 않으면 해당 함수의 에필로그로 흐름이 변경됩니다.)

그럼 이제 두 가지 조건을 성립시키기 위해 유저 애플리케이션 코드를 아래와 같이 수정합니다.

```c++
#include <stdio.h>
#include <Windows.h>

#define AA012044 0xAA012044
#define AA013044 0xAA013044

int main()
{
	const wchar_t* deviceName = L"\\\\.\\Htsysm72FB";
	HANDLE driver = CreateFile(deviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (driver == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Unable to access device driver\n");
	}

	else {
		fprintf(stdout, "Device Handle : %p\n", driver);
		PBYTE inBuffer = (PBYTE)VirtualAlloc(0, 48, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		DWORD bytesReturned = 0;
		DWORD outBuffer = 0;
		*(PULONG_PTR)inBuffer = (ULONG_PTR)(inBuffer + 8); // inBuffer(0x12345670)에 inBuffer+8 값(0x12345678)을 inBuffer에 저장
		ULONG_PTR target = (ULONG_PTR)(inBuffer + 8); // inBuffer+8 값을 target 변수에 넣어 DeviceIoControl 함수에 전달

		if (DeviceIoControl(driver, AA013044, &target, 8, &outBuffer, 4, &bytesReturned, NULL))
		{
			fprintf(stdout, "Call DeviceIoControl\n");
		}
		else 
		{
			fprintf(stderr, "Call DeviceIoControl Failed\n");
		}
		CloseHandle(driver);
	}
}
```

주석의 내용을 잘 살펴봐야 합니다. 위의 조건들에 부합하기 위한 코드입니다. 예상컨데 드라이버의 `SuspiciousFunction(sub_10524)`에 rcx 값에는 `inBuffer+8` 값이 전달되며 `[rax-8](inBuffer+8)`에는 `inBuffer+8`의 값이 존재하므로 해당 로직을 통과하게 됩니다.

유저모드에서 확인하면 아래와 같이 원하는대로 메모리에 할당이 되었습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/capcom/capcom_01.png?raw=true">

드디어 BSOD를 벗어났습니다.

```
3: kd> u @rip
Capcom+0x541:
fffff805`7f270541 488b442450      mov     rax,qword ptr [rsp+50h]
fffff805`7f270546 4889442428      mov     qword ptr [rsp+28h],rax
fffff805`7f27054b 488b05c6fdffff  mov     rax,qword ptr [Capcom+0x318 (fffff805`7f270318)]
fffff805`7f270552 4889442430      mov     qword ptr [rsp+30h],rax
fffff805`7f270557 48c744242000000000 mov   qword ptr [rsp+20h],0
fffff805`7f270560 488d0521020000  lea     rax,[Capcom+0x788 (fffff805`7f270788)]
fffff805`7f270567 488d4c2420      lea     rcx,[rsp+20h]
fffff805`7f27056c ffd0            call    rax
```

지금부터 마술을 보게 됩니다. 해당 위치에서 `g` 명령을 실행합니다.

```
3: kd> g
KDTARGET: Refreshing KD connection

*** Fatal System Error: 0x000000d1
                       (0x000002B5E5690008,0x00000000000000FF,0x000000000000005C,0x000002B5E5690008)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

nt!DbgBreakPointWithStatus:
fffff805`785c4580 cc              int     3
```

다시 한번 반가운 BSOD를 만나게 됐습니다. 콜 스택을 확인합니다.

```
3: kd> k
  *** Stack trace for last set context - .thread/.cxr resets it
 # Child-SP          RetAddr           Call Site
00 ffffd08c`362276e8 fffff805`7f270577 0x000002b5`e5690008
01 ffffd08c`362276f0 fffff805`7f270613 Capcom+0x577
...
```

다름 아닌 `inBuffer+8` 위치에 값을 실행하며 아무런 코드도 존재하지 않기 때문에 발생했던 것 입니다. 이 때 `inBuffer+8`을 호출하는 위치는 `Capcom+573h`입니다.

```
3: kd> u Capcom+573
Capcom+0x573:
fffff805`7f270573 ff542428        call    qword ptr [rsp+28h]
fffff805`7f270577 488d0522020000  lea     rax,[Capcom+0x7a0 (fffff805`7f2707a0)]
fffff805`7f27057e 488d4c2420      lea     rcx,[rsp+20h]
fffff805`7f270583 ffd0            call    rax
fffff805`7f270585 b801000000      mov     eax,1
fffff805`7f27058a 4883c448        add     rsp,48h
fffff805`7f27058e c3              ret
```

우린 `inBuffer`의 값을 마음대로 조종하여 해당 위치까지 실행하는데 성공했습니다. 그렇다면 `inBuffer+8` 위치에 우리가 원하는 코드를 복사하는게 그리 어려운 일은 아닙니다.

다음 챕터에서 해당 취약점을 이용하여 권한 상승 등 실제 명령이 실행되는 것을 구현해보도록 하겠습니다.

## [0x02] Conclusion

처음 Windows 커널 드라이버에 대한 취약점에 관심을 가졌을 때, 가장 먼저 분석한 취약점이기 때문에 애정이 담겨있습니다. 추가적으로 궁금한 점은 상단에 `feedback` 으로 메일을 주시면 답변드리겠습니다. 혹은 포스팅에 댓글 기능을 이용할 수 있습니다.