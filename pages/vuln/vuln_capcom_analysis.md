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
