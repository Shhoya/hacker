---
title: SMBGhost(CVE-2020-0796) Analysis -2-
keywords: documentation, Vulnerability, SMB, CVE 
date: 2020-03-26
tags: [Windows, Reversing, CVE, Vulnerability, Kernel]
summary: "SMBGhost(CVE-2020-0796) 분석(2)"
sidebar: vuln_sidebar
permalink: vuln_smb_analysis2.html
folder: vuln

---

## [0x00] Overview

해당 챕터에서는 본격적인 분석을 시작합니다. 매우 길고 어지러울 수 있습니다.

{% include warning.html content="작성자 또한 실수를 할 수 있습니다. 피드백을 주시면 고치도록 하겠습니다." %}



## [0x01] Analysis(BugCheck)

먼저 `windbg`로 커널 디버깅 연결을 준비합니다. 이전 챕터에서 `Page Fault Exception`을 발생시키는 PoC 코드를 활용할 것입니다. 해당 PoC 코드를 실행하면 아래와 같은 출력을 디버거에서 확인할 수 있습니다.

```
*** Fatal System Error: 0x00000050
                       (0xFFFF93901618A05F,0x0000000000000000,0xFFFFF8027DA35EE7,0x0000000000000002)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

For analysis of this file, run !analyze -v
nt!DbgBreakPointWithStatus:
fffff802`7d5c4580 cc              int     3
```

예외가 발생하면 오류에 대한 내용을 꼭 읽어봐야 합니다. `!analyze -v` 명령을 이용하여 상세 에러 메시지를 확인합니다.

```
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

PAGE_FAULT_IN_NONPAGED_AREA (50)
Invalid system memory was referenced.  This cannot be protected by try-except.
Typically the address is just plain bad or it is pointing at freed memory.
Arguments:
Arg1: ffff93901618a05f, memory referenced.
Arg2: 0000000000000000, value 0 = read operation, 1 = write operation.
Arg3: fffff8027da35ee7, If non-zero, the instruction address which referenced the bad memory
	address.
Arg4: 0000000000000002, (reserved)

Debugging Details:
------------------
…

READ_ADDRESS:  ffff93901618a05f Nonpaged pool
FAULTING_IP: 
nt!RtlDecompressBufferLZNT1+57
fffff802`7da35ee7 0fb71e          movzx   ebx,word ptr [rsi]

…

ANALYSIS_SESSION_HOST:  SHH0YA
ANALYSIS_SESSION_TIME:  03-23-2020 21:24:07.0961
ANALYSIS_VERSION: 10.0.18362.1 amd64fre

TRAP_FRAME:  fffff00184c12b90 -- (.trap 0xfffff00184c12b90)
NOTE: The trap frame does not contain all registers.
Some register values may be zeroed or incorrect.
rax=fffff00184c12d58 rbx=0000000000000000 rcx=fffff00184c12d50
rdx=0000000000000001 rsi=0000000000000000 rdi=0000000000000000
rip=fffff8027da35ee7 rsp=fffff00184c12d20 rbp=fffff00184c12d70
 r8=0000000000000000  r9=0000000000000241 r10=fffff8027da35e90
r11=0000000000000000 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
nt!RtlDecompressBufferLZNT1+0x57:
fffff802`7da35ee7 0fb71e          movzx   ebx,word ptr [rsi] ds:00000000`00000000=????
Resetting default scope

LAST_CONTROL_TRANSFER:  from fffff8027d6a6492 to fffff8027d5c4580

STACK_TEXT:  
fffff001`84c12148 fffff802`7d6a6492 : ffff9390`1618a05f 00000000`00000003 fffff001`84c122b0 fffff802`7d524f20 : nt!DbgBreakPointWithStatus
fffff001`84c12150 fffff802`7d6a5b82 : fffff802`00000003 fffff001`84c122b0 fffff802`7d5d0ce0 00000000`00000050 : nt!KiBugCheckDebugBreak+0x12
fffff001`84c121b0 fffff802`7d5bc917 : fffff802`7d8611b8 fffff802`7d6cffe5 ffff9390`1618a05f ffff9390`1618a05f : nt!KeBugCheck2+0x952
fffff001`84c128b0 fffff802`7d600b0a : 00000000`00000050 ffff9390`1618a05f 00000000`00000000 fffff001`84c12b90 : nt!KeBugCheckEx+0x107
fffff001`84c128f0 fffff802`7d4c91df : fffff802`7d863880 00000000`00000000 00000000`00000000 ffff9390`1618a05f : nt!MiSystemFault+0x18fafa
fffff001`84c129f0 fffff802`7d5ca69a : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`0000003c : nt!MmAccessFault+0x34f
fffff001`84c12b90 fffff802`7da35ee7 : 00000000`00000000 00000000`00001100 ffff938f`170fd8c0 00000000`00001000 : nt!KiPageFault+0x35a
fffff001`84c12d20 fffff802`7d467666 : ffff9390`1936804f ffff938f`170fd8c0 ffff9390`1936804f fffff802`7d4675da : nt!RtlDecompressBufferLZNT1+0x57
fffff001`84c12db0 fffff802`836ae0bd : 00000000`00000002 00000000`00000241 00000000`ffffffff fffff802`00000000 : nt!RtlDecompressBufferEx2+0x66
fffff001`84c12e00 fffff802`837e7f41 : ffff938f`00010020 ffff938f`19369150 00000000`00000001 00000000`ffffffff : srvnet!SmbCompressionDecompress+0xdd
fffff001`84c12e70 fffff802`837e699e : 00000000`00000000 ffff938f`125468e0 00000000`00000002 ffffffff`ffffffff : srv2!Srv2DecompressData+0xe1
fffff001`84c12ed0 fffff802`83829a7f : ffff938f`125468f0 ffff938f`17087001 00000000`00000000 fffff802`7d532e00 : srv2!Srv2DecompressMessageAsync+0x1e
fffff001`84c12f00 fffff802`7d5c004e : fffff001`84c10050 fffff001`839e2901 ffffffff`ee1e5d00 fffff001`84c12fd1 : srv2!RfspThreadPoolNodeWorkerProcessWorkItems+0x13f
fffff001`84c12f80 fffff802`7d5c000c : fffff001`84c12fd1 ffff938f`17087040 fffff001`84c13000 fffff802`7d4c045e : nt!KxSwitchKernelStackCallout+0x2e
fffff001`839e28f0 fffff802`7d4c045e : fffff001`84c12fd1 fffff001`84c13000 00000000`00000140 ffff938f`1252e9c0 : nt!KiSwitchKernelStackContinue
fffff001`839e2910 fffff802`7d4c025c : fffff802`83829940 ffff938f`15588e50 00000000`00000002 00000000`00000000 : nt!KiExpandKernelStackAndCalloutOnStackSegment+0x18e
fffff001`839e29b0 fffff802`7d4c00d3 : 00000000`00000080 00000000`00000088 ffff938f`17087040 fffff001`839e2b00 : nt!KiExpandKernelStackAndCalloutSwitchStack+0xdc
fffff001`839e2a20 fffff802`7d4c008d : fffff802`83829940 ffff938f`15588e50 ffff938f`15588e50 00000000`00000088 : nt!KeExpandKernelStackAndCalloutInternal+0x33
fffff001`839e2a90 fffff802`838297d7 : ffff938f`00000000 00000000`00000000 ffff8389`2b3029a0 00000000`00000000 : nt!KeExpandKernelStackAndCalloutEx+0x1d
fffff001`839e2ad0 fffff802`7db104a7 : ffff938f`125d3000 ffff938f`17087040 fffff802`7a774180 00000000`00000000 : srv2!RfspThreadPoolNodeWorkerRun+0x117
fffff001`839e2b30 fffff802`7d530925 : ffff938f`17087040 fffff802`7db10470 ffff8389`2b3029a0 0000246f`b19bbdff : nt!IopThreadStart+0x37
fffff001`839e2b90 fffff802`7d5c3d5a : fffff802`7a774180 ffff938f`17087040 fffff802`7d5308d0 00000000`00000246 : nt!PspSystemThreadStartup+0x55
fffff001`839e2be0 00000000`00000000 : fffff001`839e3000 fffff001`839dc000 00000000`00000000 00000000`00000000 : nt!KiStartSystemThread+0x2a

FOLLOWUP_IP: 
srvnet!SmbCompressionDecompress+dd
fffff802`836ae0bd 8bd8            mov     ebx,eax

FAULT_INSTR_CODE:  c085d88b
SYMBOL_STACK_INDEX:  9
SYMBOL_NAME:  srvnet!SmbCompressionDecompress+dd
FOLLOWUP_NAME:  MachineOwner
MODULE_NAME: srvnet
IMAGE_NAME:  srvnet.sys

---------

```

최대한 간추려 보았으나 매우 소중한 정보들입니다. 여기서 중요한 부분은 `STACK_TEXT` 필드입니다. `nt!KiPageFault` 가 발생하기 전 콜 스택을 확인하면 `nt!RtlDecompressBufferLZNT1+0x57` 으로 확인됩니다. 해당 함수로부터 살펴보면, `nt!RtlDecompressBufferEx2+0x66`, `srvnet!SmbCompressionDecompress0xdd`, `srv2!Srv2DecompressData+0xe1` 으로 거슬러 올라옵니다.

소개에서 언급했던 함수입니다. 최종적으로 `PageFault`가 발생한 함수를 `srvnet!SmbCompressionDecompress+0xdd` 로 분석하고 있습니다.  `srv2!SrvDecompressData` 함수 내에서 문제의 `SmbCompressionDecompress` 함수를 호출하며, 해당 함수는 `IMPORT` 함수로 `srvnet.sys`에 존재합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_06.png?raw=true">

```
3: kd> lmvm srvnet
Browse full module list
start             end                 module name
fffff802`83690000 fffff802`836e2000   srvnet     (pdb symbols)          C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\sym\srvnet.pdb\D72719A4AB2C7D0D9ADBB5166CFD74EF1\srvnet.pdb
    Loaded symbol image file: srvnet.sys
    Image path: \SystemRoot\System32\DRIVERS\srvnet.sys
    Image name: srvnet.sys
    Browse all global symbols  functions  data
    Image was built with /Brepro flag.
    Timestamp:        5F4A3694 (This is a reproducible build file hash, not a timestamp)
    CheckSum:         0004FD20
    ImageSize:        00052000
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
    Information from resource tables:
```

이번엔 `.trap` 명령을 이용하여 크래시 발생 직전의 컨텍스트로 전환합니다.

```
3: kd> .trap 0xfffff00184c12b90
NOTE: The trap frame does not contain all registers.
Some register values may be zeroed or incorrect.
rax=fffff00184c12d58 rbx=0000000000000000 rcx=fffff00184c12d50
rdx=0000000000000001 rsi=0000000000000000 rdi=0000000000000000
rip=fffff8027da35ee7 rsp=fffff00184c12d20 rbp=fffff00184c12d70
 r8=0000000000000000  r9=0000000000000241 r10=fffff8027da35e90
r11=0000000000000000 r12=0000000000000000 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
nt!RtlDecompressBufferLZNT1+0x57:
fffff802`7da35ee7 0fb71e          movzx   ebx,word ptr [rsi] ds:00000000`00000000=????
```

`rsi` 레지스터가 0인데 역참조를 하므로 예외가 발생한 것입니다. 콜 스택 확인해보면 `RtlDecompressBufferLZNT1` 함수는 `guard_dispatch_icall` 을 통해 호출된 것을 알 수 있습니다.(`Control Flow Guard` 참조)

이것 외에 특이한 점은 없습니다. 먼저 콜 스택에 존재하는 함수들을 알아보겠습니다.

### [-] nt!RtlDecompressBufferLZNT1

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_07.png?raw=true">

### [-] nt!RtlDecompressBufferEx2

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_08.png?raw=true">

### [-] srvnet!SmbCompressionDecompress

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_09.png?raw=true">

### [-] srv2!Srv2DecompressData

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_10.png?raw=true">



## [0x02] Analysis(Details)

실제로 어떻게 동작하는지 확인하기 위해 동적분석을 진행하겠습니다. `srv2!Srv2DecompressData` 함수에 브레이크 포인트를 설치합니다. 우리는 잘못된 오프셋과 길이로 인해 발생하는 Overflow라고 확인하였습니다. 그렇다면 이 값이 `srv2!Srv2DecompressData` 에서 참조될 것이라 예상할 수 있습니다.

### [-] Srv2DecompressData

먼저 어셈블리 코드를 살펴보겠습니다.

```
srv2!Srv2DecompressData:
fffff800`46387e60 488bc4          mov     rax,rsp
fffff800`46387e63 48895810        mov     qword ptr [rax+10h],rbx
fffff800`46387e67 48896818        mov     qword ptr [rax+18h],rbp
fffff800`46387e6b 48897020        mov     qword ptr [rax+20h],rsi
fffff800`46387e6f 57              push    rdi
fffff800`46387e70 4156            push    r14
fffff800`46387e72 4157            push    r15
fffff800`46387e74 4883ec40        sub     rsp,40h
fffff800`46387e78 83600800        and     dword ptr [rax+8],0
fffff800`46387e7c 488bf9          mov     rdi,rcx
fffff800`46387e7f 488b81f0000000  mov     rax,qword ptr [rcx+0F0h]
fffff800`46387e86 83782410        cmp     dword ptr [rax+24h],10h
fffff800`46387e8a 0f8204010000    jb      srv2!Srv2DecompressData+0x134 (fffff800`46387f94)
fffff800`46387e90 488b4018        mov     rax,qword ptr [rax+18h]
fffff800`46387e94 0f1000          movups  xmm0,xmmword ptr [rax] ds:002b:ffffe50f`41720050=ffffffffffff00010000023e424d53fc
fffff800`46387e97 488b4150        mov     rax,qword ptr [rcx+50h]
fffff800`46387e9b 0f11442430      movups  xmmword ptr [rsp+30h],xmm0
fffff800`46387ea0 488b88f0010000  mov     rcx,qword ptr [rax+1F0h]
fffff800`46387ea7 660f73d808      psrldq  xmm0,8
fffff800`46387eac 8ba98c000000    mov     ebp,dword ptr [rcx+8Ch]
fffff800`46387eb2 66480f7ec1      movq    rcx,xmm0
fffff800`46387eb7 0fb7c1          movzx   eax,cx
fffff800`46387eba 3be8            cmp     ebp,eax
fffff800`46387ebc 740a            je      srv2!Srv2DecompressData+0x68 (fffff800`46387ec8)
fffff800`46387ebe b8bb0000c0      mov     eax,0C00000BBh
fffff800`46387ec3 e9d1000000      jmp     srv2!Srv2DecompressData+0x139 (fffff800`46387f99)
fffff800`46387ec8 488b442430      mov     rax,qword ptr [rsp+30h]
fffff800`46387ecd 33d2            xor     edx,edx
fffff800`46387ecf 48c1e820        shr     rax,20h
fffff800`46387ed3 48c1e920        shr     rcx,20h
fffff800`46387ed7 03c8            add     ecx,eax
fffff800`46387ed9 4c8b15489a0200  mov     r10,qword ptr [srv2!_imp_SrvNetAllocateBuffer (fffff800`463b1928)]
fffff800`46387ee0 e8fbe2f6ff      call    srvnet!SrvNetAllocateBuffer (fffff800`462f61e0)
```

해당 함수에 브레이크 포인트를 설치하였고 PoC 코드를 실행하면 해당 함수에서 멈추는 것을 확인할 수 있습니다. 트레이싱을 하며 아래의 `this` 주석 위치까지 실행합니다.

```
srv2!Srv2DecompressData:
fffff800`46387e60 488bc4          mov     rax,rsp
fffff800`46387e63 48895810        mov     qword ptr [rax+10h],rbx
fffff800`46387e67 48896818        mov     qword ptr [rax+18h],rbp
fffff800`46387e6b 48897020        mov     qword ptr [rax+20h],rsi
fffff800`46387e6f 57              push    rdi
fffff800`46387e70 4156            push    r14
fffff800`46387e72 4157            push    r15
fffff800`46387e74 4883ec40        sub     rsp,40h
fffff800`46387e78 83600800        and     dword ptr [rax+8],0
fffff800`46387e7c 488bf9          mov     rdi,rcx
fffff800`46387e7f 488b81f0000000  mov     rax,qword ptr [rcx+0F0h]
fffff800`46387e86 83782410        cmp     dword ptr [rax+24h],10h
fffff800`46387e8a 0f8204010000    jb      srv2!Srv2DecompressData+0x134 (fffff800`46387f94)
fffff800`46387e90 488b4018        mov     rax,qword ptr [rax+18h] <== this
```

현재 명령에서 마지막 명령인 `mov rax, [rax+18h]` 를 실행하면 rax는 `Compression Transform Header` 의 값입니다. 
아래 그림은 PoC 코드를 통해 블루 스크린이 발생했을 때의 패킷에서 `SMB2 Compression Transform Header`의 캡쳐입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_11.png?raw=true">

그리고 명령을 실행하고 `rax` 레지스터를 확인하면 해당 내용이 헤더와 일치하는 것을 확인할 수 있습니다.

```
1: kd> db @rax
ffffe50f`41720050  fc 53 4d 42 3e 02 00 00-01 00 ff ff ff ff ff ff  .SMB>...........
ffffe50f`41720060  3d 32 fe 53 4d 42 40 00-01 00 00 00 00 00 01 00  =2.SMB@.........
ffffe50f`41720070  00 01 00 00 00 00 00 00-00 00 02 00 00 00 00 00  ................
ffffe50f`41720080  00 00 00 00 00 00 00 00-00 00 01 00 00 00 00 80  ................
ffffe50f`41720090  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
ffffe50f`417200a0  00 00 19 00 00 02 00 00-00 00 00 00 00 00 58 00  ..............X.
ffffe50f`417200b0  e6 01 00 00 00 00 00 00-00 00 4e 54 4c 4d 53 53  ..........NTLMSS
ffffe50f`417200c0  50 00 03 00 00 00 18 00-18 00 7c 00 00 00 42 01  P.........|...B.
```

`ProtocolId` 필드부터 `Compressed SMB3 Data` 필드까지 동일한 것을 확인할 수 있습니다. 다음 명령에서는 xmm 레지스터를 이용하여 `Offset` 필드까지 저장합니다. 

이러한 내용을 근거로하여 주석을 달면 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_12.png?raw=true">

마지막 주석에서부터 확인하면 `movzx eax, cx` 는 `CompressionAlgorithm(0x0001)`을 `eax` 레지스터에 저장하고, `ebp` 레지스터와 비교합니다. 이 때 레지스터 값을 확인하면 `ebp = 1` 임을 알 수 있습니다. 즉 압축 알고리즘이 지원되는지에 대한 검증 로직으로 확인할 수 있습니다.

의사코드를 보기 좋게 만들기 전에, `SMB2_COMPRESSION_TRANSFORM_HEADER` 를 포함한 몇 가지 구조체를 만들어봤습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_13.png?raw=true">

{% include warning.html content="SUSPICIOUS_STRUCT, TMP_COMPRESSION_HEADER 구조체는 보기 쉽기 위해 직접 만든 구조체입니다. 부정확할 수 있습니다. "%}

아래는 의사코드입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_14.png?raw=true">

이전보다 훨씬 보기 편해졌습니다. 단지 몇 가지 로직을 확인했을 뿐인데 코드다워졌습니다.

여기서 재밌는 코드를 확인할 수 있습니다. `SrvNetAllocateBuffer` 는 함수 이름대로 버퍼를 할당하는 함수로 보입니다. 첫 번째 파라미터를 `OriginalCompressedSegmentSize(OriginalSize)+ Offset/Length(Offset_Length)`로 전달합니다.  해당 함수는 첫 번째 파라미터를 `unsigned int`로 받지만, 명령에서는 -1로 처리되어 **패킷 기준**으로 0x23e + (-1) 으로, 전달할 때 0x23d 가 전달됩니다. 이로 인해 커널에서 의도한 값보다 작은 값을 가지게 됩니다.

`OriginalCompressedSegmentSize(OriginalSize)`는 이름 그대로 압축된 세그먼트의 원래의 크기(=압축되지 않은 데이터의 크기)를 의미합니다. `Offset/Length` 필드의 경우, 두 가지 경우에 따라 Offset으로 계산되거나 Length로 계산됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_15.png?raw=true">

위의 설명에 따르면, 만약 플래그 필드가 `0x0(SMB2_COMPRESSION_FLAG_NONE)`으로 설정되면 `Offset/Length` 필드는 `Length`로 해석됩니다. 그렇지 않은 경우에는 해당 필드는 오프셋으로 해석되며, 헤더의 끝에서부터 압축 된 데이터 세그먼트의 시작까지의 오프셋 입니다.

위의 의사코드를 보면 확인할 수 있듯이 길이에 대한 검증이 존재하지 않습니다. 좀 더 정리한 의사코드와 어셈블리 코드입니다. 다시 한번 의사코드와 주석을 정리합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_16.png?raw=true">

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_17.png?raw=true">



### [-] SmbCompressionDecompress

다음은 `srvnet!SmbCompressionDecompress` 함수입니다. 

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_18.png?raw=true">

`nt!RtlGetCOmpressionWorkSpaceSize` 함수부터 살펴보겠습니다.

```c++
NT_RTL_COMPRESS_API NTSTATUS RtlGetCompressionWorkSpaceSize(
 USHORT CompressionFormatAndEngine,
 PULONG CompressBufferWorkSpaceSize,
 PULONG CompressFragmentWorkSpaceSize
);
```

`CompressionFormatAndEngine` 의 경우, `CompressionAlgorithm` 값으로 넘겨준 `CompType_LZNT1`의 값을 기준으로 결정됩니다. 우리가 전달한 `LZNT1` 값은 아래 비트 마스크에 의해 2로 설정됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_19.png?raw=true">

다음은 `CompressBufferWorkSpaceSize` 입니다. 버퍼를 압축하는데 필요한 크기를 바이트 단위로 받는 버퍼에 대한 포인터입니다. 이 값은 RtlCompressBuffer의 WorkSpace 버퍼의 정확한 크기를 결정하는데 사용한다고 되어 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_20.png?raw=true">

마지막으로 `CompressFragmentWorkSpaceSize` 입니다. 압축 버퍼를 조각 단위(`Fragments`)로 해제하는데 필요한 크기를 바이트 단위로 받는 버퍼에 대한 포인터 입니다. `RtlDecompressFragment` 의 WorkSpace 버퍼의 정확한 크기를 결정하는데 사용되지만 현재는 해당 함수가 존재하지 않는다고 합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_21.png?raw=true">

위의 의사코드를 다시 보면 if문은 or 조건으로 `RtlGetCompressionWorkSpaceSize` 의 반환 값이 `STATUS_SUCCESS` 가 아니거나, `ExAllocatePoolWithTag` 함수로 인해 버퍼가 할당되는 경우로 되어있습니다.

```c++
if ( RtlGetCompressionWorkSpaceSize(v13, &NumberOfBytes, &v18) < 0
    || (v6 = ExAllocatePoolWithTag(0x200, NumberOfBytes, '%2SL')) != 0i64 )
  {
    v14 = a6;
    v17 = invalid_packetlength_param;
    v15 = a5;
    v10 = RtlDecompressBufferEx2(
            v13,
            invalid_compressedData_param,
            a5,
            invalid_smb2header_param,
            v17,
            0x1000,
            a6,
            v6,
            v18);
    if ( (v10 & 0x80000000) == 0 )
      *v14 = v15;
    if ( v6 )
      ExFreePoolWithTag(v6, '%2SL');
  }
```

디버깅을 해보면 아래와 같이 `RtlGetCompressionWorkSpaceSize` 함수는 `STATUS_SUCCESS` 를 반환하기 때문에 조건에 부합하지 않습니다.

```
1: kd> p
srvnet!SmbCompressionDecompress+0x6d:
fffff804`45c1e04d e84e9524fb   call  nt!RtlGetCompressionWorkSpaceSize (fffff804`40e675a0)
1: kd> p
srvnet!SmbCompressionDecompress+0x72:
fffff804`45c1e052 85c0      test  eax,eax
1: kd> r @rax
rax=0000000000000000
```

`ExAllocatePoolWithTag`의 경우 정상적으로 버퍼를 할당하므로 조건에 부합하므로 `RtlDecompressBufferEx2` 함수를 호출할 수 있습니다.

```
1: kd> p
srvnet!SmbCompressionDecompress+0x8c:
fffff804`45c1e06c e89fbf54fb      call    nt!ExAllocatePoolWithTag (fffff804`4116a010)
1: kd> p
srvnet!SmbCompressionDecompress+0x91:
fffff804`45c1e071 488bf8          mov     rdi,rax
1: kd> r @rax
rax=ffff9f021a9ce000
```



### [-] RtlDecompressBufferEx2

매우 간략하게 이루어져있습니다. `RtlDecompressBufferProcs` 배열에 저장되어 있는 함수를 호출합니다. 첫 번째 파라미터는 배열의 인덱스 값으로 확인되며 2보다 작거나 4보다 큰 경우 정상적으로 호출되지 않습니다.

{% include warning.html content="변수명의 경우 본인이 알아보기 쉽도록 정의한 것입니다. 특히 PageSize의 경우 0x1000으로 전달되는 것을 유추하여 작명한 것입니다. 실제와 다를 수 있습니다." %} 

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_22.png?raw=true">

`RtlDecompressBufferProcs`는 아래와 같이 총 3개의 함수로 이루어져 있습니다. 예상과 같이 해당 부분에서 크래시를 일으키는 `RtlDecompressBufferLZNT1` 함수를 호출합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_23.png?raw=true">

디버깅을 하면 예상한대로 아래와 같이 `RtlDecompressBufferLZNT1` 함수를 호출합니다.

```
3: kd> p
nt!RtlDecompressBufferEx2+0x61:
fffff801`19467661 e89adb1500      call    nt!guard_dispatch_icall (fffff801`195c5200)
3: kd> u @rax
nt!RtlDecompressBufferLZNT1:
fffff801`19a35e90 48895c2418      mov     qword ptr [rsp+18h],rbx
fffff801`19a35e95 48894c2408      mov     qword ptr [rsp+8],rcx
fffff801`19a35e9a 55              push    rbp
fffff801`19a35e9b 56              push    rsi
fffff801`19a35e9c 57              push    rdi
fffff801`19a35e9d 4154            push    r12
fffff801`19a35e9f 4155            push    r13
fffff801`19a35ea1 4156            push    r14
```



### [-] RtlDecompressBufferLZNT1

아래 그림을 확인하면 `PageFault Point` 주석을 작성했습니다. `pSmbHeader`는 아래와 같은 연산을 거쳐 해당 함수에 전달됬습니다.

`pSmbHeader = &Smb2CompressionTransformHeader + Smb2CompressionTransformHeader.Offset(0xffffffff) + 0x10`

어셈블리 코드와 매칭하여 확인하면 잘못된 오프셋과 주소 값의 계산으로 인해 잘못된 메모리 영역임을 알 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_24.png?raw=true">

노란 박스의 코드에서 확인해보면 아래와 같이 잘못된 메모리 영역임을 확인할 수 있습니다.

```
nt!RtlDecompressBufferLZNT1+0x57:
fffff801`19a35ee7 0fb71e          movzx   ebx,word ptr [rsi]
3: kd> dp @rsi
ffffa507`d525c05f  ????????`???????? ????????`????????
ffffa507`d525c06f  ????????`???????? ????????`????????
ffffa507`d525c07f  ????????`???????? ????????`????????
ffffa507`d525c08f  ????????`???????? ????????`????????
ffffa507`d525c09f  ????????`???????? ????????`????????
ffffa507`d525c0af  ????????`???????? ????????`????????
ffffa507`d525c0bf  ????????`???????? ????????`????????
ffffa507`d525c0cf  ????????`???????? ????????`????????
```

```
3: kd> p
KDTARGET: Refreshing KD connection

*** Fatal System Error: 0x00000050
                       (0xFFFFA507D525C05F,0x0000000000000000,0xFFFFF80119A35EE7,0x0000000000000002)


A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.
```



## [0x03] Conclusion

최대한 많은 분석 내용을 담으려고 노력했습니다. 다음 챕터에서는 PoC 코드를 작성하여 실제 악용될 수 있는 사례를 소개하겠습니다.