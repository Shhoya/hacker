---
title:  "[#] Manually Find DriverEntry(Old)"
tags: [Post, Windows, Reversing]
published: true
permalink: driverentry.html
comments: true
summary: "직접 DriverEntry 찾아가기"
---

# [+] Manually Find DriverEntry

오랜만에 블로그를 쓴다. R사의 DRM해제 등등 이것저것 회사 일과 겹쳐 시간이 없었다는 핑계를 대본다.

## [+] Find DriverEntry

까분다고 회사에 Windows 10 최신버전의 커널을 설치하고 디버깅을 하다보면 아주 미치고 환장한다. 변한게 많기떄문에... 기존에 windbg 를 이용해 `sxe` 명령으로 `DriverEntry`를 찾고 디버깅을 했었다.

이 작업을 한 이유는 특이한 악성 드라이버들 때문이다. `system` 프로세스 내 로드 된 모듈에는 올라와있으나 디버거에서 모듈 리스트를 확인하면 언로드 된 모듈로 나온다.

정상적으로 드라이버가 로드 될 때 커널에서는 같은 동작을 거치고 호출할꺼라는 생각으로 시작한 삽질이다.



### [-] Windows 7(x64), 6.1(build 7601)

정상적인 드라이버의 경우 매우 쉽게 찾을 수 있다. 먼저 `Windows 7(x64), 6.1(7601)` 에서의 삽질이다.

`ntoskrnl.exe` 를 IDA와 windbg를 교차분석하며 함수들을 분석했다.
해당 버전에서 크게 루틴을 보면 `NtLoadDriver` -> `IopLoadUnloadDriver` -> `IopLoadDriver` 순으로 돌아간다.

```
nt!NtLoadDriver+0x184:
fffff800`032f5324 e81777f5ff      call    nt!IopLoadUnloadDriver (fffff800`0324ca40)
```

```
nt!IopLoadUnloadDriver+0x36:
fffff800`0324ca76 e8b5d9f6ff      call    nt!IopOpenRegistryKey (fffff800`031ba430)
fffff800`0324ca7b 8bd8            mov     ebx,eax
fffff800`0324ca7d 85c0            test    eax,eax
fffff800`0324ca7f 7836            js      nt!IopLoadUnloadDriver+0x77 (fffff800`0324cab7)
fffff800`0324ca81 488b4c2448      mov     rcx,qword ptr [rsp+48h]
fffff800`0324ca86 4c8d4c2440      lea     r9,[rsp+40h]
fffff800`0324ca8b 4533c0          xor     r8d,r8d
fffff800`0324ca8e b201            mov     dl,1
fffff800`0324ca90 e8fbf1ffff      call    nt!IopLoadDriver (fffff800`0324bc90)
```

```
nt!IopLoadDriver+0x9fd:
fffff800`0324c68d 488bd6          mov     rdx,rsi
fffff800`0324c690 488bcb          mov     rcx,rbx
fffff800`0324c693 ff5358          call    qword ptr [rbx+58h]	; GsDriverEntry
```

위와 같이 커널단에서 수동으로 `DriverEntry`를 찾아갈 수 있다.

낮은 버전의 커널에서는 손쉽게 찾을 수 있었다. 그렇다면 나를 열받게 한 Windows 10....은...

### [-] Windows 10, 1809(build 17763.615)

테스트 버전은 다음과 같다.

`Windows 10(x64), 1809(17763.615)` 에서 `NtLoadDriver`를 확인하면 새로운 함수가 존재한다.

```
nt!NtLoadDriver:
0033:fffff800`23dcf560 4883ec28        sub     rsp,28h
0033:fffff800`23dcf564 e8b782a7ff      call    nt!IopLoadDriverImage (fffff800`23847820)
0033:fffff800`23dcf569 4883c428        add     rsp,28h
0033:fffff800`23dcf56d c3              ret
```

```
nt!IopLoadDriverImage:
0033:fffff800`23847820 48895c2408      mov     qword ptr [rsp+8],rbx
0033:fffff800`23847825 4889742410      mov     qword ptr [rsp+10h],rsi
0033:fffff800`2384782a 57              push    rdi
0033:fffff800`2384782b 4881eca0000000  sub     rsp,0A0h
0033:fffff800`23847832 488bd9          mov     rbx,rcx
0033:fffff800`23847835 33f6            xor     esi,esi
0033:fffff800`23847837 4889742430      mov     qword ptr [rsp+30h],rsi
0033:fffff800`2384783c 4885c9          test    rcx,rcx
0033:fffff800`2384783f 0f840f851a00    je      nt!IopLoadDriverImage+0x1a8534 (fffff800`239efd54)
0033:fffff800`23847845 65488b3c2588010000 mov   rdi,qword ptr gs:[188h]
0033:fffff800`2384784e 8a9732020000    mov     dl,byte ptr [rdi+232h]
0033:fffff800`23847854 84d2            test    dl,dl
0033:fffff800`23847856 0f8478010000    je      nt!IopLoadDriverImage+0x1b4 (fffff800`238479d4)
0033:fffff800`2384785c 488b0d8dfd9200  mov     rcx,qword ptr [nt!SeLoadDriverPrivilege (fffff800`241775f0)]
0033:fffff800`23847863 e878636600      call    nt!SeSinglePrivilegeCheck (fffff800`23eadbe0)
...
0033:fffff800`238479d4 0f1001          movups  xmm0,xmmword ptr [rcx]
0033:fffff800`238479d7 f30f7f442438    movdqu  xmmword ptr [rsp+38h],xmm0
0033:fffff800`238479dd 488b5c2430      mov     rbx,qword ptr [rsp+30h]
0033:fffff800`238479e2 e935ffffff      jmp     nt!IopLoadDriverImage+0xfc (fffff800`2384791c)
0033:fffff800`238479e7 e8947b5800      call    nt!IopLoadUnloadDriver (fffff800`23dcf580)
0033:fffff800`238479ec ebbb            jmp     nt!IopLoadDriverImage+0x189 (fffff800`238479a9)
0033:fffff800`238479ee 33c0            xor     eax,eax
0033:fffff800`238479f0 ebcd            jmp     nt!IopLoadDriverImage+0x19f (fffff800`238479bf)
```

기존의 루틴은  `NtLoadDriver` -> `IopLoadUnloadDriver` -> `IopLoadDriver` 이었으나 `NtLoadDriver` -> `IopLoadDriverImage` -> `IopLoadUnloadDriver` -> `IopLoadDriver` 인 것으로 예상이 된다.

내 삽질은 소중하기 때문에 결론만 정리하면 다음과 같은 루틴을 가진다. 하나도 빠짐없이 적어놨다.

```
1.nt!NtLoadDriver->
2.IopLoadDriverImage->
3.IopLoadUnloadDriver->
4.IopLoadDriver-> 
4-1.NtQueryKey -> 
4-2.IopVerifierExAllocatePool -> 
4-3.NtQueryKey -> 
4-4.IopVerifierExAllocatePool -> 
4-5.memcpy -> 
4-6.RtlAppendUnicodeToString -> 
4-7.HeadlessKernelAddLogEntry -> 
4-8.PnpDiagnosticTraceObject -> 
4-9.IopBuildFullDriverPath -> 
4-10.IopGetDriverNameFromKeyNode -> 
4-11.ExAcquireResourceExclusiveLite -> 
4-12.MmLoadSystemImageEx -> 
4-13.RtlImageNtHeader -> 
4-14.PnpPrepareDriverLoading -> 
4-15.ObCreateObjectEx -> 
4-16.memset -> 
4-17.RtlImageNtHeader -> 
4-18.ObInsertObjectEx -> 
4-19.ExReleaseResourceLite -> 
4-20.ObReferenceObjectByHandle -> 
4-21.ZwClose -> 
4-22.IopVerifierExAllocatePool -> 
4-23.memcpy -> 
4-24.IopVerifierExAllocatePool  -> 
4-25.NtQueryObject -> 
4-26.IopVerifierExAllocatePool -> 
4-27.memcpy -> 
4-28.PnpDiagnosticTraceObject -> 

4-29.guard_dispatch_icall	; nt!IopLoadDriver+0x4b8
	[-] guard_dispatch_icall+0x71:
		jmp rax ; rax = DriverName!GsDriverEntry
```

바로 `guard_dispatch_icall` 에서 `DriverEntry`를 호출하는 `GsDriverEntry`로 `jmp rax` 명령을 통해 진행되게 된다.

```
GsDriverEntry   proc near
arg_0           = qword ptr  8

48 89 5C 24 08                                mov     [rsp+arg_0], rbx
57                                            push    rdi
48 83 EC 20                                   sub     rsp, 20h
48 8B DA                                      mov     rbx, rdx
48 8B F9                                      mov     rdi, rcx
E8 17 00 00 00                                call    __security_init_cookie
48 8B D3                                      mov     rdx, rbx        ; RegistryPath
48 8B CF                                      mov     rcx, rdi        ; DriverObject
E8 E0 BF FF FF                                call    DriverEntry
48 8B 5C 24 30                                mov     rbx, [rsp+28h+arg_0]
48 83 C4 20                                   add     rsp, 20h
5F                                            pop     rdi
C3                                            retn
GsDriverEntry   endp
```

위의 어셈블리는 디버거로 제작한 드라이버의 `GsDriverEntry` 코드이다. 실제 위에서 분석한 내용을 토대로 `jmp rax` 명령을 통한 흐름의 함수를 보면 동일한 것을 확인할 수 있다.

```
fffff801`3ff25000 48895c2408      mov     qword ptr [rsp+8],rbx ss:0018:ffffd603`e5e178d0=0000000000000000
fffff801`3ff25005 57              push    rdi
fffff801`3ff25006 4883ec20        sub     rsp,20h
fffff801`3ff2500a 488bda          mov     rbx,rdx
fffff801`3ff2500d 488bf9          mov     rdi,rcx
fffff801`3ff25010 e817000000      call    LoadImageDriver+0x502c (fffff801`3ff2502c)
fffff801`3ff25015 488bd3          mov     rdx,rbx
fffff801`3ff25018 488bcf          mov     rcx,rdi
fffff801`3ff2501b e8e0bfffff      call    LoadImageDriver+0x1000 (fffff801`3ff21000)
fffff801`3ff25020 488b5c2430      mov     rbx,qword ptr [rsp+30h]
fffff801`3ff25025 4883c420        add     rsp,20h
fffff801`3ff25029 5f              pop     rdi
fffff801`3ff2502a c3              ret
```

## [+] Why

왜 이 삽질을 했는가에 대한 내용이다. 예를 들어 무슨짓을 하는지 조차 모르는 악의적인 드라이버가 존재할 경우가 분명 생길 것이라 생각했다. 대~충 어떤 동작을 하는지만 알아도 해당 동작과 연관된 함수에 bp를 설치하여 분석 시간을 줄일 수 있겠지만 그렇지 않은 경우 커널 단에서 해당 드라이버가 로드 되는 순간부터 봐야 하는 순간이 올 수 있다.

또한 MS에서 기존에 `DriverEntry`를 쉽게 찾을 수 있던 것을 특정 루틴을 추가해서 패치한 것은 분명 이유가 존재할 것이고 그것을 알아두는게 도움이 될 것이라 생각했다.

패킹 관련 테스트는 다음에!!

끗!

## [+] Video

[![Manually Find DriverEntryl](http://img.youtube.com/vi/ixj2_N_tsHw/mq3.jpg)](https://youtu.be/ixj2_N_tsHw?t=0s) 

