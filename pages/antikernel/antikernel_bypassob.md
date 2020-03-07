---
title: ObRegisterCallbacks Debugging
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "ObRegisterCallbacks Bypass(1)"
sidebar: antikernel_sidebar
permalink: antikernel_bypassob.html
folder: antikernel
---

## [0x00] Overview

먼저 ObRegisterCallbacks Bypass 에 대해 알아보겠습니다. 해당 내용은 굉장히 많은 포인트에서 사용 가능합니다. 우회를 하기 위해 먼저 실제 `ObRegisterCallbacks` 함수가 어떻게 동작하는지, 구조 등을 분석해보겠습니다.



## [0x01] ObRegisterCallbacks Debugging

먼저 이전 챕터에서 `ObRegisterCallback` 을 사용하기 위해 몇 가지 구조체를 설명했었습니다.

- Link : <a href="https://shhoya.github.io/antikernel_processprotect.html#0x01-process-protectobregistercallbacks">ObRegisterCallbacks</a>

현재 제가 만든 드라이버는 우회라고 말하기도 민망할 정도로 쉽습니다. `PreCallback` 함수를 찾아 프로세스 이름만 변조해줘도 탐지 할 수 없습니다. 우리의 목적은 `notepad.exe` 프로세스를 `x64dbg`를 이용하여 디버깅 하는 것입니다.

눈에는 눈, 이에는 이 라는 말과 같이 커널 드라이버는 커널 드라이버로 무력화 시키는 것이 가장 좋습니다. 불필요하게 메모리를 바꾸기 위해 수작업을 할 필요도 없습니다. 저는 이러한 방법 중에 `ObUnRegisterCallbacks` 함수를 이용하는 방법을 택했습니다. 바로 등록 된 콜백 루틴을 해제하는 함수입니다. 

그러기 위해선 `RegistrationHandle` 을 추적해야 합니다. (콜백 루틴 식별) 어떻게 찾을 수 있을지 분석해보겠습니다.



### [-] Analysis

IDA를 이용하여 `ntoskrnl.exe` 파일을 열어 `ObRegisterCallbacks` 함수를 살펴보겠습니다.

`ObRegisterCallbacks` 함수와 관련된 구조체들은 MS 심볼 서버에 존재하지 않습니다. 그렇기 때문에 최소한의 구조체만 아래와 같이 정의하였습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/byp_00.png?raw=true">

위와 같이 정의하고 Hexray 기능을 이용해 디컴파일하면 아래와 같은 의사코드를 볼 수 있습니다.

```c
signed __int64 __fastcall ObRegisterCallbacks(OB_CALLBACK_REGISTRATION *CallbackRegistration, PVOID *RegistrationHandle)
{
  OB_CALLBACK_REGISTRATION *vCallbackRegistration; // r15
  unsigned int v3; // edi
  PVOID *vRegistrationHandle; // r12
  signed int v5; // ebx
  unsigned __int16 v6; // ax
  unsigned int v7; // ebp
  unsigned __int16 *v8; // rax
  unsigned __int16 *v9; // rsi
  size_t v10; // r8
  char *v11; // rcx
  unsigned int v12; // ebp
  __int64 **v13; // r14
  __int64 *v14; // rcx
  __int64 *v15; // rcx
  unsigned __int64 v16; // rbx
  __int64 v17; // rcx
  __int64 v18; // rax
  unsigned __int16 *v20; // r14
  struct _KTHREAD *v21; // rax
  __int64 v22; // rcx
  unsigned __int16 **v23; // rax

  vCallbackRegistration = CallbackRegistration;
  v3 = 0;
  vRegistrationHandle = RegistrationHandle;
  v5 = 0;
  if ( (CallbackRegistration->Version & 0xFF00) != 0x100 )
    return 0xC000000Di64;
  v6 = CallbackRegistration->OperationRegistrationCount;
  if ( !v6 )
    return 0xC000000Di64;
  v7 = (v6 << 6) + *(&CallbackRegistration->Altitude.MaximumLength + 1) + 0x20;
  v8 = (unsigned __int16 *)ExAllocatePoolWithTag(PagedPool, v7, 'lFbO');
  v9 = v8;
  if ( !v8 )
    return 0xC000009Ai64;
  memset(v8, 0, v7);
  *v9 = 0x100;
  *((_QWORD *)v9 + 1) = *(PVOID *)((char *)&vCallbackRegistration->RegistrationContext + 4);
  v10 = *(&vCallbackRegistration->Altitude.MaximumLength + 1);
  v9[9] = v10;
  v9[8] = v10;
  v11 = (char *)v9 + v7 - (unsigned int)v10;
  *((_QWORD *)v9 + 3) = v11;
  memmove(v11, *(const void **)((char *)&vCallbackRegistration->Altitude.Buffer + 4), v10);
  v12 = 0;
  if ( vCallbackRegistration->OperationRegistrationCount > 0u )
  {
    while ( 1 )
    {
      v13 = (__int64 **)(*(char **)((char *)&vCallbackRegistration->OperationRegistration + 4) + 0x20 * v12);
      if ( !*((_DWORD *)v13 + 2) || !(*(_BYTE *)(**v13 + 0x42) & 0x40) )
        break;
      v14 = v13[2];
      if ( v14 )
      {
        if ( !(unsigned int)MmVerifyCallbackFunctionCheckFlags(v14, 0x20i64) )
          goto LABEL_23;
      }
      else if ( !v13[3] )
      {
        break;
      }
      v15 = v13[3];
      if ( v15 && !(unsigned int)MmVerifyCallbackFunctionCheckFlags(v15, 0x20i64) )
      {
LABEL_23:
        v5 = 0xC0000022;
        goto LABEL_24;
      }
      v16 = (unsigned __int64)&v9[0x20 * (unsigned __int64)v12 + 0x10];
      *(_QWORD *)(v16 + 8) = v16;
      *(_QWORD *)v16 = v16;
      ExInitializePushLock((PKSPIN_LOCK)(v16 + 0x38));
      *(_DWORD *)(v16 + 0x10) = *((_DWORD *)v13 + 2);
      *(_QWORD *)(v16 + 0x18) = v9;
      v17 = **v13;
      *(_QWORD *)(v16 + 0x20) = v17;
      *(_QWORD *)(v16 + 0x28) = v13[2];
      *(_QWORD *)(v16 + 0x30) = v13[3];
      v5 = ObpInsertCallbackByAltitude(v17, v16);
      if ( v5 >= 0 )
      {
        ++v9[1];
        if ( ++v12 < (unsigned __int16)vCallbackRegistration->OperationRegistrationCount )
          continue;
      }
      goto LABEL_12;
    }
    v5 = 0xC000000D;
  }
LABEL_12:
  if ( v5 < 0 )
  {
LABEL_24:
    if ( v9[1] > 0u )
    {
      do
      {
        v20 = &v9[0x20 * (unsigned __int64)v3 + 0x10];
        v21 = KeGetCurrentThread();
        --v21->SpecialApcDisable;
        ExAcquirePushLockExclusiveEx(*((_QWORD *)v20 + 4) + 0xB8i64, 0i64);
        v22 = *(_QWORD *)v20;
        if ( *(unsigned __int16 **)(*(_QWORD *)v20 + 8i64) != v20
          || (v23 = (unsigned __int16 **)*((_QWORD *)v20 + 1), *v23 != v20) )
        {
          __fastfail(3u);
        }
        *v23 = (unsigned __int16 *)v22;
        *(_QWORD *)(v22 + 8) = v23;
        ExReleasePushLockEx(*((_QWORD *)v20 + 4) + 0xB8i64, 0i64);
        KiLeaveGuardedRegionUnsafe(KeGetCurrentThread());
        ++v3;
      }
      while ( v3 < v9[1] );
    }
    ExFreePoolWithTag(v9, 'lFbO');
  }
  else
  {
    if ( v9[1] > 0u )
    {
      do
      {
        v18 = v3++;
        *(_DWORD *)&v9[0x20 * v18 + 0x1A] |= 1u;
      }
      while ( v3 < v9[1] );
    }
    *vRegistrationHandle = v9;
  }
  return (unsigned int)v5;
}
```

`OB_CALLBACK_REGISTRATION` 에 있는 멤버들에 대한 검증절차가 존재하고, 콜백 루틴에 대한 유효성 검증이 존재합니다.
모든 내용을 분석할 필요 없습니다. 실제 우리가 필요한 부분은 `RegistrationHandle`에 대한 내용입니다. 모든 검증과정을 거쳐 유효한 콜백 루틴의 경우 `RegistrationHandle` 값에 `v9` 라는 변수의 값을 저장하는 것을 볼 수 있습니다.

windbg를 이용하여 실제 이전 챕터에서 만든 드라이버를 가지고 분석해보겠습니다. 
아래와 같이 해당 드라이버가 로드 될 때 예외가 발생하도록 명령을 입력합니다.

```
Break instruction exception - code 80000003 (first chance)
*******************************************************************************
*                                                                             *
*   You are seeing this message because you pressed either                    *
*       CTRL+C (if you run console kernel debugger) or,                       *
*       CTRL+BREAK (if you run GUI kernel debugger),                          *
*   on your debugger machine's keyboard.                                      *
*                                                                             *
*                   THIS IS NOT A BUG OR A SYSTEM CRASH                       *
*                                                                             *
* If you did not intend to break into the debugger, press the "g" key, then   *
* press the "Enter" key now.  This message might immediately reappear.  If it *
* does, press "g" and "Enter" again.                                          *
*                                                                             *
*******************************************************************************
nt!DbgBreakPointWithStatus:
fffff806`24474600 cc              int     3
0: kd> sxe ld antikerneldebugging.sys
0: kd> g
```

이제 드라이버를 로드하면 아래와 같이 예외가 발생하고 디버깅이 가능합니다.

```
nt!DebugService2+0x5:
fffff806`24474655 cc              int     3
5: kd> u antikerneldebugging!obcallbackreg
AntiKernelDebugging!ObCallbackReg [D:\Shh0ya\ProcessProtection\AntiKernelDebugging\callbacks.h @ 131]:
fffff806`235a1538 4057            push    rdi
fffff806`235a153a 4883ec70        sub     rsp,70h
fffff806`235a153e 488d442440      lea     rax,[rsp+40h]
fffff806`235a1543 488bf8          mov     rdi,rax
fffff806`235a1546 33c0            xor     eax,eax
fffff806`235a1548 b928000000      mov     ecx,28h
fffff806`235a154d f3aa            rep stos byte ptr [rdi]
fffff806`235a154f 488d442420      lea     rax,[rsp+20h]
```

아래와 같이 `ObRegisterCallbacks`를 호출하는 주소에 브레이크 포인트를 설치합니다.

```
AntiKernelDebugging!ObCallbackReg:
fffff806`235a1538 4057            push    rdi
fffff806`235a153a 4883ec70        sub     rsp,70h
fffff806`235a153e 488d442440      lea     rax,[rsp+40h]
fffff806`235a1543 488bf8          mov     rdi,rax
fffff806`235a1546 33c0            xor     eax,eax
fffff806`235a1548 b928000000      mov     ecx,28h
fffff806`235a154d f3aa            rep stos byte ptr [rdi]
fffff806`235a154f 488d442420      lea     rax,[rsp+20h]
fffff806`235a1554 488bf8          mov     rdi,rax
fffff806`235a1557 33c0            xor     eax,eax
fffff806`235a1559 b920000000      mov     ecx,20h
fffff806`235a155e f3aa            rep stos byte ptr [rdi]
fffff806`235a1560 ff15e20a0000    call    qword ptr [AntiKernelDebugging!_imp_ObGetFilterVersion (fffff806`235a2048)]
fffff806`235a1566 6689442440      mov     word ptr [rsp+40h],ax
fffff806`235a156b b801000000      mov     eax,1
fffff806`235a1570 6689442442      mov     word ptr [rsp+42h],ax
fffff806`235a1575 488d1564040000  lea     rdx,[AntiKernelDebugging! ?? ::FNODOBFM::`string' (fffff806`235a19e0)]
fffff806`235a157c 488d4c2448      lea     rcx,[rsp+48h]
fffff806`235a1581 ff15910a0000    call    qword ptr [AntiKernelDebugging!_imp_RtlInitUnicodeString (fffff806`235a2018)]
fffff806`235a1587 48c744245800000000 mov   qword ptr [rsp+58h],0
fffff806`235a1590 488b05210b0000  mov     rax,qword ptr [AntiKernelDebugging!PsProcessType (fffff806`235a20b8)]
fffff806`235a1597 4889442420      mov     qword ptr [rsp+20h],rax
fffff806`235a159c c744242801000000 mov     dword ptr [rsp+28h],1
fffff806`235a15a4 488d0545000000  lea     rax,[AntiKernelDebugging!PreCallback (fffff806`235a15f0)]
fffff806`235a15ab 4889442430      mov     qword ptr [rsp+30h],rax
fffff806`235a15b0 488d0529000000  lea     rax,[AntiKernelDebugging!PostCallback (fffff806`235a15e0)]
fffff806`235a15b7 4889442438      mov     qword ptr [rsp+38h],rax
fffff806`235a15bc 488d442420      lea     rax,[rsp+20h]
fffff806`235a15c1 4889442460      mov     qword ptr [rsp+60h],rax
fffff806`235a15c6 488d15431a0000  lea     rdx,[AntiKernelDebugging!hRegistration (fffff806`235a3010)]
fffff806`235a15cd 488d4c2440      lea     rcx,[rsp+40h]
fffff806`235a15d2 ff15600a0000    call    qword ptr [AntiKernelDebugging!_imp_ObRegisterCallbacks (fffff806`235a2038)]
fffff806`235a15d8 4883c470        add     rsp,70h
fffff806`235a15dc 5f              pop     rdi
fffff806`235a15dd c3              ret

5: kd> bp fffff806`235a15d2
5: kd> g
```

이제 해당 위치에서의 파라미터 값을 주목해야 합니다. `ObRegisterCallbacks` 함수를 호출하기 전에 `rdx` 레지스터의 값(`RegistrationHandle`)을 확인하고, `Step Over`로 호출 후에 값을 확인합니다.

```
5: kd> dp @rdx
fffff806`235a3010  00000000`00000000 00000000`00000000
fffff806`235a3020  fffff806`24310c60 00000000`00000000
fffff806`235a3030  000002e8`000002e0 000003f8`00000450
fffff806`235a3040  00000000`00000000 00000000`00000000
fffff806`235a3050  00000000`00000000 00000000`00000000
fffff806`235a3060  00000000`00000000 00000000`00000000
fffff806`235a3070  00000000`00000000 00000000`00000000
fffff806`235a3080  00000000`00000000 00000000`00000000
5: kd> p
AntiKernelDebugging!ObCallbackReg+0xa0:
fffff806`235a15d8 4883c470        add     rsp,70h
5: kd> dp fffff806`235a3010
fffff806`235a3010  ffff948c`8b306110 00000000`00000000
fffff806`235a3020  fffff806`24310c60 00000000`00000000
fffff806`235a3030  000002e8`000002e0 000003f8`00000450
fffff806`235a3040  00000000`00000000 00000000`00000000
fffff806`235a3050  00000000`00000000 00000000`00000000
fffff806`235a3060  00000000`00000000 00000000`00000000
fffff806`235a3070  00000000`00000000 00000000`00000000
fffff806`235a3080  00000000`00000000 00000000`00000000
5: kd> dp ffff948c`8b306110
ffff948c`8b306110  00000000`00010100 00000000`00000000
ffff948c`8b306120  00000000`000c000c ffff948c`8b306170
ffff948c`8b306130  ffffc207`eb2ae448 ffffc207`eb2ae448
ffff948c`8b306140  00000001`00000001 ffff948c`8b306110
ffff948c`8b306150  ffffc207`eb2ae380 fffff806`235a15f0
ffff948c`8b306160  fffff806`235a15e0 00000000`00000000
ffff948c`8b306170  00300030`00300033 00000000`00300030
ffff948c`8b306180  7346744e`03080000 00000000`00005128

```

알 수 없는 주소 값이 할당되었고 내부에는 어떤 값들이 채워져 있습니다. 이제 이 값들의 정체를 알아내고, 연관성 있는 무언가를 찾아 접근하는 방법을 찾아야 합니다.



### [-] OBJECT_TYPE Structure

현재 운영체제에 존재하는 콜백 루틴들은 목록화되어 어딘가에 보관하고 있습니다. 그 내용을 가지고 있는 구조체가 바로  `OBJECT_TYPE` 입니다. 문서화되어 있지 않으므로 windbg에서 직접 찾아볼 수 있습니다.

```
5: kd> dt_OBJECT_TYPE
nt!_OBJECT_TYPE
   +0x000 TypeList         : _LIST_ENTRY
   +0x010 Name             : _UNICODE_STRING
   +0x020 DefaultObject    : Ptr64 Void
   +0x028 Index            : UChar
   +0x02c TotalNumberOfObjects : Uint4B
   +0x030 TotalNumberOfHandles : Uint4B
   +0x034 HighWaterNumberOfObjects : Uint4B
   +0x038 HighWaterNumberOfHandles : Uint4B
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : Uint4B
   +0x0c8 CallbackList     : _LIST_ENTRY
```

위 결과를 토대로 구조체를 정의하면 아래와 같습니다.

```c
typedef struct _OBJECT_TYPE
{
    LIST_ENTRY                 TypeList;
    UNICODE_STRING             Name;
    PVOID                      DefaultObject;
    ULONG                      Index;
    ULONG                      TotalNumberOfObjects;
    ULONG                      TotalNumberOfHandles;
    ULONG                      HighWaterNumberOfObjects;
    ULONG                      HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER    TypeInfo;
    EX_PUSH_LOCK               TypeLock;
    ULONG                      Key;
    LIST_ENTRY                 CallbackList;
}OBJECT_TYPE,*POBJECT_TYPE;
```

맨 마지막 멤버에 `CallbackList`가 존재하는 것을 볼 수 있습니다. 콜백 루틴을 등록할 때 `OB_OPERATION_REGISTRATION` 내 `ObjectType`을 설정했던 것을 기억해야 합니다.

이 때 `PsProcessType` 이라는 커널 내 전역변수를 사용했습니다. 이제 `windbg`에서 다시 한번 구조체를 확인해보겠습니다.

```
4: kd> dt_OBJECT_TYPE poi(nt!PsProcessType)
nt!_OBJECT_TYPE
   +0x000 TypeList         : _LIST_ENTRY [ 0xffffc207`eb2ae380 - 0xffffc207`eb2ae380 ]
   +0x010 Name             : _UNICODE_STRING "Process"
   +0x020 DefaultObject    : (null) 
   +0x028 Index            : 0x7 ''
   +0x02c TotalNumberOfObjects : 0x79
   +0x030 TotalNumberOfHandles : 0x3d0
   +0x034 HighWaterNumberOfObjects : 0x8a
   +0x038 HighWaterNumberOfHandles : 0x440
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : 0x636f7250
   +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffff948c`8b306130 - 0xffff948c`8b306130 ]
```

```
4: kd> dp 0xffff948c8b306130 
ffff948c`8b306130  ffffc207`eb2ae448 ffffc207`eb2ae448
ffff948c`8b306140  00000001`00000001 ffff948c`8b306110
ffff948c`8b306150  ffffc207`eb2ae380 fffff806`235a15f0
ffff948c`8b306160  fffff806`235a15e0 00000000`00000000
ffff948c`8b306170  00300030`00300033 00000000`00300030
ffff948c`8b306180  7346744e`03080000 00000000`00005128
ffff948c`8b306190  00010000`00000c6b 00520054`00530049
ffff948c`8b3061a0  0041004d`005c0059 004e0049`00480043
```

이제 `LIST_ENTRY` 로 이루어진 `CallbackList`에 접근하는 방법에 대해 알았습니다.



### [-] CALLBACK_ENTRY_ITEM

```c
typedef struct _CALLBACK_ENTRY_ITEM {
    LIST_ENTRY EntryItemList;
    OB_OPERATION Operations1;
    OB_OPERATION Operations2;
    CALLBACK_ENTRY* CallbackEntry;
    POBJECT_TYPE ObjectType;
    POB_PRE_OPERATION_CALLBACK PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
}CALLBACK_ENTRY_ITEM, *PCALLBACK_ENTRY_ITEM;
```

```c
typedef struct _CALLBACK_ENTRY{
     INT16 Version;
     unsigned char unknown[6];
     POB_OPERATION_REGISTRATION RegistrationContext;
     UNICODE_STRING Altitude
     CALLBACK_ENTRY_ITEM Items;
}CALLBACK_ENTRY, *PCALLBACK_ENTRY;
```

위와 같이 문서화되지 않은 구조체가 존재한다. 그리고 위에서 구한 `OBJECT_TYPE` 내 `CallbackList`의 링크 값은 `CALLBACK_ENTRY_ITEM` 에 대한 포인터입니다.

### [-] Find Register Callback routine

이제 하나씩 디버깅하며 위의 내용들에 대해 증명해보겠습니다.

먼저 `OBJECT_TYPE` 내 `CallbackList` 멤버를 찾습니다.

```
4: kd> dt_OBJECT_TYPE poi(nt!PsProcessType)
nt!_OBJECT_TYPE
   +0x000 TypeList         : _LIST_ENTRY [ 0xffffc207`eb2ae380 - 0xffffc207`eb2ae380 ]
   +0x010 Name             : _UNICODE_STRING "Process"
   +0x020 DefaultObject    : (null) 
   +0x028 Index            : 0x7 ''
   +0x02c TotalNumberOfObjects : 0x79
   +0x030 TotalNumberOfHandles : 0x3d0
   +0x034 HighWaterNumberOfObjects : 0x8a
   +0x038 HighWaterNumberOfHandles : 0x440
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : 0x636f7250
   +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffff948c`8b306130 - 0xffff948c`8b306130 ]
```

콜백 리스트의 값을 확인합니다.

```
4: kd> dp 0xffff948c`8b306130
ffff948c`8b306130  ffffc207`eb2ae448 ffffc207`eb2ae448
ffff948c`8b306140  00000001`00000001 ffff948c`8b306110
ffff948c`8b306150  ffffc207`eb2ae380 fffff806`235a15f0
ffff948c`8b306160  fffff806`235a15e0 00000000`00000000
ffff948c`8b306170  00300030`00300033 00000000`00300030
ffff948c`8b306180  7346744e`03080000 00000000`00005128
ffff948c`8b306190  00010000`00000c6b 00520054`00530049
ffff948c`8b3061a0  0041004d`005c0059 004e0049`00480043
```

`CALLBACK_ENTRY_ITEM` 구조에 맞게 만들어보겠습니다.

```
ffff948c`8b306130 ; 0x000 EntryItemList    : _LIST_ENTRY [ ffffc207`eb2ae448 - ffffc207`eb2ae448]
ffff948c`8b306140 ; 0x010 Operation1       : 0x1
ffff948c`8b306144 ; 0x014 Operation2       : 0x1
ffff948c`8b306148 ; 0x018 CallbackEntry    : CALLBACK_ENTRY* (ffff948c`8b306110)
ffff948c`8b306150 ; 0x020 ObjectType       : OBJECT_TYPE* (ffffc207`eb2ae380)
ffff948c`8b306158 ; 0x028 PreOperation     : OB_PRE_OPERATION_CALLBACK* (fffff806`235a15f0)
ffff948c`8b306160 ; 0x030 PostOperation    : OB_POST_OPERATION_CALLBACK* (fffff806`235a15e0)
```

`ObjectType`과 `PreOperation`, `PostOperation` 멤버를 통해 구조체가 일치하는지 확인합니다.

```
4: kd> dt_OBJECT_TYPE ffffc207`eb2ae380
nt!_OBJECT_TYPE
   +0x000 TypeList         : _LIST_ENTRY [ 0xffffc207`eb2ae380 - 0xffffc207`eb2ae380 ]
   +0x010 Name             : _UNICODE_STRING "Process"
   +0x020 DefaultObject    : (null) 
   +0x028 Index            : 0x7 ''
   +0x02c TotalNumberOfObjects : 0x79
   +0x030 TotalNumberOfHandles : 0x3d0
   +0x034 HighWaterNumberOfObjects : 0x8a
   +0x038 HighWaterNumberOfHandles : 0x440
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : 0x636f7250
   +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffff948c`8b306130 - 0xffff948c`8b306130 ]

4: kd> u fffff806`235a15f0 l5
AntiKernelDebugging!PreCallback [D:\Shh0ya\ProcessProtection\AntiKernelDebugging\callbacks.h @ 56]:
fffff806`235a15f0 4889542410      mov     qword ptr [rsp+10h],rdx
fffff806`235a15f5 48894c2408      mov     qword ptr [rsp+8],rcx
fffff806`235a15fa 57              push    rdi
fffff806`235a15fb 4883ec40        sub     rsp,40h
fffff806`235a15ff 488b05fa190000  mov     rax,qword ptr [AntiKernelDebugging!__security_cookie (fffff806`235a3000)]

4: kd> u fffff806`235a15e0 l5
AntiKernelDebugging!PostCallback [D:\Shh0ya\ProcessProtection\AntiKernelDebugging\callbacks.h @ 81]:
fffff806`235a15e0 4889542410      mov     qword ptr [rsp+10h],rdx
fffff806`235a15e5 48894c2408      mov     qword ptr [rsp+8],rcx
fffff806`235a15ea c3              ret
fffff806`235a15eb cc              int     3
fffff806`235a15ec cc              int     3

```

정확하게 일치하는 것을 볼 수 있습니다. 하지만 아직 가장 중요한 `RegistrationHandle`에 관한 내용이 없습니다. `CALLBACK_ENTRY_ITEM` 내에 `CallbackEntry` 내용을 살펴보겠습니다.

```
4: kd> dp ffff948c`8b306110
ffff948c`8b306110  00000000`00010100 00000000`00000000
ffff948c`8b306120  00000000`000c000c ffff948c`8b306170
ffff948c`8b306130  ffffc207`eb2ae448 ffffc207`eb2ae448
ffff948c`8b306140  00000001`00000001 ffff948c`8b306110
ffff948c`8b306150  ffffc207`eb2ae380 fffff806`235a15f0
ffff948c`8b306160  fffff806`235a15e0 00000000`00000000
ffff948c`8b306170  00300030`00300033 00000000`00300030
ffff948c`8b306180  7346744e`03080000 00000000`00005128
```

`CALLBACK_ENTRY` 구조체에 맞게 만들어보면 아래와 같습니다.

```
ffff948c`8b306110 ; 0x000 Version          : 0x100
ffff948c`8b306112 ; 0x002 Unknown[6]       : 0x00000000`0001
ffff948c`8b306118 ; 0x008 RegistrationContext       : OB_OPERATION_REGISTRATION* (0x0)
ffff948c`8b306120 ; 0x010 Altitude         : UNICODE_STRING
ffff948c`8b306130 ; 0x020 Items            : CALLBACK_ENTRY_ITEM
```

자 지금 `CALLBACK_ENTRY` 구조로 되어있는 `0xffff948c'8b306110` 은 무언가와 매우 닮아있습니다.









## [0x02] Conclusion



