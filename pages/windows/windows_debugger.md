---
title: Debugging process
keywords: documentation, technique, reversing, kernel, windows
date: 2021-06-16
tags: [Windows, Reversing, Kernel]
summary: "Debugging Process"
sidebar: windows_sidebar
permalink: windows_dbgprocess.html
folder: windows
---

## [0x00] Concept

현재도 안티 디버깅을 우회하기 위한 여러 노력들과 이를 대응하기 위한 기법들이 연구되고 개발되어지고 있습니다.

그 중에 본인은 가장 중요한 점을 빼놓고 지금까지 공부를 했다고 생각했습니다. 바로 디버깅이 동작하는 상세한 내용입니다.

분석가 또는 연구가로써 이러한 세부 로직에 대해 이해하는 것은 매우 중요하고 또한 큰 도움이 될 수 있습니다.

단순히 본인이 기존에 알던 지식은, `DebugObject` 또는 `DebugPort` 가 할당된다는 얕은 지식이었습니다.

본인의 생각은 아래와 같았습니다.

- 디버기 프로세스 오브젝트에 `DebugObject` , `DebugPort` 가 할당되어 이벤트가 발생했을 때 디버거로 전달한다.

정확히 어떻게 디버깅이 가능해지는 것 인지 확인해보도록 하겠습니다.

## [0x01] How do debugging works?

Windows API 에서 디버깅을 위해 `DebugActiveProcess` 가 존재합니다.

```cpp
BOOL DebugActiveProcess(DWORD dwProcessId)
```

위와 같이 선언되어 있으며 PID 를 파라미터로 전달 받습니다.

```cpp
BOOL __stdcall DebugActiveProcess(DWORD dwProcessId)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  ConnStatus = DbgUiConnectToDbg(); // from ntdll.dll
  if ( ConnStatus < 0 )
  {
    ErrCode = ConnStatus;
Branch_Error:
    BaseSetLastNTError(ErrCode);
    return 0;
  }
  hProcess = ProcessIdToHandle(dwProcessId);
  ProcessHandle = hProcess;
  if ( !hProcess )
    return 0;
  ActiveStatus = DbgUiDebugActiveProcess(hProcess); // from ntdll.dll
  if ( ActiveStatus < 0 )
  {
    NtClose(ProcessHandle); // from ntdll.dll
    ErrCode = ActiveStatus;
    goto Branch_Error;
  }
  NtClose(ProcessHandle); // from ntdll.dll
  return 1;
}
```

해당 API는 위와 같이 구성되어 있습니다.

```cpp
 ... 
	ConnStatus = DbgUiConnectToDbg(); // from ntdll.dll
  if ( ConnStatus < 0 )
  {
    ErrCode = ConnStatus;
Branch_Error:
    BaseSetLastNTError(ErrCode);
    return 0;
  }
  hProcess = ProcessIdToHandle(dwProcessId);
  ProcessHandle = hProcess;
  if ( !hProcess )
    return 0;
...
```

먼저 `DbgUiConnectToDbg` 라는 ntdll 에서 import 되는 함수의 결과가 `STATUS_SUCCESS` 인 경우 `ProcessIdToHandle` 함수를 이용하여 프로세스의 핸들을 가져오는 것을 확인할 수 있습니다.

그럼 먼저 `DbgUiConnectToDbg` 부터 확인해보겠습니다.

### DebugActiveProcess→DbgUiConnectToDbg

```cpp
NTSTATUS __stdcall DbgUiConnectToDbg()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  Status = 0;
  if ( !NtCurrentTeb()->DbgSsReserved[1] )
  {
    v3 = 0i64;
    v5 = 0;
    v4 = 0i64;
    v6 = 0i64;
    ObjectAttributes = 0x30;                    // IniitliazeObjectAttributes
    Status = (NtCreateDebugObject)(&NtCurrentTeb()->DbgSsReserved[1], 0x1F000Fi64, &ObjectAttributes, 1i64);// 0x1F000F == DEBUG_OBJECT_ALL_ACCESS, 0x1 == DBGK_KILL_PROCESS_ON_EXIT
  }
  return Status;
}
```

현재 프로세스의 `TEB(Thread Environment Block)` 에서 `DbgSsReserved[1]` 값이 존재하는지 확인합니다.

```cpp
kd> dt_TEB DbgSsReserved
nt!_TEB
   +0x16a0 DbgSsReserved : [2] Ptr64 Void
```

실제로 확인해보면 주소 값 2개가 저장된 배열임을 알 수 있습니다.

위에서 사용되는 `NtCreateDebugObject` 함수의 원형은 아래와 같습니다.

```cpp
NTSTATUS NTAPI NtCreateDebugObject	(	
	OUT PHANDLE 	DebugHandle,
	IN ACCESS_MASK 	DesiredAccess,
	IN POBJECT_ATTRIBUTES 	ObjectAttributes,
	IN ULONG 	Flags 
)
```

위의 코드로 예상해보면 `NtCreateDebugObject` 를 이용하여 디버그 오브젝트를 생성하고 이를 `DbgSsReserved[1]` 위치에 저장하는 것으로 보입니다.

즉 `DbgSsReserved[1]` 위치에 `Debug Object` 가 저장된다고 볼 수 있습니다.

`DbgUiConnectToDbg` 의 의미는 `NtCreateDebugObject` 를 이용하여 현재 스레드의 `DbgSsReserved[1]` 위치에 해당 핸들을 저장하는 것으로 확인할 수 있습니다.

`ProcessIdToHandle` 의 경우 내부적으로 `NtOpenProcess` 를 통해 프로세스 핸들을 반환합니다.

현재까지 진행 상황을 정리해보면 아래와 같습니다.

- A 프로세스(디버거가 될 프로세스)

- B 프로세스(디버기)의 PID를 이용하여 

  ```
  DebugActiveProcess
  ```

   호출

  - `DbgUiConnectDbg` 를 호출하며 내부적으로 `NtCreateDebugObject` 를 통해 A 프로세스 내 TEB의 `DbgSsReserved[1]` 위치에 생성한 디버그 오브젝트를 할당

- ```
  ProcessIdToHandle
  ```

   함수를 통해 B 프로세스의 PID로 B 프로세스 핸들을 획득

  - `PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_SUSPEND_RESUME|PROCESS_QUERY_INFORMATION` 권한

```cpp
...
ActiveStatus = DbgUiDebugActiveProcess(hProcess);
  if ( ActiveStatus < 0 )
  {
    NtClose(ProcessHandle);
    ErrCode = ActiveStatus;
    goto Branch_Error;
  }
  NtClose(ProcessHandle);
  return 1;
}
```

마지막은 위와 같이 `DbgUiDebugActiveProcess` 에 획득한 프로세스 핸들을 전달하는 것을 확인할 수 있습니다.

### DebugActiveProcess→DbgUiDebugActiveProcess

```cpp
NTSTATUS __fastcall DbgUiDebugActiveProcess(HANDLE ProcessHandle)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  Status = NtDebugActiveProcess(ProcessHandle, NtCurrentTeb()->DbgSsReserved[1]);
  if ( Status >= 0 )
  {
    Status = DbgUiIssueRemoteBreakin(ProcessHandle);
    if ( Status < 0 )
      ZwRemoveProcessDebug(ProcessHandle, NtCurrentTeb()->DbgSsReserved[1]);
  }
  return Status;
}
```

꽤 간단한 로직으로 이루어져 있습니다.

`NtDebugActiveProcess` 를 호출하며, 위에서 획득한 디버기의 프로세스 핸들과 디버거의 TEB 내 할당 된 디버그 오브젝트를 전달하는 것을 볼 수 있습니다. 지금부터 좀 더 상세하게 해당 로직을 살펴보도록 하겠습니다.

## [0x02] NtDebugActiveProcess

함수의 원형은 아래와 같습니다.

```c
NTSTATUS NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle
)
```

다음은 의사코드입니다.

```c
NTSTATUS __fastcall NtDebugActiveProcess(void *TargetProcessHandle, void *DebugObjectHandle)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  object = 0i64;
  Mode = KeGetCurrentThread()->PreviousMode;
  result = ObReferenceObjectByHandleWithTag(TargetProcessHandle, 0x800u, PsProcessType, Mode, 'OgbD', &object, 0i64);// Object tracing
  if ( result >= 0 )
  {
    CurrentThread = KeGetCurrentThread();
    Process = object;
    CurrentProcess = CurrentThread->ApcState.Process;
    if ( object == CurrentProcess || object == PsInitialSystemProcess )
    {
      Status = 0xC0000022;                      // STATUS_ACCESS_DENIED
    }
    else if ( PsTestProtectedProcessIncompatibility(Mode, CurrentThread->ApcState.Process, object) )
    {
      Status = 0xC0000712;                      // STATUS_PROCESS_IS_PROTECTED
    }
    else if ( (Process->SecureState.SecureHandle & 1) == 0
           || (Status = PsRequestDebugSecureProcess(Process), Status >= 0) )
    {
      v9 = CurrentProcess[1].AffinityPadding[10];
      if ( !v9
        || (v10 = *(v9 + 8), v10 != 0x14C) && v10 != 0x1C4
        || (v11 = Process[1].AffinityPadding[0xA]) != 0 && ((v12 = *(v11 + 8), v12 == 0x14C) || v12 == 0x1C4) )
      {
        Object = 0i64;
        Status = ObReferenceObjectByHandle(DebugObjectHandle, 2u, DbgkDebugObjectType, Mode, &Object, 0i64);
        if ( Status >= 0 )
        {
          v13 = ExAcquireRundownProtection(&Process[1].ProfileListHead.Blink);
          v14 = Object;
          if ( v13 )
          {
            DbgkpPostFakeProcessCreateMessages(Process);
            Status = DbgkpSetProcessDebugObject(Process, v14);
            ExReleaseRundownProtection(&Process[1].ProfileListHead.Blink);
          }
          else
          {
            Status = 0xC000010A;                // STATUS_PROCESS_IS_TERMINATING
          }
          HalPutDmaAdapter(v14);
        }
      }
      else
      {
        Status = 0xC00000BB;                    // STATUS_NOT_SUPPORTED
      }
    }
    ObfDereferenceObjectWithTag(Process, 'OgbD');
    result = Status;
  }
  return result;
```

`NtDebugActiveProcess` 분석에서 처음 보는 개념들이 존재했기 때문에 약간의 시간이 소모됐습니다.

```c
object = 0i64;
Mode = KeGetCurrentThread()->PreviousMode;
v16[0] = 0i64;
result = ObReferenceObjectByHandleWithTag(
	TargetProcessHandle, 
	0x800u,
	PsProcessType, 
	Mode, 
	'OgbD', 
	&object, 
	0i64
	);// Object tracing
```

오브젝트와 관련하여 `Reference Count` 를 확인하며 `ObReference~`  종류의 함수를 몇 가지 확인했었습니다.

`ObReferenceObject` 매크로 함수의 경우 오브젝트의 참조 카운트를 증가시켜주는 역할을 했습니다.

그리고 현재 `NtDebugActiveProcess` 에서 사용되는 `ObReferenceObjectByHandleWithTag` 의 경우에는 참조 카운트 증가 외에도 열려있는 핸들을 이용하여 오브젝트의 포인터를 반환 받을 수 있습니다.

그렇다면 `WithTag` 의 의미는 무엇인지 곰곰히 생각해봤습니다. 다행히 `MSDN` 내 답이 존재했습니다.

이는 `Object Reference Tracing` 이란 내용과 연관되어 있으며 이는 현재 내용과 맞지 않으므로 추후에 포스팅하도록 하겠습니다.

간단히 참조 카운터가 증가 혹은 감소할 때 마다 기록하고 이를 추적하기 위한 기능입니다.(`ObpTraceFlags` 참조)

전달되는 핸들이 프로세스의 핸들이기 때문에 오브젝트 유형은 위와 같이 `PsProcessType` 으로 구성되어 있는 것을 알 수 있습니다.

```c
		// nt!NtDeubgActiveProcess
		CurrentThread = KeGetCurrentThread();
    Process = object;
    CurrentProcess = CurrentThread->ApcState.Process;
    if ( object == CurrentProcess || object == PsInitialSystemProcess )
    {
      Status = 0xC0000022;                      // STATUS_ACCESS_DENIED
    }
    else if ( PsTestProtectedProcessIncompatibility(Mode, CurrentThread->ApcState.Process, object) )
    {
      Status = 0xC0000712;                      // STATUS_PROCESS_IS_PROTECTED
    }
```

다음은 `ObReferenceObjectByHandleWithTag` 을 이용해 획득한 오브젝트에 대한 검증 로직이 존재합니다. 디버거는 자신이 디버기가 될 수 없다.(Self debugging) 라는 개념과 같이 디버거 프로세스와 획득한 오브젝트가 동일한지 확인합니다.

또한 시스템 프로세스에 대한 디버깅이 불가능하도록 `PsInitialSystemProcess` 전역 변수를 이용하여 검증하는 것을 확인할 수 있습니다.

### Check Protected Process

다음으로는 `PsTestProtectedProcessIncompatibility` 함수를 이용하는데 해당 함수에 대한 많은 정보를 찾을 수 없었습니다.

먼저 현재 프로세서 모드와 디버거의 프로세스 오브젝트, 획득한 디버기 프로세스 오브젝트를 전달하는 것을 확인할 수 있었습니다.

```c
bool __stdcall PsTestProtectedProcessIncompatibility(KPROCESSOR_MODE Mode, PEPROCESS Requester, PEPROCESS Target)
{
  bool result = 0;
  if ( Requester != Target )
  {
    LOBYTE(Requester) = BYTE2(Requester[2].Header.WaitListHead.Flink);
    if ( PspCheckForInvalidAccessByProtection(Mode, Requester, BYTE2(Target[2].Header.WaitListHead.Flink)) )
    {
      if ( !CiCheckProcessDebugAccessPolicy || !CiCheckProcessDebugAccessPolicy(Requester, Target) )
        result = 1;
    }
  }
  return result;
}
```

분석을 하기 전 `CiCheckProcessDebugAccessPolicy` 의 경우 다행히 이전에 분석한 `CipInitialize` 에서 확인했기 때문에 어렵지 않게 해당 함수를 찾을 수 있었습니다.

※ 원래의 `ntoskrnl.exe` 내 에는 해당 심볼이 존재하지 않습니다.  본 블로그 내 [이곳](https://shhoya.github.io/antikernel_codeintegrity.html) 에서 확인할 수 있습니다.

먼저 `_EPROCESS.Header(DISPATCHER_HEADER).WaitListHead(LIST_ENTRY)` 와 같이 접근하는 것을 확인할 수 있습니다. 디버깅을 통해 확인한 내용은 해당 내용과 달랐습니다. 물론 `WaitListHead` 의 경우 멀티 스레드 환경에서 사용되는 리스트라는 정보는 획득하였습니다. 다만 실제 명령어를 확인해보면 아래와 같았습니다.

```c
fffff803`755fda3f 8a927a080000    mov     dl,byte ptr [rdx+87Ah]
fffff803`755fda45 458a807a080000  mov     r8b,byte ptr [r8+87Ah]
fffff803`755fda4c e82b000000      call    nt!PspCheckForInvalidAccessByProtection (fffff803`755fda7c)
3: kd> dt_EPROCESS @rdx Protection
nt!_EPROCESS
   +0x87a Protection : _PS_PROTECTION
```

즉 실제 코드는 아래와 같다고 할 수 있습니다.

```c
bool __stdcall PsTestProtectedProcessIncompatibility(KPROCESSOR_MODE Mode, PEPROCESS Requester, PEPROCESS Target)
{
  bool result = 0;
  if ( Requester != Target )
  {
    if ( PspCheckForInvalidAccessByProtection(Mode, Requester->Protection, Target->Protection)) )
    {
      if ( !CiCheckProcessDebugAccessPolicy || !CiCheckProcessDebugAccessPolicy(Requester, Target) )
        result = 1;
    }
  }
  return result;
}
```

`PspCheckForInvalidAccessByProtection` 의 경우 더 깊게 분석하지 않았습니다. 내부적으로 `RtlProtectedAccess` 라는 커널 내 4바이트 전역변수를 이용하여 보호에 의한 접근이 올바른지 확인하는 것으로 보입니다.

본인이 참고한 내용에 따르면 해당 함수는 bool 자료형으로 반환 값이 TRUE 인 경우에 `STATUS_PROCESS_IS_PROTECTED` 를 반환합니다.

이를 보았을 때 해당 루틴은 보호 프로세스인지 확인하는 루틴으로 예상하였습니다.

실제로 확인해보면 `[EPROCESS.Protection](<http://eprocess.Protection>)` 의 구조는 아래와 같습니다.

```c
1: kd> dt_PS_PROTECTION
nt!_PS_PROTECTION
   +0x000 Level            : UChar
   +0x000 Type             : Pos 0, 3 Bits
   +0x000 Audit            : Pos 3, 1 Bit
   +0x000 Signer           : Pos 4, 4 Bits
```

`Type` 이 의미하는 바는 열거형으로,

```c
PsProtectedTypeNone = 0,
PsProtectedTypeProtectedLight,
PsProtectedTypeProtected
```

위와 같이 구성되어 있습니다. 해당 로직에서 프로세스에 대해 타입을 변경하면 디버깅이 되지 않는 것을 확인할 수도 있습니다.

※ `Windows Internals` 내 프로세스 관련 정보에서 보호 프로세스와 보호 프로세스 라이트 라는 목차가 존재합니다.

### Check SecureHandle & SecureProcess

다음은 실제로 프로세스와 디버그 오브젝트를 연결하는 로직입니다. 물론 역시 마찬가지로 특별한 검사를 진행합니다.

```c
else if ( (Process->SecureState.SecureHandle & 1) == 0
           || (Status = PsRequestDebugSecureProcess(Process, 1u), Status >= 0) )
```

`EPROCESS.SecureState.SecureHandle` 필드에 값이 존재하는지 확인하며 존재하는 경우, `PsRequestDebugSecureProcess` 함수를 호출하고 이에 대한 반환 값이 `STATUS_SUCCESS` 인 경우 디버거와 디버기를 연결합니다.

보통의 프로세스를 확인하면 `SecureHandle` 값이 NULL 으로 설정되어 있습니다.

간단하게 해당 값을 1로 설정하면 `장치와 연결할 수 없습니다.` 라는 에러가 발생합니다.

`PsRequestDebugSecureProcess` 대해서는 정말 아무런 정보를 획득할 수 없었습니다.

어쨋든 현재까지 내용을 봤을 때 크게 4가지의 검증 로직이 존재합니다.

1. 디버거와 디버기의 오브젝트가 같은지 검증
2. 시스템 프로세스의 오브젝트와 같은지 검증
3. 보호 프로세스인지 검증
4. `SecureHandle` 값이 존재하는지 검증

### Check Process machine type

위에서 확인한 것과 같이 `SecureHandle` 값이 NULL 인 경우 아래와 같은 코드가 실행됩니다.

```c
else if ( (Process->SecureState.SecureHandle & 1) == 0
           || (Status = PsRequestDebugSecureProcess(Process), Status >= 0) )
    {
      v9 = CurrentProcess[1].AffinityPadding[10];
      if ( !v9
        || (v10 = *(v9 + 8), v10 != 0x14C) && v10 != 0x1C4
        || (v11 = Process[1].AffinityPadding[0xA]) != 0 && ((v12 = *(v11 + 8), v12 == 0x14C) || v12 == 0x1C4) )
      {
        Object = 0i64;
        Status = ObReferenceObjectByHandle(DebugObjectHandle, 2u, DbgkDebugObjectType, Mode, &Object, 0i64);
        if ( Status >= 0 )
        {
          v13 = ExAcquireRundownProtection(&Process[1].ProfileListHead.Blink);
          v14 = Object;
          if ( v13 )
          {
            DbgkpPostFakeProcessCreateMessages(Process);
            Status = DbgkpSetProcessDebugObject(Process, v14);
            ExReleaseRundownProtection(&Process[1].ProfileListHead.Blink);
          }
          else
          {
            Status = 0xC000010A;                // STATUS_PROCESS_IS_TERMINATING
          }
          HalPutDmaAdapter(v14);
        }
      }
      else
      {
        Status = 0xC00000BB;                    // STATUS_NOT_SUPPORTED
      }
    }
    ObfDereferenceObjectWithTag(Process, 'OgbD');
    result = Status;
  }
  return result;
```

위의 의사코드는 잘못 되었으며 어셈블리 코드를 통해 확인하여 다시 의사코드를 만들면 아래와 같습니다. 먼저 분석을 진행할 부분의 코드는 아래와 같습니다.

```c
else if ( (Process->SecureState.SecureHandle & 1) == 0
           || (Status = PsRequestDebugSecureProcess(Process), Status >= 0) )
    {
      CurWoW64Process = CurrentProcess->WoW64Process;
      if ( !CurWoW64Process
        || (CurMachineType = CurWoW64Process->Machine, 
					CurMachineType != IMAGE_FILE_MACHINE_I386) && CurMachineType != IMAGE_FILE_MACHINE_ARMNT
        || (TarWoW64Process = TargetProcess->WoW64Process != 0 && 
					((TarMachineType = TarWoW64Process->Machine, 
					TarMachineType == IMAGE_FILE_MACHINE_I386) || TarMachineType == IMAGE_FILE_MACHINE_ARMNT))
      {
        ...
      }
      else
      {
        Status = 0xC00000BB;                    // STATUS_NOT_SUPPORTED
      }
    }
...
  }
  return result;
```

조건문이 복잡하기 때문에 차례대로 확인하였습니다.

먼저 현재 프로세스(디버거) 오브젝트 내 `WoW64Process` 필드에 값이 존재하는지 확인합니다. 존재하는 경우 쉽게 생각하면 x86 프로세스로 이해할 수 있습니다.

32bit 프로세스인 경우 `_EWOW64PROCESS` 내 `Machine` 필드의 값을 가져와 머신 타입에 대한 검증을 진행합니다.

디버거 프로세스의 머신 타입이 `IMAGE_FILE_MACHINE_I386`, `IMAGE_FILE_MACHINE_ARMNT` 가 아닌 경우 지원합니다.

해당 타입이라면 디버기 프로세스의 머신 타입을 확인하고 `IMAGE_FILE_MACHINE_I386`, `IMAGE_FILE_MACHINE_ARMNT` 가 맞는 경우 지원합니다.

조건이 왜 이렇게 구성되어 있는가 고민을 했습니다. 답은 `WoW64` 하위 시스템에 있었습니다.

32bit 프로세스를 디버깅 가능한 디버거 프로세스는 64, 32bit 모두 해당됩니다. 주소체계와 이를 표현하기 위해 디버거들이 분리되어 있지만 논리적으로 가능한 것으로 보입니다.

그렇기 때문에 위와 같이 구성되었음을 예측할 수 있었습니다.

위의 조건들이 모두 성립하지 않는 경우, `STATUS_NOT_SUPPORTED` 를 반환합니다.

### Set Process debug object

위에서 머신 타입에 대한 검증을 통과하여 실제로 디버그 오브젝트와 프로세스를 연결하는 부분입니다.

```c
...
      if ( !CurWoW64Process
        || (CurMachineType = CurWoW64Process->Machine, 
					CurMachineType != IMAGE_FILE_MACHINE_I386) && CurMachineType != IMAGE_FILE_MACHINE_ARMNT
        || (TarWoW64Process = TargetProcess->WoW64Process != 0 && 
					((TarMachineType = TarWoW64Process->Machine, 
					TarMachineType == IMAGE_FILE_MACHINE_I386) || TarMachineType == IMAGE_FILE_MACHINE_ARMNT))
      {
	        Object = 0i64;
	        Status = ObReferenceObjectByHandle(DebugObjectHandle, 2u, DbgkDebugObjectType, Mode, &Object, 0i64);
	        if ( Status >= 0 )
	        {
	          v13 = ExAcquireRundownProtection(&Process[1].ProfileListHead.Blink);
	          DebugObject = Object;
	          if ( v13 )
	          {
	            v15 = DbgkpPostFakeProcessCreateMessages(Process, Object, v16);
	            Status = DbgkpSetProcessDebugObject(Process, DebugObject, v15, v16[0]);
	            ExReleaseRundownProtection(&Process[1].ProfileListHead.Blink);
	          }
	          else
	          {
	            Status = 0xC000010A;                // STATUS_PROCESS_IS_TERMINATING
	          }
	          HalPutDmaAdapter(DebugObject);
	        }
      }
      else
      {
        Status = 0xC00000BB;                    // STATUS_NOT_SUPPORTED
      }
...
```

마찬가지로 잘못된 의사코드가 존재하기 때문에 아래와 같이 수정하였습니다.

```c
					Object = 0i64;
	        Status = ObReferenceObjectByHandle(DebugObjectHandle, 2u, DbgkDebugObjectType, Mode, &Object, 0i64);
	        if ( Status >= 0 )
	        {
	          BOOLEAN Success = ExAcquireRundownProtection(CurrentProcess->RundownProtect);
	          DebugObject = Object;
	          if ( Success )
	          {
	            v15 = DbgkpPostFakeProcessCreateMessages(Process, Object, v16);
	            Status = DbgkpSetProcessDebugObject(Process, DebugObject, v15, v16[0]);
	            ExReleaseRundownProtection(CurrentProcess->RundownProtect);
	          }
	          else
	          {
	            Status = 0xC000010A;                // STATUS_PROCESS_IS_TERMINATING
	          }
	          HalPutDmaAdapter(DebugObject);
	        }
```

먼저 `NtDebugActiveProcess` 의 두번째 인자인 `DebugObjectHandle` (`DbgUiConnectToDbg` 에서 생성한 Debug object의 핸들)을 이용하여 해당 오브젝트를 가져옵니다.

성공적으로 가져온 경우 런-다운 보호 기능을 이용하여 현재 프로세스(디버거)에 대한 안전한 접근을 보장합니다. `Lock` 과 비슷하며, 상호 배제 기법으로 이해하였습니다. 다른 점은 처리 시간이 비교적 적고 메모리 요구 사항이 적다고 알려져 있습니다. 오브젝트에 대한 작업이 완료 될 때까지 오브젝트가 삭제되는 것을 지연하기 위해 레퍼런스 카운터가 연결됩니다.

디버거와 디버기를 연결 시 알 수 없는 여러가지 이유로 디버기 또는 디버거 프로세스의 오브젝트에 접근하고 사용하는 경우가 존재할 것이며 이를 안전하게 접근하기 위해 사용한다고 이해했습니다.

런-다운 보호 요청이 성공하면 `DbgkPostFakeProcessCreateMessages` 라는 함수를 호출합니다.

가짜 메시지를 생성한다는 것에서 왜라는 의문이 가장 먼저 들었고 해당 함수를 검색해봤습니다.

중국의 여러 블로그에서 어떤 기술 블로그에 내용을 따라 같은 내용이 존재하였습니다.

온전히 디버거에서 프로세스를 생성하여 디버깅을 하는 경우와 흔히 알고 있는 `Attach` 형식의 디버깅이 나누어져 있기 때문이라고 설명하는 듯 합니다.

`Attach` 하는 경우 온전한 디버그 정보를 획득할 수 없으며, 이를 위해 가짜 디버그 정보를 생성하여 디버깅에 문제가 없도록 한다 로 이해하였습니다.

해당 함수를 호출할 때 대부분의 정보에는 아래와 같이 함수가 정의되어 있다고 합니다.

```c
NTSTATUS
DbgkpPostFakeProcessCreateMessages (
    IN PEPROCESS Process,
    IN PDEBUG_OBJECT DebugObject,
    IN PETHREAD *pLastThread
    )
```

왜 `LastThread` 라고 분석하였는지에 대해서는 내부의 `DbgkpPostFakeThreadMessages` 를 보고 이해하였습니다.

내용을 확인하면 루프 안에서 `PsGetNextProcessThread` 함수를 호출을 시작으로 스레드를 순회하는 것을 볼 수 있습니다.

위의 함수를 살펴보면 다음과 같습니다.

```c
NTSTATUS __fastcall DbgkpPostFakeProcessCreateMessages(PEPROCESS Process, PVOID DebugObject, PETHREAD *LastThread)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  Thread = 0i64;
  Object = 0i64;
  ApcState.ApcListHead[0] = 0i64;
  pLastThread = 0i64;
  ApcState.ApcListHead[1] = 0i64;
  *&ApcState.Process = 0i64;
  result = DbgkpPostFakeThreadMessages(Process, DebugObject, 0i64, &Object, &pLastThread);
  if ( result >= 0 )
  {
    KiStackAttachProcess(Process, 0, &ApcState);
    DbgkpPostModuleMessages(Process, Object, DebugObject);
    KiUnstackDetachProcess(&ApcState, 0i64);
    ObfDereferenceObjectWithTag(Object, 'OgbD');
    result = 0;
    Thread = pLastThread;
  }
  *LastThread = Thread;
  return result;
}
```

여기서 주의하시길 바랍니다. `KeStackAttachProcess` 가 아닌 `Ki` `StackAttachProcess` 입니다. 두 번째 파라미터는 내부 로직을 확인했을 때 `IRQL` 이 아닐까 조심히 예측했습니다.

`KiStackAttachProcess` 내부에서는 두 번째 파라미터와 2를 비교하며, `PRCB` 내에서 `DpcRequestSummary` 등과 같이 조건문들이 존재합니다.

2는 `IRQL` 의 `DISPATCH_LEVEL` 의 상수 값으로 이를 검증하기 위한 코드가 아닐까 생각했습니다.

목적은 `KeStackAttachProcess` 와 마찬가지로 타겟 프로세스의 메모리 공간을 현재 스레드와 연결해주는 역할을 합니다.

어쨋든 위에서 말한 이유로 인해 가짜 메시지를 생성하고 드디어 `DbgkpSetProcessDebugObject` 라는 함수를 호출하게 됩니다.

### DbgkpSetProcessDebugObject

해당 함수를 보고 본인은 한숨부터 나왔던게 사실입니다. 긴 코드와 의사코드가 정확하지 않았기 때문이다.

```c
Status = DbgkpSetProcessDebugObject(TargetProcess, DebugObject, v15, LastThread);
```

먼저 위와 같이 호출부부터 확인하였습니다. 디버기 프로세스 오브젝트와 생성된 디버그 오브젝트를 전달하며, `v15` 의 경우 가짜 메시지 생성 함수에 대한 반환 값(`NTSTATUS`)입니다.

재작성한 의사코드 입니다.

```c
__int64 __stdcall DbgkpSetProcessDebugObject(_EPROCESS *Process, _DEBUG_OBJECT *DebugObject, NTSTATUS StatCreateMsg, PETHREAD *LastThread)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  LastThread_1a = LastThread;
  CurrentThread = KeGetCurrentThread();
  Object = 0i64;
  v26 = &P;
  P = &P;
  Success = StatCreateMsg;
  CurrentThread_1 = CurrentThread;
  v27 = 1;
  v28 = 0;
  if ( StatCreateMsg >= 0 )                     // Create fake message?
  {
    LastThread_2 = LastThread_1a;
    Success = 0;
  }
  else
  {
    LastThread_2 = 0i64;
    LastThread_1a = 0i64;
  }
  if ( Success >= 0 )
  {
    ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
    while ( 1 )
    {
      if ( Process->DebugPort )
      {
        Success = 0xC0000048;                   // STATUS_PORT_ALREADY_SET
        v28 = 1;
        goto LABEL_11;
      }
      Process->DebugPort = DebugObject;
      ObfReferenceObjectWithTag(LastThread_2, 'OgbD');
      v28 = 1;
      v9 = PsGetNextProcessThread(Process, LastThread_2);
      if ( !v9 )
        goto LABEL_11;
      Process->DebugPort = 0i64;
      KeReleaseGuardedMutex(&DbgkpProcessDebugPortMutex);
      v28 = 0;
      ObfDereferenceObjectWithTag(LastThread_2, 'OgbD');
      Success = DbgkpPostFakeThreadMessages(Process, &DebugObject->EventPresent, v9, &Object, &LastThread_1a);
      if ( Success < 0 )
        break;
      ObfDereferenceObjectWithTag(Object, 'OgbD');
      ExAcquireFastMutex(&DbgkpProcessDebugPortMutex);
      LastThread_2 = LastThread_1a;
    }
    LastThread_2 = 0i64;
    LastThread_1a = 0i64;
  }
LABEL_11:
  Mutex = &DebugObject->Mutex;
  ExAcquireFastMutex(&DebugObject->Mutex);
  if ( Success >= 0 )
  {
    if ( (DebugObject->Flags & 1) != 0 )
    {
      Process->DebugPort = 0i64;
      Success = 0xC0000354;                     // STATUS_DEBUGGER_INACTIVE
    }
    else
    {
      _InterlockedOr(&Process->1124, 3u);
      ObfReferenceObject(DebugObject);
      LastThread_2 = LastThread_1a;
    }
  }
  v10 = DebugObject->EventList.Flink;
  if ( v10 == &DebugObject->EventList )
    goto LABEL_37;
  do
  {
    v11 = v10;
    v10 = v10->Flink;
    v12 = *(&v11->Mutex.OldIrql + 1);
    if ( (v12 & 4) == 0 || v11->EventList.Flink != CurrentThread )
      continue;
    v13 = v11->Mutex.Event.Header.WaitListHead.Blink;
    if ( Success < 0 )
    {
      if ( v10->Blink != v11 || (v16 = v11->EventPresent.Header.WaitListHead.Flink, v16->Flink != v11) )
LABEL_45:
        __fastfail(3u);
      v16->Flink = v10;
      v10->Blink = v16;
      goto LABEL_30;
    }
    if ( (v12 & 0x10) != 0 )
    {
      _InterlockedOr(&v13[81], 0x80u);
      v14 = *&v11->EventPresent.Header.Lock;
      if ( *(*&v11->EventPresent.Header.Lock + 8i64) != v11 )
        goto LABEL_45;
      v15 = v11->EventPresent.Header.WaitListHead.Flink;
      if ( v15->Flink != v11 )
        goto LABEL_45;
      v15->Flink = v14;
      v14->Blink = v15;
LABEL_30:
      v17 = v26;
      if ( *v26 != &P )
        goto LABEL_45;
      *&v11->EventPresent.Header.Lock = &P;
      v11->EventPresent.Header.WaitListHead.Flink = v17;
      v17->Flink = v11;
      v26 = v11;
      goto LABEL_32;
    }
    if ( v27 )
    {
      *(&v11->Mutex.OldIrql + 1) = v12 & 0xFFFFFFFB;
      KeSetEvent(&DebugObject->EventPresent, 0, 0);
      v27 = 0;
    }
    v11->EventList.Flink = 0i64;
    _InterlockedOr(&v13[81], 0x40u);
LABEL_32:
    v18 = *(&v11->Mutex.OldIrql + 1);
    if ( (v18 & 8) != 0 )
    {
      *(&v11->Mutex.OldIrql + 1) = v18 & 0xFFFFFFF7;
      ExReleaseRundownProtection(&v13[79].Blink);
    }
    CurrentThread = CurrentThread_1;
  }
  while ( v10 != &DebugObject->EventList );
  LastThread_2 = LastThread_1a;
LABEL_37:
  KeReleaseGuardedMutex(Mutex);
  if ( v28 )
    KeReleaseGuardedMutex(&DbgkpProcessDebugPortMutex);
  if ( LastThread_2 )
    ObfDereferenceObjectWithTag(LastThread_2, 'OgbD');
  while ( 1 )
  {
    v19 = P;
    if ( P == &P )
      break;
    if ( *(P + 1) != &P )
      goto LABEL_45;
    v20 = *P;
    if ( *(*P + 8i64) != P )
      goto LABEL_45;
    P = *P;
    *(v20 + 8) = &P;
    DbgkpWakeTarget(v19);
  }
  if ( Success >= 0 )
    DbgkpMarkProcessPeb(Process);
  return Success;
}
```

본인은 `DebugPort` 와 `DebugObject` 를 다르게 생각했습니다. 하지만 해당 로직을 보고나서 같다는 것을 알았습니다.

코드를 살펴보면 해당 함수가 실패하는 원인은 크게 두 가지 입니다.

1. 이미 `DebugPort` 가 설정되어 있다.(0xC0000048)
2. `Debug Object` 내 `DebuggerInactive` 플래그가 설정되어 있다.

관련 자료를 검색하던 중 `_DEBUG_OBJECT` 구조를 확인할 수 있었으며 아래와 같습니다.

```c
struct _DEBUG_OBJECT
{
  _KEVENT EventPresent;
  _FAST_MUTEX Mutex;
  LIST_ENTRY EventList;
  union
  {
    ULONG Flags;
    struct
    {
      unsigned __int8 DebuggerInactive : 1;
      unsigned __int8 KillProcessOnExit : 1;
    };
  };
}DEBUG_OBJECT, *PDEBUG_OBJECT;
```

내부적으로는 더 복잡하게 동작하지만 해당 포스팅은 여기서 마치도록 하겠습니다.

## [0x03] Conclusion

언급한 것과 같이 디버깅 시 발생하는 일들에 대해 좀 더 상세히 들여다 보고자 분석을 진행하였습니다.

해당 과정을 보면 프로세스를 보호하기 위해 몇 가지 기법들을 실험적으로 사용해볼 수 있을 것 같습니다.

디버그 오브젝트와 관련해서 여러 보안 솔루션들의 우회 기법에도 많은 참조가 있습니다.

간단하게 그림으로 정리해봤습니다.(많은 부분이 생략되어 있습니다.)

!<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/debugobj.png?raw=true">

## [0x04] Reference

1. [OpenRCE](http://www.openrce.org/articles/full_view/24)
2. [Debugger.c in ReactOS](http://www.reactos.freedoors.org/Reactos 0.3.13/ReactOS-0.3.13-REL-src/dll/win32/kernel32/debug/debugger.c)
3. [Chinese Blog](https://zhuanlan.kanxue.com/article-538.htm)
4. [wdm.h in MSDN](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/)
