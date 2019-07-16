---
layout: article
title: "[Rev]ObRegisterCallbacks Bypass"
key: 20190708
tags:
  - Rev
  - Windows
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] ObRegisterCallbacks Bypass

<!--more-->

간략하게 앞에서 만들었던 프로세스 보호 드라이버를 어떻게 우회할지 고민해봤다. 가장 먼저 생각난건 역시 콜백함수를 디버깅해서 값을 변조하는 것이다.

그러기 위해선 `ObRegisterCallbacks` API의 동작원리를 파악해야 한다.

## [+] Driver Entry

해당 함수에 bp를 걸고 해도 되기야 하겠지만... 뭐 한 두개일까? 라는 생각에 DriverEntry를 찾는 연습을 해봤다.
PE 구조에서 `AddressOfEntryPoint` 라는 멤버가 있다. 이는 실행파일, 모듈에서는 EntryPoint를 의미한다. 그러나 이 EntryPoint가 메인함수를 의미하는 것은 아닌 것 처럼, 디바이스 드라이버에서는 해당 오프셋이 드라이버 초기화 함수에 해당한다. 다행히 Windbg로 확인했을 때는 그리 복잡한 과정은 없던 것 같다.

```
nt!DebugService2+0x5:
fffff803`35271bb5 cc              int     3
4: kd> lmDvm ProcessProtect
Browse full module list
start             end                 module name
fffff803`3b060000 fffff803`3b067000   ProcessProtect   (deferred)             
    Image path: ProcessProtect.sys
    Image name: ProcessProtect.sys
    Browse all global symbols  functions  data
    Timestamp:        Fri Jul  5 10:21:46 2019 (5D1EA62A)
    CheckSum:         0000CA01
    ImageSize:        00007000
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
    Information from resource tables:
```

```
4: kd> r $t0=ProcessProtect
4: kd> bp $t0+5000
4: kd> uf $t0+5000
ProcessProtect+0x5000:
fffff803`3b065000 48895c2408      mov     qword ptr [rsp+8],rbx
fffff803`3b065005 57              push    rdi
fffff803`3b065006 4883ec20        sub     rsp,20h
fffff803`3b06500a 488bda          mov     rbx,rdx
fffff803`3b06500d 488bf9          mov     rdi,rcx
fffff803`3b065010 e817000000      call    ProcessProtect+0x502c (fffff803`3b06502c)
fffff803`3b065015 488bd3          mov     rdx,rbx
fffff803`3b065018 488bcf          mov     rcx,rdi
fffff803`3b06501b e8e0bfffff      call    ProcessProtect+0x1000 (fffff803`3b061000)
fffff803`3b065020 488b5c2430      mov     rbx,qword ptr [rsp+30h]
fffff803`3b065025 4883c420        add     rsp,20h
fffff803`3b065029 5f              pop     rdi
fffff803`3b06502a c3              ret
```

위에서 0x5000 오프셋은 해당 드라이버의 `AddressOfEntryPoint` 필드의 값이다. 확인하면 간단해보이는 로직이 보인다. 위에서 두번째 함수호출 하는 부분을 확인하면 `ProcessProtect+0x1000` 으로 마치 메인함수의 주소를 보는듯한 느낌이 든다.

실제로 해당 부분에 bp를 설치하고 진행하여 확인하면 DriverEntry 임을 확인할 수 있다.

## [+] ObRegisterCallbacks

앞선 포스터에서 짠 코드를 확인하면 DriverEntry에서 ProcessProtect 함수를 호출하고 해당 함수에서 리턴 값이 ObRegisterCallbacks 함수의 반환 값임을 알 수 있다.

```c++
NTSTATUS ProcessProtect(BOOLEAN Enable){
    ...
    ...
	return ObRegisterCallbacks(&obReg, &obHandle);
}
```

해당 위치로 디버깅하여 확인해보면 아래와 같이 ObRegisterCallbacks API를 호출하는 부분을 찾을 수 있다.

```
4: kd> u $t0+10d7 l c
ProcessProtect+0x10d7:
fffff803`3b0610d7 488b05720f0000  mov     rax,qword ptr [ProcessProtect+0x2050 (fffff803`3b062050)]
fffff803`3b0610de 488d152b1f0000  lea     rdx,[ProcessProtect+0x3010 (fffff803`3b063010)]
fffff803`3b0610e5 8365bc00        and     dword ptr [rbp-44h],0
fffff803`3b0610e9 488d4dd0        lea     rcx,[rbp-30h]
fffff803`3b0610ed 488365c800      and     qword ptr [rbp-38h],0
fffff803`3b0610f2 488945b0        mov     qword ptr [rbp-50h],rax
fffff803`3b0610f6 488d0523000000  lea     rax,[ProcessProtect+0x1120 (fffff803`3b061120)]
fffff803`3b0610fd 488945c0        mov     qword ptr [rbp-40h],rax
fffff803`3b061101 488d45b0        lea     rax,[rbp-50h]
fffff803`3b061105 488945f0        mov     qword ptr [rbp-10h],rax
fffff803`3b061109 897db8          mov     dword ptr [rbp-48h],edi
fffff803`3b06110c ff150e0f0000    call    qword ptr [ProcessProtect+0x2020 (fffff803`3b062020)]
```

`ObRegisterCallbacks` API의 원형은 다음과 같다.

```c
NTSTATUS ObRegisterCallbacks(
	POB_CALLBACK_REGISTRATION CallbackRegistration,
	PVOID                     *RegistrationHandle
);
```

두 개의 인자를 전달받고 이 중 첫번째 인자는 `OB_CALLBACK_REGISTRATION` 구조체 포인터다.

### [-] OB_CALLBACK_REGISTRATION

내가 찾으려는 것은 개발자가 정의한 콜백함수다. 이 구조체를 따라 콜백함수의 주소를 찾는다. `OB_CALLBACK_REGISTRATION`의 구조체는 다음과 같다.

```c
typedef struct _OB_CALLBACK_REGISTRATION {
	USHORT                    Version;
	USHORT                    OperationRegistrationCount;
	UNICODE_STRING            Altitude;
	PVOID                     RegistrationContext;
	OB_OPERATION_REGISTRATION *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;
```

디버거에서 확인하면 다음과 같은 정보를 찾을 수 있다. 출력된 문자열은 Altitude 값임을 알 수 있다.

```
4: kd> dp rcx
ffffd88b`e90df830  00000000`00010100 00000000`000e000c
ffffd88b`e90df840  fffff803`3b0611f0 00000000`00000000
ffffd88b`e90df850  ffffd88b`e90df810 00000000`00000018
ffffd88b`e90df860  ffffd88b`e90df9d0 fffff803`3b06101e
ffffd88b`e90df870  ffffc585`e8f0d2c0 00000000`00000300
ffffd88b`e90df880  ffffd88b`e90df898 00000000`00000018
ffffd88b`e90df890  ffffd88b`e90df8a0 fffff803`3b065020
ffffd88b`e90df8a0  00000000`00000010 00000000`00000344
4: kd> du fffff803`3b0611f0
fffff803`3b0611f0  "321000"
```

즉 0xffffd88b'e90df850 의 값이 OB_OPERATION_REGISTRATION 구조체 포인터 임을 알 수 있다.

### [-] OB_OPERATION_REGISTRATION

```
typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE                *ObjectType;
    OB_OPERATION                Operations;
    POB_PRE_OPERATION_CALLBACK  PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;
```

위와 같은 구조로 되어있으며, 세번째와 네번째 멤버로 PRE 동작과 POST 동작이 정의되어 있다.

```
4: kd> dps ffffd88b`e90df810
ffffd88b`e90df810  fffff803`355f92d0 nt!PsProcessType
ffffd88b`e90df818  00000000`00000001
ffffd88b`e90df820  fffff803`3b061120 ProcessProtect+0x1120
ffffd88b`e90df828  00000000`00000000
```

즉 `ProcessProtect+0x1120` 위치에 OB_PRE_OPERATION_CALLBACK 함수가 있다라는 의미가 된다.

```
4: kd> uf ProcessProtect+0x1120
ProcessProtect+0x1120:
fffff803`3b061120 4053            push    rbx
fffff803`3b061122 4883ec30        sub     rsp,30h
fffff803`3b061126 488b4a08        mov     rcx,qword ptr [rdx+8]
fffff803`3b06112a 488bda          mov     rbx,rdx
fffff803`3b06112d ff15050f0000    call    qword ptr [ProcessProtect+0x2038 (fffff803`3b062038)]
fffff803`3b061133 0f57c0          xorps   xmm0,xmm0
fffff803`3b061136 8bc8            mov     ecx,eax
fffff803`3b061138 0f11442420      movups  xmmword ptr [rsp+20h],xmm0
fffff803`3b06113d e812ffffff      call    ProcessProtect+0x1054 (fffff803`3b061054)
fffff803`3b061142 488d542420      lea     rdx,[rsp+20h]
fffff803`3b061147 482bd0          sub     rdx,rax

ProcessProtect+0x114a:
fffff803`3b06114a 8a08            mov     cl,byte ptr [rax]
fffff803`3b06114c 880c02          mov     byte ptr [rdx+rax],cl
fffff803`3b06114f 48ffc0          inc     rax
fffff803`3b061152 84c9            test    cl,cl
fffff803`3b061154 75f4            jne     ProcessProtect+0x114a (fffff803`3b06114a)  Branch

ProcessProtect+0x1156:
fffff803`3b061156 488d15a3000000  lea     rdx,[ProcessProtect+0x1200 (fffff803`3b061200)]
fffff803`3b06115d 488d4c2420      lea     rcx,[rsp+20h]
fffff803`3b061162 e83b000000      call    ProcessProtect+0x11a2 (fffff803`3b0611a2)
fffff803`3b061167 85c0            test    eax,eax
fffff803`3b061169 752f            jne     ProcessProtect+0x119a (fffff803`3b06119a)  Branch

ProcessProtect+0x116b:
fffff803`3b06116b 833b01          cmp     dword ptr [rbx],1
fffff803`3b06116e 752a            jne     ProcessProtect+0x119a (fffff803`3b06119a)  Branch

ProcessProtect+0x1170:
fffff803`3b061170 488b4b20        mov     rcx,qword ptr [rbx+20h]
fffff803`3b061174 8b4104          mov     eax,dword ptr [rcx+4]
fffff803`3b061177 a808            test    al,8
fffff803`3b061179 7407            je      ProcessProtect+0x1182 (fffff803`3b061182)  Branch

ProcessProtect+0x117b:
fffff803`3b06117b 8321f7          and     dword ptr [rcx],0FFFFFFF7h
fffff803`3b06117e 488b4b20        mov     rcx,qword ptr [rbx+20h]

ProcessProtect+0x1182:
fffff803`3b061182 8b4104          mov     eax,dword ptr [rcx+4]
fffff803`3b061185 a810            test    al,10h
fffff803`3b061187 7407            je      ProcessProtect+0x1190 (fffff803`3b061190)  Branch

ProcessProtect+0x1189:
fffff803`3b061189 8321ef          and     dword ptr [rcx],0FFFFFFEFh
fffff803`3b06118c 488b4b20        mov     rcx,qword ptr [rbx+20h]

ProcessProtect+0x1190:
fffff803`3b061190 8b4104          mov     eax,dword ptr [rcx+4]
fffff803`3b061193 a820            test    al,20h
fffff803`3b061195 7403            je      ProcessProtect+0x119a (fffff803`3b06119a)  Branch

ProcessProtect+0x1197:
fffff803`3b061197 8321df          and     dword ptr [rcx],0FFFFFFDFh

ProcessProtect+0x119a:
fffff803`3b06119a 33c0            xor     eax,eax
fffff803`3b06119c 4883c430        add     rsp,30h
fffff803`3b0611a0 5b              pop     rbx
fffff803`3b0611a1 c3              ret
```

해당 위치에 위와 같이 bp를 설치하고 디버깅하여 우회를 해본다.

## [+] Debugging

```
ProcessProtect+0x1156:
fffff803`3b061156 488d15a3000000  lea     rdx,[ProcessProtect+0x1200 (fffff803`3b061200)]
fffff803`3b06115d 488d4c2420      lea     rcx,[rsp+20h]
fffff803`3b061162 e83b000000      call    ProcessProtect+0x11a2 (fffff803`3b0611a2)
fffff803`3b061167 85c0            test    eax,eax
fffff803`3b061169 752f            jne     ProcessProtect+0x119a (fffff803`3b06119a)  Branch
```

해당 위치에서 rdx에 어떤 값을 가져오는데, 이 값은 문자열로 "notepad.exe" 이다.

```
fffff803`3b061200 6e 6f 74 65 70 61 64 2e 65 78 65 00 ; notepad.exe
```

이 값만 바꿔주고 쭉 진행하면 프로세스 보호가 동작하지 않는 것을 확인할 수 있다~~~

기본적인 원리를 알아야 한다ㅏㅏ