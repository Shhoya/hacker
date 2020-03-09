---
title: Code Integrity
keywords: documentation, technique, debugging
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "코드 무결성, 코드 서명"
sidebar: antikernel_sidebar
permalink: antikernel_codeintegrity.html
folder: antikernel
---

## [0x00] Overview

이전 블로그에서 포스팅했던 내용 중 하나입니다. 코드 무결성에 대한 로직과 이를 이용하여 테스트 모드를 마음대로 넘나들 수 있습니다. 

{% include note.html content="이번 챕터는 부록으로 코드를 제공하지 않습니다. 하지만 도구만으로 실습이 가능합니다." %}



## [0x01] Code Integrity

Windows 10에서 부터는 커널 디버깅을 하기 위해 `DEBUGMODE`와 `DSE(Disable Signed Driver Enforcement`)가 필요합니다. `DSE`는 쉽게 말해 개발자 테스트 모드라고 볼 수 있습니다. 이전 챕터들에서 테스트 서명으로 서명 된 드라이버를 로드할 수 있는 이유가 바로 이 때문입니다. 아래는 순서대로 코드 무결성에 대한 검증 내용입니다.



### [-] NtQuerySystemInformation

`NtQuerySystemInformation` 함수를 통해 코드 무결성에 대한 정보를 획득할 수 있습니다.

```c
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemCodeIntegrityUnlockModeInformation,
	SystemCodeIntegritySyntheticCacheInformation,
```

우선 찾은 내용은 각 103(0x67), 164(0xA4), 172(0xAC), 179(0xB3), 183(0xB7),  189(0xBD), 190(0xBC), 199(0xC7), 205(0xCD), 209(0xD1) 의 `SYSTEM_INFORMATION_CLASS` 에 포함되어 있습니다. 물론 단순히 `SystemCodeIntegrity` 를 통해 검색해서 확인했기 때문에 다른 이름으로 더 있을 수 있습니다.

아래는 `NtQuerySystemInformation`의 의사코드입니다.

```c
__int64 __fastcall NtQuerySystemInformation(__int64 a1, __int64 a2, int a3, __int64 a4)
{
  int v4; // er10
  __int64 v5; // r11
  __int16 *v6; // rdx
  signed __int64 v7; // r8
  int v8; // ST20_4
  __int16 v10; // [rsp+40h] [rbp+8h]

  v4 = a3;
  v5 = a2;
  if ( (signed int)a1 < 74 || (signed int)a1 >= 83 )
  {
    switch ( (_DWORD)a1 )
    {
      case 8:
      case 0x17:
      case 0x2A:
      case 0x3D:
      case 0x53:
      case 0x64:
      case 0x6C:
      case 0x8D:
        v7 = 2i64;
        v10 = (unsigned __int8)KeGetCurrentPrcb()->Group;
        v6 = &v10;
        goto LABEL_4;
      case 0x49:
        v7 = 2i64;
        v10 = 0;
        v6 = &v10;
        goto LABEL_4;
      case 0x6B:
      case 0x79:
      case 0xB4:
        return 0xC0000003i64;
      default:
        break;
    }
  }
  v6 = 0i64;
  v7 = 0i64;
LABEL_4:
  v8 = v4;
  return ExpQuerySystemInformation(a1, v6, v7, v5, v8, a4);
}
```

 몇 가지 케이스가 존재하지 않으면 `ExpQuerySystemInformation` 함수를 호출하는 것을 확인할 수 있습니다. 해당 함수를 확인하면 100가지가 넘는 케이스로 이루어져 디컴파일이 되지 않습니다. 

`IDA`에서 `ALT+T` 를 통해 `cases 103` 라는 문자열을 검색합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/ci_00.png?raw=true">

해당 위치를 확인하면 아래와 같이 `SeCodeIntegrityQueryInformation` 함수를 호출하는 것을 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/ci_01.png?raw=true">



### [-] SeCodeIntegrityQueryInformation

```c
__int64 __fastcall SeCodeIntegrityQueryInformation(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v3; // r9
  __int64 v4; // r10
  int v5; // ecx

  v3 = a3;
  v4 = a1;
  if ( !qword_14040CEF8 )
    return 0xC0000001i64;
  v5 = (unsigned __int8)SeILSigningPolicy;
  if ( !SeILSigningPolicy )
    v5 = (unsigned __int8)SeILSigningPolicyRuntime;
  LOBYTE(a3) = v5 != 0;
  return qword_14040CEF8(v4, a2, a3, v3);
}
```

별 특별한 로직없이 `_guard_dispatch_icall` 을 통해 `jmp rax` 명령으로 함수(`qword_14040CEF8`)을 호출합니다. 이 함수의 레퍼런스를 찾아가보면 위에 `SeCiCallbacks`라는 변수를 볼 수 있습니다. 

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/ci_02.png?raw=true">

이 변수는 `SepInitializeCodeIntegrity` 함수에서 사용되고 내부에서 `CiInitialize` 함수를 호출합니다.

### [-] SepInitializeCodeIntegrity

```c
__int64 SepInitializeCodeIntegrity()
{
  unsigned int v0; // edi
  __int64 v1; // rbx
  __int64 v2; // rcx
  unsigned int *v3; // rdx

  v0 = 6;
  memset(&SeCiCallbacks, 0, 0xD0ui64);
  LODWORD(SeCiCallbacks) = 0xD0;
  v1 = 0i64;
  qword_14040CFA8 = 0xA000006i64;
  if ( KeLoaderBlock_0 )
  {
    v2 = *(_QWORD *)(KeLoaderBlock_0 + 0xF0);
    if ( v2 )
    {
      v3 = *(unsigned int **)(v2 + 0xB10);
      if ( v3 )
        v0 = *v3;
    }
    if ( *(_QWORD *)(KeLoaderBlock_0 + 0xD8) && (unsigned int)SepIsOptionPresent() )
      SeCiDebugOptions |= 1u;
    if ( KeLoaderBlock_0 )
      v1 = KeLoaderBlock_0 + 0x30;
  }
  return CiInitialize(v0, v1, &SeCiCallbacks, &SeCiPrivateApis);
}
```

마지막 `CiInitialize` 함수를 호출할 때 3번째 파라미터로 `SeCiCallbacks` 변수의 주소를 전달하는 것을 볼 수 있습니다.
해당 함수는 IMPORT 되는 함수로 `CI.dll` 이라는 모듈에서 EXPORT 됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/ci_03.png?raw=true">



### [-] CiInitialize

`IDA`를 이용하여 `%SystemRoot%\system32\ci.dll` 을 열어 아래와 같이 의사코드를 확인합니다.

```c
signed __int64 __fastcall CiInitialize(int a1, const UNICODE_STRING **a2, __int64 SeCiCallbacks, __int64 SeCiPrivateApis)
{
  __int64 SeCiPrivateApis_1; // rbx
  __int64 SeCiCallbacks_1; // rdi
  const UNICODE_STRING **v6; // rsi
  int v7; // ebp

  SeCiPrivateApis_1 = SeCiPrivateApis;
  SeCiCallbacks_1 = SeCiCallbacks;
  v6 = a2;
  v7 = a1;
  _security_init_cookie();
  return CipInitialize(v7, v6, SeCiCallbacks_1, SeCiPrivateApis_1);
}
```

파라미터에 대한 간단한 정리 후 `CipInitialize` 함수를 호출합니다.



### [-] CipInitialize

필요 없는 부분을 제외하고 아래와 같이 의사코드를 확인하겠습니다.

```c
signed __int64 __fastcall CipInitialize(int a1, const UNICODE_STRING **a2, __int64 a3, __int64 a4)
{
 ...
    if ( v20 >= 0 )
    {
LABEL_21:
      v21 = g_HvciSupported == 0;
      *(_QWORD *)(SeCiCallbacks + 0x20) = CiValidateImageHeader;
      *(_QWORD *)(SeCiCallbacks + 0x28) = CiValidateImageData;
      *(_QWORD *)(SeCiCallbacks + 0x18) = CiQueryInformation;
      *(_QWORD *)(SeCiCallbacks + 8) = CiSetFileCache;
      *(_QWORD *)(SeCiCallbacks + 0x10) = CiGetFileCache;
      *(_QWORD *)(SeCiCallbacks + 0x30) = CiHashMemory;
      *(_QWORD *)(SeCiCallbacks + 0x38) = KappxIsPackageFile;
      *(_QWORD *)(SeCiCallbacks + 0x40) = CiCompareSigningLevels;
      *(_QWORD *)(SeCiCallbacks + 0x48) = &CiValidateFileAsImageType;
      *(_QWORD *)(SeCiCallbacks + 0x50) = CiRegisterSigningInformation;
      *(_QWORD *)(SeCiCallbacks + 0x58) = CiUnregisterSigningInformation;
      *(_QWORD *)(SeCiCallbacks + 0x60) = CiInitializePolicy;
      *(_QWORD *)(SeCiCallbacks + 0x88) = CipQueryPolicyInformation;
      *(_QWORD *)(SeCiCallbacks + 0x90) = CiValidateDynamicCodePages;
      *(_QWORD *)(SeCiCallbacks + 0x98) = CiQuerySecurityPolicy;
      *(_QWORD *)(SeCiCallbacks + 0xA0) = CiRevalidateImage;
      *(_QWORD *)(SeCiCallbacks + 0xA8) = &CiSetInformation;
      *(_QWORD *)(SeCiCallbacks + 0xB0) = CiSetInformationProcess;
      *(_QWORD *)(SeCiCallbacks + 0xB8) = CiGetBuildExpiryTime;
      *(_QWORD *)(SeCiCallbacks + 0xC0) = CiCheckProcessDebugAccessPolicy;
      if ( !v21 )
      {
        *(_QWORD *)(SeCiCallbacks + 0x78) = CiGetStrongImageReference;
        *(_QWORD *)(SeCiCallbacks + 0x68) = CiReleaseContext;
        *(_QWORD *)(SeCiCallbacks + 0x80) = CiHvciSetImageBaseAddress;
      }
      PESetPhase1Initialization(v6);
      if ( (v19 & 0x80000000) == 0 )
        return v19;
      goto LABEL_29;
    }
  }
...
```

`LABEL_21`을 확인하면 `SeCiCallbacks` 배열에 각 함수 주소를 저장하는 것을 확인할 수 있습니다. 즉 위의 `SeCodeIntegrityQueryInformation` 함수에서 호출하는 `qword_14040CEF8` 함수는 `CiQueryInformation` 함수라는 것을 알 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/ci_04.png?raw=true">



### [-] CiQueryInformation

의사코드를 확인하기 전에, `SYSTEM_CODEINTEGRITY_INFORMATION` 구조체에 대해 알아보겠습니다. 아래의 마스크 값은 특정 값과 연산한 값입니다.

```c
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION{
    ULONG	Lenght;
    ULONG	CodeIntegrityOptions;
}SYSTEM_CODEINTEGRITY_INFORMATION;
```

| Mask       | Symbolic Name                                         | Versions              |
| :--------- | :---------------------------------------------------- | :-------------------- |
| 0x00000001 | **CODEINTEGRITY_OPTION_ENABLED**                      | 6.0 and higher        |
| 0x00000002 | **CODEINTEGRITY_OPTION_TESTSIGN**                     | 6.0 and higher        |
| 0x00000004 | **CODEINTEGRITY_OPTION_UMCI_ENABLED**                 | 6.2 and higher        |
| 0x00000008 | **CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED**       | 6.2 and higher        |
| 0x00000010 | **CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED**  | 6.2 and higher        |
| 0x00000080 | **CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED**            | 6.3 and higher        |
| 0x00000200 | **CODEINTEGRITY_OPTION_FLIGHTING_ENABLED**            | 10.0 and higher       |
| 0x00000400 | **CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED**            | 10.0 and higher (x64) |
| 0x00000800 | **CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED**  | 10.0 and higher (x64) |
| 0x00001000 | **CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED** | 10.0 and higher (x64) |
| 0x00002000 | **CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED**             | 10.0 and higher (x64) |

이제 의사코드를 확인해보겠습니다. 마찬가지로 중요한 부분만 확인하겠습니다.

```c
__int64 __fastcall CiQueryInformation(_DWORD *a1, unsigned int a2, char a3, _DWORD *a4)
{
 
 ...
      if ( g_CiOptions & 8 )
        v7[1] |= 2u;
      if ( *KdDebuggerEnabled && *KdDebuggerNotPresent != 1 )
        v7[1] |= 0x80u;
...
  return v8;
}
```

`g_CiOptions` 라는 변수와 8을 AND 연산한 값이 참인 경우 `v7[1]` 위치에 2를 더합니다. 또한 익숙한 `KdDebuggerEnabled` 변수와 `KdDebuggerNotPresent` 값을 비교하여 디버그 모드인 경우 `v1[1]` 위치에 0x80을 더합니다. 위의 마스크 값을 확인하면 `CODEINTEGRITY_OPTION_TESTSIGN` 과 `CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED` 로 비트가 설정되는 것입니다.

즉 `v7` 변수는 `SYSTEM_CODEINTEGRITY_INFORMATION` 구조체 변수임을 알 수 있습니다.



## [0x05] Proof Of Concept

이를 이용해 아래와 같이 재밌는 일들이 가능합니다. 사용한 도구는 `WKE`로 커널 메모리를 확인하고 수정할 수 있습니다.
영상의 내용은 `DEBUGMODE` 와 `DSE`가 비활성화 된 상태(정상 부팅)에서 테스트 인증서로 서명된 드라이버를 로드하는 내용입니다. 

<iframe src="https://youtube.com/embed/u0hs55dwzIA" allowfullscreen="" width="720" height="365"></iframe>



## [0x06] Conclusion

부록의 내용이지만 매우 유용한 내용이라 생각되어 추가하였습니다. 해당 내용과 기존 프로젝트 내용이 합쳐지면 실제 `DEBUGMODE`와 `DSE` 에 대한 상태를 마음대로 제어가 가능하기 때문에 커널 디버깅 중임을 좀 더 확실하게 회피가 가능합니다.

