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

`IDA`에서 `ALT+T` 를 통해 `cases 164` 라는 문자열을 검색합니다.

<img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/ci_00.png?raw=true">

해당 위치를 확인하면 아래와 같이 `SeCodeIntegrityQueryPolicyInformation` 함수를 호출하는 것을 확인할 수 있습니다.

<img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/ci_01.png?raw=true">



### [-] SeCodeIntegrityQueryInformation





## [0x05] Proof Of Concept

영상은 `Control Debugger`를 이용하여 `ObRegisterCallbacks` 의 콜백 루틴을 더미 함수로 교체 및 복구 합니다. 그리고 순서대로 `KdDebuggerNotPresent` 를 우회하고 `KdDebuggerEnabled` 를 우회합니다.

<iframe src="https://youtube.com/embed/YcTgkXGNNBk" allowfullscreen="" width="720" height="365"></iframe>



## [0x06] Conclusion

이로써 모든 프로젝트 과정을 마쳤습니다. 안티 디버깅, 프로세스 보호는 기술의 발전만큼 매우 다양합니다. 새로운 기법이 나타나거나, 아주 오래전에 사용한 기법을 사용하기도 합니다. 더 많은 전역변수나 `RUNTIME_FUNCTION` 내 존재하는 함수들을 이용할 수도 있습니다. 그렇기 때문에 원시적인 방법이 최선이라고 생각합니다.

긴 글을 읽어주셔서 감사합니다. 궁금한 부분이나 필요한 부분이 있다면 상단에 피드백 메뉴를 통해 전달주시면 답변해드리겠습니다.

감사합니다.