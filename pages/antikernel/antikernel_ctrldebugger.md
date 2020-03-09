---
_title: Control Debugger
keywords: documentation, technique, debugging
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "디버거 제어 드라이버"
sidebar: antikernel_sidebar
permalink: antikernel_ctrldebugger.html
folder: antikernel
---

## [0x00] Overview

이제 이 프로젝트의 최종장입니다. 보호 드라이버를 우회하는 우회 드라이버를 만들었지만 좀 더 완벽하게 디버거를 제어하기 위해 `Control Debugger` 라는 드라이버를 작성했습니다. 예제코드는 아래에서 확인할 수 있습니다.

- <a href="https://shhoya.github.io/Examples">예제 소스코드</a>



## [0x01] Control Debugger Design

먼저 두 개의 프로젝트가 필요합니다.

1. 유저모드 콘솔 프로그램
   - `DeviceIoControl` 을 통해 드라이버와 통신하며 각 기능을 제어
2. 커널 드라이버
   - 유저모드에서 전달받은 데이터로 각 기능 동작
   - `KdDebuggerEnabled` 제어
   - `KdDebuggerNotPresent` 제어
   - `ObRegisterCallbacks` 콜백 루틴 해제 및 원복
   - `DebugPort` 변조



## [0x02] Cotrol Debugger

드라이버를 로드하고 컨트롤 할 수 있는 유저모드 애플리케이션과 전달받은 컨트롤 코드에 따라 기능이 동작하는 드라이버에 대한 예제입니다. 위에서 설계한대로 만들어봤습니다.

작성중



## [0x02] Proof Of Concept

영상을 확인하면, 보호 드라이버가 로드되어 `notepad.exe`를 보호하고 있으나, 위에서 만든 우회 드라이버를 로드하면 프로세스 디버깅이 가능하고 커널 디버깅을 탐지하지 못하는 것을 알 수 있습니다.

<iframe src="https://youtube.com/embed/mCfIzeYHdbM" allowfullscreen="" width="720" height="365"></iframe>



## [0x03] Constraint

하지만 마찬가지로 제약사항이 존재합니다. 우회 드라이버를 로드하고 커널 디버깅을 시도하기 위해 `windbg` 에서 브레이크 포인트 예외를 발생시켜도 디버깅이 불가합니다. `KdDisableDebugger` 함수를 통해 디버거를 비활성화 했기 때문입니다. 뿐만아니라, 기존에 커널 디버깅을 위해 브레이크 포인트를 설정하였더라도 동작하지 않습니다.

저는 유저모드에서의 디버거 뿐 아니라, 커널모드의 디버거까지 자유롭게 사용하고 싶습니다. 저는 위와 같은 제약이 생긴 이유가 `KdDisableDebugger` 내에서 `KdpSuspendAllBreakpoints` 함수 때문이라고 생각했습니다.

`KdDebuggerEnabled` 변수의 경우 브레이크 포인트 예외와 깊은 관계를 가지고 있지 않습니다. 단지 `windbg` 에서 `pause` 기능 자체가 해당 변수와 관련이 있기 때문에 `pause` 가 되지 않는 것 뿐입니다.

`windbg`는 아래와 같이 `KdCheckForDebugBreak` 함수를 통해 현재 디버그 모드의 상태를 보고 `DbgBreakPointWithStatus` 함수로 브레이크 예외를 발생시켜 디버깅이 가능하도록 합니다.

```c
void KdCheckForDebugBreak()
{
  if ( !KdPitchDebugger && (_BYTE)KdDebuggerEnabled || KdEventLoggingEnabled )
  {
    if ( (unsigned __int8)KdPollBreakIn() )
      DbgBreakPointWithStatus(1i64);
  }
}
```

그래서 저는 `KdDisableDebugger` 함수를 호출하는 것이 아닌 필요 변수들의 값만 설정하여 두 가지 모드의 디버깅이 모두 가능한 상태로 만들기로 했습니다.



## [0x04] Conclusion

`Anti Kernel Debugging Bypass` 프로젝트의 소개에서 깊은 곳에서 궁극적으로 디버깅 중임을 알아차리지 못하게 하는 것이 이 프로젝트의 목표라고 이야기 했습니다. 다음 챕터에서는 `Control Debugger` 라고 불리는 디버거를 컨트롤하며 안티 디버깅 기법을 우회하는 기법에 대해 공개하겠습니다.