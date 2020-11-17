---
title: PatchGuard Initialize Debugging
keywords: documentation, technique, reversing, kernel, windows
date: 2020-11-17
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "PatchGuard 분석 팁(1)"
sidebar: windows_sidebar
permalink: windows_pgdbg.html
folder: windows

---

## [0x00] Tips

현재 작성자의 가상머신 기준(Windows 10, 1909)에서 패치가드의 동적 분석이 불가능하게 보일 수 있습니다.
먼저 `KdDebuggerEnabled`와 `KdDebuggerNotPresent`, `KUSER_SHARED_DATA.KdDebuggerEnabled` 등을 확인하여 디버깅 가능 여부를 확인하고 안티 디버깅 기능이 동작합니다.(무한 루프 등)

다만 이전 [포스팅](https://shhoya.github.io/gdbstub.html)에서 설명했던 GDBStub 을 이용하여 디버깅이 가능합니다. 가상머신 자체의 디버깅 기능을 이용하는 것으로 보입니다. 때문에 `Kd` 와 관련된 변수들에 영향이 가지 않습니다.

가상 머신이 시작되면서 가상 머신의 물리 메모리부터 디버깅이 가능해집니다.(메모리 주소 상 물리 주소로 추측됩니다.)우리는 패치가드가 초기화되는 과정에서 메모리의 변화등을 관찰하기 위해 아래와 같은 지점이 필요합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/pgpre_00.png?raw=true">

여기서 문제는 `GDBStub`에서 어떻게 해당 지점을 찾는가 입니다. 심볼도 존재하지 않으며 어떤 메모리 주소에 `ntoskrnl` 이 로드되는지 알 수 없습니다.

저는 Windows Internals 를 모두 정독하지 못했으며 부팅 과정에 대해 완벽히 알지 못합니다. 그렇기 때문에 위와 같은 포인트에서 디버깅이 가능해야 했습니다.

커널에서 부팅 시 `ntoskrnl`가 로드될 때 `KiSystemStartup`을 진입점으로 사용되는 것을 알고 있습니다.

`KiSystemStartup` 내부에 `KiInitializeKernel` 이라는 루틴이 존재합니다. 해당 루틴에서 우리는 해결방법을 찾을 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/pgpre_01.png?raw=true">

위의 하드코딩 되어 있는 주소를 볼 수 있습니다. (`0xFFFFF780'00000308`)

바로 `KUSER_SHARED_DATA` 구조체로 이루어진 Windows 에서 사용되는 공유 메모리 영역입니다. 해당 부분은 Windows 내부 구조에서 더 자세하게 다루겠습니다. 

어쨌든 해당되는 공유 시스템 메모리의 시작은 `0xFFFFF780'00000000` 부터 4kb 크기로 알려져 있습니다.

과감히 해당 메모리에 HWBP(RW)를 설치하고 실행하면 예외가 발생하며 브레이크 포인트가 동작하는 것을 볼 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/pgpre_02.png?raw=true">

브레이크 포인트가 동작하면 현재 시스템 이미지가 로드되는 메모리에 `ntoskrnl` 은 로드되어 있습니다. 이제 `ntoskrnl`의 베이스 주소를 찾고 심볼을 로드할 수 있습니다.

이 때 사용되는 방법은 gdb 명령 중 하나인 `r idtr` 명령을 이용하는 것 입니다.

`IDT`를 기준으로 메모리를 정렬하고 페이지 사이즈(0x1000) 만큼 감소시켜 트레버스하여 `ntoskrnl`의 시작 주소를 찾을 수 있습니다. `IDAPython` 스크립트를 이용하여 아래와 같은 코드로 `ntoskrnl` 의 시작 주소를 찾습니다.

```python
def page_align(address):
    return(address&~(0x1000-1))

monitor_result = SendDbgCommand("r idtr")
base_pos = monitor_result.find("base=")
limit_pos = monitor_result.rfind(" limit")
idt_base = monitor_result[base_pos+5:limit_pos]

idt_base = int(idt_base, 16)
OffsetLow = DbgWord(idt_base + 0)
OffsetMiddle = DbgWord(idt_base + 6)
OffsetHigh = DbgDword(idt_base + 8)

HandlerAddress = ((OffsetHigh << 32) + (OffsetMiddle << 16) + OffsetLow)

DosHeader = page_align(HandlerAddress)
while(True):
    e_magic = DbgWord(DosHeader+0)
    if e_magic == 0x5A4D:
        print "Base address located at {}".format(hex(DosHeader))
        break
    DosHeader -=0x1000
```

그리고 분석의 효율성을 위해 메모리 영역을 다시 한번 설정합니다!

```
Start : nt_BaseAddress
End : nt_BaseAddress + OptionalHeader.SizeOfImage
```

그 다음 `GDBStub` 설정 포스팅에서 설명한대로 심볼을 해당 주소에 로드합니다!([Link](https://shhoya.github.io/gdbstub.html#0x03-load-symbol))

그리고 F8(Step Over) 명령을 통해 예외 핸들링에서 `Yes(pass to app)` 을 클릭 한 후, 원하는 위치에 브레이크 포인트를 설치하고 실행하면 됩니다

패치가드의 주요 루틴 중 하나인 `KiFilterFiberContext` 에서 브레이크 포인트가 동작한 모습입니다!

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/pgpre_03.png?raw=true">



## [0x01] Reference

1. [Load GDBStub symbol](https://www.triplefault.io/2017/07/loading-kernel-symbols-vmm-debugging.html)
2. [Windows Kernel Memory Layout](https://codemachine.com/article_x64kvas.html)