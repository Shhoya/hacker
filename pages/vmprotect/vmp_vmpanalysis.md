---
title: VMP analysis
keywords: documentation, technique, debugging
date: 2020-03-10
tags: [Windows, Reversing, Dev]
summary: "VMP 동적 및 정적분석"
sidebar: vmp_sidebar
permalink: vmp_vmpanalysis.html
folder: vmprotect
---

## [0x00] Overview

VMP나 Themida로 패킹된 파일을 분석할 때 중요한 것은 운입니다. 적용할 때 단순히 패킹만 했다면 아주 감사하게 분석을 할 수 있고, Mutation과 Virtualization 을 적절하게 사용했다면 그야말로 지옥을 볼 수 밖에 없습니다.(적어도 저는 그렇습니다.)

그래서 분석하면서 느끼고 그나마 분석을 할 수 있는 패턴에 대한 내용을 준비해봤습니다.



## [0x01] Analysis

먼저 `Mutation` 과 `Virtualization` 은 다른 의미를 지닙니다. `Mutation`은 말 그대로 돌연변이를 일으킵니다. 어셈블리를 복잡하게 만들어주는 역할을 합니다. 그에 비해 `Virtualization`은 내부에 특수한 가상 CPU(명령어 해석)를 두고, 가상 CPU에서 복잡한 명령어들을 통해 코드를 실행합니다.

저는 코드 가상화 부분을 분석해봤습니다. 많은 내용들을 보았지만 사실 이해가 되지 않았습니다. 다만 분석하면서 몇 가지 패턴을 찾는데는 성공하여 동적 분석을 하며 특정 VM Macro가 어떤 함수를 호출하는지에 대해 분석할 수 있었습니다.

저는 몇 가지 용어를 정의했습니다.

- `vmmacro` : 여러 개의 매크로 함수가 존재, 특정 패턴으로 이루어져 있음
- `vmmacro_handler` : vmmacro를 호출하는 `push` 와 `call`명령어 세트
- `vmtable` : vmmacro의 집합

정확한 용어를 알지 못하므로 위와 같이 정의했습니다. 그럼 이전 챕터에서 만든 패킹 된 예제를 가지고 분석을 진행해보겠습니다.

### [-] EntryPoint

패킹을 거치고나면 EntryPoint가 `.vmp1` 섹션에 위치하게 되며 아래의 그림과 같이 구성되어 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_00.png?raw=true">

내부에는 알 수없는 명령어들로 가득합니다. EP는 vmp에서 실행 압축을 해제하고, 옵션에 따라 안티 디버깅 및 안티 VM 등의 기능을 수행합니다. 실제 분석해야 할 곳은 실행 압축이 해제되는 `.text` 섹션입니다. 아래와 같이 비어있는 `.text` 섹션에 하드웨어 브레이크 포인트를 설치하고 실행합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_01.png?raw=true">

실행 후에 특정 위치에서 실행이 멈추게 됩니다. 확인해보면 실행 압축을 해제하며 `.text` 섹션에 코드를 복사합니다. 해당 위치에서 `CTRL+F9(Execute till Return)`을 입력하면 리턴 명령을 만날때까지 실행하게 됩니다. 실행 압축이 해제되는 것을 직접 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_02.png?raw=true">

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_03.gif?raw=true">



### [-] vmtable & vmmacro_handler pattern

본격적으로 `.text` 섹션 위치에서 가상화 코드들을 확인해봅니다. 위에서 코드가 모두 풀리면 `ret` 명령에서 동작을 멈춥니다. `Step Over` 명령을 통해 다음 명령을 확인하면 확실하게 `vmmacro_handler` 를 만날 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_04.png?raw=true">

여기서 `vmmcaro_handler` 패턴에 대해 발견했습니다. `68 ?? ?? ?? ?? E8 ?? ?? ?? ?? <??>` 패턴을 가지고 있으며 `<>` 안에 값은 더미 값입니다(물론 의미있는 값이 간혹 있지만 아래 그림을 보면 이해가 될 것 입니다.). 이 패턴을 토대로 현재 명령에서 명령을 다시 어셈블하면 아래와 같은 형태를 갖추게 됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_05.png?raw=true">

이 패턴을 기억하며 스크롤을 위로 올려 더미 바이트를 nop으로 변환하고 아래와 같이 정렬합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_06.gif?raw=true">

이러한 `vmmacro_handler`의 집합을 저는 `vmtable`로 정의하였습니다. 



### [-] Analysis

여기서 중요한 점은, `Virtualizaiton` 에서 대부분 원래의 로직을 실행할 때 가상 CPU에서 연산을하여 스택에 저장하고 `ret` 명령을 통해 실행한다는 것입니다. 디버거에는 `Execute till return` 기능이 존재하고 이를 유용하게 사용할 수 있습니다. `windbg`의 경우에는 분기문을 만나면 멈추는 기능까지 존재합니다.

이제 위의 `vmtable`과 `vmmacro_handler` 패턴, 스택을 이용한 실제 로직 실행, 이 세 가지 패턴을 가지고 분석을 해보겠습니다.

실행 압축이 해제되었고, 직접 확인하려는 로직에 하드웨어 브레이크 포인트를 설치하여 분석을 시작하면 됩니다. 실습에서 분석하려는 함수는 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_07.png?raw=true">

여기서 또 한가지 확인할 수 있는 패턴이 존재하는데, 위의 그림을 `IDA`를 통해 열어보면 아래와 같은 형태를 띄게 됩니다.
바로 함수를 분리하여 분석을 어렵게 만들어놨습니다. `jmp`명령을 통해 함수의 에필로그 부분을 실행하는 것을 볼 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_08.png?raw=true">



**작성중입니다.**





