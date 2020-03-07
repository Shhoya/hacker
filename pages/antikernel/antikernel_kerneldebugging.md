---
title: Kernel Debugging
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "커널 디버깅의 원리"
sidebar: antikernel_sidebar
permalink: antikernel_kerneldebugging.html
folder: antikernel
---

## [0x00] Overview

이번 챕터에서는 본격적인 커널 디버깅 방지 우회에 들어가기 앞서, 커널 디버깅 중에 시스템에서 어떠한 변화가 있는지 살펴볼 것입니다. 매우 중요한 내용입니다. 커널 디버깅 시 시스템에서의 변화를 많이 알면 알수록 우회할 수 있는 포인트나 커널 디버깅을 방지할 수 있는 기법 개발이 가능합니다.

몇 가지 커널 디버깅 관련 함수와 전역변수들에 대해 알아 볼 것입니다. 



## [0x01] KdInitSystem

`KD` 는 `Kernel Debugger`의 약자로 Windows OS 내 커널 디버거와 관련되어 있습니다. 이전 챕터에서 `KdDebuggerEnabled`와 `KdDebuggerNotPresent` 의 접두어가 `Kd` 인 것과 관련이 깊습니다.

처음 이러한 내용을 공부할 때는 커널 내 디버거와 관련된 변수 또는 함수를 찾으면서, `Debugger` 또는 `Debugging`으로 문자열 검색을 해서 찾았습니다. 그리고 `Kd`의 존재를 알고나서 한결 수월해진 것 같습니다.

`KD` 관련된 함수와 변수를 확인하는 방법에 대한 이야기를 해보겠습니다. 우선 `ntoskrnl.exe`를 IDA의 xref 기능을 이용해 확인했습니다. 물론 더 중요한 내용들이 빠져있을 수 있지만 충분하다고 생각합니다.

꽤 길어질 수 있는 내용이기 때문에 카테고리를 분류하기로 하였습니다. 

