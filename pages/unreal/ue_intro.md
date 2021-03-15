---
title: Unreal Engine Inside
keywords: documentation, technique, reversing, unreal, game
date: 2021-03-16
tags: [Reversing, Dev]
summary: "Unreal Engine Dumper Introduction"
sidebar: unreal_sidebar
permalink: ue_intro.html
folder: unreal
---

## [0x00] Overview

사실 해당 포스팅은 약 1년전에 계획했었으나, 미루고 미루다가 이제 올리게 되었습니다.

`Unreal SDK Generator` 란 언리얼의 구조를 이용하여 게임 내 에서 사용되는 언리얼 오브젝트를 추출하고 이에 대응 하는 이름을 구함으로써 헤더 파일을 생성해주는 도구들을 통칭합니다. 

해당 헤더를 통해 게임 내 클래스, 구조에 대해 명확히 파악이 가능하며 이는 게임 해킹에 매우 큰 단서가 되고 시간을 절약하게 해줍니다.

또한 언리얼 오브젝트를 이용한 함수 호출은 `ProcessEvent` 핸들러를 이용해 함수를 호출하는데, 해당 핸들러를 후킹하고, 오브젝트의 여러 가지 속성을 비교하여 내가 원하는 흐름으로 변조가 가능합니다.

이러한 `Unreal SDK Generator` 에서 가장 중요한 오브젝트가 바로 `FName` , `GObject` 입니다. 여러 포럼들에서 각각 다르게 부르기도 합니다.(예를 들어, `GName, GObjects` , `ObjObjects` 등)

이렇게 다른 이유는 언리얼 엔진의 버전이 업데이트 되면서 심볼의 명칭이 달라지는 이유도 있습니다. 하지만 결국 역할은 같으므로 이름에 크게 신경 쓸 필요는 없습니다. 해당 문서에서는 `FName` , `GObjects` 분석 방법과 덤프에 관한 내용을 다룹니다.
