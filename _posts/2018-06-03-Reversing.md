---
layout: article
title: "[Rev]Abex' Crack me"
key: 20180603
tags:
  - Reversing
  - PE
  - Analyze
toc: true
---

# [+]Abex' Crack Me

<!--more-->

## [+]Crack Me #1

### Problem

초심으로 돌아가기 위해 다시 리버싱 핵심 원리를 다시 읽기로 했다. 리버싱이 너무 재밌었는데 요즘은 많이 스트레스를 받았던 것 같다. 그래서 진정한 리버서(?)가 되기 위해 좀 더 기초적인 것을 가다듬으려 한다.

처음 리버싱을 접할 때 가장 많이 보게 되는 문제들 중 'Abex' 시리즈가 참 좋은 것 같다.

먼저 해당 프로그램을 다음과 같은 메시지가 출력된다.

```
[abex' 1st crackme]
"Make me think your HD is CD-Rom.

# 확인 버튼 클릭 후,

[Error]
"Nah... This is not a CD-ROM Drive!"

```

CD-Rom을 모르는 세대가 올 줄 이야.............;
어쨋든 하드디스크를 CD-ROM으로 인식시켜야 하는 문제이다.



### Disassembly

Ollydbg를 이용해 해당 프로그램을 살펴보면 아래와 같다.

![abex](https://raw.githubusercontent.com/Shhoya/Shhoya.github.io/master/assets/images/task/abex1.png "Abex"){:.border}

Offset 0x00401044 에 보면 "Ok, I really think that your HD is a CD-ROM!" 이라는 문구가 보인다.
대부분 쉽게 분기문을 바꿔 문제를 풀게 된다. 조금 관심이 있으면 함수의 리턴 값을 변조한다던지 할꺼다.



### Crack

"GetDriveType" 함수의 리턴 값이 CD-ROM임을 인식시키면 된다. 그런데 **함정**이 존재한다.
"DEC EAX" 명령어가 존재한다.

먼저 GetDriveType 함수는 아래와 같이 사용 가능하다.

```C++
UINT WINAPI GetDriveType(
  _In_opt_ LPCTSTR lpRootPathName
);

/*
return value.
0x00 : Drive_Unknown
0x01 : Drive_No_Root_Dir
0x02 : Drive_Removable
0x03 : Drive_Fixed
0x04 : Drive_Remote
0x05 : Drive_Cdrom
0x06 : Drive_Ramdisk
*/
```

실제 트레이싱을 해보면 "C:\"를 인자로 받는 GetDriveType 함수의 리턴 값은 0x03(Fixed) 이다. 보통 하드디스크, 플래쉬 드라이브인 경우 이러한 리턴 값을 받게 된다.

그렇다면 이 리턴 값을 0x05 로 변조해주면 끝! 일 수 있으나 아까 위에서 말했듯, 함정이 존재한다.
실제 해당 프로그램을 속이기 위해선 0x04로 변조시켜주면 된다.

![abex](https://raw.githubusercontent.com/Shhoya/Shhoya.github.io/master/assets/images/task/abex1_1.png "Abex"){:.border}



## [+]Reference

1. <a href="https://msdn.microsoft.com/ko-kr/library/windows/desktop/aa364939(v=vs.85).aspx">*"MSDN_GetDriveType_Function"*</a>