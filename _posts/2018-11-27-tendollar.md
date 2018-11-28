---
layout: article
title: "[WriteUp]TenDollar CTF"
key: 20181127
tags:
  - WriteUp
  - Reversing
  - Forensic
  - CTF
sidebar:
  nav: sidem
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] TenDollar CTF WriteUp

<!--more-->

## [+] Everything From Nothing(Reversing)
Author: @Hackability

It's from void.

flag format : TDCTF{hexString(correct answer)}

- ex: TDCTF{0123456789abcdef}
- lower case

[*] Notice : Key is changed (Binary is not changed).



### Analysis

삽질을 엄청한 문제다.. 다름아닌 우분투 리눅스의 버전때문... 해당 문제를 풀 때는 18.04에서는 세그멘테이션 오류가 나서 풀지 못한다. 도움을 준 @burn6 에게 감사의 마음과 텐딸라의 우리 @shipik 과 @t0rchwo0d 에게도 감사의 마음을 전하옵니다

먼저 해당 바이너리를 실행해보기로 한다.

```
root@shh0ya-Linux:/mnt/hgfs/01_CTF/01_TenDollar/EFN# ./EFN
test
wrong!
```

"test" 라는 문자열을 입력하면 "wrong!" 이라는 문자열이 출력되버리고 만다. 이제 디스어셈블된 모습을 살펴본다.

해당 바이너리를 열어보면 당황스럽게도 의심스러운 함수조차 없다.
`main` 함수를 살펴보면 다음과 같이 되어있다. 

```assembly
; Attributes: bp-based frame
; int __cdecl main(int, char **, char **)

main proc near
push    rbp
mov     rbp, rsp
mov     edx, 10h        ; nbytes
lea     rsi, unk_559777066020 ; buf
mov     edi, 0          ; fd
call    read
mov     eax, 0
pop     rbp
retn
main endp
```

16byte의 문자열을 받는 `read`함수를 호출하고 `return 0` 을 시전한다. 그렇다면 메인함수 전에 "wrong!" 을 출력하는 것일까 하고 디버깅을 해봤으나 main함수 이 후에 출력되는 것을 확인할 수 있다.

그러나 메인함수 이후에는 호출되는 함수가 없는디?! 했으나 정석대로 거꾸로 돌아가본다.

문자열 찾기로 "wrong!" 문자열을 찾으면 다음과 같이 `text` 영역에 아래와 같이 해당 문자열을 출력해주는 `write`함수와 함께 함수형태로 존재하는 것을 확인할 수 있다.

```assembly
.text:0000559776E657E0 ; ---------------------------------------------------------------------------
.text:0000559776E657E0                 push    rbp
.text:0000559776E657E1                 mov     rbp, rsp
.text:0000559776E657E4                 mov     edx, 6
.text:0000559776E657E9                 lea     rsi, aWrong     ; "wrong!"
.text:0000559776E657F0                 mov     edi, 1
.text:0000559776E657F5                 call    write
.text:0000559776E657FA                 mov     edi, 0
.text:0000559776E657FF                 call    exit
.text:0000559776E65804 ; ---------------------------------------------------------------------------
.text:0000559776E65804                 push    rbp
.text:0000559776E65805                 mov     rbp, rsp
.text:0000559776E65808                 mov     edx, 8
.text:0000559776E6580D                 lea     rsi, aCorrect   ; "correct!"
.text:0000559776E65814                 mov     edi, 1
.text:0000559776E65819                 call    write
.text:0000559776E6581E                 mov     edi, 0
.text:0000559776E65823                 call    exit
```

오호? 하고 ida에서 키보드의 'x' 를 클릭하여 레퍼를 찾았지만 참조하는 그 어떤 명령어도 찾을 수 없었다. 그러면 의심할 수 있는 것은 하나다. `call eax` 와 같이 특정 값을 연산하여 레지스터에 저장하여 분기할 수 있다라는 이야기다. 

자 이제 노가다의 시작이다. 메인함수 종료 후 step over 를 통해 "wrong!" 이 출력되는 함수를 찾아야 한다.
내가 찾는 방법은 이렇다.

1. Step over를 이용해 함수단위로 쭉쭉 실행한다. 하다가 종료가 되면 종료된 함수를 기록 및 브레이크 포인트를 설정한다.
2. 해당 함수까지 다시 실행한 뒤 Step into 를 이용해 함수에 진입하고 다시 Step over로 쭉쭉 진행한다.
3. 1,2를 반복하여 찾는다.

그러다 보면 아래와 같은 명령어들을 찾을 수 있다.

```assembly
.eh_frame:000056004D0E49FE loc_56004D0E49FE:                       ; CODE XREF: .eh_frame:000056004D0E49F4↑j
.eh_frame:000056004D0E49FE add     rsi, 201020h
.eh_frame:000056004D0E4A05 jmp     short loc_56004D0E4A0F
```

`rsi` 에 담긴 값을 확인하면 해당 바이너리의 헤더 부분인 것을 확인할 수 있다.
해당 위치로부터 `0x201020` 만큼 떨어진 곳을 확인하면 내가 입력한 값이 존재하는 것을 확인할 수 있다.
점프문을 통해 다음 명령어로 넘어가보자

```assembly
.eh_frame:000056004D0E4A0F loc_56004D0E4A0F:                       ; CODE XREF: .eh_frame:000056004D0E4A05↑j
.eh_frame:000056004D0E4A0F movdqu  xmm1, xmmword ptr [rsi]
.eh_frame:000056004D0E4A13 jmp     short loc_56004D0E4A21
```

아직 나도 제대로 이해를 못해서 <a href="https://www.slideshare.net/KooKyeongWon/0204-sse">**<u>여기</u>**</a> 링크를 남긴다... 병렬처리프로그래밍과 관련이 있어보인다. 어쨋든 보면 rsi에 있는 입력 값을 `xmm1` 레지스터로 옮기는 것을 볼 수 있다.

그리고 다음 명령어로 넘어가면 대망의 조건문이 나온다.

```assembly
.eh_frame:000056004D0E4A21 loc_56004D0E4A21:                       ; CODE XREF: .eh_frame:000056004D0E4A13↑j
.eh_frame:000056004D0E4A21 ucomisd xmm1, xmm0
.eh_frame:000056004D0E4A25 jmp     short loc_56004D0E4A37
```

`ucomisd` 명령어에 관해선 <a href="https://docs.microsoft.com/ja-jp/previous-versions/yxddyw18(v=vs.110)">**<u>여기</u>**</a> 를 참조하길 바란다. 일본어 MSDN 사이트인데 번역하면 잘나온다. 마찬가지로 비교문이다. 그리고 정말 마지막 점프문!!!

```assembly
.eh_frame:000056004D0E4A37 loc_56004D0E4A37:                       ; CODE XREF: .eh_frame:000056004D0E4A25↑j
.eh_frame:000056004D0E4A37 jz      short loc_56004D0E4A6A
.eh_frame:000056004D0E4A39 mov     rcx, 100h
```

`jz` 로 보아 `zero flag`가 1이면 점프하는 것이다. 그러므로 위에 `ucomisd` 명령어는 `cmp`명령어와 흡사하구나... 하고 넘어갔지만 어쨋든 위의 두 링크는 꼭 한번 보길 권고한다. 해당 분기로 두개의 갈림길이 존재한다. 바로 "wrong!" 출력과 "conrrect" 출력이다. 그렇다면 위의 `ucomisd` 명령어에 있는 `xmm0` 에 있는 값이 바로 플래그 인 것을 확인할 수 있다.

```assembly
XMM0 47 4E 55 00 13 72 73 12 C8 ED FD 25 DE 8D F9 B9
XMM1 61 61 0A 00 00 00 00 00 00 00 00 00 00 00 00 00
```

위와 같이 xmm 16byte로 확인하면 값이 나온다. `XMM1`의 경우 내가 입력한 `aa`에 enter 키(`0a`) 가 포함되어 있다.
그대로오....

### flag

<details>
    <summary>Flag</summary>
    <p>TDCTF{474e550013727312c8edfd25de8df9b9}</p>
</details>



## [+] Ping! Ping! Ping!

Author: @deadbeef

ping! ping! ping!

> Flag format: /^TDCTF{[0-9a-zA-Z_?]*}$/



### Analysis

패킷 파일을 분석해야된다. 패킷 내용을 보면 icmp 패킷이 470..여개?정도가 있고 해당 페이로드 부분을 보면 특정 데이터가 존재하는 것을 볼 수 있다.
그러나 reqeust , reply 두 곳에 모두 있으므로 이 부분만 scapy를 이용해 걸러주고 이 데이터를 조합하여 확장자를 바꾸고 해당 파일을 열면 플래그가 존재한다.!;

### flag

<details>
    <summary>Flag</summary>
    <p>TDCTF{ Do_you_know_about_the_icmp_protocol?}</p>
</details>



