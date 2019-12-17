---
layout: article
title: "[Rev]Windbg Script Command(.for)"
key: 20191217
tags:
  - Windows
  - Reversing
  - Kerenl
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Windbg Script Command(.for)

<!--more-->

드라이버 분석을 하다가 vmp 패킹이 되어있는 드라이버를 만났다.
그것도 아주 강력하게 VMP Macro로 감싸져있었다.

내가 명명한 `VMP Mutation Table`은 여러가지 형태를 보인다. 아래 내용은 IDA를 이용하여 바이트 조각들을 복구한 모습이다. `68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? 68` 형식으로 어느정도 패턴은 있지만, 간혹 다른 패턴이 존재하기도 한다.

이러한 패턴을 이용하여 테이블을 만들고, `call` 하는 주소를 실제 구동되는 `VMP Macro`라고 명명하였다.

```
.vmp0:00000001402E3345                         VMP_Mutation_Table_2:
.vmp0:00000001402E3345 68 0F 08 FE CA                          push    0FFFFFFFFCAFE080Fh
.vmp0:00000001402E334A E8 B0 B2 FE FF                          call    vmpMacro_12
.vmp0:00000001402E334A                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E334F 60                                      db 60h
.vmp0:00000001402E3350                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E3350 68 4B 33 C0 62                          push    62C0334Bh
.vmp0:00000001402E3355 E8 98 2F EB FF                          call    vmpMacro_17
.vmp0:00000001402E3355                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E335A 67                                      db  67h ; g
.vmp0:00000001402E335B                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E335B 68 F0 BC 02 17                          push    1702BCF0h
.vmp0:00000001402E3360 E8 52 C9 EA FF                          call    vmpMacro_15
.vmp0:00000001402E3360                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E3365 2E                                      db  2Eh ; .
.vmp0:00000001402E3366                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E3366 68 41 18 8B 72                          push    728B1841h
.vmp0:00000001402E336B E8 5B 3F F6 FF                          call    vmpMacro_13
.vmp0:00000001402E336B                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E3370 B2                                      db 0B2h
.vmp0:00000001402E3371                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E3371 68 C5 0A 95 BD                          push    0FFFFFFFFBD950AC5h
.vmp0:00000001402E3376 E8 CE 10 FB FF                          call    vmpMacro_14
.vmp0:00000001402E3376                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E337B 4A                                      db  4Ah ; J
.vmp0:00000001402E337C                         ; ---------------------------------------------------------------------------
.vmp0:00000001402E337C 68 41 0E 27 A9                          push    0FFFFFFFFA9270E41h
.vmp0:00000001402E3381 E8 45 3F F6 FF                          call    vmpMacro_13
.vmp0:00000001402E3381                         ; ---------------------------------------------------------------------------
```

위의 예제는 Ultra 옵션을 통한 Mutation+Virtualizer 옵션이다. 그 외 기본 옵션에서 확인했을 때는 정확히 매크로가 10개가 존재했었으며, push 되는 값과 무슨 연관이 있는지는 알지 못했다.

어쨋든 이런 상황에서 다음과 같은 동적 분석으로 상세하게 분석을 할 수 있다.

## [+] VMP Call System

VMP 자체적으로 사용하는 함수의 경우, `CALL` 명령, `JMP` 명령, `RET` 명령을 골고루 사용했다.
그러나 사용자가 작성한 코드(known api 포함)에서는 `RET`를 통해 함수를 호출하는 것을 확인할 수 있었다.

유저모드에서는 `x64dbg` 내 `execute till return` 기능을 이용하여 분석이 가능하다. VMP에서의 안티디버깅 기법은 의외로 매우 간단하다. 직접 트레이싱해보면서 보는게 많이 도움된다.

어쨋든 커널 레벨로 내려오게 되면 `windbg`를 이용하여야 한다. 이 때 사용할 수 있는 명령어가 `pct` 명령이다.
`CALL` 또는 `RET` 명령을 만나면 멈추게 되는 명령이다.

그러나 위에서 말한 것과 같이 매우 견고하게 쌓여져 있는 경우, 보통 하나의 함수를 호출할 때 해당 `pct` 명령을 몇 천번 단위로 확인해야 된다.

이 때 `.for` 문을 이용하여 트레이싱을 하며 확인할 수 있다.



## [+] Command

```
.printf "[Start]\n"; .for (r $t0=0; @$t0<0x3e8; r $t0 = @$t0+1){pct; .printf "[+] Current Instruction Address : %p\n",@rip; .printf "[+] Disassembley Count : %d\n",@$t0; u poi(@rsp) l5;}
```

```
[+] Current Instruction Address : fffff807143dc0f4
[+] Disassembley Count : 553
fffff807`142fbd47 488b4c2500      mov     rcx,qword ptr [rbp]
fffff807`142fbd4c 66440f47fc      cmova   r15w,sp
fffff807`142fbd51 48c1e820        shr     rax,20h
fffff807`142fbd55 4881c508000000  add     rbp,8
fffff807`142fbd5c 410fb601        movzx   eax,byte ptr [r9]
[+] Current Instruction Address : fffff807143cd7ab
[+] Disassembley Count : 554
fffff807`1432b6f2 410fb611        movzx   edx,byte ptr [r9]
fffff807`1432b6f6 4d0fb7c4        movzx   r8,r12w
fffff807`1432b6fa 4981c101000000  add     r9,1
fffff807`1432b701 4032d7          xor     dl,dil
fffff807`1432b704 66410fbaf0dd    btr     r8w,0DDh
[+] Current Instruction Address : fffff8071437b6e5
[+] Disassembley Count : 555
fffff807`14358490 410fb611        movzx   edx,byte ptr [r9]
fffff807`14358494 4d63c6          movsxd  r8,r14d
fffff807`14358497 664181c0205f    add     r8w,5F20h
fffff807`1435849d 664113db        adc     bx,r11w
fffff807`143584a1 4981c101000000  add     r9,1
...
```

