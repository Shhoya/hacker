---
layout: article
title: "[Rev]Windbg pykd script for Tracing"
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

# [+] Windbg Pykd

<!--more-->

이전에 Windbg 플러그인 관련 포스팅에서 pykd 설치법은 설명해두었다. <a href="https://shhoya.github.io/2019/05/20/windbgplg.html#-twindbglike-peda">클릭</a> 

windbg에서 `.load pykd.pyd` 로 로드하고 사용할 수 있다.
파이썬 스크립트를 사용 시에는 플러그인 로드 후에 `!py <경로>.py` 를 통해 실행할 수 있다.

먼저 처음 사용하게 된 계기는 vmp 매크로를 탈출하기 위해서였다.

내가 마음대로 정한 `VMP Mutation Table`은 여러가지 형태를 보인다. 아래 내용은 IDA를 이용하여 바이트 조각들을 복구한 모습이다. `68 ?? ?? ?? ?? E8 ?? ?? ?? ?? ?? 68` 형식으로 어느정도 패턴은 있지만, 간혹 다른 패턴이 존재하기도 한다.

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


## [+]  Pykd

더 깔끔한 방법으로 `pykd` 플러그인을 이용하여 파이썬 스크립트로 자동화 하는 방법이 있다.

나름대로 하나의 패킹 된 드라이버에서 패턴을 생각하여 스크립트를 짜봤다.

```python
import pykd
from pykd import disasm
import os,collections,time
DriverEntry = 0
ImageBase = 0

#=======================================
#== Initialize Tracer                 ==
#== Get Driver ImageBase              ==
#=======================================

def InitTracer():
    global DriverEntry
    global ImageBase
    pykd.dbgCommand("bp IopLoadDriver+4b8") # Manually DriverEntry
    pykd.go()
    while(1):
        regPath = pykd.dbgCommand("du /c40 @rdx+10")
        if "??????" in regPath:
            print "[+] Find ?????? Driver"
            DriverEntry = pykd.reg("rcx")
            ImageBase = pykd.ptrPtr(DriverEntry+0x18)
            pykd.dbgCommand("r $t0 = poi(@rcx+18)")
            return
        pykd.go()

#=======================================
#== Tracer                            ==
#== Log Writer                        ==
#=======================================
def Tracer():

    global DriverEntry
    global ImageBase
    OffsetArray = []    # RET Offset List


    pykd.dbgCommand("bp $t0+370348")    # End loop routine
    pykd.dbgCommand("bp $t0+32b097")    # First mutation table
    pykd.dbgCommand("bp $t0+32AEF1")    # Fail Routine
    pykd.go()
    tmpDisasm = disasm()
    print tmpDisasm.instruction()
    time.sleep(5)
    pykd.dbgCommand("t")
    pykd.dbgCommand("t")
    print "[+] Start Tracing "
    time.sleep(5)
    i=0
    ### Need Custom range ###
    # for i in range(0,100):
    while(1):
    ### Need Custom range ###

        ### Need Custom path ###
        f = open("D:\\Tracing.Log",'a+')
        ### Need Custom path ###

        Disassem = disasm()
        Instruction = Disassem.instruction()
        rip_off = pykd.reg("rip") - ImageBase
        rsp = pykd.reg("rsp")

        if rip_off < 0:
            pykd.go()
            continue

        # Init fail routine offset
        if rip_off== 0x32AEF1:
            print "This Exit!"
            f.close()
            print "========================================"
            print "E N D"
            print "========================================"
            break

        # Loop routine start offset
        if rip_off == 0x465F9E:
            print "This Repeat!"
            pykd.go()
            f.close()
            continue

        if "call" in Instruction:
            # print "[!] Call Instruction"
            # print "\n[+] Current Instruction Offset : %X \n\t[-] Count :%d"%(rip_off,i+1)
            # print pykd.dbgCommand("u @rip L5")

            data = "\n[!] Call Instrcution\n[+] Current Instruction Offset : %X \n\t[-] Count :%d\n\n"%(rip_off,i+1)
            f.write(data)
            f.write(pykd.dbgCommand("u @rip L5"))
            f.close()

            pykd.dbgCommand("th")
            i+=1
            continue

        if "ret" in Instruction:
            # print "======================="
            # print "[!] Return Instruction"
            # print "======================="
            rsp_off = pykd.ptrPtr(rsp) - ImageBase
            # print "\n[+] Current Instruction Offset : %X \n\t[-] Count :%d"%(rip_off,i+1)
            # print "[+] Disassembly Count : %d, Offset : %X\n"%(i,rsp_off)
            # print pykd.dbgCommand("u poi(@rsp) L6")

            data = "\n[!] Return Instrcution\n[+] Current Instruction Offset : %X \n\t[-] Count :%d\n[+] Disassembly Count : %d, Offset : %X\n\n"%(rip_off,i+1,i+1,rsp_off)
            f.write(data)
            f.write(pykd.dbgCommand("u poi(@rsp) L10"))
            f.close()

            OffsetArray.append(rsp_off)

            pykd.dbgCommand("th")
            i+=1
            continue

        # print "\n[+] Current Instruction Offset : %X \n\t[-] Count :%d"%(rip_off,i+1)
        # print pykd.dbgCommand("u @rip L5")
        pykd.dbgCommand("th")
        i+=1

    # Write RET Offset and count
    count = collections.Counter(OffsetArray)
    for i in count:

        ### Need Custom path ###
        f = open("D:\\DuplicateList.txt","a+")
        ### Need Custom path ###

        data = "[+] Duplicate Offset : %X\n\t[-] Count : %d\n"%(i,count[i])
        f.write(data)
        f.close()

if __name__ == '__main__':
    print "[+] Shh0ya Trace Logger"
    InitTracer()
    Tracer()

```

굉장히 지저분하지만 몇개 구문에 대해 설명으로 쉽게 이해할 수 있다.

### [-] InitTracer

```python
def InitTracer():
    global DriverEntry
    global ImageBase
    pykd.dbgCommand("bp IopLoadDriver+4b8") # Manually DriverEntry
    pykd.go()
    while(1):
        regPath = pykd.dbgCommand("du /c40 @rdx+10")
        if "??????" in regPath:
            print "[+] Find ?????? Driver"
            DriverEntry = pykd.reg("rcx")
            ImageBase = pykd.ptrPtr(DriverEntry+0x18)
            pykd.dbgCommand("r $t0 = poi(@rcx+18)")
            return
        pykd.go()
```

먼저 `IopLoadDriver+4b8` 에 브레이크 포인트를 설치하는 이유는 패킹 된 드라이버에서 드라이버 엔트리를 찾기 위함이다. 이전 포스팅에서 해당 내용은 확인할 수 있다.(<a href="https://shhoya.github.io/2019/10/26/DriverEntry.html">클릭</a>)

해당 위치에서 레지스터는 이미 `DriverObject`와 `RegistryPath`가 파라미터로 만들어진다. 각 구조체는 `DRIVER_OBJECT`와 `UNICODE_STRING`이며 x64 기준으로 `RDX` 레지스터에서 0x10 떨어진 위치에 `wchar` 형태로 경로가 저장된다.

이를 이용하여 `regPath` 라는 변수에 경로르 담고 해당 변수에 내가 원하는 드라이버의 경로가 존재하는지 확인한다.
그리고 내가 원하는 드라이버라면 전역변수인 `DriverEntry`와 `ImageBase`를 저장하게 된다.

`DRIVER_OBJECT`에서 0x18 위치에 `DriverStart` 라는 멤버가 존재하며 이는 `ImageBase`를 의미한다.

### [-] Tracer

```python
def Tracer():

    global DriverEntry
    global ImageBase
    OffsetArray = []    # RET Offset List


    pykd.dbgCommand("bp $t0+370348")    # End loop routine
    pykd.dbgCommand("bp $t0+32b097")    # First mutation table
    pykd.dbgCommand("bp $t0+32AEF1")    # Fail Routine
    pykd.go()
    tmpDisasm = disasm()
    print tmpDisasm.instruction()
    time.sleep(5)
    pykd.dbgCommand("t")
    pykd.dbgCommand("t")
    print "[+] Start Tracing "
    time.sleep(5)
    i=0
    ### Need Custom range ###
    # for i in range(0,100):
    while(1):
    ### Need Custom range ###

        ### Need Custom path ###
        f = open("D:\\Tracing.Log",'a+')
        ### Need Custom path ###

        Disassem = disasm()
        Instruction = Disassem.instruction()
        rip_off = pykd.reg("rip") - ImageBase
        rsp = pykd.reg("rsp")

        if rip_off < 0:
            pykd.go()
            continue

        # Init fail routine offset
        if rip_off== 0x32AEF1:
            print "This Exit!"
            f.close()
            print "========================================"
            print "E N D"
            print "========================================"
            break

        # Loop routine start offset
        if rip_off == 0x465F9E:
            print "This Repeat!"
            pykd.go()
            f.close()
            continue

        if "call" in Instruction:
            # print "[!] Call Instruction"
            # print "\n[+] Current Instruction Offset : %X \n\t[-] Count :%d"%(rip_off,i+1)
            # print pykd.dbgCommand("u @rip L5")

            data = "\n[!] Call Instrcution\n[+] Current Instruction Offset : %X \n\t[-] Count :%d\n\n"%(rip_off,i+1)
            f.write(data)
            f.write(pykd.dbgCommand("u @rip L5"))
            f.close()

            pykd.dbgCommand("th")
            i+=1
            continue

        if "ret" in Instruction:
            # print "======================="
            # print "[!] Return Instruction"
            # print "======================="
            rsp_off = pykd.ptrPtr(rsp) - ImageBase
            # print "\n[+] Current Instruction Offset : %X \n\t[-] Count :%d"%(rip_off,i+1)
            # print "[+] Disassembly Count : %d, Offset : %X\n"%(i,rsp_off)
            # print pykd.dbgCommand("u poi(@rsp) L6")

            data = "\n[!] Return Instrcution\n[+] Current Instruction Offset : %X \n\t[-] Count :%d\n[+] Disassembly Count : %d, Offset : %X\n\n"%(rip_off,i+1,i+1,rsp_off)
            f.write(data)
            f.write(pykd.dbgCommand("u poi(@rsp) L10"))
            f.close()

            OffsetArray.append(rsp_off)

            pykd.dbgCommand("th")
            i+=1
            continue

        # print "\n[+] Current Instruction Offset : %X \n\t[-] Count :%d"%(rip_off,i+1)
        # print pykd.dbgCommand("u @rip L5")
        pykd.dbgCommand("th")
        i+=1

    # Write RET Offset and count
    count = collections.Counter(OffsetArray)
    for i in count:

        ### Need Custom path ###
        f = open("D:\\DuplicateList.txt","a+")
        ### Need Custom path ###

        data = "[+] Duplicate Offset : %X\n\t[-] Count : %d\n"%(i,count[i])
        f.write(data)
        f.close()
```

코드가 많이 더럽다. 추후에 템플릿으로 범용적으로 사용할 수 있게 만들 생각이다.
처음에는 windbg에 출력할 생각이었지만, 분석을 위함이므로 파일형태로 저장하도록 했다.

```python
 pykd.dbgCommand("bp $t0+370348")    # End loop routine
 pykd.dbgCommand("bp $t0+32b097")    # First mutation table
 pykd.dbgCommand("bp $t0+32AEF1")    # Fail Routine
 pykd.go()
 tmpDisasm = disasm()
 print tmpDisasm.instruction()
 time.sleep(5)
 pykd.dbgCommand("t")
 pykd.dbgCommand("t")
 print "[+] Start Tracing "
 time.sleep(5)
 i=0
```

총 3개의 브레이크 포인트를 설치하는 것을 볼 수 있다. 각 브레이크 포인트의 설명은 아래와 같다.

1. 첫 번째 브레이크 포인트 :

   VMP Macro에서는 아주 두꺼운 반복 매크로가 존재한다.
   시간을 단축하기 위해 해당 반복문이 종료되는 루틴을 찾고 해당 위치에 브레이크 포인트를 설치한 것이다. 그리고 추후에 Instruction Pointer가 반복문의 시작을 가르키게 되는 경우 `go` 명령을 통해 빠르게 진행하기 위함이다.

2. 두 번째 브레이크 포인트 :

   분석 할 매크로의 시작점이다. 위에서 말한 `VMP Mutation Table` 이 되겠다. 

   

3. 세 번째 브레이크 포인트 :

   종료되는 시점을 의미한다. 즉 어느 지점까지 분석할지에 대한 오프셋이 되겠다.

```python
 pykd.go()
 tmpDisasm = disasm()
 print tmpDisasm.instruction()
 time.sleep(5)
 pykd.dbgCommand("t")
 pykd.dbgCommand("t")
 print "[+] Start Tracing "
 time.sleep(5)
```

위 코드는 트레이싱을 진행하기 위한 직전의 루틴이다.

위의 코드까지 왔을 때 Instruction Pointer는 IopLoadDriver+4b8 위치에 멈춰있으며 원하는 오프셋에 브레이크 포인트가 설치되어 있는 상태다.

위 상황에서 `go` 함수를 이용하여 진행하면 `VMP Mutation Table` 위치에 멈추게 된다. 정확한 확인을 위해 해당 위치에서의 인스트럭션을 출력하도록 해놨다. 위에서 `VMP Mutation Table` 모양을 보면 알겠지만 `PUSH` 명령 이후, 매크로 내부로 진입하게 된다. 때문에 windbg의 `t` 명령을 두번 실행하여 내부로 진입하고 트레이싱을 시작하게 된다.

나머지는 기본적이므로 설명을 생략한다. 대부분 현재 인스트럭션을 기준으로 `JMP` 명령인지 `RET`명령인지 `CALL`인지 구분하거나 특정 오프셋을 기준으로 분기하게 된다.

루프를 다 돌게되면 `DuplicateList` 라는 파일을 만들도록 해놨다.

현재까지 약 20만번의 카운트가 될 때까지 잘 도는 것을 확인했다. 이제 작성된 로그를 파싱하여 정리하면 하나의 자동화 툴이 완성되게 된다.

끗!