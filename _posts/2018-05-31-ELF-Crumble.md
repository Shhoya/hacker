---
layout: article
title: "[WriteUp]ELF Crubmle(DEFCON_2018)"
key: 20180531
tags:
  - CTF
  - WriteUp
  - Reversing
  - Binary
toc: true
---

# [+]ELF Crumble(Defcon CTF 2018)

<!--more-->

## [+]Fragment File

### FILE Analyze

총 9개의 파일이 주어지며, 파일이름은 각 'broken', 'fragment1 ~ 8' 까지 존재한다.
파일 이름만으로도 일단 파일이 깨졌으니 갖다 붙혀라 이런 의미의 문제인 것 같다.

![ELF-File](https://raw.githubusercontent.com/shhoya/shhoya.github.io/master/assets/images/task/elf_1.png "ELF_1"){:.border}

그림을 보면 ELF 파일로 되어 있으며 Offset 0x5AD + 0x327 만큼 0x58 로 채워진 것을 확인할 수 있다. 그리고 조각난 8개의 파일을 모두 합치면 0x327만큼의 크기가 나오는 것을 알 수 있다.

CTF의 가장 큰 문제는 사람의 머리를 꼬아놓는다는 것이다..

---------------------------------------

### Join Fragment

매우 유용한 IDA를 이용해 조각난 파일들의 합체를 시도한다. 이것 저것 일단 섞어보다 보면 몇가지 사실을 알 수 있다.
f1, f2, f3, recover_flag, main가 존재한다는 어마어마한 사실을..!

자 여기서 내 나름대로의 지식을 긁어모아 추리를 해야 한다. 과연 첫번째 순서에 오는 파일은 무엇일까?
나는 함수의 프롤로그와 에필로그를 이용해 조합을 해보았다.

### Function Call

먼저 Callee와 Caller의 관계에 대해서 알아야 한다. Callee는 호출을 당하는(?) 녀석, Caller는 호출을 하는 녀석이다.
Main 함수에서 'func1'이라는 함수를 호출하게 되면 Callee는 main함수, caller는 'func1'이 된다.

써보니 딱히 쓸모 없을지도..?; 근데 어쨋든 함수의 시작과 종료 과정을 알면 매우 유용하다.
보통 함수는 시작할 때 아래와 같은 코드를 가진다.

```assembly
0xblahblah 	CALL main.00401000
0xclahclah  blahblah

# main function
0x00401000 	PUSH EBP
0x00401001 	MOV EBP, ESP
```

'CALL main' 명령의 경우 , 스택 최상단에 현재의 EIP('0xclahclah')를 PUSH 하고 main(0x00401000)으로 JMP 하게 된다.
그 다음, PUSH EBP를 통해 현재 Stack frame을 백업한다. 그리고 MOV EBP, ESP 명령어를 통해 현재 최상단의 스택을 EBP로 설정하여 새로운 stack frame을 구성하게 된다.

정리하면, CALL 명령(EIP 백업, return address), PUSH  EBP(현재 stack frame 백업), MOV EBP, ESP(새로운 stack frame 할당) 이 되겠다.

---------------------------------------

### Flag

결론적으로 가장 처음 오는 조각 파일의 첫 값은 'PUSH EBP'의 OPCODE인 0x55, 0x89, 0xE5 일 것이다.
이런 식으로 함수 프롤로그와 에필로그를 이용하고 IDA를 이용해 쭉쭉 짜 맞힌 결과, 8 - 7 - 1 - 5 - 6 - 2 - 3 - 4 순서의 조합임을 알 수 있다.



![ELF-File2](https://raw.githubusercontent.com/shhoya/shhoya.github.io/master/assets/images/task/elf_2.png "ELF_2"){:.border}



```
root@Shhoya:~/ELF# ./broken
welcOOOme
```

