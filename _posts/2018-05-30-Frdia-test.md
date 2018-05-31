---
layout: article
title: "[Mobile]Frida Hooking Test"
key: 20180530
tags:
  - Frida
  - Hooking
  - Security
  - Mobile
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+]Frida Hooking Test

<!--more-->

## [+]Hooking Test

### 1.Ready

Frida 툴에 제대로 입문하고자 <a href="https://www.frida.re/docs/home/">공식페이지</a> 에 있는 튜토리얼부터 진행해보기로 한다.

진행은 C를 이용한 간단한 프로그램 제작과 python 을 이용해 해당 프로그램을 후킹하여 값을 읽거나 변조한다.



```c
#include <stdio.h>

void f (int n)
{
  printf ("Number: %d\n", n);
}

int main (int argc,char * argv[])
{
  int i = 0;

  printf ("f() is at %p\n", f);

  while (1)
  {
    f (i++);
    sleep (1);
  }
}
```

```
# 실행결과

> a.exe           
f() is at 00401560
Number: 0         
Number: 1         
Number: 2         
Number: 3         
Number: 4         
Number: 5         
Number: 6         
```

------



### 2.Hooking

<a href="#1ready">준비과정</a> 에서 제작한 프로그램은 간단하게 해당 f 함수에 대한 주소 값과 1씩 증가하는 Number를 출력하여 준다.

python 을 이용하여 해당 프로그램에 후킹을 시도한다.

```python
import frida
import sys

session = frida.attach("a.exe") # attach 할 프로그램
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter: function(args) {
        args[0] = ptr("444"); # 변조할 값
    }
});
""" % int(sys.argv[1], 16))
script.load()
sys.stdin.read()

```

```
# 실행결과

> a.exe				           					
f() is at 00401560
Number: 0         
Number: 1         
Number: 2         
Number: 3         
Number: 4         
Number: 5         
Number: 6

> frida_test.py 0x00401560

Number: 444
Number: 444
Number: 444
```

~~사진 찍기가 귀찮..........다.~~ 어쨋든 실행하면 값이 잘 바뀐다. 간단하게 Frida를 이용한 후킹이 되겠다.

~~포스트를 조금이라도 더 채우고 싶은 맘이다 크~~



