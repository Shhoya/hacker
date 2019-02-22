---
layout: article
title: "[ML]Perceptron"
key: 20180530
tags:
  - ML
  - Dev
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+]Perceptron

<!--more-->

## [+]Concept

퍼셉트론이란, 신경망의 기원이 되는 알고리즘이다.

퍼셉트론은 다수의 신호를 입력받아 하나의 신호로 출력한다. 컴퓨터의 기본원리를 생각하면 쉽게 받아들일 수 있다. 1과 0의 신호로 이루어진 컴퓨터는 다양한 입력 값을 받아 결국 1과 0의 신호로 돌아가기 때문이다.



{% highlight Pseudo%}
x = Input signal
y = Output signal
w = Weight
θ = Critical Value


if(w1x1 + w2x2 <= θ )

{

​	y=0;

}

if(w1x1 + w2x2 > θ)

{

​	y=1;

}
{% endhighlight %}

입력 신호가 뉴런으로 보내질 때 각각의 가중치(w)가 곱해진다. (x1y1,x2y2…)
이때 보내진 신호의 총 합이 정해진 한계를 넘어서면 1을 출력한다.( 뉴런을 활성화한다고도 함)
그 한계를 임계값 이라고 하며  θ (Theta) 로 나타낸다.

$$x_1w_1 + x_2w_2 <= θ$$  일 때, $$y=0$$ 

$$x_1w_1 + x_2w_2 > θ$$ 일 때,  $$y = 1$$ 



## [+]Logic Gate

퍼셉트론을 이용하여 AND, NAND, OR 회로를 구현해본다.

단, 위에서 언급한 기존 수식을 약간 변경하여 구현한다.

$$θ$$ 를 $$b$$ (bias,편향)으로 치환한다.

첫 포스팅 급하니깐 일단 대충 수식을 넣어본다.

$$y=0$$      $$(b +w_1x_1 + w_2x_2 <= 0)$$

$$y=1$$      $$(b +w_1x_1 + w_2x_2 > 0)$$

 

```python
import numpy as np # numpy 모듈 이용

def AND(x1, x2):
    x = np.array([x1,x2])
    w = np.array([0.5,0.5])
    b = -0.7 # 편향, 
    tmp = np.sum(w*x)+b
    
    if tmp <= 0:
        return 0
    else:
        return 1

def NAND(x1,x2):
    x=np.array([x1,x2])
    w=np.array([-0.5,-0.5])
    b=0.7
    tmp=np.sum(w*x)+b
    
    if tmp<=0:
        return 0
    elses:
        return 1

def OR(x1,x2):
    x=np.array([x1,x2])
    w=np.array([0.5,0.5])
    b=-0.2
    tmp=np.sum(w*x)+b
    
    if tmp<=0:
        return 0
    else:
        return 1
```

자 여기서 문제는, 이러한 퍼셉트론을 이용하여 XOR 게이트를 어찌 구현할것인가이다.

테스트 포스팅이므로 여기까지.

## [+] Reference

1. <a href="http://www.hanbit.co.kr/store/books/look.php?p_code=B8475831198">밑바닥부터 시작하는 딥러닝</a>

