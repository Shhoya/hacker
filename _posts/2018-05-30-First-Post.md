---
layout: article
title: [ML]Perceptron
key: 20180530
tags:
  - ML
  - Perceptron
  - Dev
toc: true
---

# [+]Perceptron

## Concept

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

