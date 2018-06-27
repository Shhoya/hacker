---
layout: article
title: "[ML]Tensor Flow"
key: 20180627
tags:
  - Dev
  - ML
  - Neural
  - Python
  - TensorFlow
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Tensor Flow

<!--more-->

## [+] Setup

### Installation

파이썬에 올라가는 모듈이다. 내 환경은 파이썬 3.6.5 (64bit)를 사용하였다.

```
pip install --upgrade tensorflow
```

위의 명령어면 설치 끝이다. 너무 간단하다. 설치확인하기 위해서 아래와 같이 입력하면 된다

```
Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import tensorflow as tf
>>> tf.__version__
'1.8.0'
>>>
```

### Hello World!

역시 뭐든간에 헬로월드지.

```python
import tensorflow as tf

hello = tf.constant("Hello World!") # "Hello world!" in node
sess = tf.Session() # Session Create
print("Version : "+tf.__version__)
print(sess.run(hello))
```

```
Console
Version : 1.8.0
[Warning ~~~] , 직접 빌드하지 않아서 느릴 수 있다라는 경고..
b 'Hello World!
```

텐서플로는 다른 프로그래밍과 다르게 세션을 생성하여 실행시켜줘야 한다. 자 아래는 노드간의 계산 예제이다.

```python
import tensorflow as tf

node1 = tf.constant(1.0)
node2 = tf.constant(2.0)
sess = tf.Session()
print(sess.run(node1+node2))
```

```
Console
3.0
```

자 이렇게다..

### PlaceHolder

위에서는 constant를 이용해 값을 정해주고 노드를 실행시켰다. 그렇다며 반대로 노드를 먼저 생성하고 값을 넣어 연산할 때 Placeholder라는 속성을 사용한다.

```python
import tensorflow as tf
#노드 생성
node1 = tf.placeholder(tf.float32)
node2 = tf.placeholder(tf.float32)
add = node1 + node2
#세션 생성 및 실행
sess=tf.Session()
print(sess.run(add, feed_dict={node1:3.0 ,node2:4.0}))
```

```
Console
7.0
```

Logistic Classification 구현을 위해 이 과정을 준비해봤다.
배우고 싶고 배워야 하는 것들이 너무많다. ㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎ

# [+] Reference 

1. <a href="https://www.youtube.com/playlist?list=PLlMkM4tgfjnLSOjrEJN31gZATbcj_MpUm">*모두를 위한 딥러닝*</a>

