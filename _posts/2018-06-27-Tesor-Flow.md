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
sidebar:
  nav: sidem
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



## [+] Linear Regression

### TF Operation

$$H(x) = Wx + b$$

$$cost(W,b)= \frac{1}{m}\sum^m_{i=0}(H(x^{(i)}) - y^{(i)})^2$$ 

```python
import tensorflow as tf

x_train = [1,2,3]
y_train = [1,2,3]

W = tf.Variable(tf.random_normal([1]), name='weight')
b = tf.Variable(tf.random_normal([1]), name='bias')

hypothesis = x_train * W + b

#cost function
cost = tf.reduce_mean(tf.square(hypothesis - y_train))

#minimize

optimizer = tf.train.GradientDescentOptimizer(learning_rate=0.01)
train = optimizer.minimize(cost)

sess = tf.Session()
sess.run(tf.global_variables_initializer()) # Variable Init

# Fit the line
for step in range(2001):
    sess.run(train)
    if step % 20 == 0:
        print(step, sess.run(cost), sess.run(W), sess.run(b))
```

```
Console
0 28.053223 [-1.5895715] [0.32294732]
20 0.44792736 [0.29116443] [1.0815728]
40 0.17987074 [0.4919712] [1.1044239]
...
1840 3.0649222e-05 [0.9935701] [0.01461675]
1860 2.7835902e-05 [0.9938723] [0.01392981]
1880 2.5280637e-05 [0.99416023] [0.01327514]
1900 2.296092e-05 [0.9944347] [0.01265126]
1920 2.0853331e-05 [0.9946962] [0.01205671]
1940 1.8939842e-05 [0.9949454] [0.01149014]
1960 1.7201231e-05 [0.99518305] [0.01095016]
1980 1.5622312e-05 [0.9954094] [0.01043553]
2000 1.4187969e-05 [0.99562514] [0.00994509]
```

필기하기 빡시다;
오.. 정말 W는 점점 1에 가까워지고 b는 0에 가까워진다 신기하다;;
여기에 Placeholder를 이용할 수 있다.

```python
import tensorflow as tf
W=tf.Variable(tf.random_normal([1]), name='weight')
b=tf.Variable(tf.random_normal([1]), name='bias')
X=tf.placeholder(tf.float32)
Y=tf.placeholder(tf.float32)

hypothesis = X * W + b
cost=tf.reduce_mean(tf.square(hypothesis - Y))
optimizer=tf.train.GradientDescentOptimizer(learning_rate=0.01)
train=optimizer.minimize(cost)

sess=tf.Session()
sess.run(tf.global_variables_initializer())

for step in range(2001):
    cost_val, W_val, b_val, _ = sess.run([cost, W, b, train], feed_dict={X:[1,2,3,4,5], Y:[1,2,3,4,5]})
    if step % 20 ==0:
        print(step, cost_val, W_val, b_val)

print(sess.run(hypothesis, feed_dict={X:[5]}))
print(sess.run(hypothesis, feed_dict={X:[2.5]}))
print(sess.run(hypothesis, feed_dict={X:[1.5, 3.5]}))
```



# [+] Reference 

1. <a href="https://www.youtube.com/playlist?list=PLlMkM4tgfjnLSOjrEJN31gZATbcj_MpUm">*모두를 위한 딥러닝*</a>

