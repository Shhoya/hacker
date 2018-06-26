---
layout: article
title: "[Mobile]Frida Android Hooking -2-"
key: 20180604
tags:
  - Frida
  - Hooking
  - Security
  - Mobile
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Android Hooking Example

<!--more-->

## [+] Example

### Rock Paper Scissors

<a href="https://www.frida.re/docs/examples/android/">Frida</a> 공식 페이지에 나와있는 예제로 Hooking 연습을 해보자.

SECCON Quals CTF 2015 에 출제 되었던 APK 문제이며, 가위바위보를 하여 1000번을 연속으로 이겨야 플래그를 얻을 수 있는 문제이다.

<a href="https://github.com/ctfs/write-ups-2015/tree/master/seccon-quals-ctf-2015/binary/reverse-engineering-android-apk-1">rps.apk</a> <- 해당 apk 파일 다운로드



### Analyze

해당 apk 파일을 분석하면 아래와 같은 코드를 확인할 수 있다. (jeb 사용)

```java
       public void run() {
            View v0 = MainActivity.this.findViewById(2131492946);
            if(MainActivity.this.n - MainActivity.this.m == 1) {
                ++MainActivity.this.cnt;
                ((TextView)v0).setText("WIN! +" + String.valueOf(MainActivity.this.cnt));
            }
            else if(MainActivity.this.m - MainActivity.this.n == 1) {
                MainActivity.this.cnt = 0;
                ((TextView)v0).setText("LOSE +0");
            }
            else if(MainActivity.this.m == MainActivity.this.n) {
                ((TextView)v0).setText("DRAW +" + String.valueOf(MainActivity.this.cnt));
            }
            else if(MainActivity.this.m < MainActivity.this.n) {
                MainActivity.this.cnt = 0;
                ((TextView)v0).setText("LOSE +0");
            }
            else {
                ++MainActivity.this.cnt;
                ((TextView)v0).setText("WIN! +" + String.valueOf(MainActivity.this.cnt));
            }

            if(1000 == MainActivity.this.cnt) {
                ((TextView)v0).setText("SECCON{" + String.valueOf((MainActivity.this.cnt + MainActivity.this.calc()) * 107) + "}");
            }

            MainActivity.this.flag = 0;
        }
    }
```

맨 마지막 if문을 확인하면 "MainActivity.this.cnt"의 값이 1000일 때 "SECCON{ flag }" 를 출력하는 것을 확인할 수 있다.

플래그는 cnt 값 + calc() 리턴 값 x 107 인 것으로 보인다.

```java
    public void onClick(View arg11) {
        int v9 = 3;
        int v8 = 2;
        if(this.flag != 1) {
            this.flag = 1;
            this.findViewById(2131492946).setText("");
            View v2 = this.findViewById(2131492944);
            View v3 = this.findViewById(2131492945);
            this.m = 0;
            this.n = new Random().nextInt(v9);
            String[] v1 = new String[v9];
            v1[0] = "CPU: Paper";
            v1[1] = "CPU: Rock";
            v1[v8] = "CPU: Scissors";
            ((TextView)v3).setText(v1[this.n]);
            if(arg11 == this.P) {
                ((TextView)v2).setText("YOU: Paper");
                this.m = 0;
            }

            if(arg11 == this.r) {
                ((TextView)v2).setText("YOU: Rock");
                this.m = 1;
            }

            if(arg11 == this.S) {
                ((TextView)v2).setText("YOU: Scissors");
                this.m = v8;
            }

            this.handler.postDelayed(this.showMessageTask, 1000);
        }
    }
```

자 실질적으로 후킹을 진행할 함수는 위와 같다.



### Hooking

이전 <a href="https://shhoya.github.io/2018/06/04/frida-android.html">포스트</a>에 Frida에 대한 간단한 사용법이 있다.

```javascript
function Hooking() {
	console.log("[*] Hook Start");
	
	Java.perform(function(){
		var Hook_RPS = Java.use("com.example.seccon2015.rock_paper_scissors.MainActivity");
		Hook_RPS.onClick.implementation = function(v){	
			console.log("[*] Success!");
        //send('onClick');
        this.onClick(v);
        this.cnt.value = 1000;
			
		}
		})
};


setImmediate(function() {
	Hooking();
	console.log("[*] Finish!");
});
```

위와 같이 js를 이용하면 간단하게 플래그를 얻을 수 있다.

## [+] Reference

1. <a href="https://www.frida.re/docs/examples/android/">*"Frida Android Example"*</a>