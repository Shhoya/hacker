---
title:  "[#] DR7 Register"
tags: [Post, Windows, Dev]
published: true
permalink: debugregister.html
comments: true
summary: "하드웨어 브레이크 포인트 구현"
---

## [0x00] Overview

최근에 업무중에 최적화 관련하여 이슈가 있다는 이야기를 들었습니다. 가상 메모리 내부에 특정 영역에 접근하는 함수를 확인하여 해결해야 했습니다.
그래서 VS를 제외한 디버거를 사용 못하는 상황에서 몇 가지 제안을 하였고 다행히 해당 이슈를 해결하였습니다. 디버그 레지스터를 이용하여 `Single Step Exception`을 발생시켜 콜 스택을 확인하였습니다.



## [0x01] Debug Register

아래는 인텔 문서에 나와있는 디버그 레지스터에 관한 내용입니다. 해당 포스팅은 아래 빨간 박스 친 `DR7` 레지스터에 관한 포스팅 입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/post/dr_0.png?raw=true">



### [-] L0 ~ L3(bits 0, 2, 4, 6), G0 ~ G3(bits 1, 3, 5, 7)

먼저 8비트는 `Local Breakpoint Enable Flag(L0-3)`, `Global Breakpoint Enable Flag(E0-3)` 으로 이루어집니다. 둘의 차이는 프로세서가 자동으로 플래그를 전환하는가 안하는가에 차이라고 하는데 사실 이 부분은 저도 이해가 가질 않습니다. 다만 테스트 결과, `Ln` 의 경우에는 디버거에서 `Single Step Exception`이 발생하지만 `Gn`에서는 발생하지 않았습니다.



### [-] LE, GE(bits 8, 9)

`Local, Global Exact Flag` 비트는 `P6 Processor`, `IA-32` 에서는 지원하지 않습니다. `Intel 64 Processor`에서는 해당 플래그가 설정되면 브레이크 포인트 상태를 발생시킨 조건을 일으키는 정확한 브레이크포인트가 필요한 경우 설정하라고 설명되어 있다. (확인 불가)



### [-] GD(bit 13)

`General Detect Enable Flag`는 `Debug Register`에 접근하는 경우 예외가 발생합니다. 이는 Debug Register를 보호하기 위해 사용되는 것으로 보입니다.



### [-] R/W0~4, LEN0~4(bits 16~ 31)

바로 하드웨어 브레이크 포인트 조건에 해당됩니다. 각 4비트씩 하나의 하드웨어 브레이크 포인트에 대한 조건을 갖습니다. `R/W0 ~ 3` 은 각각 16,17, 20,21, 24,25, 28,29 비트에 조건에 따라 설정됩니다.

- 00 : 실행이 일어나는 경우 브레이크
- 01 : 메모리에 쓰기가 발생하는 경우 브레이크
- 10 : I/O 읽기/쓰기가 발생하는 경우 브레이크
- 11 : 메모리를 읽거나 쓰기가 발생하는 경우 브레이크(Instruction fetch의 경우 패스)

{% include note.html content="Intel386, Intel486에서는 10 비트는 쓰지 않습니다." %}

`LEN0 ~3` 은 각각 18,19, 22,23, 26,27, 30,31 비트에 설정됩니다. 말 그대로 길이에 관한 플래그입니다.

- 00 : 1byte(BYTE)
- 01 : 2byte(WORD)
- 10 : 8byte(QWORD)
- 11 : 4byte(DWORD)



## [0x02] Example

저는 이러한 내용에 대해 비트 필드를 이용하여 구조체를 할당하고, `SetThreadContext`를 이용하여 `Debug Register`를 조작했습니다.

```c
#include <stdio.h>
#include <Windows.h>

#define EXECUTE_COND        0
#define WRITE_COND          1
#define IO_READWRITE_COND   2
#define READWRITE_COND      3

#define SIZE_BYTE  0
#define SIZE_WORD  1
#define SIZE_DWORD 3
#define SIZE_QWORD 2

// Debug Register 7 field
typedef struct _DR_CONTROL_BIT
{
	unsigned long Dr0_LocalBp : 1;           // 00 (1)
	unsigned long Dr0_GlobalBp : 1;          // 01 (1)
	unsigned long Dr1_LocalBp : 1;           // 02 (1)
	unsigned long Dr1_GlobalBp : 1;          // 03 (1)
	unsigned long Dr2_LocalBp : 1;           // 04 (1)
	unsigned long Dr2_GlobalBp : 1;          // 05 (1)
	unsigned long Dr3_LocalBp : 1;           // 06 (1)
	unsigned long Dr3_GlobalBp : 1;          // 07 (1)
	unsigned long LocalExactBp : 1;          // 08 (1)
	unsigned long GlobalExactBp : 1;         // 09 (1)
	unsigned long Reserved_0 : 3;            // 10 (3)
	unsigned long GeneralDetectEnable : 1;   // 13 (1)
	unsigned long Reserved_1 : 2;            // 14 (2)
	unsigned long Dr0_Control : 2;           // 16 (2)
	unsigned long Dr0_Size : 2;              // 18 (2)
	unsigned long Dr1_Control : 2;           // 20 (2)
	unsigned long Dr1_Size : 2;              // 22 (2)
	unsigned long Dr2_Control : 2;           // 24 (2)
	unsigned long Dr2_Size : 2;              // 26 (2)
	unsigned long Dr3_Control : 2;           // 28 (2)
	unsigned long Dr3_Size : 2;              // 30 (2)
	unsigned long Dummy;                     // 32 (32)

}DR_CONTROL_BIT, * PDR_CONTROL_BIT;


BOOLEAN CreateException(PVOID pTarget, PCONTEXT context, PDR_CONTROL_BIT ControlFlag, DWORD Condition, DWORD Size)
{
	int count = 0;
	for (int i = 0; i < 4; i++)
	{
		if (*((&context->Dr0) + i) != 0)
		{
			count++;
			continue;
		}
		else
		{
			*((&context->Dr0) + i) = (DWORD64)pTarget;
			count++;
			switch (count)
			{
			case 1:
				ControlFlag->Dr0_LocalBp = 1;
				ControlFlag->Dr0_Control = Condition;
				ControlFlag->Dr0_Size = Size;
				return TRUE;

			case 2:
				ControlFlag->Dr1_LocalBp = 1;
				ControlFlag->Dr1_Control = Condition;
				ControlFlag->Dr1_Size = Size;
				return TRUE;

			case 3:
				ControlFlag->Dr2_LocalBp = 1;
				ControlFlag->Dr2_Control = Condition;
				ControlFlag->Dr2_Size = Size;
				return TRUE;

			case 4:
				ControlFlag->Dr3_LocalBp = 1;
				ControlFlag->Dr3_Control = Condition;
				ControlFlag->Dr3_Size = Size;
				return TRUE;
			}
			return FALSE;
		}
	}
	return FALSE;
}


int main()
{
	PVOID pVirtual = VirtualAlloc(0, USN_PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	CONTEXT ct = { 0, };
	DR_CONTROL_BIT ControlFlag = { 0, };

	ct.ContextFlags = CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS;

	CreateException(pVirtual, &ct, &ControlFlag, READWRITE_COND, SIZE_BYTE);
	memcpy(&ct.Dr7, &ControlFlag, 8);
	SetThreadContext(GetCurrentThread(), &ct);
	
	// Exception Code
	int a = 0x1337;
	memcpy(pVirtual, &a, 4);
}
```

메인 함수 내에 주석부분을 확인하면 하드웨어 브레이크 포인트가 설치된 메모리에 쓰기 동작을 하면서 `Single Step Exception`이 발생하며, 콜 스택을 보며 추적할 수 있습니다.



## [0x03] Conclusion

물론 VS의 데이터 중단점을 활용하는 방법도 있지만, 편리한 기능들로 인해 지나칠 수 있는 내용에 대해 좀 더 깊이 알아볼 수 있는 것이 매우 좋다고 생각합니다. 업무와 자기계발이 함께 되는 좋은 경험이었습니다.



## [0x04] Reference

1. https://www.intel.com/content/dam/support/us/en/documents/processors/pentium4/sb/253669.pdf
   - Intel® 64 and IA-32 Architectures Software Developer’s Manual