---
title: I/O Transfer Example
keywords: documentation, technique, reversing, kernel, windows
date: 2021-05-27
tags: [Windows, Reversing, Kernel]
summary: "I/O Transfer Example"
sidebar: windows_sidebar
permalink: windows_iotransfer.html
folder: windows
---

## [0x00] Concept

지금까지 IRP와 I/O 메커니즘, 이를 사용하기 위한 MS의 IOCTL CODE 정의 방법까지 알아봤습니다.

실제로 유저모드 애플리케이션과 커널 드라이버 간의 통신 방법을 확인하기 위한 예제 챕터입니다.

먼저 Input 과 Output 의 개념은 드라이버의 관점에서 바라봐야 한다는 것을 미리 말씀드립니다.

즉 Input Buffer 는 드라이버에서 입력되는 버퍼, Output Buffer 는 드라이버에서 입력해서 출력되는 버퍼를 의미합니다.

반대로 유저모드에서는 Input Buffer 는 입력해서 드라이버로 전달하는 버퍼, Output Buffer는 드라이버에서 입력을 받아 유저모드에서 출력 가능한 버퍼를 의미합니다.

※ 일반적으로 디스패치 루틴은 PASSIVE_LEVEL 에서 동작합니다. 예외의 경우 [여기](https://docs.microsoft.com/ko-kr/windows-hardware/drivers/kernel/dispatch-routines-and-irqls) 에서 확인 가능합니다.

## [0x01] I/O Method

`Driver Stack` 개념에서 주요 책임 중 하나가 유저모드 애플리케이션과 시스템 디바이스 간의 데이터를 전송하는 것 입니다. 운영 체제는 데이터 버퍼에 접근하기 위해 3 가지 방법 전략을 사용합니다.

- Buffered I/O
  - 운영체제에서 유저모드 애플리케이션에서 사용되는 버퍼와 동일한 크기의 `Non-Paged System Buffer` 를 할당합니다. `Write` 작업 시 I/O Manager 는 드라이버 스택을 호출하기 전에 유저모드의 데이터를 할당 된 시스템 버퍼에 복사합니다. `Read` 작업의 경우 요청 된 작업을 완료한 후에 할당 된 시스템 버퍼의 데이터를 유저모드 애플리케이션 버퍼로 복사합니다.
- Direct I/O
  - 운영체제가 메모리 내 유저모드 애플리케이션의 버퍼를 잠급니다. 잠긴 메모리 페이지를 식별할 수 있는 `MDL` 을 생성하고 해당 `MDL` 을 드라이버에 전달합니다. 드라이버 또한 해당 `MDL` 을 통해 메모리 페이지에 접근합니다.
- Neither I/O
  - 운영체제가 유저모드 애플리케이션의 버퍼 가상 주소와 해당 크기를 드라이버에 전달합니다. 해당 버퍼는 해당 애플리케이션의 스레드 컨텍스트에서 실행되는 드라이버에서만 접근이 가능합니다.

## [0x02] Buffered I/O

유저모드 애플리케이션에서 `METHOD_BUFFERED` (입,출력 버퍼), `METHOD_IN(OUT)_DIRECT` (입력버퍼) 방식을 사용하는 경우 Buffered I/O 방식을 사용하게 됩니다.

일반적으로 `IRP_MJ_DEVICE_CONTROL` 으로 요청된 경우에는 `Direct I/O` 방식일지라도 입력버퍼의 경우 Buffered I/O 방식으로 처리되게 됩니다.

이러한 플래그를 확인하여 커널 드라이버에서 허용되지 않은 I/O 방식에 대해 제한을 둘 수도 있습니다.

`Device object` 의 플래그 설정 내 `DO_BUFFERED_IO` 가 설정되어 있는지 확인하고, 이를 기반으로 제어가 가능합니다.

`MSDN` 내 설명된 그림은 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/iotransfer_00.png?raw=true">

아래는 위의 순서와 관계없는 요약입니다.

1. 유저모드 애플리케이션이 `DeviceIoControl` 을 이용하여 작업 요청(`IRP_MJ_DEVICE_CONTROL`)
2. I/O Manager는 사용자 버퍼를 확인하고 `ExAllocatePool` 을 이용하여 사용자 버퍼와 동일한 크기의 `Non-Paged Pool` 에 `SystemBuffer` 를 할당
3. I/O Manager 는 `IRP` 내 `SystemBuffer` 에 할당된 포인터를 저장하고 시스템 버퍼로 유저모드 버퍼의 데이터를 복사합니다.
4. 드라이버로 전송하고 드라이버는 작업을 진행 및 완료 후 `IoCompleteRequest` 로 완료되었음을 알립니다.
5. I/O Manager는 시스템 버퍼에서 유저모드 버퍼로 값을 복사하고 `ExFreePool` 을 이용하여 사용한 시스템 버퍼를 해제합니다.

과정은 매우 간단하며, 요약하면 유저모드의 데이터를 커널모드의 `Non-paged pool` 에 복사하여 사용하고 이를 다시 유저모드 버퍼에 복사해주는 방식입니다.

## [0x03] Direct I/O

`Direct I/O` 방식의 경우  두 가지 방식이 존재합니다. `DMA(Direct Memory Access)` 방식과 `PIO(Programmed I/O)` 방식입니다. 다만 `IRP_MJ_DEVICE_CONTROL` 작업의 경우 이와 관계없이 입력 버퍼는 `Buffered I/O` 방식을 따르게 됩니다.

`METHOD_IN(OUT)_DIRECT` 방식으로 전달 시, 출력 버퍼는 `MDL(Memory Descriptor List)` 를 이용합니다. 아래 예제에서 상세하게 설명됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/iotransfer_01.png?raw=true">

위의 그림은 `MSDN` 에 존재하는 예제로써 `IRP_MJ_READ` 작업에 대한 예제입니다. `IRP_MJ_DEVICE_CONTROL` 에 맞게 설명합니다.

1. 유저모드 애플리케이션이 `DeviceIoControl` 을 이용하여 작업 요청(`IRP_MJ_DEVICE_CONTROL`)
2. I/O Manager 는 유저모드 가상 주소로 `MDL` 을 생성하고, `MmProbeAndLockPages` 함수를 이용하여 페이지를 고정합니다.(본 블로그 내 `Memory Descriptor List` 참조)
3. I/O Manager 는 `IRP` 내 `MdlAddress` 에 해당 `MDL` 주소 값을 저장합니다.
4. `MmGetMdlVirtualAddress` 함수에 해당 `MDL` 주소 값을 넘겨 할당 된 가상 주소 값을 반환 받습니다.
5. 나머지 작업을 처리합니다.

## [0x04] Proof of Concept

### METHOD_BUFFERED

샘플 코드에서 존재하는 코드 블럭입니다.

```cpp
// User-mode Application
...
case DeviceIoControl_SystemBuffer:
    {
      unsigned int inBuffer = 0x1337;
      unsigned int outBuffer = 0;
	    DeviceIoControl(
			DeviceHandle,
			IOCTL_SHD_SYSTEM_BUFFER,
			&inBuffer,
			sizeof(unsigned int),
			&outBuffer,
			sizeof(unsigned int),
			&ret,
			nullptr
		);
        printf("0x%X\\n", outBuffer);
        break;
    }
...
```

`IOCTL_SHD_SYSTEM_BUFFER` 를 `IOCTL_CODE` 로 전달하고 있으며, `CTL_CODE` 매크로 함수를 이용하여 만든 제어 코드입니다. 해당 코드에는 `METHOD_BUFFERED` 가 포함되어 있습니다.

다음은 커널 드라이버 코드입니다.

```cpp
// Kernel-mode Driver
...
NTSTATUS DriverDeviceControl(IN OUT PDEVICE_OBJECT DeviceObject, IN OUT PIRP Irp)
{
	PIO_STACK_LOCATION IoStackLocation = NULL;
	IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	Log("Stack Location : %p\\n", IoStackLocation);
	__debugbreak();
	// Filter I/O Method
	ULONG ControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
	ULONG MethodType = ControlCode & 0xFF;
	switch (MethodType)
	{
	case METHOD_BUFFERED:
	{
		if ((ShGlobal.DeviceObject->Flags & DO_BUFFERED_IO) == FALSE)
		{
			Log("Not allowed Buffered I/O Method\\n");
			IoCompleteRoutine(Irp, STATUS_ACCESS_DENIED, 0);
			return STATUS_ACCESS_DENIED;
		}
		ULONG* RecvBuffer = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		Log("Recv : 0x%X\\n", *RecvBuffer);
		ULONG BufferSize = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG Buffer = 0xdeadbeef;
		RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Buffer, BufferSize);
		IoCompleteRoutine(Irp, STATUS_SUCCESS, BufferSize);
		return STATUS_SUCCESS;
	}
...
```

위의 내용을 확인하면 `Device Object` 에 `DO_BUFFERED_IO` 플래그가 존재하지 않으면 별 다른 작업이 없는 것을 볼 수 있습니다.

`IRP` 개념에서 설명했던 내용이 그대로 사용되는 것 또한 확인할 수 있습니다.

`IoGetCurrentIrpStackLocation` 을 이용하여 현재 스택 로케이션(`IO_STACK_LOCATION`)을 가져오고 해당 내용에서 제어 코드를 확인하고, 이에 대한 작업을 진행하는 것을 볼 수 있습니다.

간단히 위의 코드를 설명하면, 스택 로케이션 내 제어 코드가 `METHOD_BUFFERED` 인지 확인합니다.

그리고, `Device Object` 내 `Flags` 에서 `DO_BUFFERED_IO` 값이 설정되어 있는지 확인합니다.

가능한 경우 시스템 버퍼 내 값을 `0xdeadbeef` 로 변경하여 작업을 완료합니다.

스택 로케이션을 가져온 다음부터 디버깅을 진행해보겠습니다.

```
; Check Stack Location

3: kd> dt nt!_IO_STACK_LOCATION FFFFB58BF9EE4AA0
   +0x000 MajorFunction    : 0xe ''
   +0x001 MinorFunction    : 0 ''
   +0x002 Flags            : 0x5 ''
   +0x003 Control          : 0 ''
   +0x008 Parameters       : <anonymous-tag>
   +0x028 DeviceObject     : 0xffffb58b`fdacfe00 _DEVICE_OBJECT
   +0x030 FileObject       : 0xffffb58b`ff8d95d0 _FILE_OBJECT
   +0x038 CompletionRoutine : (null) 
   +0x040 Context          : (null)

; Check IRP

3: kd> dt_IRP @rdi
ntdll!_IRP
   +0x000 Type             : 0n6
   +0x002 Size             : 0x118
   +0x004 AllocationProcessorNumber : 3
   +0x006 Reserved         : 0
   +0x008 MdlAddress       : (null) 
   +0x010 Flags            : 0x60070
   +0x018 AssociatedIrp    : <anonymous-tag>
...
   +0x050 UserEvent        : (null) 
   +0x058 Overlay          : <anonymous-tag>
   +0x068 CancelRoutine    : (null) 
   +0x070 UserBuffer       : 0x00000057`977ff9e0 Void
   +0x078 Tail             : <anonymous-tag>
```

스택 로케이션에는 이전 포스팅에서 설명한 것과 같은 내용들이 존재합니다. `MajorFunction` 은 `IRP_MJ_XXXX` 를 의미하는 작업 유형을 나타냅니다.

가장 중요한 `Parameters` 필드는 `MajorFunction, MinorFunction` 에 따라 다른 공용체 입니다. 예제에서 `IRP_MJ_DEVICE_CONTROL` 의 경우 `DeviceIoControl` 구조체를 사용하게 됩니다.

다음은 `IRP` 입니다.  `MdlAddress` 는 본 블로그 내 설명되어 있는 `Memory Descriptor List` 의 주소 값으로 `Direct I/O` 를 사용하고 `IRP_MJ_READ, WRITE, DEVICE_CONTROL, INTERNAL_DEVICE_CONTROL` 을 사용할 때 사용됩니다.

`AssociatedIrp` 의 경우 `Buffered I/O` 에서 반드시 필요한 `SystemBuffer` 를 포함한 공용체 입니다.

여기서 `IRP` 의 `Flags` 필드에 대한 의문이 들어서 찾아봤지만 명확한 답변을 찾을 수 없었습니다. 왜냐하면 `Flags` 의 필드와 관련된 데이터에서 0x40000, 0x20000 을 찾을 수 없기 때문이었습니다.

마지막으로 `UserBuffer` 의 경우 현재 유저모드의 가상 주소 값이 존재하는 것을 알 수 있습니다.

해당 필드가 적용되는 경우는 다음과 같습니다.

- 스택 로케이션의 `MajorFunction` 이 `IRP_MJ_DEVICE_CONTROL, INTERNAL_DEVICE_CONTROL` 인 경우,
- `IOCTL CODE` 가 `METHOD_NEITHER` 또는 `METHOD_BUFFERED` 일 때,

위의 두 가지가 모두 충족되면 해당 필드는 유저모드의 가상 주소 값이 저장됩니다.

필드의 이름만 보고 해당 위치에 값을 쓰거나 변경해서는 안됩니다. 드라이버가 작업을 완료하면 I/O Manager는 `SystemBuffer` 의 내용을 `UserBuffer`에 복사합니다.

실제로 `UserBuffer` 를 메모리에서 확인하면 아래와 같습니다.

```
3: kd> dp 00000057`977ff9e0
00000057`977ff9e0  00001337`00000000 00000000`00000000
00000057`977ff9f0  00000004`00000001 00000000`00000001
00000057`977ffa00  00000000`00000000 00000000`00000000
```

0x1337 은 유저모드의 `InBuffer` 에 할당한 값입니다. 조금 이상한 점은 `00000057'977ff9e0` 에 값이 있지 않고 4바이트 떨어진 `00000057'977ff9e4` 에 0x1337 이 존재합니다.

여기서 유저모드의 코드를 살펴보면 연속된 변수의 할당으로 인해 주소 값이 연속된 것을 볼 수 있습니다.

```cpp
...
case DeviceIoControl_SystemBuffer:
    {
        unsigned int inBuffer = 0x1337;
        unsigned int outBuffer = 0;
...
```

때문에 `InBuffer` 와 `OutBuffer` 가 연속되는 것이 보장되지 않는다는 것을 기억해야 합니다. `UserBuffer` 에 할당된 유저모드 가상 주소는 `DeviceIoControl` 의 `OutBuffer` 주소 값입니다.

`IoCompleteRequest` 가 호출되고, `UserBuffer` 를 확인하면 커널 드라이버에서 의도한대로 0xdeadbeef 값이 복사된 것을 확인할 수 있습니다.

```
3: kd> dp 00000057`977ff9e0
00000057`977ff9e0  00001337`deadbeef 00000000`00000000
00000057`977ff9f0  00000004`00000001 00000000`00000001
00000057`977ffa00  00000000`00000000 00000000`00000000
```

추가적으로 확인해보고 싶은 점이 있었으며, 해당 내용은 추후에 다뤄보겠습니다.

해당 내용은 `MSDN` 에서는 `UserBuffer` 에 드라이버가 직접 값을 변경하면 안된다고 되어 있지만.. 만일 `IoCompleteRequest` 가 완료된 후에, 유저 모드 버퍼의 주소 값을 저장해두고 `KeStackAttachProcess` 와 같은 함수를 이용하여 접근해 변경하면 어떨까 라는 생각을 해봤습니다.

추후에 확인해보도록 하겠습니다.

### METHOD_IN(OUT)_DIRECT

`Direct I/O` 를 의미하는 해당 방식 또한 입력 버퍼(User to Kernel)에 `SystemBuffer` 가 사용됩니다. `METHOD_BUFFERED` 와 다른 점은 출력 버퍼(Kernel to User)에 대한 정보가 `MDL` 으로 이루어져 있다는 점 입니다.

`MSDN` 에서는 `IN,OUT` 의 차이를 실행중인 스레드에서 해당 버퍼에 대한 접근 권한의 차이로 설명합니다. `IN` 의 경우 `READ`, `OUT`의 경우 `WRITE` 권한을 갖는다고 이야기하고 있습니다.

이제 실제로 어떤 구조로 되어 있는지 확인합니다.

먼저 해당 내용을 시작하기 앞서 본 블로그 내 [Memory Descriptor List](https://shhoya.github.io/windows_MDL.html) 글을 읽는 것을 추천합니다.

해당 내용을 어느정도 숙지했다는 가정으로 진행합니다.

`METHOD_BUFFERED` 에서는 I/O 관리자가 할당한 `SystemBuffer` 에 데이터를 쓸 수 있었습니다.(Driver)

다행히 `MDL` 에 대한 선행 학습이 있었고 출력 버퍼를 찾는데 그리 오랜 시간이 걸리지 않았습니다.

```cpp
...
case METHOD_IN_DIRECT:
	{
		if ((ShGlobal.DeviceObject->Flags & DO_DIRECT_IO) == FALSE)
		{
			Log("Not allowed Direct I/O Method\\n");
			IoCompleteRoutine(Irp, STATUS_ACCESS_DENIED, 0);
			return STATUS_ACCESS_DENIED;
		}
		ULONG* RecvBuffer = (ULONG*)Irp->AssociatedIrp.SystemBuffer;
		Log("Recv : 0x%X\\n", *RecvBuffer);
		ULONG BufferSize = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG Buffer = 0xdeadbeef;
		ULONG* SendBuffer = (ULONG*)MmGetMdlVirtualAddress(Irp->MdlAddress);
		RtlCopyMemory(SendBuffer, &Buffer, BufferSize);
		IoCompleteRoutine(Irp, STATUS_SUCCESS, BufferSize);
		return STATUS_SUCCESS;
	}
...
```

I/O Manager 는 출력 버퍼에 대한 유저모드 가상 메모리 공간에 대한 `MDL` 을 생성하고 이에 대한 포인터를 `IRP` 에 할당합니다. 코드를 보면 알 수 있지만 `METHOD_IN_DIRECT` 방식 또한 입력 버퍼는 `SystemBuffer` 를 사용합니다.

실제로 디버깅을 해보면 아래와 같습니다.

```
3: kd> dt nt!_IRP @rdi
   +0x000 Type             : 0n6
   +0x002 Size             : 0x118
   +0x004 AllocationProcessorNumber : 3
   +0x006 Reserved         : 0
   +0x008 MdlAddress       : 0xffffb58b`ff324a80 _MDL
   +0x010 Flags            : 0x60030
   +0x018 AssociatedIrp    : <anonymous-tag>
   +0x020 ThreadListEntry  : _LIST_ENTRY [ 0xffffb58b`fe717530 - 0xffffb58b`fe717530 ]
   +0x030 IoStatus         : _IO_STATUS_BLOCK
   +0x040 RequestorMode    : 1 ''
   +0x041 PendingReturned  : 0 ''
   +0x042 StackCount       : 1 ''
   +0x043 CurrentLocation  : 1 ''
   +0x044 Cancel           : 0 ''
   +0x045 CancelIrql       : 0 ''
   +0x046 ApcEnvironment   : 0 ''
   +0x047 AllocationFlags  : 0x6 ''
   +0x048 UserIosb         : 0x000000e7`0c58f6b0 _IO_STATUS_BLOCK
   +0x050 UserEvent        : (null) 
   +0x058 Overlay          : <anonymous-tag>
   +0x068 CancelRoutine    : (null) 
   +0x070 UserBuffer       : (null) 
   +0x078 Tail             : <anonymous-tag>
```

`METHOD_BUFFERED` 와 다른 점을 확인할 수 있습니다. `METHOD_BUFFERED` 방식에서는 출력 버퍼를 `SystemBuffer` 의 값을 `UserBuffer` 로 복사했기 때문에 `UserBuffer` 필드에 버퍼 주소가 저장되었지만, `METHOD_IN(OUT)_DIRECT` 의 경우 위와 같이 `UserBuffer` 는 존재하지 않으며 대신 `MdlAddress` 필드에 값이 채워져 있는 것을 확인할 수 있습니다.

```
3: kd> dt nt!_mdl 0xffffb58b`ff324a80
   +0x000 Next             : (null) 
   +0x008 Size             : 0n56
   +0x00a MdlFlags         : 0n266
   +0x00c AllocationProcessorNumber : 3
   +0x00e Reserved         : 0
   +0x010 Process          : 0xffffb58b`fef1f300 _EPROCESS
   +0x018 MappedSystemVa   : 0xffffb58c`004fd000 Void
   +0x020 StartVa          : 0x000000e7`0c58f000 Void
   +0x028 ByteCount        : 4
   +0x02c ByteOffset       : 0x760

; Output Buffer
3: kd> db 0xe70c58f000+0x760 l8
000000e7`0c58f760  00 00 00 00 37 13 00 00
```

이제 `MDL` 을 확인하면 위와 같이 출력 버퍼가 할당되어 있음을 확인할 수 있습니다.

유저모드에서 출력 버퍼 주소를 확인하면 다음과 같이 동일한 것을 확인할 수 있습니다.

```
[LOG] DeviceIoControl_MDL
[LOG] Output Buffer : 0x000000E70C58F760
```

### METHOD_NEITHER

`METHOD_NEITHER` 방식은 `Buffered I/O` 와 `Direct I/O` 방식을 사용하지 않습니다.

I/O Manager는 `IRP` 에 유저 모드의 가상 주소를 드라이버로 전달합니다.

유저 모드 버퍼의 가상 주소 유효성을 확인하고 작업 유형에 따라  `ProbeForRead` 및 `ProbeForWrite` 를 사용하여  `READ, WRITE` 권한을 확인해야 합니다. 드라이버에서 `Buffered I/O` , `Direct I/O` 방식에 대한 지원만 가능한 경우 이에 대한 예외처리 또는 이에 맞는 방식으로 버퍼를 처리해야 합니다.

즉 `Buffered I/O` 방식만 지원하는 경우, `METHOD_NEITHER` 방식으로 호출되는 경우 I/O Manager가 수행하는 것과 같이 버퍼에 대한 작업을 직접 수행해줘야 합니다. `Direct I/O` 의 경우 `MDL` 을 할당하고 `MmProbeAndLockPages` 와 같은 함수를 이용하여 메모리를 고정하고 사용해야 합니다.

입력 버퍼의 경우 스택 로케이션 내 `Parameters.DeviceIoControl.Type3InputBuffer` 에 의해 제공됩니다. `Type3` 의 의미는 `Buffered I/O` , `Direct I/O`  가 아닌 타입을 의미합니다.

출력 버퍼는 위에서 설명한 것과 같이 `IRP` 내 `UserBuffer` 에 의해 제공됩니다.

위의 설명을 기반으로 작성한 코드입니다.

```cpp
...
case METHOD_NEITHER:
	{
		ULONG InBufferSize = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		ULONG OutBufferSize = IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		
		__debugbreak();
		__try {
			ProbeForRead(IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer, sizeof(ULONG), 1);
			ProbeForWrite(Irp->UserBuffer, sizeof(ULONG), 1);
		}
		__except(EXCEPTION_EXECUTE_HANDLER){
			Log("Invalid User buffer\\n");
			IoCompleteRoutine(Irp, STATUS_ACCESS_DENIED, 0);
			return STATUS_ACCESS_DENIED;
		}

		ULONG* RecvBuffer = (ULONG*)IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
		Log("Recv : 0x%X\\n", *RecvBuffer);
		ULONG Buffer = 0xdeadbeef;
		ULONG* SendBuffer = (ULONG*)Irp->UserBuffer;
		RtlCopyMemory(SendBuffer, &Buffer, OutBufferSize);
		IoCompleteRoutine(Irp, STATUS_SUCCESS, OutBufferSize);
		return STATUS_SUCCESS;
	}
...
```

`ProbeForRead` 를 통해 입력 버퍼에 대한 유효성을 검사하고, `ProbeForWrite` 를 이용하여 출력 버퍼의 유효성 검사를 진행했습니다.

## [0x05] Conclusion

버퍼를 처리하는 3가지 전략과 이러한 전략을 구현한 4가지 방식을 확인했습니다. 간단하게 그림으로 표현해봤습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/iotransfer_02.png?raw=true">

## [0x06] Reference

1. [MSDN Methods for Accessing Data Buffers](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/methods-for-accessing-data-buffers)

