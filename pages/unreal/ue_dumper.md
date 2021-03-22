---
title: Unreal Engine 4 Dumper
keywords: documentation, technique, reversing, unreal, game
date: 2021-03-23
tags: [Reversing, Dev]
summary: "Unreal Engine Name&Object Dumper"
sidebar: unreal_sidebar
permalink: ue_dumper.html
folder: unreal
---

## [0x00] Overview

가장 최신 버전인 `Unreal 4.26.1` 의 샘플 빌드를 이용하여, 오브젝트 덤프를 생성하도록 하겠습니다.

해당 덤퍼는 튜토리얼 용으로, 언리얼 엔진 4.26.1 버전의 환경에서 샘플 게임을 빌드하여 테스트하였습니다.

예제에 사용된 소스코드는 추후 공개됩니다.

## [0x01] Name Dump

현재 게임에 할당된 모든 `Name` 을 찾기 위해서는 앞서 말한대로, `FNames` 라고 잘 알려진 오브젝트를 확인해야 합니다.

먼저 4.26.1 기준으로 `NamePoolData` 를 패턴을 찾습니다.(외부에 잘 알려진 패턴 스캔 라이브러리를 사용하십시오)

`ReClass` 를 이용하여 아래와 같이 정의할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/ue_02.png?raw=true">

`NamePoolData` 아래와 같은 구조로 이루어져 있습니다.(`UE 4.26.1 NameTypes.h` 참조)

```cpp
struct FNameEntryAllocator{
	mutable PVOID Lock;
	unsigned int CurrentBlock;
	unsigned int CurrentByCursor;
	PVOID Blocks[FNameMaxBlocks];
}

struct FNamePool{
	FNameEntryAllocator Entires;
	...
}
```

여기서 `Blocks` 는 각 Name Pool 의 블록으로 이해할 수 있습니다. 해당 블록에는 `FNameEntry` 으로 이루어진 각각의 엔트리가 존재합니다.

`FNameEntry` 는 아래와 같은 구조로 이루어져 있습니다.

```cpp
struct FNameEntryHeader {
	USHORT bIsWide : 1;
	USHORT Len : 15;
};

struct FNameEntry {
	FNameEntryHeader Header;
	union
	{
		char	AnsiName[NAME_SIZE];
		wchar_t	WideName[NAME_SIZE];
	};
}
```

{% include tip.html content="해당 하는 상수 또는 열거 값(NAME_SIZE, FNameMaxBlocks 등)은 언리얼 엔진 소스 코드 내에 동일하게 작성되어 있습니다."%}

잠시 위의 내용을 보고 고민해보면, 덤프를 위한 모든 준비가 되었음을 알 수 있습니다.

Name Pool 의 블록 수를 알 수 있고, 각 엔트리가 어떻게 이루어진지도 알 수 있습니다.

## [0x02] Name Dump Tutorial

이제 구현해야 할 것은 각 이름들을 길이만큼 복사하고, 포인터를 옮기고, 파일에 저장하는 일입니다.

여기서 이름의 길이와, 다음 포인터를 구하기 위한 공식이 필요합니다. 언리얼 엔진 소스에는 이러한 공식들이 친절하게 설명되어 있으며, 구현되어 있습니다.

이러한 정보들과 약간의 노력이면 쉽게 덤프를 생성할 수 있습니다.

먼저 `FNameEntry` 를 살펴 보겠습니다.

```
2A 01 4E 6F 6E 65 08 03  ; None
42 79 74 65 50 72 6F 70  ; ByteProp
```

2바이트의 헤더와 문자열로 이루어져 있습니다. 정확히는 `FNameEntryHeader` 와 문자열 입니다.

`0x12A` 가 헤더이고, `None` 이 해당 문자열로 유추할 수 있지만, 보는 것과 같이 널 바이트가 있거나 문자열의 끝을 알리는 어떠한 내용도 없습니다.

먼저 문자열의 길이를 구하는 공식은 아래와 같습니다.

```cpp
Length = (Header >> 1) << 1  // len is 15 bit
Length = Length >> 6
```

`Header` 내 `bIsWide` 1비트를 지우고, 순수한 길이 값을 계산하는 것 입니다. 물론 `bIsWide` 값에 따라 `Length * 2` 로 길이를 계산할 수 있습니다.

다음은 `FNameEntry` 의 실제 크기를 구하는 것 입니다. 이는 언리얼 엔진 소스코드 내 `alignment` 와 관련된 함수에서도 찾아볼 수 있습니다.

```cpp
int EntrySize = 
	Length + alignof(FNameEntryHeader) + 
	FNameAllocator::Stride - 1) & ~(FNameEntryAllocator::Stride - 1);
```

이제 위의 계산들을 토대로 아래와 같이 블록 당 모든 엔트리를 순회하며 이름을 가져올 수 있습니다.

```cpp
BOOLEAN Dumper::NameDump()
{
	DWORD BlockSize = 0, NameCount = 0;
	if (!(BlockSize = DumperData.FNameData->GetBlockSize())) { return FALSE; }
	for (int idx = 0; idx < BlockSize + 1; idx++)
	{
		FNameEntry* NamePtr = NULL;
		NamePtr = Read<FNameEntry*>(&DumperData.FNameData->Entries.Blocks[idx]);
		NameCount += NamePtr->GetNameDump();
	}
...
...
}

DWORD FNameEntry::GetNameDump()
{
  ...
  ...
	for (int i = 0; i < FNameEntryAllocator::BlockSizeBytes; i++)
		{
			FNameEntry NameEntry = { 0, };
	
			NameEntry = Read<FNameEntry>(pNameEntry);
			if (!NameEntry.GetName()) { break; }    // Get name and Save name
			Size = NameEntry.GetEntrySize();        // Get entry size
			pNameEntry = (PVOID)((DWORD64)pNameEntry + Size); // next entry pointer
			NameId = NameId + Size / FNameEntryAllocator::Stride;
			Count++;
		}
	return Count;
}
```

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/ue_03.png?raw=true">

## [0x03] Object Dump

(작성 중)