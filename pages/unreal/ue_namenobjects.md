---
title: Unreal Engine FName&GObjects
keywords: documentation, technique, reversing, unreal, game
date: 2021-03-16
tags: [Reversing, Dev]
summary: "Unreal Engine FName & GObjects"
sidebar: unreal_sidebar
permalink: ue_namenobjects.html
folder: unreal
---

## [0x00] Overview

앞서 말한 것과 같이 핵심이 되는 오브젝트는 `FName` , `GObjects` 입니다. 
이번 챕터에서는 이러한 오브젝트를 어떻게 찾고 분석하는지에 대한 내용입니다.

## [0x01] How to find FName & GObjects

간략히 설명하면 아래와 같습니다.

1. 언리얼 게임 바이너리 내 언리얼 버전 확인
2. 해당 버전에 맞는 언리얼 엔진 설치(디버깅 심볼 포함)
3. 샘플 게임 빌드
4. 심볼과 UE 소스코드를 비교하여 `FName`, `GObjects` 패턴 획득

물론 게임사의 보안 수준 및 엔진에 대한 이해도에 따라 기본 패턴과 달라질 수 있습니다.

(아직까지 그러한 게임은 보지 못했습니다.)

실제로 아래와 같이 `IDA`를 이용하여 심볼을 이용할 수 있습니다.

```c
__int64 __fastcall FName::GetPlainNameString(_DWORD *a1, __int64 a2)
{
  __int64 v3; // rbx
  RTL_SRWLOCK *v4; // r8
  int v6; // [rsp+34h] [rbp+Ch]

  v3 = HIWORD(*a1);
  v6 = (unsigned __int16)*a1;
  if ( byte_143E54CA8 )
  {
    v4 = &stru_143E54CC0;
  }
  else
  {
    v4 = (RTL_SRWLOCK *)FNamePool::FNamePool((FNamePool *)&stru_143E54CC0); // NamePoolData
    byte_143E54CA8 = 1;
  }
  FNameEntry::GetPlainNameString((char *)v4[v3 + 2].Ptr + (unsigned int)(2 * v6), a2);
  return a2;
}
```

위의 `FName::GetPlainNameString` 의 경우 `FNamePool::FNamePool` 생성자에 전달되는 주소가 `FName` 으로 이해할 수 있습니다.

`GObjects` 의 경우에도 마찬가지 입니다.

```c
void UObjectBaseInit(void)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  FCompressedChunk::FCompressedChunk((FCompressedChunk *)v2);
  v6 = 0x200000;
  v5 = 0;
  v4 = 0;
  v3 = 0;
  v1[0] = 0i64;
  v1[1] = 0i64;
  v0 = FCommandLine::Get();
  if ( FParse::Value(v0, L"-filehostip=", (struct FString *)v1, 1) )
  {
    GCreateGCClusters = 0;
  }
  else
  {
...
...
  if ( v1[0] )
    FMemory::Free(v1[0]);
  GUObjectAllocator = v4;
  qword_143E6D1A0 = (__int64)FMemory::MallocPersistentAuxiliary(v4, 0);
  qword_143E6D1A8 = qword_143E6D1A0;
  qword_143E6D1B0 = qword_143E6D1A0;
  FUObjectArray::AllocateObjectPool((FUObjectArray *)&GUObjectArray, v6, v5, v3);
  InitAsyncThread();
  byte_143E6D374 = 1;
  sub_140D78570();
  TArray<float,TSizedDefaultAllocator<32>>::~TArray<float,TSizedDefaultAllocator<32>>(v2);
}
```

`UObjectBaseInit` 함수 내부를 확인하면 `FUObjectArray::AllocateObjectPool` 함수를 통해 오브젝트 풀을 할당하는 것을 볼 수 있으며, 이 때 전달되는 `GUObjectArray` 라는 전역 변수를 확인할 수 있습니다. `FUObjectArray` 라는 클래스의 인스턴스이며, 실제 소스코드를 확인하면 아래와 같습니다.

```c
class FUObjectArray
....
private:

	//typedef TStaticIndirectArrayThreadSafeRead<UObjectBase, 8 * 1024 * 1024 /* Max 8M UObjects */, 16384 /* allocated in 64K/128K chunks */ > TUObjectArray;
	typedef FChunkedFixedUObjectArray TUObjectArray;

	// note these variables are left with the Obj prefix so they can be related to the historical GObj versions

	/** First index into objects array taken into account for GC.							*/
	int32 ObjFirstGCIndex;
	/** Index pointing to last object created in range disregarded for GC.					*/
	int32 ObjLastNonGCIndex;
	/** Maximum number of objects in the disregard for GC Pool */
	int32 MaxObjectsNotConsideredByGC;

	/** If true this is the intial load and we should load objects int the disregarded for GC range.	*/
	bool OpenForDisregardForGC;
	/** Array of all live objects.											*/
	TUObjectArray ObjObjects;
	/** Synchronization object for all live objects.											*/
	FCriticalSection ObjObjectsCritical;
	/** Available object indices.											*/
	TLockFreePointerListUnordered<int32, PLATFORM_CACHE_LINE_SIZE> ObjAvailableList;
#if UE_GC_TRACK_OBJ_AVAILABLE
	/** Available object index count.										*/
	FThreadSafeCounter ObjAvailableCount;
#endif
```

위의 클래스를 `ReClass` 를 이용하여 확인하면 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/ue_00.png?raw=true">

`ObjObjects` 는 `TUObjectArray` 는 `FChunkedFixedUObjectArray` 와 같습니다.

```c
class FChunkedFixedUObjectArray
{
	enum
	{
		NumElementsPerChunk = 64 * 1024,
	};

	/** Master table to chunks of pointers **/
	FUObjectItem** Objects;
	/** If requested, a contiguous memory where all objects are allocated **/
	FUObjectItem* PreAllocatedObjects;
	/** Maximum number of elements **/
	int32 MaxElements;
	/** Number of elements we currently have **/
	int32 NumElements;
	/** Maximum number of chunks **/
	int32 MaxChunks;
	/** Number of chunks we currently have **/
	int32 NumChunks;
....
```

`FUObjectItem` 의 구조체는 아래와 같습니다.

```c
struct FUObjectItem
{
	// Pointer to the allocated object
	class UObjectBase* Object;
	// Internal flags
	int32 Flags;
	// UObject Owner Cluster Index
	int32 ClusterRootIndex;	
	// Weak Object Pointer Serial number associated with the object
	int32 SerialNumber;
...
```

이렇게 소스코드와 비교하며 실제 오브젝트 배열을 확인하면 아래와 같이 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/ue_01.png?raw=true">

매우 쉽게 구하면서도 강력한 정보들임이 틀림 없습니다. `Unreal SDK Generator` 의 소스코드들을 보면 많은 방법들로 값을 구하고, 오브젝트들에 대한 주소와 이름을 생성합니다.

아래는 언리얼 샘플 빌드의 오브젝트 덤프 입니다.

```
[014267] [0x1BEE0D773C0] SkeletalMeshComponent FirstPersonCharacter.Default__FirstPersonCharacter_C.CharacterMesh0
[014268] [0x1BEEB91C640] BP_Sky_Sphere_C BP_Sky_Sphere.Default__BP_Sky_Sphere_C
[014269] [0x1BEEB91DC40] BP_Sky_Sphere_C FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.SkySphereBlueprint
[014270] [0x1BEF5FD7B30] FirstPersonCharacter_C FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.FirstPersonCharacter_C_2
[014271] [0x1BEE0A84980] CapsuleComponent FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.FirstPersonCharacter_C_2.CollisionCylinder
[014272] [0x1BEDD30B9E0] CharacterMovementComponent FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.FirstPersonCharacter_C_2.CharMoveComp
[014273] [0x1BEE0D76700] SkeletalMeshComponent FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.FirstPersonCharacter_C_2.CharacterMesh0
[014274] [0x1BEEF935950] CameraComponent FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.FirstPersonCharacter_C_2.FirstPersonCamera
[014275] [0x1BEF5FD8080] MotionControllerComponent FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.FirstPersonCharacter_C_2.L_MotionController
[014276] [0x1BEF5FD85D0] MotionControllerComponent FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.FirstPersonCharacter_C_2.R_MotionController
[014277] [0x1BEEA62C200] SceneComponent FirstPersonExampleMap.FirstPersonExampleMap.PersistentLevel.SkySphereBlueprint.Base
```

위와 같이 덤프를 생성하기 위해선, `FName`, `GObjects` 간의 연관성에 대해 알아야 하지만, 해답은 언리얼 엔진 소스코드에 모두 존재합니다.

좀 더 상세하게 설명하고 싶지만 상세 내용은 실습으로 대체합니다. 다음 챕터에서는 샘플 빌드를 가지고 실제 덤프를 뜨는 코드를 작성하고 테스트 하는 내용을 소개하겠습니다.

편리함이 계속되면 틀에 갇히게 됩니다. 마찬가지로 편리한 프레임 워크일수록 깊이 아는 것이 중요합니다.

## [0x03] Reference

1. [Guided Hacking](https://guidedhacking.com)
2. [Feckless SDK Generator](https://www.unknowncheats.me/forum/unreal-engine-3-a/71911-thefeckless-ue3-sdk-generator.html)