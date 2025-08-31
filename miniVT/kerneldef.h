#pragma once
#include"header.h"

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22
} SYSTEM_INFORMATION_CLASS;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;



//vad------------------------------------

typedef struct _MM_GRAPHICS_VAD_FLAGS        // 15 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Lock : 1;                   // 0 BitPosition                   
	/*0x000*/     ULONG32      LockContended : 1;          // 1 BitPosition                   
	/*0x000*/     ULONG32      DeleteInProgress : 1;       // 2 BitPosition                   
	/*0x000*/     ULONG32      NoChange : 1;               // 3 BitPosition                   
	/*0x000*/     ULONG32      VadType : 3;                // 4 BitPosition                   
	/*0x000*/     ULONG32      Protection : 5;             // 7 BitPosition                   
	/*0x000*/     ULONG32      PreferredNode : 6;          // 12 BitPosition                  
	/*0x000*/     ULONG32      PageSize : 2;               // 18 BitPosition                  
	/*0x000*/     ULONG32      PrivateMemoryAlwaysSet : 1; // 20 BitPosition                  
	/*0x000*/     ULONG32      WriteWatch : 1;             // 21 BitPosition                  
	/*0x000*/     ULONG32      FixedLargePageSize : 1;     // 22 BitPosition                  
	/*0x000*/     ULONG32      ZeroFillPagesOptional : 1;  // 23 BitPosition                  
	/*0x000*/     ULONG32      GraphicsAlwaysSet : 1;      // 24 BitPosition                  
	/*0x000*/     ULONG32      GraphicsUseCoherentBus : 1; // 25 BitPosition                  
	/*0x000*/     ULONG32      GraphicsPageProtection : 3; // 26 BitPosition                  
}MM_GRAPHICS_VAD_FLAGS, * PMM_GRAPHICS_VAD_FLAGS;
typedef struct _MM_PRIVATE_VAD_FLAGS         // 15 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Lock : 1;                   // 0 BitPosition                   
	/*0x000*/     ULONG32      LockContended : 1;          // 1 BitPosition                   
	/*0x000*/     ULONG32      DeleteInProgress : 1;       // 2 BitPosition                   
	/*0x000*/     ULONG32      NoChange : 1;               // 3 BitPosition                   
	/*0x000*/     ULONG32      VadType : 3;                // 4 BitPosition                   
	/*0x000*/     ULONG32      Protection : 5;             // 7 BitPosition                   
	/*0x000*/     ULONG32      PreferredNode : 6;          // 12 BitPosition                  
	/*0x000*/     ULONG32      PageSize : 2;               // 18 BitPosition                  
	/*0x000*/     ULONG32      PrivateMemoryAlwaysSet : 1; // 20 BitPosition                  
	/*0x000*/     ULONG32      WriteWatch : 1;             // 21 BitPosition                  
	/*0x000*/     ULONG32      FixedLargePageSize : 1;     // 22 BitPosition                  
	/*0x000*/     ULONG32      ZeroFillPagesOptional : 1;  // 23 BitPosition                  
	/*0x000*/     ULONG32      Graphics : 1;               // 24 BitPosition                  
	/*0x000*/     ULONG32      Enclave : 1;                // 25 BitPosition                  
	/*0x000*/     ULONG32      ShadowStack : 1;            // 26 BitPosition                  
}MM_PRIVATE_VAD_FLAGS, * PMM_PRIVATE_VAD_FLAGS;


typedef struct _MMVAD_FLAGS            // 9 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Lock : 1;             // 0 BitPosition                  
	/*0x000*/     ULONG32      LockContended : 1;    // 1 BitPosition                  
	/*0x000*/     ULONG32      DeleteInProgress : 1; // 2 BitPosition                  
	/*0x000*/     ULONG32      NoChange : 1;         // 3 BitPosition                  
	/*0x000*/     ULONG32      VadType : 3;          // 4 BitPosition                  
	/*0x000*/     ULONG32      Protection : 5;       // 7 BitPosition                  
	/*0x000*/     ULONG32      PreferredNode : 6;    // 12 BitPosition                 
	/*0x000*/     ULONG32      PageSize : 2;         // 18 BitPosition                 
	/*0x000*/     ULONG32      PrivateMemory : 1;    // 20 BitPosition                 
}MMVAD_FLAGS, * PMMVAD_FLAGS;

typedef struct _MM_SHARED_VAD_FLAGS            // 11 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Lock : 1;                     // 0 BitPosition                   
	/*0x000*/     ULONG32      LockContended : 1;            // 1 BitPosition                   
	/*0x000*/     ULONG32      DeleteInProgress : 1;         // 2 BitPosition                   
	/*0x000*/     ULONG32      NoChange : 1;                 // 3 BitPosition                   
	/*0x000*/     ULONG32      VadType : 3;                  // 4 BitPosition                   
	/*0x000*/     ULONG32      Protection : 5;               // 7 BitPosition                   
	/*0x000*/     ULONG32      PreferredNode : 6;            // 12 BitPosition                  
	/*0x000*/     ULONG32      PageSize : 2;                 // 18 BitPosition                  
	/*0x000*/     ULONG32      PrivateMemoryAlwaysClear : 1; // 20 BitPosition                  
	/*0x000*/     ULONG32      PrivateFixup : 1;             // 21 BitPosition                  
	/*0x000*/     ULONG32      HotPatchAllowed : 1;          // 22 BitPosition                  
}MM_SHARED_VAD_FLAGS, * PMM_SHARED_VAD_FLAGS;

typedef struct _MMVAD_FLAGS2             // 7 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     ULONG32      FileOffset : 24;        // 0 BitPosition                  
	/*0x000*/     ULONG32      Large : 1;              // 24 BitPosition                 
	/*0x000*/     ULONG32      TrimBehind : 1;         // 25 BitPosition                 
	/*0x000*/     ULONG32      Inherit : 1;            // 26 BitPosition                 
	/*0x000*/     ULONG32      NoValidationNeeded : 1; // 27 BitPosition                 
	/*0x000*/     ULONG32      PrivateDemandZero : 1;  // 28 BitPosition                 
	/*0x000*/     ULONG32      Spare : 3;              // 29 BitPosition                 
}MMVAD_FLAGS2, * PMMVAD_FLAGS2;

typedef struct _MMVAD_SHORT
{
	RTL_BALANCED_NODE VadNode;
	UINT32 StartingVpn;               /*0x18*/
	UINT32 EndingVpn;                 /*0x01C*/
	UCHAR StartingVpnHigh;
	UCHAR EndingVpnHigh;
	UCHAR CommitChargeHigh;
	UCHAR SpareNT64VadUChar;
	INT32 ReferenceCount;
	EX_PUSH_LOCK PushLock;            /*0x028*/
	struct
	{
		union
		{
			ULONG_PTR flag;
			MM_PRIVATE_VAD_FLAGS PrivateVadFlags;                        /*0x030*/
			MMVAD_FLAGS  VadFlags;
			MM_GRAPHICS_VAD_FLAGS GraphicsVadFlags;
			MM_SHARED_VAD_FLAGS   SharedVadFlags;
		}Flags;

	}u1;

	PVOID EventList;                        /*0x038*/

}MMVAD_SHORT, * PMMVAD_SHORT;

typedef struct _MMADDRESS_NODE
{
	ULONG64 u1;
	struct _MMADDRESS_NODE* LeftChild;
	struct _MMADDRESS_NODE* RightChild;
	ULONG64 StartingVpn;
	ULONG64 EndingVpn;
}MMADDRESS_NODE, * PMMADDRESS_NODE;

typedef struct _MMEXTEND_INFO     // 2 elements, 0x10 bytes (sizeof) 
{
	/*0x000*/     UINT64       CommittedSize;
	/*0x008*/     ULONG32      ReferenceCount;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
}MMEXTEND_INFO, * PMMEXTEND_INFO;
struct _SEGMENT
{
	struct _CONTROL_AREA* ControlArea;
	ULONG TotalNumberOfPtes;
	ULONG SegmentFlags;
	ULONG64 NumberOfCommittedPages;
	ULONG64 SizeOfSegment;
	union
	{
		struct _MMEXTEND_INFO* ExtendInfo;
		void* BasedAddress;
	}u;
	ULONG64 SegmentLock;
	ULONG64 u1;
	ULONG64 u2;
	PVOID* PrototypePte;
	ULONGLONG ThePtes[0x1];
};

typedef struct _EX_FAST_REF
{
	union
	{
		PVOID Object;
		ULONG_PTR RefCnt : 3;
		ULONG_PTR Value;
	};
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _CONTROL_AREA                      // 17 elements, 0x80 bytes (sizeof) 
{
	/*0x000*/     struct _SEGMENT* Segment;
	union                                         // 2 elements, 0x10 bytes (sizeof)  
	{
		/*0x008*/         struct _LIST_ENTRY ListHead;              // 2 elements, 0x10 bytes (sizeof)  
		/*0x008*/         VOID* AweContext;
	};
	/*0x018*/     UINT64       NumberOfSectionReferences;
	/*0x020*/     UINT64       NumberOfPfnReferences;
	/*0x028*/     UINT64       NumberOfMappedViews;
	/*0x030*/     UINT64       NumberOfUserReferences;
	/*0x038*/     ULONG32 u;                     // 2 elements, 0x4 bytes (sizeof)   
	/*0x03C*/     ULONG32 u1;                    // 2 elements, 0x4 bytes (sizeof)   
	/*0x040*/     struct _EX_FAST_REF FilePointer;              // 3 elements, 0x8 bytes (sizeof)   
	// 4 elements, 0x8 bytes (sizeof)   
}CONTROL_AREA, * PCONTROL_AREA;

typedef struct _SUBSECTION_
{
	struct _CONTROL_AREA* ControlArea;

}SUBSECTION, * PSUBSECTION;

typedef struct _MMVAD
{
	MMVAD_SHORT Core;
	union                 /*0x040*/
	{
		UINT32 LongFlags2;
		//现在用不到省略
		MMVAD_FLAGS2 VadFlags2;

	}u2;
	PSUBSECTION Subsection;               /*0x048*/
	PVOID FirstPrototypePte;        /*0x050*/
	PVOID LastContiguousPte;        /*0x058*/
	LIST_ENTRY ViewLinks;           /*0x060*/
	PEPROCESS VadsProcess;          /*0x070*/
	PVOID u4;                       /*0x078*/
	PVOID FileObject;               /*0x080*/
}MMVAD, * PMMVAD;

typedef struct _RTL_AVL_TREE         // 1 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_BALANCED_NODE* Root;
}RTL_AVL_TREE, * PRTL_AVL_TREE;

typedef struct _VAD_INFO_
{
	ULONG_PTR pVad;
	ULONG_PTR startVpn;
	ULONG_PTR endVpn;
	ULONG_PTR pFileObject;
	ULONG_PTR flags;
}VAD_INFO, * PVAD_INFO;

typedef struct _ALL_VADS_
{
	ULONG nCnt;
	VAD_INFO VadInfos[1];
}ALL_VADS, * PALL_VADS;

typedef struct _MMSECTION_FLAGS                        // 27 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     UINT32       BeingDeleted : 1;                     // 0 BitPosition                   
	/*0x000*/     UINT32       BeingCreated : 1;                     // 1 BitPosition                   
	/*0x000*/     UINT32       BeingPurged : 1;                      // 2 BitPosition                   
	/*0x000*/     UINT32       NoModifiedWriting : 1;                // 3 BitPosition                   
	/*0x000*/     UINT32       FailAllIo : 1;                        // 4 BitPosition                   
	/*0x000*/     UINT32       Image : 1;                            // 5 BitPosition                   
	/*0x000*/     UINT32       Based : 1;                            // 6 BitPosition                   
	/*0x000*/     UINT32       File : 1;                             // 7 BitPosition                   
	/*0x000*/     UINT32       AttemptingDelete : 1;                 // 8 BitPosition                   
	/*0x000*/     UINT32       PrefetchCreated : 1;                  // 9 BitPosition                   
	/*0x000*/     UINT32       PhysicalMemory : 1;                   // 10 BitPosition                  
	/*0x000*/     UINT32       ImageControlAreaOnRemovableMedia : 1; // 11 BitPosition                  
	/*0x000*/     UINT32       Reserve : 1;                          // 12 BitPosition                  
	/*0x000*/     UINT32       Commit : 1;                           // 13 BitPosition                  
	/*0x000*/     UINT32       NoChange : 1;                         // 14 BitPosition                  
	/*0x000*/     UINT32       WasPurged : 1;                        // 15 BitPosition                  
	/*0x000*/     UINT32       UserReference : 1;                    // 16 BitPosition                  
	/*0x000*/     UINT32       GlobalMemory : 1;                     // 17 BitPosition                  
	/*0x000*/     UINT32       DeleteOnClose : 1;                    // 18 BitPosition                  
	/*0x000*/     UINT32       FilePointerNull : 1;                  // 19 BitPosition                  
	/*0x000*/     ULONG32      PreferredNode : 6;                    // 20 BitPosition                  
	/*0x000*/     UINT32       GlobalOnlyPerSession : 1;             // 26 BitPosition                  
	/*0x000*/     UINT32       UserWritable : 1;                     // 27 BitPosition                  
	/*0x000*/     UINT32       SystemVaAllocated : 1;                // 28 BitPosition                  
	/*0x000*/     UINT32       PreferredFsCompressionBoundary : 1;   // 29 BitPosition                  
	/*0x000*/     UINT32       UsingFileExtents : 1;                 // 30 BitPosition                  
	/*0x000*/     UINT32       PageSize64K : 1;                      // 31 BitPosition                  
}MMSECTION_FLAGS, * PMMSECTION_FLAGS;

typedef struct _SECTION                          // 9 elements, 0x40 bytes (sizeof) 
{
	/*0x000*/     struct _RTL_BALANCED_NODE SectionNode;       // 6 elements, 0x18 bytes (sizeof) 
	/*0x018*/     UINT64       StartingVpn;
	/*0x020*/     UINT64       EndingVpn;
	/*0x028*/     union {
		PCONTROL_AREA   ControlArea;
		PVOID   FileObject;

	}u1;                   // 4 elements, 0x8 bytes (sizeof)  
	/*0x030*/     UINT64       SizeOfSection;
	/*0x038*/     union {
		ULONG32 LongFlags;
		MMSECTION_FLAGS Flags;
	}u;                    // 2 elements, 0x4 bytes (sizeof)  
	struct                                       // 3 elements, 0x4 bytes (sizeof)  
	{
		/*0x03C*/         ULONG32      InitialPageProtection : 12; // 0 BitPosition                   
		/*0x03C*/         ULONG32      SessionId : 19;             // 12 BitPosition                  
		/*0x03C*/         ULONG32      NoValidationNeeded : 1;     // 31 BitPosition                  
	};
}SECTION, * PSECTION;


//vad------------------------------------







//PEB------------------------------------

typedef struct _PEB_LDR_DATA32
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    ULONG SsHandle;                                                         //0x8
    LIST_ENTRY32 InLoadOrderModuleList;                               //0xc
    LIST_ENTRY32 InMemoryOrderModuleList;                             //0x14
    LIST_ENTRY32 InInitializationOrderModuleList;                     //0x1c
    ULONG EntryInProgress;                                                  //0x24
    UCHAR ShutdownInProgress;                                               //0x28
    ULONG ShutdownThreadId;                                                 //0x2c
}PEB_LDR_DATA32, * PPEB_LDR_DATA32;
typedef struct _LDR_DATA_TABLE_ENTRY64
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    LONGLONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
}LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32 InLoadOrderLinks;                                    //0x0
    LIST_ENTRY32 InMemoryOrderLinks;                                  //0x8
    LIST_ENTRY32 InInitializationOrderLinks;                          //0x10
    ULONG DllBase;                                                          //0x18
    ULONG EntryPoint;                                                       //0x1c
    ULONG SizeOfImage;                                                      //0x20
    UNICODE_STRING32 FullDllName;                                     //0x24
    UNICODE_STRING32 BaseDllName;                                     //0x2c
    ULONG Flags;                                                            //0x34
    USHORT LoadCount;                                                       //0x38
    USHORT TlsIndex;                                                        //0x3a
}LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
typedef struct _PEB_LDR_DATA64
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA64, * PPEB_LDR_DATA64;
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;                                         //0x0
    VOID* Handle;                                                           //0x10
}CURDIR, * PCURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;                                                           //0x0
    USHORT Length;                                                          //0x2
    ULONG TimeStamp;                                                        //0x4
    STRING DosPath;                                                 //0x8
}RTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
    ULONG MaximumLength;                                                    //0x0
    ULONG Length;                                                           //0x4
    ULONG Flags;                                                            //0x8
    ULONG DebugFlags;                                                       //0xc
    VOID* ConsoleHandle;                                                    //0x10
    ULONG ConsoleFlags;                                                     //0x18
    VOID* StandardInput;                                                    //0x20
    VOID* StandardOutput;                                                   //0x28
    VOID* StandardError;                                                    //0x30
    CURDIR CurrentDirectory;                                        //0x38
    UNICODE_STRING DllPath;                                         //0x50
    UNICODE_STRING ImagePathName;                                   //0x60
    UNICODE_STRING CommandLine;                                     //0x70
    VOID* Environment;                                                      //0x80
    ULONG StartingX;                                                        //0x88
    ULONG StartingY;                                                        //0x8c
    ULONG CountX;                                                           //0x90
    ULONG CountY;                                                           //0x94
    ULONG CountCharsX;                                                      //0x98
    ULONG CountCharsY;                                                      //0x9c
    ULONG FillAttribute;                                                    //0xa0
    ULONG WindowFlags;                                                      //0xa4
    ULONG ShowWindowFlags;                                                  //0xa8
    UNICODE_STRING WindowTitle;                                     //0xb0
    UNICODE_STRING DesktopInfo;                                     //0xc0
    UNICODE_STRING ShellInfo;                                       //0xd0
    UNICODE_STRING RuntimeData;                                     //0xe0
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
    ULONGLONG EnvironmentSize;                                              //0x3f0
    ULONGLONG EnvironmentVersion;                                           //0x3f8
    VOID* PackageDependencyData;                                            //0x400
    ULONG ProcessGroupId;                                                   //0x408
    ULONG LoaderThreads;                                                    //0x40c
    UNICODE_STRING RedirectionDllName;                              //0x410
    UNICODE_STRING HeapPartitionName;                               //0x420
    ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
    ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
    ULONG DefaultThreadpoolThreadMaximum;                                   //0x43c
}RTL_USER_PROCESS_PARAMETERS64, * PRTL_USER_PROCESS_PARAMETERS64;


typedef struct _RTL_DRIVE_LETTER_CURDIR32
{
	USHORT Flags;                                                           //0x0
	USHORT Length;                                                          //0x2
	ULONG TimeStamp;                                                        //0x4
	STRING32 DosPath;                                                 //0x8
}RTL_DRIVE_LETTER_CURDIR32, * PRTL_DRIVE_LETTER_CURDIR32;
typedef struct _CURDIR32
{
	UNICODE_STRING32 DosPath;                                         //0x0
	ULONG Handle;                                                           //0x8
}CURDIR32, * PCURDIR32;
typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	ULONG ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x14
	ULONG StandardInput;                                                    //0x18
	ULONG StandardOutput;                                                   //0x1c
	ULONG StandardError;                                                    //0x20
	CURDIR32 CurrentDirectory;                                        //0x24
	UNICODE_STRING32 DllPath;                                         //0x30
	UNICODE_STRING32 ImagePathName;                                   //0x38
	UNICODE_STRING32 CommandLine;                                     //0x40
	ULONG Environment;                                                      //0x48
	ULONG StartingX;                                                        //0x4c
	ULONG StartingY;                                                        //0x50
	ULONG CountX;                                                           //0x54
	ULONG CountY;                                                           //0x58
	ULONG CountCharsX;                                                      //0x5c
	ULONG CountCharsY;                                                      //0x60
	ULONG FillAttribute;                                                    //0x64
	ULONG WindowFlags;                                                      //0x68
	ULONG ShowWindowFlags;                                                  //0x6c
	UNICODE_STRING32 WindowTitle;                                     //0x70
	UNICODE_STRING32 DesktopInfo;                                     //0x78
	UNICODE_STRING32 ShellInfo;                                       //0x80
	UNICODE_STRING32 RuntimeData;                                     //0x88
	RTL_DRIVE_LETTER_CURDIR32 CurrentDirectores[32];                  //0x90
	ULONG EnvironmentSize;                                                  //0x290
	ULONG EnvironmentVersion;                                               //0x294
	ULONG PackageDependencyData;                                            //0x298
	ULONG ProcessGroupId;                                                   //0x29c
	ULONG LoaderThreads;                                                    //0x2a0
	UNICODE_STRING32 RedirectionDllName;                              //0x2a4
	UNICODE_STRING32 HeapPartitionName;                               //0x2ac
	ULONG DefaultThreadpoolCpuSetMasks;                                //0x2b4
	ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x2b8
	ULONG DefaultThreadpoolThreadMaximum;                                   //0x2bc
}RTL_USER_PROCESS_PARAMETERS32, * PRTL_USER_PROCESS_PARAMETERS32;
typedef struct _PEB32 {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR Spare;
    ULONG Mutant;
    ULONG ImageBaseAddress;
    ULONG/*PPEB_LDR_DATA32*/ Ldr;
    ULONG ProcessParameters;                                                //0x10
} PEB32, * PPEB32;
typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsLegacyProcess : 1;                                        //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR SpareBits : 3;                                              //0x3
        };
    };
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    PRTL_USER_PROCESS_PARAMETERS64 ProcessParameters;
}PEB64, * PPEB64;
//PEB------------------------------------



//_TOKEN------------------------------------
struct _SEP_AUDIT_POLICY
{
	struct _TOKEN_AUDIT_POLICY AdtTokenPolicy;                              //0x0
	UCHAR PolicySetStatus;                                                  //0x1e
};
struct _SEP_TOKEN_PRIVILEGES
{
	ULONGLONG Present;                                                      //0x0
	ULONGLONG Enabled;                                                      //0x8
	ULONGLONG EnabledByDefault;                                             //0x10
};
struct _TOKEN
{
	struct _TOKEN_SOURCE TokenSource;                                       //0x0
	struct _LUID TokenId;                                                   //0x10
	struct _LUID AuthenticationId;                                          //0x18
	struct _LUID ParentTokenId;                                             //0x20
	union _LARGE_INTEGER ExpirationTime;                                    //0x28
	struct _ERESOURCE* TokenLock;                                           //0x30
	struct _LUID ModifiedId;                                                //0x38
	struct _SEP_TOKEN_PRIVILEGES Privileges;                                //0x40
	struct _SEP_AUDIT_POLICY AuditPolicy;                                   //0x58
	ULONG SessionId;                                                        //0x78
	ULONG UserAndGroupCount;                                                //0x7c
	ULONG RestrictedSidCount;                                               //0x80
	ULONG VariableLength;                                                   //0x84
	ULONG DynamicCharged;                                                   //0x88
	ULONG DynamicAvailable;                                                 //0x8c
	ULONG DefaultOwnerIndex;                                                //0x90
	struct _SID_AND_ATTRIBUTES* UserAndGroups;                              //0x98
	struct _SID_AND_ATTRIBUTES* RestrictedSids;                             //0xa0
	VOID* PrimaryGroup;                                                     //0xa8
	ULONG* DynamicPart;                                                     //0xb0
	struct _ACL* DefaultDacl;                                               //0xb8
	enum _TOKEN_TYPE TokenType;                                             //0xc0
	enum _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;                  //0xc4
	ULONG TokenFlags;                                                       //0xc8
	UCHAR TokenInUse;                                                       //0xcc
	ULONG IntegrityLevelIndex;                                              //0xd0
	ULONG MandatoryPolicy;                                                  //0xd4
	struct _SEP_LOGON_SESSION_REFERENCES* LogonSession;                     //0xd8
	struct _LUID OriginatingLogonSession;                                   //0xe0
	struct _SID_AND_ATTRIBUTES_HASH SidHash;                                //0xe8
	struct _SID_AND_ATTRIBUTES_HASH RestrictedSidHash;                      //0x1f8
	struct _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION* pSecurityAttributes; //0x308
	VOID* Package;                                                          //0x310
	struct _SID_AND_ATTRIBUTES* Capabilities;                               //0x318
	ULONG CapabilityCount;                                                  //0x320
	struct _SID_AND_ATTRIBUTES_HASH CapabilitiesHash;                       //0x328
	struct _SEP_LOWBOX_NUMBER_ENTRY* LowboxNumberEntry;                     //0x438
	struct _SEP_CACHED_HANDLES_ENTRY* LowboxHandlesEntry;                   //0x440
	struct _AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION* pClaimAttributes;       //0x448
	VOID* TrustLevelSid;                                                    //0x450
	struct _TOKEN* TrustLinkedToken;                                        //0x458
	VOID* IntegrityLevelSidValue;                                           //0x460
	struct _SEP_SID_VALUES_BLOCK* TokenSidValues;                           //0x468
	struct _SEP_LUID_TO_INDEX_MAP_ENTRY* IndexEntry;                        //0x470
	struct _SEP_TOKEN_DIAG_TRACK_ENTRY* DiagnosticInfo;                     //0x478
	struct _SEP_CACHED_HANDLES_ENTRY* BnoIsolationHandlesEntry;             //0x480
	VOID* SessionObject;                                                    //0x488
	ULONGLONG VariablePart;                                                 //0x490
};
//_TOKEN------------------------------------
//PPL------------------------------------
//0x1 bytes (sizeof)
struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;                                                        //0x0
		struct
		{
			UCHAR Type : 3;                                                   //0x0
			UCHAR Audit : 1;                                                  //0x0
			UCHAR Signer : 4;                                                 //0x0
		};
	};
};
//PPL------------------------------------

typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientIs;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   ThreadState;
	KWAIT_REASON            WaitReason;
}SYSTEM_THREADS, * PSYSTEM_THREADS;

#pragma pack(8)
//进程信息结构体  
typedef struct _SYSTEM_PROCESSES
{
	ULONG                           NextEntryDelta;    //链表下一个结构和上一个结构的偏移
	ULONG                           ThreadCount;
	ULONG                           Reserved[6];
	LARGE_INTEGER                   CreateTime;
	LARGE_INTEGER                   UserTime;
	LARGE_INTEGER                   KernelTime;
	UNICODE_STRING                  ProcessName;     //进程名字
	KPRIORITY                       BasePriority;
	size_t                          ProcessId;      //进程的pid号
	size_t                          InheritedFromProcessId;
	ULONG                           HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	VM_COUNTERS                     VmCounters;
	IO_COUNTERS                     IoCounters; //windows 2000 only  
	struct _SYSTEM_THREADS          Threads[1];
}SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;




//API------------------------------------
EXTERN_C PVOID NTAPI PsGetProcessWow64Process(_In_ PEPROCESS Process);
EXTERN_C PVOID NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);
EXTERN_C PCHAR PsGetProcessImageFileName(PEPROCESS pEProcess);
EXTERN_C NTSTATUS PsReferenceProcessFilePointer(PEPROCESS Process, PFILE_OBJECT* OutFileObject);
EXTERN_C NTSTATUS MmCopyVirtualMemory(
    IN PEPROCESS FromProcess,
    IN CONST VOID* FromAddress,
    IN PEPROCESS ToProcess,
    OUT PVOID ToAddress,
    IN SIZE_T BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T NumberOfBytesCopied
);

EXTERN_C
NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);


EXTERN_C NTSTATUS ZwQuerySystemInformation(
	DWORD32 systemInformationClass,
	PVOID systemInformation,
	ULONG systemInformationLength,
	PULONG returnLength);

EXTERN_C NTSTATUS
NTAPI
ZwOpenThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
);

EXTERN_C NTSTATUS
NTAPI
ZwGetNextThread(
	__in HANDLE ProcessHandle,
	__in HANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in ULONG HandleAttributes,
	__in ULONG Flags,
	__out PHANDLE NewThreadHandle
);

EXTERN_C NTSTATUS
NTAPI
PsSetContextThread(
	__in PETHREAD Thread,
	__in PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
);

EXTERN_C NTSTATUS
NTAPI
PsGetContextThread(
	__in PETHREAD Thread,
	__inout PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
);

EXTERN_C
PVOID
PsGetThreadTeb(
	__in PETHREAD Thread
);
EXTERN_C PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);
//API------------------------------------


EXTERN_C POBJECT_TYPE* IoDriverObjectType;