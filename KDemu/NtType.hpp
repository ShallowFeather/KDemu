

#define OBJ_CASE_INSENSITIVE 0x00000040
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = r;                         \
    (p)->Attributes = a;                            \
    (p)->ObjectName = n;                            \
    (p)->SecurityDescriptor = s;                    \
    (p)->SecurityQualityOfService = NULL;           \
}
#endif
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
    ULONG ProviderSignature;
    ULONG Action;
    ULONG TableID;
    ULONG Reserved;
    UCHAR Data[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    uint64_t ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

struct FAKE_MDL {
    uint64_t Next;
    uint16_t Size;
    uint16_t MdlFlags;
    uint64_t Process;
    uint64_t MappedSystemVa;
    uint64_t StartVa;
    uint32_t ByteCount;
    uint32_t ByteOffset;
};
enum OB_OPERATION {
    OB_OPERATION_HANDLE_CREATE = 0x1,
    OB_OPERATION_HANDLE_DUPLICATE = 0x2
};
using POB_PRE_OPERATION_CALLBACK = uint64_t;
using POB_POST_OPERATION_CALLBACK = uint64_t;

struct _OBJECT_TYPE {
    UNICODE_STRING Name;
    uint32_t ObjectTypeFlags;
};
typedef struct _OBJECT_TYPE* POBJECT_TYPE;

typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE ObjectType;
    OB_OPERATION Operations;
    POB_PRE_OPERATION_CALLBACK PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, * POB_OPERATION_REGISTRATION;



typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT Version;
    USHORT OperationRegistrationCount;
    UNICODE_STRING Altitude;
    PVOID RegistrationContext;
    OB_OPERATION_REGISTRATION* OperationRegistration;
} OB_CALLBACK_REGISTRATION, * POB_CALLBACK_REGISTRATION;


struct ObCallbackEntry {
    uint64_t RegistrationContext;
    uint64_t ObjectType;
    uint32_t Operations;
    uint64_t PreOperation;
    uint64_t PostOperation;
};

typedef struct _WIN_CERTIFICATE
{
    DWORD dwLength;
    WORD  wRevision;
    WORD  wCertificateType;
    BYTE  bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE, * LPWIN_CERTIFICATE;


typedef enum _KERNEL_STACK_LIMITS {
    BugcheckStackLimits,
    DPCStackLimits,
    ExpandedStackLimits,
    NormalStackLimits,
    Win32kStackLimits,
    MaximumStackLimits
} KERNEL_STACK_LIMITS, * PKERNEL_STACK_LIMITS;
typedef struct _KERNEL_STACK_SEGMENT
{
    ULONG StackBase;
    ULONG StackLimit;
    ULONG KernelStack;
    ULONG InitialStack;
    ULONG ActualLimit;
} KERNEL_STACK_SEGMENT, * PKERNEL_STACK_SEGMENT;



typedef struct _KTRAP_FRAME
{
    ULONG DbgEbp;
    ULONG DbgEip;
    ULONG DbgArgMark;
    ULONG DbgArgPointer;
    WORD TempSegCs;
    UCHAR Logging;
    UCHAR Reserved;
    ULONG TempEsp;
    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;
    ULONG SegGs;
    ULONG SegEs;
    ULONG SegDs;
    ULONG Edx;
    ULONG Ecx;
    ULONG Eax;
    ULONG PreviousPreviousMode;
    PEXCEPTION_REGISTRATION_RECORD ExceptionList;
    ULONG SegFs;
    ULONG Edi;
    ULONG Esi;
    ULONG Ebx;
    ULONG Ebp;
    ULONG ErrCode;
    ULONG Eip;
    ULONG SegCs;
    ULONG EFlags;
    ULONG HardwareEsp;
    ULONG HardwareSegSs;
    ULONG V86Es;
    ULONG V86Ds;
    ULONG V86Fs;
    ULONG V86Gs;
} KTRAP_FRAME, * PKTRAP_FRAME;
typedef struct _KERNEL_STACK_CONTROL
{
    union
    {
        PKTRAP_FRAME PreviousTrapFrame;
        PVOID PreviousExceptionList;
    };
    ULONG StackControlFlags;
    ULONG PreviousLargeStack : 1;
    ULONG PreviousSegmentsPresent : 1;
    ULONG ExpandCalloutStack : 1;
    KERNEL_STACK_SEGMENT Previous;
} KERNEL_STACK_CONTROL, * PKERNEL_STACK_CONTROL;


union SegmentDescriptor {
    ULONG64 all;
    struct {
        ULONG64 limit_low : 16;
        ULONG64 base_low : 16;
        ULONG64 base_mid : 8;
        ULONG64 type : 4;
        ULONG64 system : 1;
        ULONG64 dpl : 2;
        ULONG64 present : 1;
        ULONG64 limit_high : 4;
        ULONG64 avl : 1;
        ULONG64 l : 1;
        ULONG64 db : 1;
        ULONG64 gran : 1;
        ULONG64 base_high : 8;
    } fields;
};

struct SegmentDesctiptorX64 {
    SegmentDescriptor descriptor;
    ULONG32 base_upper32;
    ULONG32 reserved;
};

union SegmentSelector {
    unsigned short all;
    struct {
        unsigned short rpl : 2;
        unsigned short ti : 1;
        unsigned short index : 13;
    } fields;
};

enum class Msr : unsigned int {
    kIa32ApicBase = 0x01B,

    kIa32FeatureControl = 0x03A,

    kIa32SysenterCs = 0x174,
    kIa32SysenterEsp = 0x175,
    kIa32SysenterEip = 0x176,

    kIa32Debugctl = 0x1D9,

    kIa32MtrrCap = 0xFE,
    kIa32MtrrDefType = 0x2FF,
    kIa32MtrrPhysBaseN = 0x200,
    kIa32MtrrPhysMaskN = 0x201,
    kIa32MtrrFix64k00000 = 0x250,
    kIa32MtrrFix16k80000 = 0x258,
    kIa32MtrrFix16kA0000 = 0x259,
    kIa32MtrrFix4kC0000 = 0x268,
    kIa32MtrrFix4kC8000 = 0x269,
    kIa32MtrrFix4kD0000 = 0x26A,
    kIa32MtrrFix4kD8000 = 0x26B,
    kIa32MtrrFix4kE0000 = 0x26C,
    kIa32MtrrFix4kE8000 = 0x26D,
    kIa32MtrrFix4kF0000 = 0x26E,
    kIa32MtrrFix4kF8000 = 0x26F,

    kIa32VmxBasic = 0x480,
    kIa32VmxPinbasedCtls = 0x481,
    kIa32VmxProcBasedCtls = 0x482,
    kIa32VmxExitCtls = 0x483,
    kIa32VmxEntryCtls = 0x484,
    kIa32VmxMisc = 0x485,
    kIa32VmxCr0Fixed0 = 0x486,
    kIa32VmxCr0Fixed1 = 0x487,
    kIa32VmxCr4Fixed0 = 0x488,
    kIa32VmxCr4Fixed1 = 0x489,
    kIa32VmxVmcsEnum = 0x48A,
    kIa32VmxProcBasedCtls2 = 0x48B,
    kIa32VmxEptVpidCap = 0x48C,
    kIa32VmxTruePinbasedCtls = 0x48D,
    kIa32VmxTrueProcBasedCtls = 0x48E,
    kIa32VmxTrueExitCtls = 0x48F,
    kIa32VmxTrueEntryCtls = 0x490,
    kIa32VmxVmfunc = 0x491,

    kIa32Efer = 0xC0000080,
    kIa32Star = 0xC0000081,
    kIa32Lstar = 0xC0000082,

    kIa32Fmask = 0xC0000084,

    kIa32FsBase = 0xC0000100,
    kIa32GsBase = 0xC0000101,
    kIa32KernelGsBase = 0xC0000102,
    kIa32TscAux = 0xC0000103,
};

typedef struct _KPCR
{
    SegmentDesctiptorX64 gdt[8];
}KPCR;

union FlagRegister {
    ULONG_PTR all;
    struct {
        ULONG_PTR cf : 1;
        ULONG_PTR reserved1 : 1;
        ULONG_PTR pf : 1;
        ULONG_PTR reserved2 : 1;
        ULONG_PTR af : 1;
        ULONG_PTR reserved3 : 1;
        ULONG_PTR zf : 1;
        ULONG_PTR sf : 1;
        ULONG_PTR tf : 1;
        ULONG_PTR intf : 1;
        ULONG_PTR df : 1;
        ULONG_PTR of : 1;
        ULONG_PTR iopl : 2;
        ULONG_PTR nt : 1;
        ULONG_PTR reserved4 : 1;
        ULONG_PTR rf : 1;
        ULONG_PTR vm : 1;
        ULONG_PTR ac : 1;
        ULONG_PTR vif : 1;
        ULONG_PTR vip : 1;
        ULONG_PTR id : 1;
        ULONG_PTR reserved5 : 10;
    } fields;
};



/*
    x64的teb_64 32位的没做
*/
struct _ACTIVATION_CONTEXT_STACK
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;
    struct _LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
};
struct _GDI_TEB_BATCH
{
    ULONG Offset : 31;
    ULONG HasRenderingCommand : 1;
    ULONGLONG HDC;
    ULONG Buffer[310];
};
struct _CLIENT_ID
{
    DWORD64 UniqueProcess;
    DWORD64 UniqueThread;
};
static_assert(sizeof(_CLIENT_ID) == 0x10, "_CLIENT_ID Size check");

static_assert(sizeof(_NT_TIB) == 0x38, "_NT_TIB Size check");
typedef struct X64TEB {
    struct _NT_TIB NtTib;
    VOID* EnvironmentPointer;
    struct _CLIENT_ID ClientId;
    VOID* ActiveRpcHandle;
    VOID* ThreadLocalStoragePointer;
    struct _PEB* ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    VOID* CsrClientThread;
    VOID* Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    VOID* WOW32Reserved;
    ULONG CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    VOID* ReservedForDebuggerInstrumentation[16];
    VOID* SystemReserved1[30];
    CHAR PlaceholderCompatibilityMode;
    UCHAR PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];
    ULONG ProxiedProcessId;
    struct _ACTIVATION_CONTEXT_STACK _ActivationStack;
    UCHAR WorkingOnBehalfTicket[8];
    LONG ExceptionCode;
    UCHAR Padding0[4];
    struct _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
    ULONGLONG InstrumentationCallbackSp;
    ULONGLONG InstrumentationCallbackPreviousPc;
    ULONGLONG InstrumentationCallbackPreviousSp;
    ULONG TxFsContext;
    UCHAR InstrumentationCallbackDisabled;
    UCHAR UnalignedLoadStoreExceptions;
    UCHAR Padding1[2];
    struct _GDI_TEB_BATCH GdiTebBatch;
    struct _CLIENT_ID RealClientId;
    VOID* GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    VOID* GdiThreadLocalInfo;
    ULONGLONG Win32ClientInfo[62];
    VOID* glDispatchTable[233];
    ULONGLONG glReserved1[29];
    VOID* glReserved2;
    VOID* glSectionInfo;
    VOID* glSection;
    VOID* glTable;
    VOID* glCurrentRC;
    VOID* glContext;
    ULONG LastStatusValue;
    UCHAR Padding2[4];
    struct _UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    UCHAR Padding3[6];
    VOID* DeallocationStack;
    VOID* TlsSlots[64];
    struct _LIST_ENTRY TlsLinks;
    VOID* Vdm;
    VOID* ReservedForNtRpc;
    VOID* DbgSsReserved[2];
    ULONG HardErrorMode;
    UCHAR Padding4[4];
    VOID* Instrumentation[11];
    struct _GUID ActivityId;
    VOID* SubProcessTag;
    VOID* PerflibData;
    VOID* EtwTraceData;
    VOID* WinSockData;
    ULONG GdiBatchCount;
    union
    {
        struct _PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };
    ULONG GuaranteedStackBytes;
    UCHAR Padding5[4];
    VOID* ReservedForPerf;
    VOID* ReservedForOle;
    ULONG WaitingOnLoaderLock;
    UCHAR Padding6[4];
    VOID* SavedPriorityState;
    ULONGLONG ReservedForCodeCoverage;
    VOID* ThreadPoolData;
    VOID** TlsExpansionSlots;
    VOID* DeallocationBStore;
    VOID* BStoreLimit;
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    VOID* NlsCache;
    VOID* pShimData;
    ULONG HeapData;
    UCHAR Padding7[4];
    VOID* CurrentTransactionHandle;
    struct _TEB_ACTIVE_FRAME* ActiveFrame;
    VOID* FlsData;
    VOID* PreferredLanguages;
    VOID* UserPrefLanguages;
    VOID* MergedPrefLanguages;
    ULONG MuiImpersonation;
    union
    {
        volatile USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SpareSameTebBits : 1;
        };
    };
    VOID* TxnScopeEnterCallback;
    VOID* TxnScopeExitCallback;
    VOID* TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    VOID* ResourceRetValue;
    VOID* ReservedForWdf;
    ULONGLONG ReservedForCrt;
    struct _GUID EffectiveContainerId;
};
static_assert(sizeof(X64TEB) == 0x1838, "TEB Size check");

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CREATE_NAMED_PIPE        0x01
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_QUERY_INFORMATION        0x05
#define IRP_MJ_SET_INFORMATION          0x06
#define IRP_MJ_QUERY_EA                 0x07
#define IRP_MJ_SET_EA                   0x08
#define IRP_MJ_FLUSH_BUFFERS            0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION 0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION   0x0b
#define IRP_MJ_DIRECTORY_CONTROL        0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL      0x0d
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL  0x0f
#define IRP_MJ_SHUTDOWN                 0x10
#define IRP_MJ_LOCK_CONTROL             0x11
#define IRP_MJ_CLEANUP                  0x12
#define IRP_MJ_CREATE_MAILSLOT          0x13
#define IRP_MJ_QUERY_SECURITY           0x14
#define IRP_MJ_SET_SECURITY             0x15
#define IRP_MJ_POWER                    0x16
#define IRP_MJ_SYSTEM_CONTROL           0x17
#define IRP_MJ_DEVICE_CHANGE            0x18
#define IRP_MJ_QUERY_QUOTA              0x19
#define IRP_MJ_SET_QUOTA                0x1a
#define IRP_MJ_PNP                      0x1b
#define IRP_MJ_PNP_POWER                IRP_MJ_PNP
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b



typedef struct _USER_DRIVER_OBJECT {
    SHORT Type;
    SHORT Size;
    PVOID DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PVOID DriverExtension;
    UNICODE_STRING DriverName;
    PVOID HardwareDatabase;
    PVOID FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PVOID MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} USER_DRIVER_OBJECT, * PUSER_DRIVER_OBJECT;


typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;
            UCHAR Balance : 2;
        };
        ULONGLONG ParentValue;
    };
};

struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;
    struct _LIST_ENTRY InMemoryOrderLinks;
    struct _LIST_ENTRY InInitializationOrderLinks;
    VOID* DllBase;
    VOID* EntryPoint;
    ULONG SizeOfImage;
    struct _UNICODE_STRING FullDllName;
    struct _UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    struct _LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    VOID* Lock;
    struct _LDR_DDAG_NODE* DdagNode;
    struct _LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    VOID* ParentDllBase;
    VOID* SwitchBackContext;
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONGLONG OriginalBase;
    union _LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    enum _LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel;
    ULONG CheckSum;
    VOID* ActivePatchImageBase;
    enum _LDR_HOT_PATCH_STATE HotPatchState;
};

struct _PRIMITIVE_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    WCHAR* Buffer;
};

typedef struct _DRIVER_OBJECT {
    SHORT Type;
    SHORT Size;
    struct _DEVICE_OBJECT* DeviceObject;
    ULONG Flags;
    VOID* DriverStart;
    ULONG DriverSize;
    VOID* DriverSection;
    struct _DRIVER_EXTENSION* DriverExtension;
    struct _PRIMITIVE_UNICODE_STRING DriverName;
    struct _PRIMITIVE_UNICODE_STRING* HardwareDatabase;
    struct _FAST_IO_DISPATCH* FastIoDispatch;
    LONG(*DriverInit)(struct _DRIVER_OBJECT* arg1, struct _UNICODE_STRING* arg2);
    VOID(*DriverStartIo)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2);
    VOID(*DriverUnload)(struct _DRIVER_OBJECT* arg1);
    PVOID MajorFunction;
}DRIVER_OBJECT, * PDRIVER_OBJECT;
struct _KDEVICE_QUEUE {
    SHORT Type;
    SHORT Size;
    struct _LIST_ENTRY DeviceListHead;
    ULONGLONG Lock;
    union {
        UCHAR Busy;
        struct {
            LONGLONG Reserved : 8;
            LONGLONG Hint : 56;
        };
    };
};
struct _KDPC {
    union {
        ULONG TargetInfoAsUlong;
        struct {
            UCHAR Type;
            UCHAR Importance;
            volatile USHORT Number;
        };
    };
    struct _SINGLE_LIST_ENTRY DpcListEntry;
    ULONGLONG ProcessorHistory;
    VOID(*DeferredRoutine)(struct _KDPC* arg1, VOID* arg2, VOID* arg3, VOID* arg4);
    VOID* DeferredContext;
    VOID* SystemArgument1;
    VOID* SystemArgument2;
    VOID* DpcData;
};
struct _KDEVICE_QUEUE_ENTRY {
    struct _LIST_ENTRY DeviceListEntry;
    ULONG SortKey;
    UCHAR Inserted;
};
struct _WAIT_CONTEXT_BLOCK {
    union {
        struct _KDEVICE_QUEUE_ENTRY WaitQueueEntry;
        struct {
            struct _LIST_ENTRY DmaWaitEntry;
            ULONG NumberOfChannels;
            ULONG SyncCallback : 1;
            ULONG DmaContext : 1;
            ULONG ZeroMapRegisters : 1;
            ULONG Reserved : 9;
            ULONG NumberOfRemapPages : 20;
        };
    };
    enum _IO_ALLOCATION_ACTION(*DeviceRoutine)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2, VOID* arg3, VOID* arg4);
    VOID* DeviceContext;
    ULONG NumberOfMapRegisters;
    VOID* DeviceObject;
    VOID* CurrentIrp;
    struct _KDPC* BufferChainingDpc;
};
struct _DISPATCHER_HEADER {
    union {
        volatile LONG Lock;
        LONG LockNV;
        struct {
            UCHAR Type;
            UCHAR Signalling;
            UCHAR Size;
            UCHAR Reserved1;
        };
        struct {
            UCHAR TimerType;
            union {
                UCHAR TimerControlFlags;
                struct {
                    UCHAR Absolute : 1;
                    UCHAR Wake : 1;
                    UCHAR EncodedTolerableDelay : 6;
                };
            };
            UCHAR Hand;
            union {
                UCHAR TimerMiscFlags;
                struct {
                    UCHAR Index : 6;
                    UCHAR Inserted : 1;
                    volatile UCHAR Expired : 1;
                };
            };
        };
        struct {
            UCHAR Timer2Type;
            union {
                UCHAR Timer2Flags;
                struct {
                    UCHAR Timer2Inserted : 1;
                    UCHAR Timer2Expiring : 1;
                    UCHAR Timer2CancelPending : 1;
                    UCHAR Timer2SetPending : 1;
                    UCHAR Timer2Running : 1;
                    UCHAR Timer2Disabled : 1;
                    UCHAR Timer2ReservedFlags : 2;
                };
            };
            UCHAR Timer2ComponentId;
            UCHAR Timer2RelativeId;
        };
        struct {
            UCHAR QueueType;
            union {
                UCHAR QueueControlFlags;
                struct {
                    UCHAR Abandoned : 1;
                    UCHAR DisableIncrement : 1;
                    UCHAR QueueReservedControlFlags : 6;
                };
            };
            UCHAR QueueSize;
            UCHAR QueueReserved;
        };
        struct {
            UCHAR ThreadType;
            UCHAR ThreadReserved;
            union {
                UCHAR ThreadControlFlags;
                struct {
                    UCHAR CycleProfiling : 1;
                    UCHAR CounterProfiling : 1;
                    UCHAR GroupScheduling : 1;
                    UCHAR AffinitySet : 1;
                    UCHAR Tagged : 1;
                    UCHAR EnergyProfiling : 1;
                    UCHAR SchedulerAssist : 1;
                    UCHAR ThreadReservedControlFlags : 1;
                };
            };
            union {
                UCHAR DebugActive;
                struct {
                    UCHAR ActiveDR7 : 1;
                    UCHAR Instrumented : 1;
                    UCHAR Minimal : 1;
                    UCHAR Reserved4 : 2;
                    UCHAR AltSyscall : 1;
                    UCHAR UmsScheduled : 1;
                    UCHAR UmsPrimary : 1;
                };
            };
        };
        struct {
            UCHAR MutantType;
            UCHAR MutantSize;
            UCHAR DpcActive;
            UCHAR MutantReserved;
        };
    };
    LONG SignalState;
    struct _LIST_ENTRY WaitListHead;
};

struct _KEVENT {
    struct _DISPATCHER_HEADER Header;
};

struct _DEVICE_OBJECT {
    SHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    struct _DRIVER_OBJECT* DriverObject;
    struct _DEVICE_OBJECT* NextDevice;
    struct _DEVICE_OBJECT* AttachedDevice;
    struct _IRP* CurrentIrp;
    struct _IO_TIMER* Timer;
    ULONG Flags;
    ULONG Characteristics;
    struct _VPB* Vpb;
    VOID* DeviceExtension;
    ULONG DeviceType;
    CHAR StackSize;
    union {
        struct _LIST_ENTRY ListEntry;
        struct _WAIT_CONTEXT_BLOCK Wcb;
    } Queue;
    ULONG AlignmentRequirement;
    struct _KDEVICE_QUEUE DeviceQueue;
    struct _KDPC Dpc;
    ULONG ActiveThreadCount;
    VOID* SecurityDescriptor;
    struct _KEVENT DeviceLock;
    USHORT SectorSize;
    USHORT Spare1;
    struct _DEVOBJ_EXTENSION* DeviceObjectExtension;
    VOID* Reserved;
};


typedef union _UNWIND_CODE {
    struct {
        UCHAR CodeOffset;
        UCHAR UnwindOp : 4;
        UCHAR OpInfo : 4;
    };

    USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    UCHAR Version : 3;
    UCHAR Flags : 5;
    UCHAR SizeOfProlog;
    UCHAR CountOfCodes;
    UCHAR FrameRegister : 4;
    UCHAR FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];


} UNWIND_INFO, * PUNWIND_INFO;
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SPARE_CODE1,
    UWOP_SPARE_CODE2,
    UWOP_SAVE_XMM128,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_OP_CODES, * PUNWIND_OP_CODES;

typedef struct _TIME_FIELDS {
    SHORT Year;
    SHORT Month;
    SHORT Day;
    SHORT Hour;
    SHORT Minute;
    SHORT Second;
    SHORT Milliseconds;
    SHORT Weekday;
} TIME_FIELDS, * PTIME_FIELDS;

struct FILE_STANDARD_INFORMATION {
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t NumberOfLinks;
    uint8_t  DeletePending;
    uint8_t  Directory;
};
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION;
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;
typedef LONG KPRIORITY;
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION {
    ULONG  CodeIntegrityOptions;
    ULONG  CodeIntegrityPolicy;
    ULONG  Reserved;
} SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION, * PSYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION;
typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
#pragma warning(push)
#pragma warning(disable: 4201)
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
#pragma warning(pop)

    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
typedef
VOID
(NTAPI* PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#endif

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

#define FILE_VALID_OPTION_FLAGS                 0x00ffffff
#define FILE_VALID_PIPE_OPTION_FLAGS            0x00000032
#define FILE_VALID_MAILSLOT_OPTION_FLAGS        0x00000032
#define FILE_VALID_SET_FLAGS                    0x00000036
struct RTL_BITMAP {
    uint32_t SizeOfBitMap;
    uint32_t* Buffer;
};

struct KPROCESS
{
    uint8_t Header[0x18];
    struct _LIST_ENTRY ProfileListHead;
    ULONGLONG DirectoryTableBase;
    struct _LIST_ENTRY ThreadListHead;
    ULONG ProcessLock;
    ULONG ProcessTimerDelay;
    ULONGLONG DeepFreezeStartTime;
    uint8_t Affinity[0x108];
    struct _LIST_ENTRY ReadyListHead;
    struct _SINGLE_LIST_ENTRY SwapListEntry;
    uint8_t ActiveProcessors[0x278 - 0x170];
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;
            ULONG DisableBoost : 1;
            ULONG DisableQuantum : 1;
            ULONG DeepFreeze : 1;
            ULONG TimerVirtualization : 1;
            ULONG CheckStackExtents : 1;
            ULONG CacheIsolationEnabled : 1;
            ULONG PpmPolicy : 4;
            ULONG VaSpaceDeleted : 1;
            ULONG MultiGroup : 1;
            ULONG ReservedFlags : 19;
        };
        volatile LONG ProcessFlags;
    };
    ULONG ActiveGroupsMask;
    CHAR BasePriority;
    CHAR QuantumReset;
    CHAR Visited;
    uint8_t Flags;
    USHORT ThreadSeed[32];
    USHORT IdealProcessor[32];
    USHORT IdealNode[32];
    USHORT IdealGlobalNode;
    USHORT Spare1;
    USHORT StackCount;
    struct _LIST_ENTRY ProcessListEntry;
    ULONGLONG CycleTime;
    ULONGLONG ContextSwitches;
    struct _KSCHEDULING_GROUP* SchedulingGroup;
    ULONG FreezeCount;
    ULONG KernelTime;
    ULONG UserTime;
    ULONG ReadyTime;
    ULONGLONG UserDirectoryTableBase;
    UCHAR AddressPolicy;
    UCHAR Spare2[71];
    VOID* InstrumentationCallback;
    union
    {
        ULONGLONG SecureHandle;
        struct
        {
            ULONGLONG SecureProcess : 1;
            ULONGLONG Unused : 1;
        } Flags;
    } SecureState;
    ULONGLONG KernelWaitTime;
    ULONGLONG UserWaitTime;
    ULONGLONG LastRebalanceQpc;
    VOID* PerProcessorCycleTimes;
    ULONGLONG ExtendedFeatureDisableMask;
    USHORT PrimaryGroup;
    USHORT Spare3[3];
    VOID* UserCetLogging;
    ULONGLONG EndPadding[3];
};

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    struct KPROCESS* Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
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

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX {
    USHORT NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG  ImageChecksum;
    ULONG  TimeDateStamp;
    PVOID  DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, * PRTL_PROCESS_MODULE_INFORMATION_EX;

typedef struct _RTL_PROCESS_MODULES_EX {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_EX Modules[1];
} RTL_PROCESS_MODULES_EX, * PRTL_PROCESS_MODULES_EX;


typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

struct SYSTEM_MODULE_INFORMATION_ENTRY {
    void* Section;
    void* MappedBase;
    void* ImageBase;
    uint32_t ImageSize;
    uint32_t Flags;
    uint16_t LoadOrderIndex;
    uint16_t InitOrderIndex;
    uint16_t LoadCount;
    uint16_t OffsetToFileName;
    char FullPathName[256];
};

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ModuleCount;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
typedef struct _Asn1BlobPtr
{
    int size;
    PVOID ptrToData;
} Asn1BlobPtr, * pAsn1BlobPtr;

typedef struct _CertificatePartyName
{
    PVOID pointerToName;
    short nameLen;
    short unknown;
} CertificatePartyName, * pCertificatePartyName;

typedef struct _CertChainMember
{
    int digestIdetifier;
    int digestSize;
    BYTE digestBuffer[64];
    CertificatePartyName subjectName;
    CertificatePartyName issuerName;
    Asn1BlobPtr certificate;
} CertChainMember, * pCertChainMember;

typedef struct _CertChainInfoHeader
{
    int bufferSize;
    pAsn1BlobPtr ptrToPublicKeys;
    int numberOfPublicKeys;
    pAsn1BlobPtr ptrToEkus;
    int numberOfEkus;
    pCertChainMember ptrToCertChainMembers;
    int numberOfCertChainMembers;
    int unknown;
    Asn1BlobPtr variousAuthenticodeAttributes;
} CertChainInfoHeader, * pCertChainInfoHeader;

typedef struct _PolicyInfo
{
    int structSize;
    NTSTATUS verificationStatus;
    int flags;
    pCertChainInfoHeader certChainInfo;
    FILETIME revocationTime;
    FILETIME notBeforeTime;
    FILETIME notAfterTime;
} PolicyInfo, * pPolicyInfo;