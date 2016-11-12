/********************************************************************
	Created:	2012/02/01  18:17
	Filename: 	NativeAPI.h
	Author:		rrrfff
	Url:	    http://blog.csdn.net/rrrfff
*********************************************************************/
#ifndef USE_NATIVEAPI
#define USE_NATIVEAPI
#include "../RLib.h"
#include <WinNT.h>
#include <winternl.h>
//////////////////////////////////////////////////////////////////////////
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
typedef struct _INITIAL_TEB {
	struct {
		PVOID OldStackBase;
		PVOID OldStackLimit;
	} OldInitialTeb;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID StackAllocationBase;
} INITIAL_TEB, *PINITIAL_TEB;
typedef enum _BASE_CONTEXT_TYPE {
	BaseContextTypeProcess,
	BaseContextTypeThread,
	BaseContextTypeFiber
} BASE_CONTEXT_TYPE, *PBASE_CONTEXT_TYPE;
typedef struct __TEB {
	NT_TIB                  Tib;
	PVOID                   EnvironmentPointer;
	CLIENT_ID               Cid;
	PVOID                   ActiveRpcInfo;
	PVOID                   ThreadLocalStoragePointer;
	PPEB                    Peb;
	ULONG                   LastErrorValue;
	ULONG                   CountOfOwnedCriticalSections;
	PVOID                   CsrClientThread;
	PVOID                   Win32ThreadInfo;
	ULONG                   Win32ClientInfo[0x1F];
	PVOID                   WOW32Reserved;
	ULONG                   CurrentLocale;
	ULONG                   FpSoftwareStatusRegister;
	PVOID                   SystemReserved1[0x36];
	PVOID                   Spare1;
	ULONG                   ExceptionCode;
	ULONG                   SpareBytes1[0x28];
	PVOID                   SystemReserved2[0xA];
	ULONG                   GdiRgn;
	ULONG                   GdiPen;
	ULONG                   GdiBrush;
	CLIENT_ID               RealClientId;
	PVOID                   GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID                   GdiThreadLocaleInfo;
	PVOID                   UserReserved[5];
	PVOID                   GlDispatchTable[0x118];
	ULONG                   GlReserved1[0x1A];
	PVOID                   GlReserved2;
	PVOID                   GlSectionInfo;
	PVOID                   GlSection;
	PVOID                   GlTable;
	PVOID                   GlCurrentRC;
	PVOID                   GlContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING          StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[0x105];
	PVOID                   DeallocationStack;
	PVOID                   TlsSlots[0x40];
	LIST_ENTRY              TlsLinks;
	PVOID                   Vdm;
	PVOID                   ReservedForNtRpc;
	PVOID                   DbgSsReserved[0x2];
	ULONG                   HardErrorDisabled;
	PVOID                   Instrumentation[0x10];
	PVOID                   WinSockData;
	ULONG                   GdiBatchCount;
	ULONG                   Spare2;
	ULONG                   Spare3;
	ULONG                   Spare4;
	PVOID                   ReservedForOle;
	ULONG                   WaitingOnLoaderLock;
	PVOID                   StackCommit;
	PVOID                   StackCommitMax;
	PVOID                   StackReserved;
} TEB_, *PTEB_;
typedef struct __PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID/*PPEBLOCKROUTINE*/FastPebLockRoutine;
	PVOID/*PPEBLOCKROUTINE */FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID/*PPVOID*/         KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID/*PPEB_FREE_BLOCK*/FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID/*PPVOID*/         ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID/*PPVOID*/        *ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB_, *PPEB_;
typedef struct _FILE_NETWORK_OPEN_INFORMATION {
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;
typedef struct _FILE_DISPOSITION_INFORMATION {
	BOOLEAN Delete;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;
typedef struct _FILE_RENAME_INFORMATION {
	BOOLEAN ReplaceIfExists;
	HANDLE  RootDirectory;
	ULONG   FileNameLength;
	WCHAR   FileName[MAX_PATH + 4];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;
typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, *PFILE_POSITION_INFORMATION;
typedef struct _FILE_END_OF_FILE_INFORMATION {
	LARGE_INTEGER EndOfFile;
} FILE_END_OF_FILE_INFORMATION, *PFILE_END_OF_FILE_INFORMATION;
typedef enum _THREAD_INFORMATION_CLASS {
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPendingRRRFFF,//重定义
	ThreadHideFromDebugger
} THREAD_INFORMATION_CLASS, *PTHREAD_INFORMATION_CLASS;

//
// Determine if an argument is present by testing the value of the pointer
// to the argument value.
//
#define ARGUMENT_PRESENT(ArgumentPointer)    (\
	(CHAR *)((ULONG_PTR)(ArgumentPointer)) != (CHAR *)(NULL) )
#define NtCurrentPeb() (PPEB_(((TEB_ *)NtCurrentTeb())->Peb))
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define ROUND_UP(x, align) (((int) (x) + (align - 1)) & ~(align - 1))
#define SET_THREAD_ENTRY_ROUTINE 9  

extern "C"
{
	HANDLE NTAPI BaseGetNamedObjectDirectory();
	POBJECT_ATTRIBUTES NTAPI BaseFormatObjectAttributes(OUT POBJECT_ATTRIBUTES ObjectAttributes, IN PUNICODE_STRING ObjectName);
	VOID NTAPI BaseInitializeContext(OUT PCONTEXT Context,IN PVOID Parameter OPTIONAL,IN PVOID InitialPc OPTIONAL,
	 		IN PVOID InitialSp OPTIONAL,IN BASE_CONTEXT_TYPE ContextType);
	VOID NTAPI RtlAcquirePebLock(VOID);
	VOID NTAPI RtlReleasePebLock(VOID);

	HANDLE NTAPI CreateRemoteThreadS(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, DWORD dwStackSize, 
		LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

	NTSTATUS NTAPI BaseCreateStack(IN HANDLE Process, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize, OUT PINITIAL_TEB InitialTeb);

	PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID);
	PVOID RtlImageDirectoryEntryToData(IN PVOID Base, IN BOOLEAN MappedAsImage, IN USHORT DirectoryEntry, OUT PULONG Size);

	VOID BaseThreadStart(PTHREAD_START_ROUTINE pfnStartAddr, PVOID pvParam);
	VOID NTAPI BaseProcessStart(LPVOID lpfnStartRoutine);

	NTSTATUS NTAPI NtOpenDirectoryObject(__out PHANDLE DirectoryHandle, __in ACCESS_MASK DesiredAccess, __in POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);
	NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG RegionSize, ULONG FreeType);
	NTSTATUS NTAPI NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID *UnsafeBaseAddress, IN OUT SIZE_T *UnsafeNumberOfBytesToProtect,
		IN ULONG NewAccessProtection, OUT PULONG UnsafeOldAccessProtection);
	NTSTATUS NTAPI NtSetInformationThread(IN HANDLE ThreadHandle, IN THREAD_INFORMATION_CLASS ThreadInformationClass, IN PVOID ThreadInformation, 
		IN ULONG ThreadInformationLength );
	NTSTATUS NTAPI NtSuspendThread(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL);
	NTSTATUS NTAPI NtResumeThread(IN HANDLE ThreadHandle,  OUT PULONG PreviousSuspendCount OPTIONAL);
	NTSTATUS NTAPI NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout OPTIONAL);
	NTSTATUS NTAPI NtTerminateThread(HANDLE ThreadHandle, LONG ExitStatus);
	NTSTATUS NTAPI NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
		HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended);
};
extern "C"
{
	NTSTATUS NTAPI NtQueryFullAttributesFile(
		__in   POBJECT_ATTRIBUTES ObjectAttributes,
		__out  PFILE_NETWORK_OPEN_INFORMATION FileInformation
		);
	NTSTATUS NTAPI NtSetInformationFile(
		__in   HANDLE FileHandle,
		__out  PIO_STATUS_BLOCK IoStatusBlock,
		__in   PVOID FileInformation,
		__in   ULONG Length,
		__in   FILE_INFORMATION_CLASS FileInformationClass
		);
	NTSTATUS NTAPI NtQueryInformationFile(
		__in   HANDLE FileHandle,
		__out  PIO_STATUS_BLOCK IoStatusBlock,
		__out  PVOID FileInformation,
		__in   ULONG Length,
		__in   FILE_INFORMATION_CLASS FileInformationClass
		);
	NTSTATUS NTAPI NtReadFile(
		__in      HANDLE FileHandle,
		__in_opt  HANDLE Event,
		__in_opt  PIO_APC_ROUTINE ApcRoutine,
		__in_opt  PVOID ApcContext,
		__out     PIO_STATUS_BLOCK IoStatusBlock,
		__out     PVOID Buffer,
		__in      ULONG Length,
		__in_opt  PLARGE_INTEGER ByteOffset,
		__in_opt  PULONG Key
		);
	NTSTATUS NTAPI NtWriteFile(
		__in      HANDLE FileHandle,
		__in_opt  HANDLE Event,
		__in_opt  PIO_APC_ROUTINE ApcRoutine,
		__in_opt  PVOID ApcContext,
		__out     PIO_STATUS_BLOCK IoStatusBlock,
		__in      PVOID Buffer,
		__in      ULONG Length,
		__in_opt  PLARGE_INTEGER ByteOffset,
		__in_opt  PULONG Key
		);
};
#endif