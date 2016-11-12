/********************************************************************
	Created:	2012/02/01  18:17
	Filename: 	NativeAPI.cpp
	Author:		rrrfff
	Url:	    http://blog.csdn.net/rrrfff
*********************************************************************/
#include "../Lib_Base.h"
#include "NativeAPI.h"
#pragma comment(lib, "Lib/ntoskrnl.lib")
/************************************************************************/
POBJECT_ATTRIBUTES NTAPI BaseFormatObjectAttributes(OUT POBJECT_ATTRIBUTES ObjectAttributes,IN PUNICODE_STRING ObjectName)
{
	HANDLE RootDirectory;
	ULONG Attributes;
	PVOID SecurityDescriptor = NULL;

	if (ARGUMENT_PRESENT(ObjectName) ) {
		if ( ARGUMENT_PRESENT(ObjectName) ) {
			RootDirectory = BaseGetNamedObjectDirectory();
		}
		else {
			RootDirectory = NULL;
		}

		if ( ARGUMENT_PRESENT(ObjectName) ) {
			Attributes |= OBJ_OPENIF;
		}

		InitializeObjectAttributes(
			ObjectAttributes,
			ObjectName,
			Attributes,
			RootDirectory,
			SecurityDescriptor
			);
		return ObjectAttributes;
	}else{
		return NULL;
	}
}

NTSTATUS NTAPI BaseCreateStack(IN HANDLE Process, IN SIZE_T StackSize, IN SIZE_T MaximumStackSize, OUT PINITIAL_TEB InitialTeb)
{
	NTSTATUS Status;
	PCH Stack;
	BOOLEAN GuardPage;
	SIZE_T RegionSize;
	ULONG OldProtect;
	SIZE_T ImageStackSize, ImageStackCommit;
	PIMAGE_NT_HEADERS NtHeaders;
	PPEB_ Peb;
	ULONG PageSize;

	Peb = NtCurrentPeb();

	//BaseStaticServerData = BASE_SHARED_SERVER_DATA;
	PageSize = System::AppBase::GetSystemInfo()->PhysicalPageSize/*BASE_SYSINFO.PageSize*/;

	//
	// If the stack size was not supplied, then use the sizes from the
	// image header.
	//

	NtHeaders = RtlImageNtHeader(Peb->ImageBaseAddress);
	ImageStackSize = NtHeaders->OptionalHeader.SizeOfStackReserve;
	ImageStackCommit = NtHeaders->OptionalHeader.SizeOfStackCommit;

	if ( !MaximumStackSize ) {
		MaximumStackSize = ImageStackSize;
	}
	if (!StackSize) {
		StackSize = ImageStackCommit;
	}
	else {

		//
		// Now Compute how much additional stack space is to be
		// reserved. This is done by... If the StackSize is <=
		// Reserved size in the image, then reserve whatever the image
		// specifies. Otherwise, round up to 1Mb.
		//

		if ( StackSize >= MaximumStackSize ) {
			MaximumStackSize = ROUND_UP(StackSize, (1024*1024));
		}
	}

	//
	// Align the stack size to a page boundry and the reserved size
	// to an allocation granularity boundry.
	//

	StackSize = ROUND_UP( StackSize, PageSize );

	MaximumStackSize = ROUND_UP(
		MaximumStackSize,
		System::AppBase::GetSystemInfo()->AllocationGranularity
		);

#if !defined (_IA64_)

	//
	// Reserve address space for the stack
	//

	Stack = NULL,
		Status = NtAllocateVirtualMemory(
		Process,
		(PVOID *)&Stack,
		0,
		&MaximumStackSize,
		MEM_RESERVE,
		PAGE_READWRITE
		);
#else

	//
	// Take RseStack into consideration.
	// RSE stack has same size as memory stack, has same StackBase,
	// has a guard page at the end, and grows upwards towards higher
	// memory addresses
	//

	//
	// Reserve address space for the two stacks
	//
	{
		SIZE_T TotalStackSize = MaximumStackSize * 2;

		Stack = NULL,
			Status = NtAllocateVirtualMemory(
			Process,
			(PVOID *)&Stack,
			0,
			&TotalStackSize,
			MEM_RESERVE,
			PAGE_READWRITE
			);
	}

#endif // IA64
	if ( !NT_SUCCESS( Status ) ) {
		return Status;
	}

	InitialTeb->OldInitialTeb.OldStackBase = NULL;
	InitialTeb->OldInitialTeb.OldStackLimit = NULL;
	InitialTeb->StackAllocationBase = Stack;
	InitialTeb->StackBase = Stack + MaximumStackSize;

#if defined (_IA64_)
	InitialTeb->OldInitialTeb.OldBStoreLimit = NULL;
#endif //IA64

	Stack += MaximumStackSize - StackSize;
	if (MaximumStackSize > StackSize) {
		Stack -= PageSize;
		StackSize += PageSize;
		GuardPage = TRUE;
	}
	else {
		GuardPage = FALSE;
	}

	//
	// Commit the initially valid portion of the stack
	//

#if !defined(_IA64_)

	Status = NtAllocateVirtualMemory(
		Process,
		(PVOID *)&Stack,
		0,
		&StackSize,
		MEM_COMMIT,
		PAGE_READWRITE
		);
#else
	{
		//
		// memory and rse stacks are expected to be contiguous
		// reserver virtual memory for both stack at once
		//
		SIZE_T NewCommittedStackSize = StackSize * 2;

		Status = NtAllocateVirtualMemory(
			Process,
			(PVOID *)&Stack,
			0,
			&NewCommittedStackSize,
			MEM_COMMIT,
			PAGE_READWRITE
			);
	}

#endif //IA64

	if ( !NT_SUCCESS( Status ) ) {

		//
		// If the commit fails, then delete the address space for the stack
		//

		RegionSize = 0;
		NtFreeVirtualMemory(
			Process,
			(PVOID *)&Stack,
			&RegionSize,
			MEM_RELEASE
			);

		return Status;
	}

	InitialTeb->StackLimit = Stack;

#if defined(_IA64_)
	InitialTeb->BStoreLimit = Stack + 2 * StackSize;
#endif

	//
	// if we have space, create a guard page.
	//

	if (GuardPage) {
		RegionSize = PageSize;
		Status = NtProtectVirtualMemory(
			Process,
			(PVOID *)&Stack,
			&RegionSize,
			PAGE_GUARD | PAGE_READWRITE,
			&OldProtect
			);
		if ( !NT_SUCCESS( Status ) ) {
			return Status;
		}
		InitialTeb->StackLimit = (PVOID)((PUCHAR)InitialTeb->StackLimit + RegionSize);

#if defined(_IA64_)
		//
		// additional code to Create RSE stack guard page
		//
		Stack = ((PCH)InitialTeb->StackBase) + StackSize - PageSize;
		RegionSize = PageSize;
		Status = NtProtectVirtualMemory(
			Process,
			(PVOID *)&Stack,
			&RegionSize,
			PAGE_GUARD | PAGE_READWRITE,
			&OldProtect
			);
		if ( !NT_SUCCESS( Status ) ) {
			return Status;
		}
		InitialTeb->BStoreLimit = (PVOID)Stack;

#endif // IA64

	}

	return STATUS_SUCCESS;
}

HANDLE BaseNamedObjectDirectory = NULL; 
HANDLE NTAPI BaseGetNamedObjectDirectory(VOID)
{
	OBJECT_ATTRIBUTES Obja;
	NTSTATUS Status;
	ACCESS_MASK DirAccess = DIRECTORY_ALL_ACCESS &
		~(DELETE | WRITE_DAC | WRITE_OWNER);

	RtlAcquirePebLock();

	if ( !BaseNamedObjectDirectory ) {
		InitializeObjectAttributes(
			&Obja,
			NULL,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
			);
		Status = NtOpenDirectoryObject(
			&BaseNamedObjectDirectory,
			DirAccess,
			&Obja
			);
		if ( !NT_SUCCESS(Status) ) {
			BaseNamedObjectDirectory = NULL;
		}
	}
	RtlReleasePebLock();
	return BaseNamedObjectDirectory;
}

VOID NTAPI BaseProcessStart(LPVOID lpfnStartRoutine)     
{     
	DWORD retValue = 0;     
	__try    
	{     
		//将主线程的入口函数设置为mainCRTStartup     
		NtSetInformationThread(GetCurrentThread(),ThreadQuerySetWin32StartAddress,     
			&lpfnStartRoutine,sizeof(lpfnStartRoutine));     

		//retValue = lpfnStartRoutine();   
		__asm
		{
			call lpfnStartRoutine
			mov retValue, eax 
		}
	}     
	__except(retValue=GetExceptionCode(),  
		UnhandledExceptionFilter(GetExceptionInformation()))     
	{     
		//if(BaseRunningInServerProcess)  
		//	ExitThread(retValue);  
		//else  
			ExitProcess(retValue);  
	}  
}  

VOID NTAPI BaseInitializeContext(OUT PCONTEXT Context, IN PVOID Parameter OPTIONAL, IN PVOID InitialPc OPTIONAL, 
	IN PVOID InitialSp OPTIONAL, IN BASE_CONTEXT_TYPE ContextType)

/*++

Routine Description:

    This function initializes a context structure so that it can
    be used in a subsequent call to NtCreateThread.

Arguments:

    Context - Supplies a context buffer to be initialized by this routine.

    Parameter - Supplies the thread's parameter.

    InitialPc - Supplies an initial program counter value.

    InitialSp - Supplies an initial stack pointer value.

    NewThread - Supplies a flag that specifies that this is a new
        thread, or a new process.

Return Value:

    Raises STATUS_BAD_INITIAL_STACK if the value of InitialSp is not properly
           aligned.

    Raises STATUS_BAD_INITIAL_PC if the value of InitialPc is not properly
           aligned.

--*/

{

    Context->Eax = (ULONG)InitialPc;
    Context->Ebx = (ULONG)Parameter;

    Context->SegGs = 0;
    Context->SegFs = 0x38/*KGDT_R3_TEB*/;
    Context->SegEs = 0x20/*KGDT_R3_DATA*/;
    Context->SegDs = 0x20/*KGDT_R3_DATA*/;
    Context->SegSs = 0x20/*KGDT_R3_DATA*/;
    Context->SegCs = 0x18/*KGDT_R3_CODE*/;

    //
    // Start the thread at IOPL=3.
    //

    Context->EFlags = 0x3000;

    //
    // Always start the thread at the thread start thunk.
    //

    Context->Esp = (ULONG) InitialSp;

    if ( ContextType == BaseContextTypeThread ) {
        Context->Eip = (ULONG) BaseProcessStart;
        }
    else if ( ContextType == BaseContextTypeFiber ) {
        Context->Eip = (ULONG) BaseProcessStart;
        }
    else {
        Context->Eip = (ULONG) BaseProcessStart;
        }
    //
    // add code to check alignment and raise exception...
    //

    Context->ContextFlags = CONTEXT_FULL;
    Context->Esp -= sizeof(Parameter); // Reserve room for ret address
}

HANDLE APIENTRY CreateRemoteThreadS(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, DWORD dwStackSize, 
	LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	POBJECT_ATTRIBUTES pObja;
	HANDLE Handle;
	CONTEXT ThreadContext;
	INITIAL_TEB InitialTeb;
	CLIENT_ID ClientId;

	// Allocate a stack for this thread
	Status = BaseCreateStack(hProcess, dwStackSize, 0L, &InitialTeb );

	// Create an initial context
	BaseInitializeContext( &ThreadContext, lpParameter, (PVOID)lpStartAddress, InitialTeb.StackBase, BaseContextTypeThread);

	//pObja = BaseFormatObjectAttributes(&Obja, lpThreadAttributes, NULL);

	Status = NtCreateThread( &Handle, THREAD_ALL_ACCESS, pObja, hProcess, &ClientId, &ThreadContext, &InitialTeb, TRUE ); 
	return Handle;
}