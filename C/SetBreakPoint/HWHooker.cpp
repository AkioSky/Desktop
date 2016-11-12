#include "stdafx.h"
#include "HWHooker.h" 

#pragma hdrstop
HWHooker *hk = new HWHooker; 
BREAKPOINT *Bp;

char g_szBuffer1[0x20000];

void _cdecl my_OutputDebugStringA1(char * lpszFormat, ...)
{
	va_list args;
	va_start(args, lpszFormat);
	int nBuf;
	nBuf = _vsnprintf(g_szBuffer1, sizeof(g_szBuffer1), lpszFormat, args);
	va_end(args);
	::OutputDebugStringA(g_szBuffer1);
}

void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a, PVOID r, PVOID s)
{
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );
	(p)->RootDirectory = r;
	(p)->Attributes = a;
	(p)->ObjectName = n;
	(p)->SecurityDescriptor = s;
	(p)->SecurityQualityOfService = NULL;
}

LONG CALLBACK HWHandler(PEXCEPTION_POINTERS ExceptionInfo) 
{ 
	hk->handlingexceptions = 1; 

	if(ExceptionInfo->ExceptionRecord->ExceptionCode != 0x40010006) //DBG_PRINTEXCEPTION_C
	{ 
		//DbgPrint("Exception C0DE: %X", ExceptionInfo->ExceptionRecord->ExceptionCode); 

		if(ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) 
		{ 
			for(DWORD j = 0; j < hk->breakpoints->GetCount(); j++) 
			{ 
				Bp = (BREAKPOINT*)hk->breakpoints->GetAt(j); 
				if(ExceptionInfo->ContextRecord->Dr6 & (1 << Bp->dbgreg)) //one of our breakpoints triggered the exception, so handle it! 
				{ 
					my_OutputDebugStringA1("EIP: %p; ExceptionAddress: %p (from %X)", 
						ExceptionInfo->ContextRecord->Eip, ExceptionInfo->ExceptionRecord->ExceptionAddress, 
						*(DWORD*)ExceptionInfo->ContextRecord->Esp);
					ExceptionInfo->ContextRecord->Esp -= 4;
					*(DWORD*)ExceptionInfo->ContextRecord->Esp = ExceptionInfo->ContextRecord->Ebp;
					ExceptionInfo->ContextRecord->Eip ++;
					ExceptionInfo->ContextRecord->Dr6 = 0xFFFF0FF0; 
					hk->handlingexceptions = 0; 
					return EXCEPTION_CONTINUE_EXECUTION; 
				} 
			} 
		} 
	} 

	hk->handlingexceptions = 0; 
	return EXCEPTION_CONTINUE_SEARCH; 
}

BREAKPOINT::BREAKPOINT() 
{ 
	address = 0; 
	type = 0; 
	size = 0; 
	dbgreg = -1; 
} 

BREAKPOINT::~BREAKPOINT() 
{ 

} 

HWHooker::HWHooker() 
{ 
	NtOpenThread = (NTOPENTHREAD)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenThread"); 
	threads = new CArray<UINT, UINT>; 
	breakpoints = new CArray<PVOID, PVOID>; 
	ExceptionHandler = 0; 
	handlingexceptions = 0; 
} 

HWHooker::~HWHooker() 
{ 
	breakpoints->RemoveAll(); 
	delete threads; 
	delete breakpoints; 
} 

void HWHooker::GetAllThreads() 
{ 
	THREADENTRY32 *te = new THREADENTRY32; 
	HANDLE Snap; 

	te->dwSize = sizeof(THREADENTRY32); 
	Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); 

	if(Snap != INVALID_HANDLE_VALUE) 
	{ 
		if(Thread32First(Snap, te)) 
		{ 
GetNextThread: 
			if(te->th32OwnerProcessID == GetCurrentProcessId()) 
			{
				BOOL bflag = FALSE;
				for(int i = 0; i < threads->GetCount(); i ++)
				{
					if(threads->GetAt(i) == te->th32ThreadID)
					{
						bflag = TRUE;
						break;
					}
				}

				if(bflag == FALSE)
				{
					my_OutputDebugStringA1("New Thread Added ID=%X", te->th32ThreadID);
					threads->Add(te->th32ThreadID); 
				}
			} 

			if(Thread32Next(Snap, te)) 
				goto GetNextThread; 
		} 

		CloseHandle(Snap); 
	} 
	delete te; 
} 

int HWHooker::SetSingleBP(BREAKPOINT *bp, DWORD threadid) 
{ 
	HANDLE hThread; 
	OBJECT_ATTRIBUTES ObjAttribs; 
	CLIENT_ID cID; 
	NTSTATUS Status; 

	InitializeObjectAttributes(&ObjAttribs, 0, 0, 0, 0); 

	cID.UniqueProcess = 0; 
	cID.UniqueThread = threadid; 

	Status = NtOpenThread(&hThread, THREAD_ALL_ACCESS, &ObjAttribs, &cID); 
	if(Status == 0) 
	{ 
		CONTEXT Context; 
		Context.ContextFlags = CONTEXT_DEBUG_REGISTERS; 
		GetThreadContext(hThread, &Context); 

		// find available hardware register 
		if(bp->dbgreg == 0xFFFFFFFF)//debug register to use for this breakpoint not gotten yet 
		{ 
			for(DWORD o = 0; o < 4; o++) 
			{ 
				if((Context.Dr7 & (1 << (o * 2))) == 0) 
				{ 
					//found unused debug register 
					*(&Context.Dr0 + o) = (DWORD)bp->address; 

					SETBITS(Context.Dr7, 16 + o*4, 2, bp->type); 
					SETBITS(Context.Dr7, 18 + o*4, 2, bp->size); 
					SETBITS(Context.Dr7, o * 2, 1, 1); 

					SetThreadContext(hThread, &Context); 
					bp->dbgreg = o; //use this debug register for rest of threads 
					break; 
				} 
			} 
		} 
		else 
		{ 
			DWORD r = bp->dbgreg; 
			if((Context.Dr7 & (1 << r * 2)) == 0) 
			{ 
				*(&Context.Dr0 + r) = (DWORD)bp->address; 

				SETBITS(Context.Dr7, 16 + r*4, 2, bp->type); 
				SETBITS(Context.Dr7, 18 + r*4, 2, bp->size); 
				SETBITS(Context.Dr7, r * 2, 1, 1); 

				SetThreadContext(hThread, &Context); 
			} 
		} 
		CloseHandle(hThread); 
	} 

	if(bp->dbgreg >= 0) 
		return bp->dbgreg; 
	else 
		return -1; 

} 

int HWHooker::SetBreakpoint(DWORD type, DWORD bpsize, LPVOID address, DWORD pThreadID) 
{ 
	BREAKPOINT *bp, *tp; 
	int successful = 0; 

	bp = NULL;

	for(DWORD l = 0; l < breakpoints->GetCount(); l++) 
	{ 
		tp = (BREAKPOINT*)breakpoints->GetAt(l); 
		//if(tp->type == type && tp->size == bpsize && tp->address == address) 
		if(tp->type == type && tp->address == address) 
		{ 
			//breakpoint already existing... don't set it again. 
			//return -1; 
			bp = tp;
			break;
		} 
	} 

	if(bp == NULL)
	{
		bp = new BREAKPOINT; 
		bp->address = address; 
		bp->type = type; 
		//bp->size = bpsize; 

		if(bpsize == 8) 
			bp->size = (bpsize >> 2); 
		else if(bpsize >= 1 && bpsize <= 2 || bpsize == 4) //1, 2, 4, 8 
			bp->size = (bpsize - 1); 
		else 
			bp->size = 3; //default to 4 byte break point 


		breakpoints->Add(bp); 
	}

	if(!ExceptionHandler) //Add exception handler to the mix, if it isn't already 
		ExceptionHandler = AddVectoredExceptionHandler(0x1339, HWHandler); 

	if(pThreadID != 0)
	{
		BOOL	bFlag = FALSE;
		for(int j = 0; j < bp->threads.GetCount(); j ++)
		{
			if(pThreadID == bp->threads.GetAt(j))
			{
				bFlag = TRUE;
				break;
			}
		}
		if(bFlag == TRUE)
			return -1;

		if(SetSingleBP(bp, pThreadID) >= 0) 
		{ 
			//successfully set breakpoint for this thread 
			my_OutputDebugStringA1("            Set BP To Thread ID=%X", pThreadID);
			successful = 1;
			bp->threads.Add(pThreadID);
		}
		else
		{
			my_OutputDebugStringA1("            Set BP Error To Thread ID=%X", pThreadID);
		}
	}
	else
	{
		GetAllThreads(); //Get all currently running threads in within current executable 

		for(DWORD i = 0; i < threads->GetCount(); i++) 
		{
			BOOL	bFlag = FALSE;
			DWORD	dwThreadID = (DWORD)threads->GetAt(i);
			for(int j = 0; j < bp->threads.GetCount(); j ++)
			{
				if(dwThreadID == bp->threads.GetAt(j))
				{
					bFlag = TRUE;
					break;
				}
			}
			if(bFlag == TRUE)
				continue;

			if(SetSingleBP(bp, dwThreadID) >= 0) 
			{ 
				//successfully set breakpoint for this thread 
				my_OutputDebugStringA1("            Set BP To Thread ID=%X", dwThreadID);
				successful = 1;
				bp->threads.Add(dwThreadID);
			} 
		} 
	}

	if(successful) 
		return 1; 
	else 
		return -1; 
} 

int HWHooker::ResetAll() 
{ 
	HANDLE hThread; 
	OBJECT_ATTRIBUTES ObjAttribs; 
	CLIENT_ID cID; 
	NTSTATUS Status; 
	BREAKPOINT *bp; 

	while(handlingexceptions == 1) //while handling exceptions, wait before removing any breakpoints 
	{ 
		Sleep(10); 
	} 

	//This isn't really necessary but I thought it might help prevent crashing... 
	if(ExceptionHandler) 
	{ 
		RemoveVectoredExceptionHandler(ExceptionHandler); 
		ExceptionHandler = 0; 
	} 

	InitializeObjectAttributes(&ObjAttribs, 0, 0, 0, 0); 
	for(DWORD i = 0; i < threads->GetCount(); i++) 
	{ 
		cID.UniqueProcess = 0; 
		cID.UniqueThread = (DWORD)threads->GetAt(i); 

		Status = NtOpenThread(&hThread, THREAD_ALL_ACCESS, &ObjAttribs, &cID); 
		if(Status == 0) 
		{ 
			CONTEXT Context; 
			Context.ContextFlags = CONTEXT_DEBUG_REGISTERS; 
			GetThreadContext(hThread, &Context); 

			//Clear all debug registers for this thread 
			Context.Dr0 = 0; 
			Context.Dr1 = 0; 
			Context.Dr2 = 0; 
			Context.Dr3 = 0; 
			Context.Dr6 = 0; 
			Context.Dr7 = 0; 

			SetThreadContext(hThread, &Context); 
			CloseHandle(hThread); 
		} 
	} 

	breakpoints->RemoveAll(); //delete any breakpoint objects from breakpoints array 
	return 1; 
}