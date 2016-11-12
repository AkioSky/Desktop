#ifndef _HWHOOKER_H 
#define _HWHOOKER_H 

//#include "ArrayClass.h" 
//#include "Unit1.h" 
#include <stdio.h>
#include <tlhelp32.h> 
#include <Ntsecapi.h> 

typedef struct _OBJECT_ATTRIBUTES 
{ 
	ULONG Length; 
	PVOID RootDirectory; 
	PUNICODE_STRING ObjectName; 
	ULONG Attributes; 
	PVOID SecurityDescriptor; 
	PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES; 

void InitializeObjectAttributes(POBJECT_ATTRIBUTES p, PUNICODE_STRING n, ULONG a, PVOID r, PVOID s);

/*
#define InitializeObjectAttributes( p, n, a, r, s ) {
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );
	(p)->RootDirectory = r;
	(p)->Attributes = a;
	(p)->ObjectName = n;
	(p)->SecurityDescriptor = s;
	(p)->SecurityQualityOfService = NULL;
} 
*/

typedef struct _CLIENT_ID 
{ 
	DWORD UniqueProcess; 
	DWORD UniqueThread; 
} CLIENT_ID, *PCLIENT_ID; 

typedef NTSTATUS (WINAPI *NTOPENTHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID); 
typedef NTSTATUS (WINAPI *NTGETCONTEXTTHREAD)(HANDLE, LPCONTEXT); 

class BREAKPOINT 
{ 
public: 
	LPVOID address; 
	DWORD type; //0 = break on execute, 1 = on write, 3 = on access 
	DWORD size; //breakpoint size 1, 2, or 4 
	DWORD dbgreg; // 0 - 3 //debug registers 1-4 
	CArray<UINT, UINT> threads;

	BREAKPOINT(); 
	~BREAKPOINT(); 
}; 

class HWHooker 
{ 
private: 
	void GetAllThreads(); 

public: 
	NTOPENTHREAD NtOpenThread; 
	CArray<UINT, UINT> *threads; 
	CArray<PVOID, PVOID> *breakpoints; 
	PVOID ExceptionHandler; 
	int handlingexceptions; 

	HWHooker(); 
	~HWHooker(); 
	int SetSingleBP(BREAKPOINT *bp, DWORD threadid); 
	int SetBreakpoint(DWORD type, DWORD bpsize, LPVOID address, DWORD pThreadID); 
	//int RemoveBreakpoint(DWORD DbgRegister); //not yet implemented 
	int ResetAll(); //unset + delete all breakpoints 
}; 

inline void SETBITS(unsigned long& dw, int lowBit, int bits, int newValue) 
{ 
	int mask = (1 << bits) - 1; 
	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit); 
} 

#endif