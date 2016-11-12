# Set Break Point

1. Copy "HWHooker.h" and "HWHooker.cpp" files to project folder.

2. Add these 2 files to solution.

3. Insert below code to project.
```
#include "HWHooker.h"
extern HWHooker * hk;
extern BREAKPOINT * bp;
```

4. Insert breakpoint setting code.
```
void sub_XXXX()
{
  //...

  DWORD dwDestAddr = 0xXXXXXX;	// Address to set Breakpoint
  DWORD size = 4; 		// default
  DWORD type = 1; 		// 0:execute, 1:+w, 3:+rw
  DWORD regnum;			// return value

  regnum = hk->SetBreakpoint(type, size, (void *)dwDestAddr, 0);
  if (regnum != 0xFFFFFFFF)
    OutputDebugStringA("Breakpoint set!");
  else
    OutputDebugStringA("Breakpoint error!");

  //...
}
```
