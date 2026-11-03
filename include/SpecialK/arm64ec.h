#pragma once

// x86-64 emulation on ARM64 (Windows on ARM, Wine/Proton ARM64EC builds).

#include <Windows.h>

// True when this x86-64 process runs emulated on an ARM64 machine.
static __inline BOOL
SK_IsX64EmulatedOnARM64 (void)
{
  static volatile LONG result = -1;

  if (result == -1)
  {
    typedef BOOL (WINAPI *IsWow64Process2_pfn)(HANDLE, USHORT*, USHORT*);

    HMODULE             hKernel32        = GetModuleHandleW (L"kernel32.dll");
    IsWow64Process2_pfn IsWow64Process2_ = hKernel32 == NULL ? NULL :
      (IsWow64Process2_pfn)GetProcAddress (hKernel32, "IsWow64Process2");

    USHORT processMachine = 0,
           nativeMachine  = 0;

    InterlockedExchange (&result,
      ( IsWow64Process2_ != NULL &&
        IsWow64Process2_ (GetCurrentProcess (), &processMachine, &nativeMachine) &&
        nativeMachine == IMAGE_FILE_MACHINE_ARM64 ) ? 1 : 0);
  }

  return result == 1;
}

// True when pAddress is native ARM64EC code. An x86-64 inline hook written there is never emulated;
//   it runs as ARM64 and crashes with STATUS_ILLEGAL_INSTRUCTION.
static __inline BOOL
SK_IsArm64ECCode (LPVOID pAddress)
{
  typedef BOOLEAN (NTAPI *RtlIsEcCode_pfn)(ULONG64);

  static RtlIsEcCode_pfn RtlIsEcCode_ = NULL;
  static volatile LONG   resolved     = 0;

  if (! resolved)
  {
    HMODULE hNtDll = GetModuleHandleW (L"ntdll.dll");
    RtlIsEcCode_   = hNtDll == NULL ? NULL :
      (RtlIsEcCode_pfn)GetProcAddress (hNtDll, "RtlIsEcCode");
    InterlockedExchange (&resolved, 1);
  }

  return pAddress != NULL && RtlIsEcCode_ != NULL && RtlIsEcCode_ ((ULONG64)(ULONG_PTR)pAddress);
}
