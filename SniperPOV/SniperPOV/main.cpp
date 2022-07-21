#include "pch.h"

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include "tfcond.h"
#include "intrin.h"


#pragma comment (lib, "detours.lib")
#include "detours.h"


using namespace std;


auto InCondOffset = 0x4c17d0;
auto WearableDrawOffset = 0x3227f0;
auto PlayerShouldDrawOffset = 0x409db0;
HMODULE base1, base2;


typedef bool (__thiscall* oFunction) (void* ecx, ETFCond cond);
oFunction Function;

bool __fastcall CTFPlayerShared_InCond(void* ecx, ETFCond cond) {

    //auto caller = _ReturnAddress();

    return false;

	//return Function(ecx, cond);
}

DWORD WINAPI entry(LPVOID lpparam)
{	
    //auto sig = find_ida_sig("client.dll", { "55 8B EC 83 EC 08 56 57 8B 7D 08 8B F1 83 FF 20" });

    //auto base = GetModuleHandleA("client.dll");


    //Function = (oFunction)((DWORD)base + InCondOffset);
    //Function = (oFunction)(sig);

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)Function, CTFPlayerShared_InCond);
	DetourTransactionCommit();

	return 69;
}

BOOL WINAPI DllMain(
    _In_      HINSTANCE hinstdll,
    _In_      DWORD     fdwreason,
    _In_opt_  LPVOID    lpvreserved)
{
    switch (fdwreason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstdll);
        CreateThread(nullptr, 0, entry, hinstdll, 0, nullptr);
        return TRUE;
    case DLL_PROCESS_DETACH:
        FreeLibraryAndExitThread(hinstdll, 0);
        return TRUE;
    default:
        return TRUE;
    }
}