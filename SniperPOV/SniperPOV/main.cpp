#include "pch.h"

#include <Windows.h>
#include <format>

#pragma comment (lib, "detours.lib")
#include "detours.h"

#include "tfcond.h"
#include "intrin.h"

using namespace std;


DWORD InCondOffset = 0x4c17d0;
DWORD WearableDrawOffset = 0x3227f0;
DWORD PlayerShouldDrawOffset = 0x409db0;


typedef bool(__thiscall* tInCond) (void* ths, ETFCond cond);
tInCond oInCond;

bool __fastcall hInCond(void* ecx, void* edx, ETFCond cond) {

	//auto caller = _ReturnAddress();
	//if (caller == (base + WearableDrawOffset) { return false; }
	//if (caller == (base + PlayerShouldDrawOffset) { return false; }
	//return Function(ecx, cond);
	MessageBox(NULL, "Hooked Function!", "Sniper POV", MB_SYSTEMMODAL);
	return false;


}



DWORD WINAPI entry(LPVOID lpparam)
{

	//auto sig = find_ida_sig("client.dll", { "55 8B EC 83 EC 08 56 57 8B 7D 08 8B F1 83 FF 20" });
	//Function = (oFunction)(sig);


	auto base = GetModuleHandle("client.dll");

	oInCond = (tInCond)((DWORD)base + InCondOffset);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	auto error = DetourAttach(&(PVOID&)oInCond, hInCond);
	DetourTransactionCommit();


	if (error != NO_ERROR) {
		MessageBox(NULL, "Failed to hook!", "Sniper POV", MB_SYSTEMMODAL);
		return -1;
	}

	return 3133;
}

void do_entry_thread(HINSTANCE hinstdll) {
	// https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices
	DisableThreadLibraryCalls(hinstdll);
	CreateThread(nullptr, 0, entry, hinstdll, 0, nullptr);
}

BOOL WINAPI DllMain(
	_In_      HINSTANCE hinstdll,
	_In_      DWORD     fdwreason,
	_In_opt_  LPVOID    lpvreserved)
{
	switch (fdwreason) {
	case DLL_PROCESS_ATTACH:
		do_entry_thread(hinstdll);
		return true;
	case DLL_PROCESS_DETACH:
		FreeLibraryAndExitThread(hinstdll, 0);
		return true;
	default:
		return true;
	}
}