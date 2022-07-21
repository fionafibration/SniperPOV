gi#include "pch.h"

#include <Windows.h>
#include "tfcond.h"
#include "intrin.h"

#pragma comment (lib, "detours.lib")
#include "detours.h"


using namespace std;


auto InCondOffset = 0x4c17d0;
auto WearableDrawOffset = 0x3227f0;
auto PlayerShouldDrawOffset = 0x409db0;


typedef bool(__fastcall* tInCond) (void* ths, ETFCond cond);
tInCond oInCond;

bool __fastcall hInCond(void* ecx, void* edx, ETFCond cond) {

	//auto caller = _ReturnAddress();

	return false;

	//return Function(ecx, cond);
}

DWORD WINAPI entry(LPVOID lpparam)
{

	//auto sig = find_ida_sig("client.dll", { "55 8B EC 83 EC 08 56 57 8B 7D 08 8B F1 83 FF 20" });
	//Function = (oFunction)(sig);


	auto base = GetModuleHandleA("client.dll");

	oInCond = (tInCond)((DWORD)base + InCondOffset);


	DetourTransactionBegin();
	DetourAttach(&(PBOOL&) oInCond, hInCond);
	DetourTransactionCommit();

	return 3133;
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