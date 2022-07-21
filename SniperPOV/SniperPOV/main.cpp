#include "pch.h"

#include <Windows.h>
#include <format>
#include <Psapi.h>
#include <TlHelp32.h>

#pragma comment (lib, "detours.lib")
#include "detours.h"

#include "tfcond.h"
#include "intrin.h"

using namespace std;

DWORD FindPattern(const char* pattern, const char* mask)
{

	MODULEINFO info = {};
	auto hmod = GetModuleHandle("client.dll");
	if (hmod == nullptr) {
		return NULL;
	}
	GetModuleInformation(GetCurrentProcess(), hmod, &info, sizeof(MODULEINFO));
	DWORD base = (DWORD)info.lpBaseOfDll;
	DWORD size = (DWORD)info.SizeOfImage;

	DWORD patternLength = (DWORD)strlen(mask);

	for (DWORD i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for (DWORD j = 0; j < patternLength; j++)
		{
			found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
		}

		if (found)
		{
			return base + i;
		}
	}

	return NULL;
}


DWORD InCondOffset = 0x4c17d0;
DWORD WearableDrawOffset = 0x3227f0;
DWORD PlayerShouldDrawOffset = 0x409db0;

DWORD base;


typedef bool(__thiscall* tInCond) (void* ths, ETFCond cond);
tInCond oInCond;

bool __fastcall hInCond(void* ecx, void* edx, ETFCond cond) {

	MessageBox(NULL, "Hooked Function!", "Sniper POV", MB_SYSTEMMODAL);

	if ((DWORD) _ReturnAddress() == (base + WearableDrawOffset)) { return false; }
	if ((DWORD) _ReturnAddress() == (base + PlayerShouldDrawOffset)) { return false; }
	return oInCond(ecx, cond);

	return false;

}

DWORD WINAPI entry(LPVOID lpparam)
{

	//auto sig = find_ida_sig("client.dll", { "55 8B EC 83 EC 08 56 57 8B 7D 08 8B F1 83 FF 20" });
	auto sig = FindPattern("\x55\x8B\xEC\x83\xEC\x08\x56\x57\x8B\x7D\x08\x8B\xF1\x83\xFF\x20", "xxxxxxxxxxxxxxxx");
	oInCond= (tInCond)(sig);



	base = (DWORD) GetModuleHandle(nullptr);

	auto addr = (base + InCondOffset);

	oInCond = (tInCond)(addr);

	if (true) {

	}

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