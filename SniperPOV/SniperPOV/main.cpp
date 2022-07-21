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

DWORD search_pattern(const char* pattern, const char* mask)
{

	MODULEINFO info = {};
	auto hmod = GetModuleHandle("client.dll");
	if (hmod == nullptr) {
		return NULL;
	}
	GetModuleInformation(GetCurrentProcess(), hmod, &info, sizeof(MODULEINFO));

	DWORD base = (DWORD)info.lpBaseOfDll;
	DWORD size = (DWORD)info.SizeOfImage;

	DWORD len = (DWORD)strlen(pattern);

	for (DWORD i = 0; i < size - len; i++)
	{
		bool found = true;
		for (DWORD j = 0; j < len; j++)
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

//DWORD base;


// Return addresses of the wearable and player draw functions so we can say no to sniper zoom
DWORD wearable_draw;
DWORD player_draw;


typedef bool(__thiscall* tInCond) (void* ths, ETFCond cond);
tInCond oInCond;

bool __fastcall hInCond(void* ecx, void* edx, ETFCond cond) {

	//MessageBox(NULL, "Hooked Function!", "Sniper POV", MB_SYSTEMMODAL);

	if (cond == TFCond_Zoomed) {
		if ((DWORD)_ReturnAddress() == wearable_draw) { return false; }
		if ((DWORD)_ReturnAddress() == player_draw) { return false; }
	}

	return oInCond(ecx, cond);

}

DWORD WINAPI entry(LPVOID lpparam)
{

	auto sig = search_pattern("\x55\x8B\xEC\x83\xEC\x08\x56\x57\x8B\x7D\x08\x8B\xF1\x83\xFF\x20", "xxxxxxxxxxxxxxxx");
	
	// Find the CALL instructions to the incond and add 5 to get the address they will be returning to

	wearable_draw = search_pattern("\xE8????\x84\xC0\x75\xE1\x6A\x03", "x????xxxxxx") + 5;
	
	player_draw = search_pattern("\xE8????\x84\xC0\x75\xC5", "x????xxxx") + 5;

	oInCond= (tInCond)(sig);



	//base = (DWORD) GetModuleHandle("client.dll");

	//auto addr = (base + InCondOffset);

	//oInCond = (tInCond)(addr);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	auto error = DetourAttach(&(PVOID&)oInCond, hInCond);
	DetourTransactionCommit();


	if (error != NO_ERROR) {
		MessageBox(NULL, "Failed to hook!", "Sniper POV", MB_SYSTEMMODAL);
		return -1;
	}

	return 0;
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