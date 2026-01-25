#include "pch.h"
#include <Windows.h>
#include <format>
#include <Psapi.h>
#include <TlHelp32.h>
#include "detours.h"
#include "tfcond.h"
#include "intrin.h"

#ifdef _M_X64
	#pragma comment (lib, "lib/x64/detours.lib")
#else
	#pragma comment (lib, "lib/x86/detours.lib")
#endif

using namespace std;

bool WaitForClientDll(int timeout) { // time in ms
	HMODULE h = NULL;
	int time_elapsed = 0;
	while (time_elapsed < timeout) {
		h = GetModuleHandleA("client.dll");
		if (h) {
			return true;
		}
		Sleep(500);
		time_elapsed += 500;
	}
	return false;
}

uintptr_t search_pattern(const char* pattern, const char* mask)
{

	MODULEINFO info = {};
	auto hmod = GetModuleHandleA("client.dll");
	if (hmod == nullptr) {
		MessageBoxA(NULL, "client.dll not loaded yet (code error, contact dev)", "Sniper POV", MB_SYSTEMMODAL);
		return NULL;
	}
	GetModuleInformation(GetCurrentProcess(), hmod, &info, sizeof(MODULEINFO));

	uintptr_t base = (uintptr_t)info.lpBaseOfDll;
	uintptr_t size = (uintptr_t)info.SizeOfImage;

	uintptr_t len = (uintptr_t)strlen(pattern);

	for (uintptr_t i = 0; i < size - len; i++)
	{
		bool found = true;
		for (uintptr_t j = 0; j < len; j++)
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

// Return addresses of the wearable and player draw functions so we can say no to sniper zoom
uintptr_t wearable_draw;
uintptr_t player_draw;

#ifdef _M_X64
	typedef bool(__fastcall* tInCond) (void* ths, ETFCond cond);
#else
	typedef bool(__thiscall* tInCond) (void* ths, ETFCond cond);
#endif
tInCond oInCond;

#ifdef _M_X64
// Hooked Function
bool __fastcall hInCond(void* ths, ETFCond cond) {
	if (cond == TFCond_Zoomed) {
		uintptr_t retAddr = (uintptr_t)_ReturnAddress();
		if (retAddr == wearable_draw || retAddr == player_draw) {
			return false;
		}
	}
	return oInCond(ths, cond);
}
#else
bool __fastcall hInCond(void* ecx, void* edx, ETFCond cond) {
	if (cond == TFCond_Zoomed) {
		if ((uintptr_t)_ReturnAddress() == wearable_draw) { return false; }
		if ((uintptr_t)_ReturnAddress() == player_draw) { return false; }
	}

	return oInCond(ecx, cond);

}
#endif

DWORD WINAPI entry(LPVOID lpparam)
{
	// Allow client.dll to load (60000 ms / 60 s)
	if (!WaitForClientDll(60000)) {
		MessageBoxA(NULL, "Failed to hook!\nLoading Client.dll exceeded timeout limit (60s).\n(try again, or contact dev)", "Sniper POV", MB_SYSTEMMODAL);
		return -1;
	}

	uintptr_t sig;

#ifdef _M_X64 // UPDATED SIGNATURES POST-JANUARY 24th 2026
	// 64-bit signatures
	sig = search_pattern("\x48\x89\x5C\x24?\x57\x48\x83\xEC?\x8B\xDA\x48\x8B\xF9\x83\xFA\x20\x7D?\x48\x81\xC1", "xxxx?xxxx?xxxxxxxxx?xxx");
	// Find the CALL instructions to the incond and add 5 to get the address they will be returning to
	wearable_draw = search_pattern("\xE8????\x84\xC0\x0F\x85????\x41\xBF\x03", "x????xxxx????xxx") + 5;
	player_draw = search_pattern("\xE8????\x84\xC0\x74?\x32\xC0\x48\x8B\x74\x24", "x????xxx?xxxxxx") + 5;
#else
	// 32-bit signatures
	sig = search_pattern("\x55\x8B\xEC\x83\xEC\x08\x56\x57\x8B\x7D\x08\x8B\xF1\x83\xFF\x20", "xxxxxxxxxxxxxxxx");
	wearable_draw = search_pattern("\xE8????\x84\xC0\x0F\x85????\x6A\x03\x8B\xCB\xE8????\x84\xC0\x0F\x84????", "x????xxxx????xxxxx????xxxx????") + 5;
	player_draw = search_pattern("\xE8????\x84\xC0\x74?\x5E\x32\xC0\x5B\xC3", "x????xxx?xxxxx") + 5;
#endif

	if (sig == NULL) {
		MessageBoxA(NULL, "Failed to hook!\nSIG pattern could not be found.\n(an update may have broken it, contact dev)", "Sniper POV", MB_SYSTEMMODAL);
		return -1;
	}
	if (wearable_draw == 5) { // failure = NULL + 5 = 5
		MessageBoxA(NULL, "Failed to hook!\nWearable_draw pattern could not be found.\n(an update may have broken it, contact dev)", "Sniper POV", MB_SYSTEMMODAL);
		return -1;
	}
	if (player_draw == 5) {
		MessageBoxA(NULL, "Failed to hook!\nPlayer_draw pattern could not be found.\n(an update may have broken it, contact dev)", "Sniper POV", MB_SYSTEMMODAL);
		return -1;
	}

	oInCond = (tInCond)(sig);

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	auto error = DetourAttach(&(PVOID&)oInCond, hInCond);
	DetourTransactionCommit();


	if (error != NO_ERROR) {
		MessageBoxA(NULL, "Failed to hook!\n(unclear what went wrong, contact dev)", "Sniper POV", MB_SYSTEMMODAL);
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