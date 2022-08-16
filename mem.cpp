#include "mem.h"
#include "globals.h"

void mem::Patch(BYTE* dst, BYTE* src, unsigned int size) {
	DWORD oldprotect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);

	memcpy(dst, src, size);
	VirtualProtect(dst, size, oldprotect, &oldprotect);
}

void mem::PatchEx(BYTE* dst, BYTE* src, unsigned int size, HANDLE hProcess) {
	DWORD oldprotect;
	VirtualProtectEx(hProcess, dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	WriteProcessMemory(hProcess, dst, src, size, nullptr);
	VirtualProtectEx(hProcess, dst, size, oldprotect, &oldprotect);
}

void mem::Nop(BYTE* dst, unsigned int size) {
	DWORD oldprotect;
	VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	memset(dst, 0x90, size);
	VirtualProtect(dst, size, oldprotect, &oldprotect);
}

void mem::NopEx(BYTE* dst, unsigned int size, HANDLE hProcess) {
	BYTE* nopArray = new BYTE[size];
	memset(nopArray, 0x90, size);

	PatchEx(dst, nopArray, size, hProcess);
	delete[] nopArray;
}

uintptr_t mem::FindDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets) {
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i) {
		addr = *(uintptr_t*)addr;
		addr += offsets[i];
	}
	return addr;
}

uintptr_t mem::FindDMAAddyEx(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets) {
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i) {
		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), nullptr);
		addr += offsets[i];
	}
	return addr;
}

bool mem::Hook(DWORD dst, void* function, unsigned int size) {
	if (size < 5) return false; // size of JMP

	DWORD curProtection;
	VirtualProtect((void*)(dst + settings.moduleBase), size, PAGE_EXECUTE_READWRITE, &curProtection);

	memset((void*)(dst + settings.moduleBase), 0x90, size); // NOP used memory before placing JMP

	DWORD reletiveAddress{ (DWORD)function - (dst + settings.moduleBase) - 5 }; // account for JMP size

	*(BYTE*)(dst + settings.moduleBase) = 0xE9; // start of JMP
	*(DWORD*)(dst + settings.moduleBase + 1) = reletiveAddress; // set the rest of JMP after first instruction (+1) to our relative addy

	VirtualProtect((void*)(dst + settings.moduleBase), size, curProtection, &curProtection);

	return true;
}

bool mem::Detour32(BYTE* src, BYTE* dst, const uintptr_t len) {
	if (len < 5) return false;

	DWORD curProtection;
	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &curProtection);

	uintptr_t relativeAddress = dst - src - 5;

	*src = 0xE9;

	*(uintptr_t*)(src + 1) = relativeAddress;

	VirtualProtect(src, len, curProtection, &curProtection);

	return true;
}

BYTE* mem::TrampHook32(BYTE* src, BYTE* dst, const uintptr_t len) {
	if (len < 5) return 0;

	// gateway
	BYTE* gateway = (BYTE*)VirtualAlloc(0, len + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// write stolen bytes to the gate
	memcpy_s(gateway, len, src, len);

	// get gateway dst
	uintptr_t gatewayRelativeAddress = src - gateway - 5;

	// add the jmp
	*(gateway + len) = 0xE9;

	// write the address of gate to the jmp
	*(uintptr_t*)((uintptr_t)gateway + len + 1) = gatewayRelativeAddress;

	// detour
	Detour32(src, dst, len);

	return gateway;
}