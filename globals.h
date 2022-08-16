#pragma once
#include "pch.h"

extern struct globalVariables settings;

// VARIABLES
struct globalVariables {
	uintptr_t moduleBase = (uintptr_t)GetModuleHandle(L"PlantsVsZombies.exe");
};