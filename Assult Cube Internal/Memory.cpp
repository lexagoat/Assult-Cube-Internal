#include "stdafx.h"
#include "Memory.h"

uintptr_t mem::FindMultiLevelPointer(uintptr_t pointer, std::vector<uintptr_t>offsets)
{
	for (int i = 0; i < offsets.size(); i++)
	{
		pointer = *(uintptr_t*)(pointer);
		pointer += offsets[i];
	}

	return pointer;
}

void mem::Nop(BYTE* destination_address, unsigned int size_of_source)
{
	DWORD current_protections;

	VirtualProtect(destination_address, sizeof(destination_address), PAGE_EXECUTE_READWRITE, &current_protections);

	memset(destination_address, 0x90, size_of_source);

	VirtualProtect(destination_address, size_of_source, current_protections, &current_protections);
}

void mem::Patch(BYTE* source_address, BYTE* destination_address, unsigned int size)
{
	DWORD current_protections;

	VirtualProtect(destination_address, size, PAGE_EXECUTE_READWRITE, &current_protections);

	memcpy_s(destination_address, size, source_address, size);

	VirtualProtect(destination_address, size, current_protections, &current_protections);
}

uintptr_t mem::Detour32(BYTE* source_address, BYTE* destination_address, uintptr_t length_of_bytes)
{
	if (length_of_bytes < 5) return -1;

	DWORD current_protections;

	VirtualProtect(source_address, length_of_bytes, PAGE_EXECUTE_READWRITE, &current_protections);

	Nop(source_address, length_of_bytes);

	uintptr_t relative_jump_address = destination_address - source_address - 5;

	*(source_address) = 0xE9;

	*(uintptr_t*)(source_address + 0x1) = relative_jump_address;

	VirtualProtect(source_address, length_of_bytes, current_protections, &current_protections);

	return (uintptr_t)destination_address;
}

BYTE* mem::TrampHook32(BYTE* source_address, BYTE* destination_address, uintptr_t length_of_bytes)
{
	if (length_of_bytes < 0x5) return 0;

	BYTE* gateway = (BYTE*)VirtualAlloc(0, length_of_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	memcpy_s(gateway, length_of_bytes, source_address, length_of_bytes);

	uintptr_t gatewayRelativeAddr = source_address - gateway - 0x5;

	*(gateway + length_of_bytes) = 0xE9;

	*(uintptr_t*)(gateway + length_of_bytes + 0x1) = gatewayRelativeAddr;

	Detour32(source_address, destination_address, length_of_bytes);

	return gateway;
}