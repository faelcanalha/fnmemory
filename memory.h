#pragma once
#include <iostream>
#include <Windows.h>
#include <algorithm>
#include <vector>
#include <TlHelp32.h>
#include <tchar.h>
#include <codecvt>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

class c_fn_memory {
public:
	DWORD processId = 0;
	HANDLE processHandle;

	BOOL set_privilege(HANDLE processhandle, std::string perm);
	BOOL attack_process(const char* processName);

	std::vector<BYTE> hex_string_to_byte(const std::string& hex_string);

	std::vector<LPVOID> find_byte(const std::vector<BYTE>& byteSequence);
	std::vector<LPVOID> find_byte(const std::string& hex_sequence);

	BOOL replace_byte(const std::string& findPattern, const std::string& replacePattern);
	BOOL replace_byte(const std::vector<BYTE>& findPattern, const std::vector<BYTE>& replacePattern);
};