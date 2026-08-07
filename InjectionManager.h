#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <iostream>


class InjectionManager {


public:
	static void self_inject_shellcode(const unsigned char* content, int size);
	static void remote_inject_shellcode(int pid, unsigned char* content, int size);
	static void self_inject_dll_from_file(const char* filename, int filenamelength);
	static void remote_inject_dll_from_file(int pid, const char* filename, int filenamelength);



};

