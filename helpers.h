#pragma once
#include <Windows.h>



__forceinline ULONGLONG exportforwarderresolver(const char* forwarder);
__forceinline ULONGLONG getdllexportfunctionaddress(ULONGLONG dllbase,
	const char* functionname);


// read *T elements until we encounter *T as 0
template <typename T>
__forceinline size_t mystrlen(const T* char1ptr) {

	if (char1ptr == NULL) { return 0 };

	size_t length = 0;
	while (*char1ptr) {
		length++;
		char1ptr++;
	}


	return length;
}


template<typename T, typename U>
__forceinline bool mystrcmp(const T* char1ptr, const U* char2ptr) {

	if (char1ptr == NULL || char2ptr == NULL) { return false; }

	while (*char1ptr && *char2ptr) {

		char char1 = *char1ptr;
		char char2 = *char2ptr;

		// converting to lowercase if char is uppercase
		if (char1 >= 'A' && char1 <= 'Z') {
			char1 += 32;
		}

		if (char2 >= 'A' && char2 <= 'Z') {
			char2 += 32;
		}


		if (char1 != char2) {
			return false;
		}

		char1ptr++; char2ptr++;

	}

	return (*char1ptr == 0 && *char2ptr == 0);

}



__forceinline ULONGLONG getdllbase(const char* dll) {
	auto ppeb = __readgsqword(0x60);
	// ldr address
	ULONGLONG ldr = *(ULONGLONG*)((char*)ppeb + 0x18);
	// ldr+0x10 inloadordermodulelist
	ULONGLONG firstldrdatatableentry = *(ULONGLONG*)((char*)ldr + 0x10);

	while (firstldrdatatableentry != ldr + 0x10) {
		// ldrdatatableentry+0x58 basedllname UNICODE_STRING, 
		ULONGLONG namebuf = *(ULONGLONG*)((char*)firstldrdatatableentry + 0x58 + 0x8);
		//std::wcout << std::hex << "dllname: " << (wchar_t*)namebuf << std::endl;

		bool isourdll = true;
		wchar_t* namebufptr = (wchar_t*)namebuf;
		const char* dllptr = dll;
		if (!mystrcmp<wchar_t, char>(namebufptr, dllptr)) {
			isourdll = false;
		}

		if (isourdll) {
			return *(ULONGLONG*)(firstldrdatatableentry + 0x30);
		}

		firstldrdatatableentry = *(ULONGLONG*)(firstldrdatatableentry);

	}

	return 0;
}



__forceinline ULONGLONG getdllexportfunctionaddress(ULONGLONG dllbase,
	const char* functionname) {

	IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)dllbase;
	IMAGE_FILE_HEADER* fileheader = (IMAGE_FILE_HEADER*)((char*)dllbase + dosheader->e_lfanew + 4);
	IMAGE_OPTIONAL_HEADER64* optionalheader = (IMAGE_OPTIONAL_HEADER64*)((char*)dllbase + dosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
	IMAGE_EXPORT_DIRECTORY* exportdirectory = (IMAGE_EXPORT_DIRECTORY*)((char*)dllbase + optionalheader->DataDirectory[0].VirtualAddress);


	auto entptr = (char*)dllbase + exportdirectory->AddressOfNames;
	auto eotptr = (char*)dllbase + exportdirectory->AddressOfNameOrdinals;
	auto eatptr = (char*)dllbase + exportdirectory->AddressOfFunctions;

	for (int i = 0;i < exportdirectory->NumberOfNames;i++) {
		ULONG namerva = *(ULONG*)((char*)entptr + i * 4);
		SHORT ordinal = *(SHORT*)((char*)eotptr + i * 2);
		ULONG funcrva = *(ULONG*)((char*)eatptr + ordinal * 4);

		ULONGLONG funcaddress = dllbase + funcrva;
		char* funcnameptr = (char*)dllbase + namerva;
		const char* functionnameptr = functionname;

		bool isourfunction = true;

		if (!mystrcmp(funcnameptr, functionnameptr)) {
			isourfunction = false;
		}

		if (isourfunction) {

			// if our function has forwarder
			if (funcrva >= optionalheader->DataDirectory[0].VirtualAddress &&
				funcrva < ((ULONGLONG)optionalheader->DataDirectory[0].VirtualAddress + optionalheader->DataDirectory[0].Size)) {
				// funcaddress is forwarder
				// eg: kernelbase.testfunction


				return exportforwarderresolver((const char*)funcaddress);

				//return 0;
			}

			return funcaddress;
		}



		//std::cout << "functionname: " << (char*)dllbase + namerva << std::endl;

		//std::cout << "Funcaddress: " << funcaddress << std::endl;

	}
	return 0;
}




__forceinline ULONGLONG exportforwarderresolver(const char* forwarder) {

	// forwarder points to NTDLL.RtlUserExitThread for example
	char dllnametofind[128]{ 0 }, functionnametofind[128]{ 0 };
	char* dllnametofindptr = &dllnametofind[0],
		* functionnametofindptr = &functionnametofind[0];

	char* funcaddressptr = (char*)forwarder;
	while (true) {

		if (*funcaddressptr == '.') {
			break;
		}

		*dllnametofindptr = *funcaddressptr;

		dllnametofindptr++;
		funcaddressptr++;
	}
	funcaddressptr++;
	*dllnametofindptr = '.'; dllnametofindptr++;
	*dllnametofindptr = 'd'; dllnametofindptr++;
	*dllnametofindptr = 'l'; dllnametofindptr++;
	*dllnametofindptr = 'l'; dllnametofindptr++;


	while (true) {

		if (*funcaddressptr == 0) {
			break;
		}

		*functionnametofindptr = *funcaddressptr;

		functionnametofindptr++;
		funcaddressptr++;
	}

	auto forwardedbase = getdllbase(&dllnametofind[0]);
	if (forwardedbase) {
		return getdllexportfunctionaddress(forwardedbase, &functionnametofind[0]);
	}

	return 0;
}

