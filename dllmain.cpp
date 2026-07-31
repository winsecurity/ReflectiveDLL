// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>



BOOL __declspec(dllexport) DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBoxA(NULL, "subscribe to tech69 youtube channel", "title bar", 0);
		break;

	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		//MessageBoxA(NULL, "test", "test", 0);
		break;
	}
	return TRUE;
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
		while (*dllptr ) {

			if (*namebufptr == 0 ) {
				break;
			}
			
			if (*namebufptr != *dllptr) {
				isourdll = false;
				break;
			}

			namebufptr++;
			dllptr++;

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
		while (*functionnameptr) {

			if (*funcnameptr == 0) {
				break;
			}

			if (*funcnameptr != *functionnameptr) {
				isourfunction = false;
				break;
			}
			funcnameptr++;
			functionnameptr++;


		}

		if (isourfunction) {
			return funcaddress;
		}
		


		//std::cout << "functionname: " << (char*)dllbase + namerva << std::endl;

		//std::cout << "Funcaddress: " << funcaddress << std::endl;

	}
	return 0;
}


extern "C" void __declspec(dllexport) test() {

	ULONGLONG loadlibraryaddress = 0;
	ULONGLONG getprocaddressaddress = 0;
	ULONGLONG virtualallocaddress = 0;
	ULONGLONG ourdllbase = 0;
	ULONGLONG virtualprotectaddress = 0;
	char dll1[] = { 'K','E','R','N','E','L','3','2','.','D','L','L',0 };
	char func1[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
	char func2[] = { 'V','i','r','t','u','a','l','A','l','l','o','c',0 };
	char func3[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
	char func4[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0 };
	ourdllbase = getdllbase(&dll1[0]);
	if (ourdllbase) {
		loadlibraryaddress = getdllexportfunctionaddress(ourdllbase, &func1[0]);
		getprocaddressaddress = getdllexportfunctionaddress(ourdllbase, &func3[0]);
		virtualallocaddress = getdllexportfunctionaddress(ourdllbase, &func2[0]);
		virtualprotectaddress = getdllexportfunctionaddress(ourdllbase, &func4[0]);
	}

	if (!loadlibraryaddress || !getprocaddressaddress || !virtualallocaddress || !virtualprotectaddress) {
		return;
	}
	 
	 /*auto ppeb = __readgsqword(0x60);
	 // ldr address
	 ULONGLONG ldr = *(ULONGLONG*)((char*)ppeb + 0x18);
	 // ldr+0x10 inloadordermodulelist
	 ULONGLONG firstldrdatatableentry = *(ULONGLONG*)((char*)ldr + 0x10);

	 while (firstldrdatatableentry != ldr + 0x10) {
		 // ldrdatatableentry+0x58 basedllname UNICODE_STRING, 
		 ULONGLONG namebuf = *(ULONGLONG*)((char*)firstldrdatatableentry + 0x58 + 0x8);
		 //std::wcout << std::hex << "dllname: " << (wchar_t*)namebuf << std::endl;

		 char* namebufptr = (char*)namebuf;
		 if (*namebufptr == 'K' && (*(namebufptr + 2)) == 'E'
			 && (*(namebufptr + 4)) == 'R'
			 && (*(namebufptr + 6)) == 'N' && (*(namebufptr + 8)) == 'E'
			 && (*(namebufptr + 10)) == 'L' && (*(namebufptr + 12)) == '3'
			 && (*(namebufptr + 14)) == '2') {
	
			ULONGLONG dllbase = *(ULONGLONG*)(firstldrdatatableentry + 0x30);
			 
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
				 if (funcnameptr[0] == 'V' && funcnameptr[1] == 'i' &&
					 funcnameptr[2] == 'r' && funcnameptr[3] == 't' &&
					 funcnameptr[4] == 'u' && funcnameptr[5] == 'a' && funcnameptr[6] == 'l' &&
					 funcnameptr[7] == 'A' && funcnameptr[8] == 'l' && funcnameptr[9] == 'l' &&
					 funcnameptr[10] == 'o' && funcnameptr[11] == 'c' && funcnameptr[12] == '\0') {

			
					 virtualallocaddress = funcaddress;
				 }


				 if (funcnameptr[0] == 'G' && funcnameptr[1] == 'e' &&
					 funcnameptr[2] == 't' && funcnameptr[3] == 'P' &&
					 funcnameptr[4] == 'r' && funcnameptr[5] == 'o' && funcnameptr[6] == 'c' &&
					 funcnameptr[7] == 'A' && funcnameptr[8] == 'd' && funcnameptr[9] == 'd' &&
					 funcnameptr[10] == 'r' && funcnameptr[11] == 'e' && funcnameptr[12] == 's') {

				
					 getprocaddressaddress = funcaddress;
				 }



				 if (funcnameptr[0] == 'L' && funcnameptr[1] == 'o' &&
					 funcnameptr[2] == 'a' && funcnameptr[3] == 'd' &&
					 funcnameptr[4] == 'L' && funcnameptr[5] == 'i' && funcnameptr[6] == 'b' &&
					 funcnameptr[7] == 'r' && funcnameptr[8] == 'a' && funcnameptr[9] == 'r' &&
					 funcnameptr[10] == 'y' && funcnameptr[11] == 'A') {

					
					 loadlibraryaddress = funcaddress;
				 }


				 if (funcnameptr[0] == 'V' && funcnameptr[1] == 'i' &&
					 funcnameptr[2] == 'r' && funcnameptr[3] == 't' &&
					 funcnameptr[4] == 'u' && funcnameptr[5] == 'a' && funcnameptr[6] == 'l' &&
					 funcnameptr[7] == 'P' && funcnameptr[8] == 'r' && funcnameptr[9] == 'o' &&
					 funcnameptr[10] == 't' && funcnameptr[11] == 'e' && funcnameptr[12] == 'c'
					 && funcnameptr[13] == 't'
					 && funcnameptr[14] == 0) {


					 virtualprotectaddress = funcaddress;
				 }


				 //std::cout << "functionname: " << (char*)dllbase + namerva << std::endl;

				 //std::cout << "Funcaddress: " << funcaddress << std::endl;

			 }

		 }



		 firstldrdatatableentry = *(ULONGLONG*)(firstldrdatatableentry);

	 }
	 */

	 auto mainaddr = (char*)&DllMain;
	 while (true) {

		 if (*mainaddr == 'M' && *(mainaddr + 1) == 'Z') {
			 break;
		 }

		 mainaddr--;
	 }

	 ourdllbase = (ULONGLONG)(mainaddr);

	 
	 IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER*)ourdllbase;
	 IMAGE_FILE_HEADER* fileheader = (IMAGE_FILE_HEADER*)((char*)ourdllbase + dosheader->e_lfanew + 4);
	 IMAGE_OPTIONAL_HEADER64* optionalheader = (IMAGE_OPTIONAL_HEADER64*)((char*)ourdllbase +
		 dosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));

	 auto virtualallocaddressrunner = (LPVOID(*)(LPVOID, SIZE_T, DWORD, DWORD)) virtualallocaddress;
	 LPVOID baseaddress = virtualallocaddressrunner(NULL, optionalheader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);


	 // copying headers
	 for (int i = 0;i < optionalheader->SizeOfHeaders;i++) {
		 *((char*)baseaddress + i) = *((char*)ourdllbase + i);
	 }




	 // copying sections to their respective virutal addresses
	 IMAGE_SECTION_HEADER* sectionheader = (IMAGE_SECTION_HEADER*)
		 ((char*)ourdllbase +
			 dosheader->e_lfanew + 4 +
			 sizeof(IMAGE_FILE_HEADER) + fileheader->SizeOfOptionalHeader);



	 for (int i = 0;i < fileheader->NumberOfSections;i++) {


		 auto sectionva = sectionheader->VirtualAddress;
		 auto rawdata = sectionheader->PointerToRawData;
		 auto sizeofrawdata = sectionheader->SizeOfRawData;
		 for (int j = 0;j < sizeofrawdata;j++) {

			 *(char*)((char*)baseaddress + sectionva + j) =
				 *(char*)((char*)ourdllbase + rawdata + j);
		 }

		
		 sectionheader++;
	 }


	 //dosheader = (IMAGE_DOS_HEADER*)baseaddress;
	 // fileheader = (IMAGE_FILE_HEADER*)((char*)baseaddress + dosheader->e_lfanew + 4);
	 //optionalheader = (IMAGE_OPTIONAL_HEADER64*)((char*)baseaddress +
	 //	dosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));

	 // fixing base relocations
	 if (optionalheader->DataDirectory[5].Size) {

		 IMAGE_BASE_RELOCATION* baserelocation = (IMAGE_BASE_RELOCATION*)((char*)baseaddress + optionalheader->DataDirectory[5].VirtualAddress);

		 auto delta = (LONGLONG)baseaddress - optionalheader->ImageBase;

		 while (baserelocation->VirtualAddress) {

			 auto pagerva = (char*)baseaddress + baserelocation->VirtualAddress;
			 auto blocksize = baserelocation->SizeOfBlock;


			 for (int i = 0;i < (blocksize - 8) / 2;i++) {

				 WORD* entry = (WORD*)((char*)baserelocation + 8 + i * 2);
				 // 64 bit
				 if ((*entry & 0xF000) == 0xA000) {
					 WORD entryvalue = (*entry) & 0x0FFF;
					 auto relocrva = pagerva + entryvalue;

					 ULONGLONG oldaddress = *(ULONGLONG*)relocrva;
					 ULONGLONG newaddress = oldaddress + delta;

					 // writing new address
					 *(ULONGLONG*)relocrva = newaddress;

				 }
				 

			 }

			 baserelocation = (IMAGE_BASE_RELOCATION*)((char*)baserelocation + blocksize);

		 }





	 }


	 // fixing imports
	 if (optionalheader->DataDirectory[1].Size) {

		 IMAGE_IMPORT_DESCRIPTOR* importptr = (IMAGE_IMPORT_DESCRIPTOR*)((char*)baseaddress + 
			 optionalheader->DataDirectory[1].VirtualAddress);

		 while (importptr->Name) {

			 auto dllnameptr = (char*)baseaddress + importptr->Name;

			 HMODULE dllhandle = ((HMODULE(*)(LPCSTR))loadlibraryaddress) (dllnameptr);

			 ULONGLONG* ogfirstthunkptr = (ULONGLONG*)((char*)baseaddress + importptr->OriginalFirstThunk);
			 ULONGLONG* firstthunkptr = (ULONGLONG*)((char*)baseaddress + importptr->FirstThunk);

			 while (*ogfirstthunkptr) {


				 char* funcnamerva = (char*)baseaddress + *ogfirstthunkptr + 2;

				 FARPROC funcaddress = ((FARPROC(*)(HMODULE, LPCSTR))getprocaddressaddress)(dllhandle, funcnamerva);

				 // write legit function address at firstthunk ptr
				 *firstthunkptr = (ULONGLONG)funcaddress;


				 ogfirstthunkptr++;
				 firstthunkptr++;
			 }



			 importptr++;
		 }

	 }


	 // resetting sectionheaderptr
	 sectionheader = (IMAGE_SECTION_HEADER*)
		 ((char*)ourdllbase +
			 dosheader->e_lfanew + 4 +
			 sizeof(IMAGE_FILE_HEADER) + fileheader->SizeOfOptionalHeader);

	 for (int i = 0;i < fileheader->NumberOfSections;i++) {

		 auto characteristics = sectionheader->Characteristics;
		 DWORD oldprotect = 0;
		 auto sectionva = sectionheader->VirtualAddress;

		 if (((characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ) &&
			 ((characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) &&
			 ((characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)) {
			 //RWX

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);

		 }


		 else if (((characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ) &&
			 ((characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)) {
			 // RW

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_READWRITE, &oldprotect);

		 }

		 else if (((characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ) &&
			 ((characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)) {
			 // RX

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_EXECUTE_READ, &oldprotect);

		 }
		 else if (((characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE) &&
			 ((characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)) {
			 // WX

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);

		 }


		 else if (((characteristics & IMAGE_SCN_MEM_READ) == IMAGE_SCN_MEM_READ)) {
			 //R

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_READONLY, &oldprotect);

		 }

		 else if (((characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE)) {
			 // X

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_EXECUTE, &oldprotect);

		 }


		 else if (((characteristics & IMAGE_SCN_MEM_WRITE) == IMAGE_SCN_MEM_WRITE)) {
			 // W

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_READWRITE, &oldprotect);

		 }
		 else {

			 ((bool (*)(LPVOID, SIZE_T, DWORD, PDWORD))(virtualprotectaddress))(
				 (char*)baseaddress + sectionva, sectionheader->Misc.VirtualSize, PAGE_NOACCESS, &oldprotect);

		 }


		 sectionheader++;
	 }
	 

	 //((void(*)())((char*)baseaddress + optionalheader->AddressOfEntryPoint))();

	((BOOL (*)(HMODULE,DWORD,LPVOID))
		((char*)baseaddress + optionalheader->AddressOfEntryPoint))(NULL,DLL_PROCESS_ATTACH,NULL);

}


 
