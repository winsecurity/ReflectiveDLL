
#include "PEManager.h"





void peparser(char* filename) {

	if (!std::filesystem::exists(filename)) {
		std::cout << "file does not exist\n";
		return;
	}



	std::ifstream fd;
	fd.open(filename, std::ios::binary | std::ios::in);

	
	auto filesize = std::filesystem::file_size(filename);
	std::vector<char> pecontents(filesize, 0);

	if (!fd.is_open()) {

		std::cout << "cannot open file\n" << std::endl;
		return;
	}
	
	fd.read(pecontents.data(), filesize);
	fd.close();
	
	
	IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER * )pecontents.data();

	if (dosheader->e_magic != 0x5a4d) {
		std::cout << "File is not valid PE\n";
		return;
	}

	std::cout << "Magic number: " << std::hex << dosheader->e_magic << std::endl;
	std::cout << "elfa new: " << dosheader->e_lfanew << std::endl;

	DWORD* signature = (DWORD*)(pecontents.data() + dosheader->e_lfanew);
	std::cout << "PE Signature: " << *signature << std::endl;

	IMAGE_FILE_HEADER* fileheader = (IMAGE_FILE_HEADER*)(pecontents.data() + dosheader->e_lfanew + 4);
	std::cout << "Machine: " << fileheader->Machine << std::endl;
	std::cout << "Number of sections: " << fileheader->NumberOfSections << std::endl;
	std::cout << "Size of optional header: " << fileheader->SizeOfOptionalHeader << std::endl;


	IMAGE_OPTIONAL_HEADER64* optionalheader = (IMAGE_OPTIONAL_HEADER64*)(pecontents.data() + dosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
	std::cout << "Magic optionalheader: " << optionalheader->Magic << std::endl;
	std::cout << "Entry point: " << optionalheader->AddressOfEntryPoint << std::endl;
	std::cout << "Image base: " << optionalheader->ImageBase << std::endl;
	std::cout << "Section Alignment: " << optionalheader->SectionAlignment << std::endl;
	std::cout << "File Alignment: " << optionalheader->FileAlignment << std::endl;
	std::cout << "Size of image: " << optionalheader->SizeOfImage << std::endl;
	

	IMAGE_SECTION_HEADER* sectionheader = (IMAGE_SECTION_HEADER*)(pecontents.data() + dosheader->e_lfanew+ 4 + sizeof(IMAGE_FILE_HEADER) + fileheader->SizeOfOptionalHeader);
	for (int i = 0;i < fileheader->NumberOfSections;i++) {
		
		std::cout << "Section name: " << sectionheader->Name  << std::endl;
		std::cout << "raw address: " << sectionheader->PointerToRawData << std::endl;
		std::cout << "Virtual Address: " << sectionheader->VirtualAddress << std::endl;
		std::cout << "characteristics: " << sectionheader->Characteristics << std::endl;

		sectionheader++;
	}



	if (optionalheader->DataDirectory[0].Size) {

		IMAGE_EXPORT_DIRECTORY* exportdirectory = (IMAGE_EXPORT_DIRECTORY*)(pecontents.data() + optionalheader->DataDirectory[0].VirtualAddress);

		std::string dllname = pecontents.data() + exportdirectory->Name;
		std::cout << "export dll name: " << dllname << std::endl;

	}


	/*if (optionalheader->DataDirectory[1].Size) {
		IMAGE_IMPORT_DESCRIPTOR *import =  (IMAGE_IMPORT_DESCRIPTOR*) (pecontents.data() +optionalheader->DataDirectory[1].VirtualAddress);

		while (import->Name) {

			std::string dllname = pecontents.data() + import->Name;
			std::cout << "DLL name: " << dllname << std::endl;


			ULONGLONG *ogfirstthunkptr = (ULONGLONG * )(pecontents.data() + import->OriginalFirstThunk);

			while (ULONGLONG funcnameptr = *ogfirstthunkptr) {

				std::string funcname = pecontents.data() + funcnameptr + 2;
				std::cout << "functionname: " << funcname << std::endl;
				ogfirstthunkptr++;
			
			}



			import++;

		}

		

			


	}*/


	/*if (optionalheader->DataDirectory[5].Size) {

		IMAGE_BASE_RELOCATION* baserelocation = (IMAGE_BASE_RELOCATION*)(pecontents.data() +
			optionalheader->DataDirectory[5].VirtualAddress);

		int baserelocsize = optionalheader->DataDirectory[5].Size;

		while (baserelocation->VirtualAddress && baserelocsize) {

			std::cout << "virtual address: " << baserelocation->VirtualAddress << std::endl;
			std::cout << "size: " << baserelocation->SizeOfBlock << std::endl;
				

			for (int i = 0;i < (baserelocation->SizeOfBlock - 8) / 2;i++) {
				WORD relocvalue = *(WORD*)( (char*)baserelocation + 8 + i * 2);
				std::cout << "Reloc value: " << relocvalue << std::endl;


				auto relocrva =  baserelocation->VirtualAddress + (relocvalue&0x0FFF);
				std::cout << "Reloc rva: " << relocrva << std::endl;

			}


			baserelocsize -= baserelocation->SizeOfBlock;
			baserelocation = (IMAGE_BASE_RELOCATION*)((char*)baserelocation + baserelocation->SizeOfBlock);

		}
		
		




	}
	*/




}


std::expected<std::unique_ptr<PEParser64>, std::string> ParsePEFromFile(char* filename) {

	if (!std::filesystem::exists(filename)) {
		return std::unexpected("File does not exist");
	}

	std::ifstream fd;
	fd.open(filename, std::ios::binary);

	if (!fd.is_open()) {
		return std::unexpected("Cannot open the file");
	}

	auto filesize = std::filesystem::file_size(filename);
	std::vector<char> buffer (filesize);
	
	fd.read(&buffer[0], filesize);

	fd.close();

	IMAGE_DOS_HEADER* dosheader = (IMAGE_DOS_HEADER * )buffer.data();
	if (dosheader->e_magic != 0x5a4d) {
		return std::unexpected("File is not valid PE file");
	}



	IMAGE_FILE_HEADER* fileheader = (IMAGE_FILE_HEADER*)(buffer.data() + dosheader->e_lfanew + 4);
	if (fileheader->Machine != 0x8664) {
		return std::unexpected("File is not valid 64bit PE file");
	}


	return std::make_unique<PEParser64>(buffer, true);


}


std::expected<std::unique_ptr<PEParser64>, std::string> ParsePEFromMemory(int pid) {

	HANDLE processhandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (processhandle == NULL) {
		
		return std::unexpected("Opening process failed: " + GetLastError());
	}
	
	std::vector<char> buffer (sizeof(PROCESS_BASIC_INFORMATION));
	ULONG returnlength = 0;
	NTSTATUS res = NtQueryInformationProcess(processhandle, ProcessBasicInformation, buffer.data(), buffer.size(), &returnlength);
	if (res != 0) {
		CloseHandle(processhandle);
		return std::unexpected("Querying process failed: " + res);
	}

	PPROCESS_BASIC_INFORMATION pbi = (PPROCESS_BASIC_INFORMATION)buffer.data();
	MY_PEB peb{};
	SIZE_T bytesread = 0;
	ReadProcessMemory(processhandle, pbi->PebBaseAddress, &peb, sizeof(MY_PEB), &bytesread);
	//std::cout << "bytesread: " << bytesread << std::endl;
	//std::cout << "process base address: " << std::hex<< peb.ImageBaseAddress << std::endl;

	IMAGE_DOS_HEADER dosheader;
	ReadProcessMemory(processhandle, peb.ImageBaseAddress, &dosheader, sizeof(IMAGE_DOS_HEADER), &bytesread);
	
	if (dosheader.e_magic != 0x5a4d) {
		CloseHandle(processhandle);
		return std::unexpected("Not valid PE memory: " + GetLastError());
	}

	IMAGE_FILE_HEADER fileheader;
	ReadProcessMemory(processhandle,
		((char*)peb.ImageBaseAddress+dosheader.e_lfanew+4), &fileheader, sizeof(IMAGE_FILE_HEADER), &bytesread);


	if (fileheader.Machine != 0x8664) {
		CloseHandle(processhandle);
		return std::unexpected("Not valid x64 PE memory: " + GetLastError());
	}

	IMAGE_OPTIONAL_HEADER64 optionalheader;
	ReadProcessMemory(processhandle, ((char*)peb.ImageBaseAddress + dosheader.e_lfanew+4+
		sizeof(IMAGE_FILE_HEADER)), &optionalheader, sizeof(IMAGE_OPTIONAL_HEADER64), &bytesread);

	
	std::vector<char> buffer2(optionalheader.SizeOfImage);
	ReadProcessMemory(processhandle, peb.ImageBaseAddress, buffer2.data(),
		optionalheader.SizeOfImage, &bytesread);

	
	CloseHandle(processhandle);
	return std::make_unique<PEParser64>(buffer2, false);

}



PEParser64::PEParser64(std::vector<char> buffer, bool isparsedfromfile) {

	this->isparsedfromfile = isparsedfromfile;
	this->pecontents = buffer;

}


const IMAGE_DOS_HEADER* PEParser64::get_dos_header() {


	if (pecontents.size() >= sizeof(IMAGE_DOS_HEADER)) {
		return (IMAGE_DOS_HEADER * )pecontents.data();
	}

	return nullptr;
}


DWORD PEParser64::get_signature() {

	if (auto dosheader = get_dos_header()) {
		return *(DWORD*)(pecontents.data() + dosheader->e_lfanew);
	}
	return 0;
}



const IMAGE_FILE_HEADER* PEParser64::get_file_header() {

	if (auto dosheader = get_dos_header()) {
		return (IMAGE_FILE_HEADER*)(pecontents.data() + dosheader->e_lfanew + 4);
	}

	return nullptr;

}

const IMAGE_OPTIONAL_HEADER64* PEParser64::get_optional_header() {

	if (auto dosheader = get_dos_header()) {
		return (IMAGE_OPTIONAL_HEADER64*)(pecontents.data() + dosheader->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER));
	}

	return nullptr;

}



const IMAGE_SECTION_HEADER* PEParser64::get_section_header() {

	if (auto dosheader = get_dos_header()) {
		auto fileheader = get_file_header();
		return (IMAGE_SECTION_HEADER*)(pecontents.data() +
			dosheader->e_lfanew + 4 +
			sizeof(IMAGE_FILE_HEADER) + fileheader->SizeOfOptionalHeader);
	}

	return nullptr;

}




int PEParser64::rva2fileoffset(int rva) {
	
	auto fileheader = get_file_header();
	if (!fileheader) { return 0; }

	auto sectionheader = this->get_section_header();
	if (!sectionheader) { return 0; }


	for (int i = 0;i < fileheader->NumberOfSections;i++) {
		
		DWORD maxsize = max(sectionheader->SizeOfRawData, sectionheader->Misc.VirtualSize);
		if (sectionheader->VirtualAddress <= rva && rva < (sectionheader->VirtualAddress + maxsize)) {
			// rva belongs to this section
			auto delta = rva - sectionheader->VirtualAddress;
			return delta + sectionheader->PointerToRawData;
		}
		sectionheader++;
	}


}


std::unordered_map<std::string, ULONGLONG> PEParser64::get_exports() {

	std::unordered_map<std::string, ULONGLONG> result;
	auto optionalheader = get_optional_header();
	if (!optionalheader) { return result; }

	if (!optionalheader->DataDirectory[0].Size) { return result; }


	IMAGE_EXPORT_DIRECTORY* exportdirectory;

	if (isparsedfromfile) {
		exportdirectory = (IMAGE_EXPORT_DIRECTORY * ) (pecontents.data() + rva2fileoffset(optionalheader->DataDirectory[0].VirtualAddress));
	}
	else {
		exportdirectory = (IMAGE_EXPORT_DIRECTORY*)(pecontents.data() + optionalheader->DataDirectory[0].VirtualAddress);
	}



	std::string dllname;
	if (isparsedfromfile) {
		dllname = pecontents.data() + rva2fileoffset(exportdirectory->Name);
	}
	else {
		dllname = pecontents.data() + exportdirectory->Name;
	}

	
	PVOID funcptr, nameptr, ordinalptr;
	if (isparsedfromfile) {
		funcptr = pecontents.data() + rva2fileoffset(exportdirectory->AddressOfFunctions);
		nameptr = pecontents.data() + rva2fileoffset(exportdirectory->AddressOfNames);
		ordinalptr = pecontents.data() + rva2fileoffset(exportdirectory->AddressOfNameOrdinals);

	}

	else {
		funcptr = pecontents.data() + (exportdirectory->AddressOfFunctions);
		nameptr = pecontents.data() + (exportdirectory->AddressOfNames);
		ordinalptr = pecontents.data() + (exportdirectory->AddressOfNameOrdinals);

	}

	
	for (int i = 0;i < exportdirectory->NumberOfNames;i++) {

		auto namerva= *(DWORD*) ((char*)nameptr + i * 4);
		auto ordinalvalue = *(WORD*)((char*)ordinalptr + i * 2);
		auto funcrva = *(DWORD*)((char*)funcptr + ordinalvalue * 4);

		if (isparsedfromfile) {
			//std::cout << "Function name: " << (pecontents.data() + rva2fileoffset(namerva)) << std::endl;
			//std::cout << "Ordinal value: " << ordinalvalue << std::endl;
			//std::cout << "Function rva: " << funcrva << std::endl;
			result.insert({ (pecontents.data() + rva2fileoffset(namerva)) ,funcrva });

		}
		else {
			//std::cout << "Function name: " << (pecontents.data() + (namerva)) << std::endl;
			//std::cout << "Ordinal value: " << ordinalvalue << std::endl;
			//std::cout << "Function rva: " << funcrva << std::endl;
			result.insert({ (pecontents.data() + (namerva)) ,funcrva });

		}




	
	}



	return result;
}


std::unordered_map<std::string, std::vector<std::unordered_map<std::string, int>>> PEParser64::get_imports() {

	std::unordered_map<std::string, std::vector<std::unordered_map<std::string, int>>> result;


	auto optionalheader = get_optional_header();
	if (!optionalheader) { return result; }

	if (!optionalheader->DataDirectory[1].Size) { return result; }

	IMAGE_IMPORT_DESCRIPTOR *importptr;
	if (isparsedfromfile) {
		importptr= (IMAGE_IMPORT_DESCRIPTOR*)(pecontents.data() + rva2fileoffset(optionalheader->DataDirectory[1].VirtualAddress));
	
	}
	else {
		importptr= (IMAGE_IMPORT_DESCRIPTOR*)(pecontents.data() + (optionalheader->DataDirectory[1].VirtualAddress));

	}



	while (importptr->Name) {

		std::string dllname;
		if (isparsedfromfile) {
			dllname = pecontents.data() + rva2fileoffset(importptr->Name);
		}
		else {
			dllname = pecontents.data() + (importptr->Name);
		}
		

		//std::cout << "Dllname: " << dllname << std::endl;


		ULONGLONG* ogfirstthunk, *firstthunkptr;
		if (isparsedfromfile) {
			ogfirstthunk = (ULONGLONG *) (pecontents.data() + rva2fileoffset(importptr->OriginalFirstThunk));
			firstthunkptr = (ULONGLONG*)(pecontents.data() + rva2fileoffset(importptr->FirstThunk));
		}
		else {
			ogfirstthunk = (ULONGLONG*)(pecontents.data() + (importptr->OriginalFirstThunk));
			firstthunkptr = (ULONGLONG*)(pecontents.data() + (importptr->FirstThunk));
		}

		std::vector<std::unordered_map<std::string, int>> result2;

		while (*ogfirstthunk) {

			auto funcnamerva = *ogfirstthunk;
			std::string funcname;
			if (isparsedfromfile) {
				funcname = pecontents.data() + rva2fileoffset(funcnamerva) + 2;
			}
			else {
				funcname = pecontents.data() + (funcnamerva)+2;
			}

			//std::cout << "function name: " << funcname << std::endl;
			//std::cout << "firstthunk rva: " << *firstthunkptr << std::endl;
			
			result2.push_back(std::unordered_map<std::string, int> {{ funcname, * firstthunkptr} });


			ogfirstthunk++;
			firstthunkptr++;

		}


		result.insert({ dllname,result2 });


		importptr++;
	}

	return result;

}


std::vector<int> PEParser64::get_baserelocations() {

	std::vector<int> relocations{ NULL };

	auto optionalheader = get_optional_header();
	if (!optionalheader) { return relocations; }


	if (!optionalheader->DataDirectory[5].Size) { return relocations; }

	auto totalsize = optionalheader->DataDirectory[5].Size;
	IMAGE_BASE_RELOCATION* baserelocation;
	if (isparsedfromfile) {
		baserelocation = (IMAGE_BASE_RELOCATION * )(pecontents.data() + rva2fileoffset(optionalheader->DataDirectory[5].VirtualAddress));
	}
	else {
		baserelocation = (IMAGE_BASE_RELOCATION*)(pecontents.data() + optionalheader->DataDirectory[5].VirtualAddress);
	}


	while (totalsize) {

		//std::cout << "Page RVA: " << baserelocation->VirtualAddress << std::endl;

		for (int i = 0;i < (baserelocation->SizeOfBlock - 8) / 2;i++) {
			WORD *relocrva = (WORD*)((char*)baserelocation + 8 + i * 2);
			WORD relocrva2 = *relocrva & 0x0FFF;
			//std::cout << "Reloc rva: " << baserelocation->VirtualAddress + relocrva2 << std::endl;
			relocations.push_back(baserelocation->VirtualAddress + relocrva2);
		}


		totalsize -= baserelocation->SizeOfBlock;

		baserelocation = (IMAGE_BASE_RELOCATION*)(( (char*)baserelocation + baserelocation->SizeOfBlock));
		
	}


	return relocations;

}



std::expected<bool, std::string> reflectiveloader::load_to_self_from_file(char* filename) {


	if (!std::filesystem::exists(filename)) {
		return std::unexpected("File does not exist");
	}

	std::ifstream fd;
	fd.open(filename, std::ios::binary);

	if (!fd.is_open()) {
		return std::unexpected("Cannot open the file");
	}

	auto filesize = std::filesystem::file_size(filename);
	this->pecontents.resize(filesize);
	this->isparsedfromfile = true;

	fd.read(pecontents.data(), filesize);

	fd.close();


	const IMAGE_DOS_HEADER* dosheader = get_dos_header();
	if (dosheader->e_magic != 0x5a4d) {
		return std::unexpected("File is not valid PE file");
	}



	const IMAGE_FILE_HEADER* fileheader = get_file_header();
	if (fileheader->Machine != 0x8664) {
		return std::unexpected("File is not valid 64bit PE file");
	}


	std::cout << "Machine: " << fileheader->Machine << std::endl;
	std::cout << "Number of sections: " << fileheader->NumberOfSections << std::endl;
	std::cout << "size of optional header: " << fileheader->SizeOfOptionalHeader << std::endl;

	auto optionalheader = get_optional_header();

	auto imagesize = optionalheader->SizeOfImage;

	LPVOID baseaddress = VirtualAlloc(NULL, imagesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (baseaddress == NULL) {
		return std::unexpected("Virtualalloc failed: " + GetLastError());
	}

	// copying headers
	memcpy(baseaddress, pecontents.data(), optionalheader->SizeOfHeaders);


	// copying sections
	const IMAGE_SECTION_HEADER* sectionheader = get_section_header();
	for (int i = 0;i < fileheader->NumberOfSections;i++) {



		std::cout << "sectionname: " << sectionheader->Name << std::endl;
		
		
		memcpy((char*)baseaddress + sectionheader->VirtualAddress,
			pecontents.data() + sectionheader->PointerToRawData, 
			sectionheader->SizeOfRawData);

		sectionheader++;

	}


	// fixing imports
	auto imports = get_imports();
	for (auto i : imports) {
		// dllname i.first
		HMODULE dllhandle = LoadLibraryA(i.first.data());

		for (auto j : i.second) {
			
			for (auto k : j) {
				// k.first = functionname
				// k.second = firstthunk rva
				
				FARPROC functionaddress = GetProcAddress(dllhandle, k.first.data());

				memcpy((char*)baseaddress + k.second, &functionaddress, 8);


			}
			

		}
	}


	// fixing base relocations
	auto relocations = get_baserelocations();
	auto delta = (char*)baseaddress - optionalheader->ImageBase;

	for (auto i : relocations) {
		// reading address at baseaddress+relocation
		ULONGLONG reloc1;
		memcpy(&reloc1, (char*)baseaddress + i, 8);

		reloc1 += (ULONGLONG)delta;
	
		// write the fixed after relocation
		memcpy((char*)baseaddress + i, &reloc1, 8);
	}


	ULONG threadid = 0;
	HANDLE threadhandle = CreateThread(NULL, 0,LPTHREAD_START_ROUTINE ((char*)baseaddress + optionalheader->AddressOfEntryPoint),
		NULL, 0, &threadid);
	if (threadhandle == NULL) {
		std::cout << "CreateThread failed: " << GetLastError() << std::endl;
	}






}


reflectiveloader::reflectiveloader() {

}

PEParser64::PEParser64() {

}
