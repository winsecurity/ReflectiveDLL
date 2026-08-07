#pragma once


#include <fstream>
#include <filesystem>
#include <iostream>
#include <Windows.h>
#include <winnt.h>
#include <algorithm>
#include <unordered_map>
#include <expected>
#include <winternl.h>
#include "utils.h"


#pragma comment(lib,"ntdll.lib")


void peparser(char* filename);






class PEParser64 {

protected:
	std::vector<char> pecontents;
	bool isparsedfromfile;
public:
	PEParser64(std::vector<char> buffer, bool);
	PEParser64();

	const IMAGE_DOS_HEADER* get_dos_header();
	DWORD get_signature();
	const IMAGE_FILE_HEADER* get_file_header();
	const IMAGE_OPTIONAL_HEADER64* get_optional_header();
	const IMAGE_SECTION_HEADER* get_section_header();
	int rva2fileoffset(int rva);

	std::unordered_map<std::string, ULONGLONG> get_exports();

	// dllname, [funcname,rva]
	std::unordered_map<std::string, std::vector<std::unordered_map<std::string,int>>> get_imports();

	std::vector<int> get_baserelocations();

};



std::expected<std::unique_ptr<PEParser64>, std::string> ParsePEFromFile(char* filename);

std::expected<std::unique_ptr<PEParser64>, std::string> ParsePEFromMemory(int pid);



class reflectiveloader: PEParser64 {


public:

	reflectiveloader();
	
	std::expected<bool, std::string> load_to_self_from_file(char* filename);




};

