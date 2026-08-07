

#include "InjectionManager.h"
#include <fstream>
#include <thread>
#include <chrono>



int main() {

	// "C:\Users\NIKHIL\source\repos\mydll\x64\Release\mydll.dll"
	std::string dllpath = "C:\\Users\\NIKHIL\\source\\repos\\reflectiveloader\\x64\\Release\\reflectiveloader.dll";




	auto filesize = std::filesystem::file_size(dllpath);
	std::vector<char> buffer(filesize);

	std::ifstream fd;
	fd.open(dllpath, std::ios::binary);

	if (fd.is_open()) {
	
		fd.read(buffer.data(), filesize);
			
		fd.close();
	}


	auto res5 = ParsePEFromFile(dllpath.data());
	if (res5.has_value()) {
		auto pe = std::move(res5.value());

		auto optionalheader = pe->get_optional_header();
		/*LPVOID baseaddress = VirtualAlloc(NULL, optionalheader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (baseaddress) {


			WriteProcessMemory(GetCurrentProcess(), baseaddress, buffer.data(),
				buffer.size(), NULL);

			auto exports = pe->get_exports();
			for (auto& i : exports) {
				if (i.first == "test") {
					// i.second funcrva
					std::cout << i.first << std::endl;
					std::cout << std::hex << pe->rva2fileoffset(i.second) << std::endl;
					//((void (*)())((char*)baseaddress + pe->rva2fileoffset(i.second)))();

					ULONG threadid = 0;
					HANDLE threadhandle = CreateThread(NULL, 0, LPTHREAD_START_ROUTINE((char*)baseaddress + pe->rva2fileoffset(i.second)),
						nullptr, 0, &threadid);

					if (threadhandle) {

						WaitForSingleObject(threadhandle, INFINITE);

					}
				}
			}
			//VirtualFree(baseaddress, 0, MEM_RELEASE);

		}
		
		*/
		auto prochandle = OpenProcess(PROCESS_ALL_ACCESS, false, 42004);
			if (prochandle) {

				LPVOID remotebase = VirtualAllocEx(prochandle,NULL, optionalheader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (remotebase) {


					WriteProcessMemory(prochandle, remotebase, buffer.data(),
						buffer.size(), NULL);
					std::cout << "remotebase : " <<std::hex<< (ULONGLONG*)remotebase << std::endl;
					auto exports = pe->get_exports();
					for (auto& i : exports) {
						if (i.first == "test") {
							// i.second funcrva
							std::cout << i.first << std::endl;
							std::cout << std::hex << pe->rva2fileoffset(i.second) << std::endl;
							//((void (*)())((char*)baseaddress + pe->rva2fileoffset(i.second)))();

							ULONG threadid = 0;
							HANDLE threadhandle = CreateRemoteThread(prochandle,NULL, 0, LPTHREAD_START_ROUTINE((char*)remotebase + pe->rva2fileoffset(i.second)),
								nullptr, 0, &threadid);


						}
					}

			}

				std::this_thread::sleep_for(std::chrono::seconds(2));
				VirtualFreeEx(prochandle,remotebase, 0, MEM_RELEASE);

				CloseHandle(prochandle);

			

		



		}
			
	
	}
	
	



	return 0;

}
