#include <Windows.h>

#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "scanner.h"

namespace fs = std::filesystem;

std::vector<std::string> scanner::GetFilesInDirectory(const char* path, const std::string& extension)
{
    std::vector<std::string> fileNames;

    for (const fs::directory_entry& entry : fs::directory_iterator(path))
    {
        if (entry.status().type() != fs::file_type::regular)
        {
            continue;
        }

        if (entry.path().extension() == extension)
        {
            fileNames.push_back(entry.path().string());
        }
    }

    return fileNames;
}

DWORD RvaToFileOffset(DWORD rva, IMAGE_NT_HEADERS* ntHeader)
{
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
    bool sectionFound = false;
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
    {
        if (rva >= sectionHeader->VirtualAddress && rva <= sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData)
        {
            sectionFound = true;
            break;
        }

        sectionHeader++;
    }

    if (sectionFound)
    {
        return rva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
    }
    else
    {
        return 0;
    }
}

std::vector<std::string> scanner::FindPEImports(const std::string& driverPath, const std::vector<std::string>& importNames)
{
    std::vector<std::string> foundImports;

    std::ifstream driverFile;

    driverFile.open(driverPath, std::ios_base::binary);
    if (!driverFile.is_open())
    {
        std::cout << "Error opening file: " << driverPath << std::endl;
        return foundImports;
    }

    struct stat fileInfo;
    stat(driverPath.c_str(), &fileInfo);
    char* fileBuffer = reinterpret_cast<char*>(VirtualAlloc(nullptr, fileInfo.st_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!fileBuffer)
    {
        std::cout << "Error, unable to allocate bytes for file: " << driverPath << std::endl;
        driverFile.close();
        return foundImports;
    }

    driverFile.read(fileBuffer, fileInfo.st_size);
    driverFile.close();

    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBuffer);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cout << "Error, invalid DOS signature for file: " << driverPath << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return foundImports;
    }

    IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBuffer + dosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cout << "Error, invalid NT signature for file: " << driverPath << std::endl;
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        return foundImports;
    }

    DWORD importDescriptorVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(fileBuffer + RvaToFileOffset(importDescriptorVA, ntHeader));

    for (int i = 0; importDescriptor[i].Characteristics != 0; i++)
    {
        DWORD importedFuncVA = importDescriptor[i].OriginalFirstThunk ? importDescriptor[i].OriginalFirstThunk : importDescriptor[i].FirstThunk;
        IMAGE_THUNK_DATA* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(fileBuffer + RvaToFileOffset(importedFuncVA, ntHeader));

        for (int j = 0; thunk[j].u1.AddressOfData != 0; j++)
        {
            DWORD importedFuncOffset = RvaToFileOffset(static_cast<DWORD>(thunk[j].u1.AddressOfData), ntHeader);
            if (!importedFuncOffset) { continue; }
            IMAGE_IMPORT_BY_NAME* importedFunc = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(fileBuffer + importedFuncOffset);

            for (const std::string &importName : importNames)
            {
                const std::string funcName = std::string(importedFunc->Name);
                if (funcName == importName && std::find(foundImports.begin(), foundImports.end(), importName) == foundImports.end() 
                    || funcName == "IoCreateDevice" && std::find(foundImports.begin(), foundImports.end(), "IoCreateDevice") == foundImports.end())
                {
                    foundImports.push_back(funcName);
                }
            }
        }
    }

    VirtualFree(fileBuffer, 0, MEM_RELEASE);

    if(std::find(foundImports.begin(), foundImports.end(), "IoCreateDevice") == foundImports.end() 
        || foundImports.size() == 1 && foundImports.back() == "IoCreateDevice")
    {
        foundImports.clear();
    }

    return foundImports;
}