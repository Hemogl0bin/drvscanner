#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#include "scanner.h"
#include "utils.h"

namespace fs = std::filesystem;

std::vector<std::string> targetImports = { "MmMapIoSpace", "MmGetPhysicalAddress", "MmMapLockedPagesSpecifyCache", "MmBuildMdlForNonPagedPool" };

class DriverInfo
{
public:
    DriverInfo(const fs::path &driverPath, const std::vector<std::string> &imports)
        : driverPath(driverPath)
        , imports(imports)
    {
    }

    fs::path driverPath;
    std::vector<std::string> imports;
};

std::vector<DriverInfo> resultingDrivers;

bool DriverInfoSortComparison(const DriverInfo &d1, const DriverInfo &d2)
{
    return d1.imports.size() > d2.imports.size();
}

int main(int argc, const char** argv)
{
    if (argc < 2)
    {
        std::cout << "Incorrect Usage! Please use drvscanner.exe [folder path] [target imports file](optional)" << std::endl;
        return 0;
    }

    if (!fs::is_directory(argv[1]))
    {
        std::cout << "Could not find directory " << argv[1] << "." << std::endl;
        return 0;
    }

    if(argc == 3)
    {
        std::ifstream targetImportsFile;
        targetImportsFile.open(argv[2], std::ios::in);
        if(!targetImportsFile.is_open())
        {
            std::cout << "Could not find target_imports.txt." << std::endl;
            return 0;
        }

        targetImports.clear();
        std::string currentImport = "";
        while(targetImportsFile.peek() != EOF)
        {
            targetImportsFile >> currentImport;
            targetImports.push_back(currentImport);
        }
    }

    std::vector<std::string> drivers = scanner::GetFilesInDirectory(argv[1], ".sys");
    std::cout << "[~] Found " << drivers.size() << " drivers." << std::endl;

    std::ofstream logFile;
    logFile.open("log.txt", std::ios::out);
    if (!logFile.is_open())
    {
        std::cout << "Unable to open log file." << std::endl;
        return 0;
    }

    std::cout << "[~] Searching for the following imports: " << std::endl;
    for (int i = 0; i < targetImports.size(); i++)
    {
        std::cout << "  (" << i << ") " << targetImports[i] << std::endl;
    }

    std::vector<std::string> resultingDriverFileNames;

    for (std::string driverPathStr : drivers)
    {
        std::vector<std::string> foundImports = scanner::FindPEImports(driverPathStr, targetImports);
        std::sort(foundImports.begin(), foundImports.end());
        if (foundImports.empty()) { continue; }
        fs::path driverPath = fs::path(driverPathStr);
        resultingDrivers.push_back(DriverInfo(driverPathStr, foundImports));
        resultingDriverFileNames.push_back(driverPath.filename().string());
    }

    std::sort(resultingDrivers.begin(), resultingDrivers.end(), DriverInfoSortComparison);

    size_t longestDriverFileNameLength = utils::GetLongestStringLength(resultingDriverFileNames);
    for (const DriverInfo &driverInfo : resultingDrivers)
    {
        std::string fileName = driverInfo.driverPath.filename().string();
        std::string logText = fileName;
        
        for (size_t i = 0; i < longestDriverFileNameLength - fileName.length() + 5; i++)
        {
            logText += " ";
        }

        logText += "[";

        for (const std::string &importName : driverInfo.imports)
        {
            std::stringstream appendText;
            appendText << importName;
            if(driverInfo.imports.back() == importName)
            {
                 appendText << "] (" << driverInfo.imports.size() << ")";
            }
            else
            {
                appendText << " / ";
            }

            logText = logText + appendText.str();
        }
    
        logFile << logText << std::endl;
    }

    logFile.close();

    std::cout << "[~] Done, found " << resultingDrivers.size() << " potentially vulnerable drivers." << std::endl;

    return 0;
}