#pragma once
#include <string>
#include <vector>

namespace scanner
{
    std::vector<std::string> GetFilesInDirectory(const char* path, const std::string& extension);
    std::vector<std::string> FindPEImports(const std::string& driverPath, const std::vector<std::string>& importNames);
}