#include "utils.h"

size_t utils::GetLongestStringLength(const std::vector<std::string>& strings)
{
    size_t longestStringLength = 0;
    for (const std::string& str : strings)
    {
        if (str.length() > longestStringLength)
        {
            longestStringLength = str.length();
        }
    }

    return longestStringLength;
}