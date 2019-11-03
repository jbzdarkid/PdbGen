#pragma once
#include <vector>
#include <string>

class MD5 final {
public:
    static std::vector<uint8_t> HashFile(const std::string& filename);
};
