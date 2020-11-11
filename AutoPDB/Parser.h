#pragma once
#include <vector>
#include <unordered_map>
#include <tuple>

using byte = unsigned char;
using signed_byte = signed char;

class Parser final {
public:
    Parser(const std::vector<byte>& bytes);
    void Parse(unsigned int startAddr);

private:
    // Yes
    void ParseOneFunction();
    byte ReadByte();
    signed_byte ReadSignedByte();
    int ReadSignedInt();
    void ReadBadByte();

    // Maybe, might need cleanup
    void Sub();
    void Add();
    void Mul();
    void Mov(bool reversed = false);
    void Xor();
    void And();
    void Or();
    void Cmp();
    void Test();
    void Dec();
    void Inc(const std::string& dst);
    void Div(const std::string& src);
    void Push(const std::string& src);
    void Pop(const std::string& dst);
    void Ret();
    void Call(unsigned int addr);
    void Cdq();

    void Add(const std::string& dst, byte src);
    void Sub(const std::string& dst, byte src);

    // Maybe
    std::string ReadEbpRel();
    std::string ReadEspRel();
    std::tuple<std::string, std:string> ReadRegisters();


    int _ebp_esp = 0;
    std::vector<byte> _bytes;
    std::unordered_map<unsigned int, std::string> _functions;
    std::vector<unsigned int> _unparsedFunctions;
    unsigned int _addr;
};

