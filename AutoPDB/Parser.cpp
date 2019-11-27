#include "Parser.h"
#include <iostream>

// @Performance, why am I copying this buffer? I guess in the future this will be just a reference to the buffer...
Parser::Parser(const std::vector<byte>& bytes) : _bytes(bytes)
{
}

void Parser::Parse(unsigned int startAddr)
{
    std::string name = "func0000";
    _functions[startAddr] = name;
    _unparsedFunctions.emplace_back(startAddr);
    while (_unparsedFunctions.size() > 0) ParseOneFunction();

}

void Parser::ParseOneFunction()
{
    _addr = _unparsedFunctions.front();
    _unparsedFunctions.pop_back();
    std::cout << "\nFunction " << _functions[_addr] << " at address " << std::hex << std::showbase << _addr << std::endl;

    while (1) {
        switch (ReadByte()) {
        case 0x03:
            auto [src, dst] = ReadRegisters();
            Add(src, dst);
            break;
        case 0x0B:
            auto [src, dst] = ReadRegisters();
            Or(src, dst);
            break;
        case 0x23:
            auto [src, dst] = ReadRegisters();
            And(src, dst);
            break;
        case 0x2B:
            auto [src, dst] = ReadRegisters();
            Sub(src, dst);
            break;
        case 0x33:
            auto [src, dst] = ReadRegisters();
            Xor(src, dst);
            break;
        case 0x51:
            Push("eax");
            break;
        case 0x55:
            Push("ebp");
            break;
        case 0x5D:
            Pop("ebp");
            break;
        case 0x83:
            switch (ReadByte()) {
            case 0x7D:
                auto [src, dst] = ReadRegisters();
                Cmp(src, dst);
                break;
            case 0xC0:
                Add("eax", ReadByte());
                break;
            case 0xE8:
                Sub("eax", ReadByte());
                break;
            case 0xEC:
                Sub("esp", ReadByte());
                break;
            default:
                ReadBadByte();
            }
        case 0x89:
            auto [dst, src] = ReadRegisters();
            Mov(dst, src);
            break;

        // 0x0F is for 2-byte opcodes.
        case 0x0F:
            switch (ReadByte()) {
            case 0xAF:
                auto [src, dst] = ReadRegisters();
                Mul(src, dst);
                break;
            default:
                ReadBadByte();
            }
            break;
        default:
            ReadBadByte();
        }

    }

      elif byte == 0x89:
        self.mov(*self.read_registers(reversed=True))
 
      elif byte == 0x8B:
        self.mov(*self.read_registers())

      elif byte == 0x99:
        self.cdq()
      
      elif byte == 0xC3:
        self.ret()
        break

      elif byte == 0xC7:
        if self.read_byte() == 0x45:
          self.mov(self.read_ebp_rel(), self.read_signed_int())

      elif byte == 0xE8:
        # Relative near call
        relative_addr = self.read_signed_int()
        self.call(self.addr + relative_addr) # Relative to the next call, so evaluate after reading
      
      elif byte == 0xF7:
        if self.read_byte() == 0x7D:
          self.div(self.read_ebp_rel())
      
      else:
        print('Failed to parse byte: ' + hex(byte))
        exit(1)

}

byte Parser::ReadByte()
{
    byte b = _bytes[_addr++];
    std::cout << std::hex << std::showbase << b << ", ";
    return b;
}

signed_byte Parser::ReadSignedByte()
{
    return static_cast<signed_byte>(ReadByte());
}

int Parser::ReadSignedInt()
{
    int i;
    i = ReadByte();
    i += ReadByte() * 0x100;
    i += ReadByte() * 0x10000;
    i += ReadByte() * 0x1000000;
    std::cout << std::hex << std::showbase << i << ", ";
    return i;
}
