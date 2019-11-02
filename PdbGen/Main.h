#pragma once

#include <llvm/DebugInfo/CodeView/TypeIndex.h>

namespace llvm::pdb { class DbiModuleDescriptorBuilder; class DbiStreamBuilder; class GSIStreamBuilder; class TpiStreamBuilder; }
namespace llvm::codeview { class DebugChecksumsSubsection; class DebugStringTableSubsection; class GlobalTypeTableBuilder; }

struct Local {
    int32_t offset; // Offset from EBP (I think)
    llvm::codeview::TypeIndex type;
    std::string name;
};

struct Function {
    std::vector<std::tuple<int, int>> lines;
    std::vector<llvm::codeview::TypeIndex> arguments;
    std::vector<Local> locals;
    llvm::codeview::TypeIndex returnType;
    uint16_t segment;
    uint32_t offset;
    uint32_t length; // Total instruction count, including ret

    // The "thunk" is a jump redirect to a function.
    uint16_t thunkSegment;
    uint32_t thunkOffset; // Thunk for this function (if any)
    uint16_t thunkLength; // Total instruction count (5 for a simple jump)

    std::string properName;
    std::string nickName;
    std::string filename;
} fooFunction, mainFunction;

class Main {
public:
    void GeneratePDB(const char* outputFileName);
    void AddFunction(const Function& function);

private:
    llvm::pdb::DbiModuleDescriptorBuilder* _module;
    llvm::pdb::DbiStreamBuilder* _dbiBuilder;
    llvm::pdb::GSIStreamBuilder* _gsiBuilder;
    llvm::pdb::TpiStreamBuilder* _tpiBuilder; 

    llvm::codeview::GlobalTypeTableBuilder* _typeBuilder;
    llvm::codeview::DebugStringTableSubsection* _strings;
    std::shared_ptr<llvm::codeview::DebugChecksumsSubsection> _checksums;
};
