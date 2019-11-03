#pragma once

#include <llvm/DebugInfo/CodeView/TypeIndex.h>
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/Support/Allocator.h>
#include <llvm/Support/Error.h>

namespace llvm::pdb { class DbiModuleDescriptorBuilder; class DbiStreamBuilder; class GSIStreamBuilder; class TpiStreamBuilder; class PDBFileBuilder; class InfoStreamBuilder; }
namespace llvm::codeview { class DebugChecksumsSubsection; class DebugStringTableSubsection; class GlobalTypeTableBuilder; }
namespace llvm::msf { class MSFBuilder; }

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
};

class Main {
public:
    Main(const std::string& inputExe);
    void GeneratePDB(const std::string& outputFileName, const Function& fooFunction, const Function& mainFunction);
    void AddFunction(const Function& function);

private:
    template <typename SymType>
    llvm::codeview::CVSymbol CreateSymbol(SymType& sym) {
        return llvm::codeview::SymbolSerializer::writeOneSymbol(sym, _allocator, CodeViewContainer::Pdb);
    }

    llvm::BumpPtrAllocator _allocator;
    llvm::ExitOnError ExitOnErr;

    llvm::pdb::PDBFileBuilder* _builder;
    llvm::msf::MSFBuilder* _msfBuilder;
    llvm::pdb::InfoStreamBuilder* _infoBuilder;
    llvm::pdb::DbiStreamBuilder* _dbiBuilder;
    llvm::pdb::TpiStreamBuilder* _tpiBuilder; 
    llvm::pdb::TpiStreamBuilder* _ipiBuilder; 
    llvm::codeview::DebugStringTableSubsection* _strings;
    llvm::pdb::GSIStreamBuilder* _gsiBuilder;
    llvm::codeview::GlobalTypeTableBuilder* _typeBuilder;

    std::shared_ptr<llvm::codeview::DebugChecksumsSubsection> _checksums;
    llvm::pdb::DbiModuleDescriptorBuilder* _module;
};
