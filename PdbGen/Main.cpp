#pragma warning(push)
#pragma warning(disable : 4141)
#pragma warning(disable : 4146)
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#pragma warning(disable : 4996)
#pragma warning(disable : 4624)
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/CodeView/GlobalTypeTableBuilder.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiHashing.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>

#pragma warning(pop)

#include <cstdlib>

#include "MD5.h"

using namespace std;
using namespace llvm::pdb;
using namespace llvm::COFF;
using namespace llvm::codeview;
using namespace llvm::msf;
using namespace llvm;
using namespace llvm::object;

// I hate globals.
llvm::BumpPtrAllocator llvmAllocator;
llvm::ExitOnError ExitOnErr;

struct ModuleInfo
{
    bool is64Bit{};
    vector<llvm::object::coff_section> sections;
    GUID guid{};
    uint32_t age{};
    uint32_t signature{};
};

struct Local {
    int32_t offset; // Offset from EBP (I think)
    TypeIndex type;
    std::string name;
};

struct Function {
    std::vector<std::tuple<int, int>> lines;
    std::vector<TypeIndex> arguments;
    std::vector<Local> locals;
    TypeIndex returnType;
    uint16_t segment;
    uint32_t offset;
    uint32_t length; // Total instruction count, including ret

    std::string properName;
    std::string nickName;
} fooFunction, mainFunction;

ModuleInfo ReadModuleInfo(const string& modulePath)
{
    ModuleInfo info;

    OwningBinary<Binary> binary = ExitOnErr(createBinary(modulePath));

    if (!binary.getBinary()->isCOFF()) {
        ExitOnErr(errorCodeToError(make_error_code(errc::not_supported)));
    }

    const COFFObjectFile* obj = llvm::cast<COFFObjectFile>(binary.getBinary());
    for (const auto& sectionRef : obj->sections())
        info.sections.push_back(*obj->getCOFFSection(sectionRef));

    info.is64Bit = obj->is64();
    for (const auto& debugDir : obj->debug_directories()) {
        info.signature = debugDir.TimeDateStamp; // TODO: Timestamp.now()?
        if (debugDir.Type == COFF::IMAGE_DEBUG_TYPE_CODEVIEW) {
            const DebugInfo* debugInfo;
            StringRef pdbFileName;
            if (auto ec = obj->getDebugPDBInfo(&debugDir, debugInfo, pdbFileName))
                ExitOnErr(errorCodeToError(ec));

            if (debugInfo->Signature.CVSignature == OMF::Signature::PDB70) {
                info.age = debugInfo->PDB70.Age;
                for (size_t i = 0; i<16; i++) info.guid.Guid[i] = debugInfo->PDB70.Signature[i];
                // memcpy(&info.guid, debugInfo->PDB70.Signature, sizeof(info.guid));
                break;
            }
        }
    }

    return info;
}

// Returns {Section index, offset}
// Adapted from https://github.com/Mixaill/FakePDB/blob/master/src_pdbgen/pefile.cpp
std::tuple<uint16_t, uint32_t> ConvertRVA(uint64_t rva) {
    OwningBinary<Binary> binary = ExitOnErr(createBinary("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe"));
    assert(binary.getBinary()->isCOFF());
    const COFFObjectFile* obj = llvm::cast<COFFObjectFile>(binary.getBinary());

    rva -= obj->getImageBase();

    uint16_t index = 1;
    for (const SectionRef& sectionRef : obj->sections()) {
        const coff_section* section = obj->getCOFFSection(sectionRef);
        uint32_t s_va = section->VirtualAddress;
        if (s_va <= rva && rva <= s_va + section->VirtualSize) {
            return {index, rva - s_va};
        }

        index++;
    }
    return {0, 0};
}

// TODO: in64_t? How else do we work with 64 bit processes?
PublicSym32 CreatePublicSymbol(const char* name, int32_t offset) {
    using namespace llvm::codeview;
    PublicSym32 symbol(SymbolRecordKind::PublicSym32);
    symbol.Flags = PublicSymFlags::Function;
    symbol.Offset = offset;
    symbol.Segment = 1;
    symbol.Name = name;
    return symbol;
}

template <typename SymType>
CVSymbol AddSymbol(llvm::pdb::DbiModuleDescriptorBuilder& module, SymType& sym) {
    CVSymbol cvSym = SymbolSerializer::writeOneSymbol(sym, llvmAllocator, CodeViewContainer::Pdb);
    module.addSymbol(cvSym);
    return cvSym;
}

void FuckYou(llvm::pdb::DbiModuleDescriptorBuilder& module) {
    auto sym1 = ProcSym(SymbolRecordKind::GlobalProcSym);
    sym1.Parent = 0;
    sym1.End = module.getNextSymbolOffset() - 4; //  + 60; // 104
    sym1.Next = 0;
    sym1.CodeSize = fooFunction.length;
    sym1.FunctionType = TypeIndex(0x1001);
    sym1.CodeOffset = fooFunction.offset;
    sym1.Segment = fooFunction.segment;
    sym1.Flags = ProcSymFlags::HasFP;
    sym1.Name = fooFunction.nickName;
    CVSymbol cvSym1 = SymbolSerializer::writeOneSymbol(sym1, llvmAllocator, CodeViewContainer::Pdb);

    CVSymbol cvSym2;
    for (const Local& local : fooFunction.locals) {
        auto sym2 = BPRelativeSym(SymbolRecordKind::BPRelativeSym);
        sym2.Offset = local.offset;
        sym2.Type = local.type;
        sym2.Name = local.name;
        cvSym2 = SymbolSerializer::writeOneSymbol(sym2, llvmAllocator, CodeViewContainer::Pdb);
    }
    auto sym3 = ScopeEndSym(SymbolRecordKind::ScopeEndSym);
    CVSymbol cvSym3 = SymbolSerializer::writeOneSymbol(sym3, llvmAllocator, CodeViewContainer::Pdb);

    sym1.End += cvSym1.data().size();
    sym1.End += cvSym2.data().size();
    sym1.End += cvSym3.data().size();
    cvSym1 = SymbolSerializer::writeOneSymbol(sym1, llvmAllocator, CodeViewContainer::Pdb);

    module.addSymbol(cvSym1);
    module.addSymbol(cvSym2);
    module.addSymbol(cvSym3);

}


void GeneratePDB(char const* outputFileName) {
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");
    // Name doesn't actually matter, since there is no real object file.
    const char* moduleName = "D:/dummy.obj";
    // This one might matter. Unsure.
    const char* filename = R"(C:\Users\localhost\Documents\GitHub\PdbGen\Generated\Main.cpp)";
    // I really hope this one doesn't matter.
    const char* tmpFilename = R"(C:\Users\LOCALH~1\AppData\Local\Temp\lnk{CD77352F-E54C-4392-A458-0DE42662F1A3}.tmp)";


    PDBFileBuilder* builder = new PDBFileBuilder(llvmAllocator);
    ExitOnErr(builder->initialize(4096)); // Blocksize
    MSFBuilder& msfBuilder = builder->getMsfBuilder();
    InfoStreamBuilder& infoBuilder = builder->getInfoBuilder();
    DbiStreamBuilder& dbiBuilder = builder->getDbiBuilder();
    DebugStringTableSubsection* strings = new DebugStringTableSubsection();
    GSIStreamBuilder& gsiBuilder = builder->getGsiBuilder();
    TpiStreamBuilder& tpiBuilder = builder->getTpiBuilder();
    TpiStreamBuilder& ipiBuilder = builder->getIpiBuilder();
    GlobalTypeTableBuilder* typeBuilder = new GlobalTypeTableBuilder(llvmAllocator);

    // Add each of the reserved streams. We may not put any data in them, but they at least have to be present.
    for (int i=0; i<kSpecialStreamCount; i++) ExitOnErr(msfBuilder.addStream(0));

    infoBuilder.setAge(moduleInfo.age);
    infoBuilder.setGuid(moduleInfo.guid);
    infoBuilder.setSignature(moduleInfo.signature);
    infoBuilder.addFeature(PdbRaw_FeatureSig::VC140);
    infoBuilder.setVersion(PdbImplVC70);

    const vector<SecMapEntry> sectionMap = DbiStreamBuilder::createSectionMap(moduleInfo.sections);
    dbiBuilder.setSectionMap(sectionMap);
    ExitOnErr(dbiBuilder.addDbgStream(
        DbgHeaderType::SectionHdr,
        {reinterpret_cast<const uint8_t*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

    dbiBuilder.setVersionHeader(PdbDbiV70);
    dbiBuilder.setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());
    ExitOnErr(dbiBuilder.addModuleInfo("* Linker Generated Manifest RES *"));
    
    tpiBuilder.setVersionHeader(PdbTpiV80);

    { // Module: Main.obj
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo(moduleName));
        module.setObjFileName(moduleName);
        ExitOnErr(dbiBuilder.addModuleSourceFile(module, filename));

        auto checksums = make_shared<DebugChecksumsSubsection>(*strings);
        checksums->addChecksum(filename, FileChecksumKind::MD5, ::MD5::HashFile(filename));
        module.addDebugSubsection(checksums);

        { // foo
            auto debugSubsection = make_shared<DebugLinesSubsection>(*checksums, *strings);
            debugSubsection->createBlock(filename);
            debugSubsection->setCodeSize(fooFunction.length);
            debugSubsection->setRelocationAddress(fooFunction.segment, fooFunction.offset);
            for (const auto& [offset, line] : fooFunction.lines) {
                debugSubsection->addLineInfo(offset, LineInfo(line, line, true)); // Offset, Start, End, isStatement
            }
            module.addDebugSubsection(debugSubsection);
        }

        { // main
            auto debugSubsection = make_shared<DebugLinesSubsection>(*checksums, *strings);
            debugSubsection->createBlock(filename);
            debugSubsection->setCodeSize(mainFunction.length);
            debugSubsection->setRelocationAddress(mainFunction.segment, mainFunction.offset);
            for (const auto& [offset, line] : mainFunction.lines) {
                debugSubsection->addLineInfo(offset, LineInfo(line, line, true)); // Offset, Start, End, isStatement
            }
            module.addDebugSubsection(debugSubsection);
        }

        {
            // The backend version must be a valid MSVC version. See LLD documentation:
            // https://github.com/llvm-mirror/lld/blob/master/COFF/PDB.cpp#L1395
            auto sym = Compile3Sym();
            sym.VersionBackendMajor = 14;
            sym.VersionBackendMinor = 10;
            sym.VersionBackendBuild = 25019;
            sym.VersionBackendQFE = 0;
            sym.Version = "AutoPDB v0.1";
            sym.setLanguage(SourceLanguage::Cpp);
            AddSymbol(module, sym);
        }
        FuckYou(module);
        {
            auto sym = ProcSym(SymbolRecordKind::GlobalProcSym);
            sym.Parent = 0;
            sym.End = module.getNextSymbolOffset() + 92; // 336
            sym.Next = 0;
            sym.CodeSize = mainFunction.length;
            sym.FunctionType = TypeIndex(0x1003); 
            sym.CodeOffset = mainFunction.offset;
            sym.Segment = mainFunction.segment;
            sym.Flags = ProcSymFlags::HasFP;
            sym.Name = mainFunction.nickName;
            AddSymbol(module, sym);
        }
        {
            auto sym = FrameProcSym(SymbolRecordKind::FrameProcSym);
            sym.TotalFrameBytes = 4;
            sym.PaddingFrameBytes = 0;
            sym.OffsetToPadding = 0;
            sym.BytesOfCalleeSavedRegisters = 0;
            sym.OffsetOfExceptionHandler = 0;
            sym.SectionIdOfExceptionHandler = 0;
            sym.Flags = FrameProcedureOptions::AsynchronousExceptionHandling | FrameProcedureOptions::OptimizedForSpeed;
            AddSymbol(module, sym);
        }
        for (const Local& local : mainFunction.locals) {
            auto sym = BPRelativeSym(SymbolRecordKind::BPRelativeSym);
            sym.Offset = local.offset;
            sym.Type = local.type;
            sym.Name = local.name;
            AddSymbol(module, sym);
        }
        {
            auto sym = ScopeEndSym(SymbolRecordKind::ScopeEndSym);
            AddSymbol(module, sym);
        }
    }
    { // Module: Linker
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo("* Linker *"));

        // The "thunk" is a jump redirect to a function. This "5" refers to 0x401005 -- 5 instructions off of the base.

        { // Foo thunk
            TrampolineSym sym(SymbolRecordKind::TrampolineSym);
            sym.Type = TrampolineType::TrampIncremental;
            sym.Size = 5; // Total number of opcodes in this symbol
            sym.ThunkOffset = 5; 
            sym.ThunkSection = 1;
            sym.TargetOffset = fooFunction.offset;
            sym.TargetSection = fooFunction.segment;
            AddSymbol(module, sym);
        }
        { // Main thunk
            TrampolineSym sym(SymbolRecordKind::TrampolineSym);
            sym.Type = TrampolineType::TrampIncremental;
            sym.Size = 5;
            sym.ThunkOffset = 10;
            sym.ThunkSection = 1;
            sym.TargetOffset = mainFunction.offset;
            sym.TargetSection = mainFunction.segment;
            AddSymbol(module, sym);
        }
    }

    {
        SectionContrib sc{};
        sc.Imod = 2;
        sc.ISect = 1;
        sc.Off = 0;
        sc.Size = 15;
        sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        dbiBuilder.addSectionContrib(sc);
    }
    {
        SectionContrib sc{};
        sc.Imod = 1;
        sc.ISect = 1;
        sc.Off = 32;
        sc.Size = 123;
        sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        dbiBuilder.addSectionContrib(sc);
    }

    {
        PublicSym32 sym(SymbolRecordKind::PublicSym32);
        sym.Flags = PublicSymFlags::Function;
        sym.Offset = fooFunction.offset;
        sym.Segment = fooFunction.segment;
        sym.Name = fooFunction.properName;
        gsiBuilder.addPublicSymbol(sym);
    }
    {
        ProcRefSym sym(SymbolRecordKind::ProcRefSym);
        sym.Module = 2;
        sym.Name = fooFunction.nickName;
        sym.SymOffset = 148;
        sym.SumName = 0;
        gsiBuilder.addGlobalSymbol(sym);
    }
    {
        PublicSym32 sym(SymbolRecordKind::PublicSym32);
        sym.Flags = PublicSymFlags::Function;
        sym.Offset = mainFunction.offset;
        sym.Segment = mainFunction.segment;
        sym.Name = mainFunction.properName;
        gsiBuilder.addPublicSymbol(sym);
    }
    {
        ProcRefSym sym(SymbolRecordKind::ProcRefSym);
        sym.Module = 2;
        sym.Name = mainFunction.nickName;
        sym.SymOffset = 244;
        sym.SumName = 0;
        gsiBuilder.addGlobalSymbol(sym);
    }

    {
        {
            ProcedureRecord procedure(TypeRecordKind::Procedure);
            procedure.ReturnType = fooFunction.returnType;
            procedure.CallConv = CallingConvention::NearC;
            procedure.Options = FunctionOptions::None;
            assert(fooFunction.arguments.size() <= 0xFFFF);
            procedure.ParameterCount = static_cast<uint16_t>(fooFunction.arguments.size());
            {
                ArgListRecord argList(TypeRecordKind::ArgList);
                argList.ArgIndices = fooFunction.arguments;
                procedure.ArgumentList = typeBuilder->writeLeafType(argList);
                CVType cvt = typeBuilder->getType(procedure.ArgumentList);
                tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
            }
            CVType cvt = typeBuilder->getType(typeBuilder->writeLeafType(procedure));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
        {
            ProcedureRecord procedure(TypeRecordKind::Procedure);
            procedure.ReturnType = mainFunction.returnType;
            procedure.CallConv = CallingConvention::NearC;
            procedure.Options = FunctionOptions::None;
            assert(mainFunction.arguments.size() <= 0xFFFF);
            procedure.ParameterCount = static_cast<uint16_t>(mainFunction.arguments.size());
            {
                ArgListRecord argList(TypeRecordKind::ArgList);
                argList.ArgIndices = mainFunction.arguments;
                procedure.ArgumentList = typeBuilder->writeLeafType(argList);
                CVType cvt = typeBuilder->getType(procedure.ArgumentList);
                tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
            }
            CVType cvt = typeBuilder->getType(typeBuilder->writeLeafType(procedure));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
    }

    ipiBuilder.setVersionHeader(PdbTpiV80);

    GUID ignoredOutGuid;
    // Also commits all other stream builders.
    ExitOnErr(builder->commit(outputFileName, &ignoredOutGuid));
}

int main(int argc, char** argv) {
    {
        auto [section, offset] = ConvertRVA(0x401020);
        fooFunction.segment = section;
        fooFunction.offset = offset;
    }
    fooFunction.length = 48;
    fooFunction.lines = {
        {0x00, 6},
        {0x03, 7},
        {0x0C, 8},
        {0x13, 9},
        {0x1C, 10},
        {0x2B, 11},
        {0x2E, 12},
    };
    fooFunction.arguments = {TypeIndex(SimpleTypeKind::Int32)};
    fooFunction.returnType = TypeIndex(SimpleTypeKind::Int32);
    fooFunction.properName = "?foo@@YAHH@Z";
    fooFunction.nickName = "foo";
    fooFunction.locals.emplace_back(Local{
        8,
        TypeIndex(SimpleTypeKind::Int32),
        "bar"
    });

    {
        auto [section, offset] = ConvertRVA(0x401050);
        mainFunction.segment = section;
        mainFunction.offset = offset;
    }
    mainFunction.length = 75;
    mainFunction.lines = {
        {0x00, 14},
        {0x04, 15},
        {0x0B, 16},
        {0x1B, 17},
        {0x24, 18},
        {0x2C, 19},
        {0x35, 20},
        {0x44, 21},
        {0x47, 22},
    };
    mainFunction.arguments = {};
    mainFunction.returnType = TypeIndex(SimpleTypeKind::Int32);
    mainFunction.properName = "_main";
    mainFunction.nickName = "main";
    mainFunction.locals.emplace_back(Local{
        -4,
        TypeIndex(SimpleTypeKind::Int32),
        "a"
    });

    GeneratePDB("../Generated/PdbTest.pdb");
}
