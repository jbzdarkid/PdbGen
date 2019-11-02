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
const COFFObjectFile* obj;

struct ModuleInfo
{
    bool is64Bit{};
    vector<llvm::object::coff_section> sections;
    GUID guid{};
    uint32_t age{};
    uint32_t signature{};
};

ModuleInfo ReadModuleInfo(const string& modulePath)
{
    ModuleInfo info;

    OwningBinary<Binary> binary = ExitOnErr(createBinary(modulePath));

    if (!binary.getBinary()->isCOFF()) {
        ExitOnErr(errorCodeToError(make_error_code(errc::not_supported)));
    }

    obj = llvm::cast<COFFObjectFile>(binary.getBinary());
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
std::tuple<uint16_t, uint32_t> ConvertRVA(uint32_t rva) {
    rva -= obj->getImageBase();

    uint16_t index = 1;
    for (const SectionRef& sectionRef : obj->sections()) {
        const coff_section* section = obj->getCOFFSection(sectionRef);
        int a = sectionRef.getIndex();
        int b = sectionRef.getAddress();
        int c = sectionRef.getSize();
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
void AddSymbol(llvm::pdb::DbiModuleDescriptorBuilder& modiBuilder, SymType& sym) {
    CVSymbol cvSym = SymbolSerializer::writeOneSymbol(sym, llvmAllocator, CodeViewContainer::Pdb);
    modiBuilder.addSymbol(cvSym);
}

struct MainFunction {
    std::vector<std::tuple<int, int>> lines;
} mainFunction;

struct FooFunction {
    std::vector<std::tuple<int, int>> lines;
} fooFunction;

void GeneratePDB(char const* outputFileName) {
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");
    // Name doesn't actually matter, since there is no real object file.
    const char* moduleName = R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\Main.obj)";
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
            debugSubsection->setCodeSize(48); // Function length (Total instruction count, including ret)
            debugSubsection->setRelocationAddress(1, 32); // Offset from the program base (?)

            for (const auto& [offset, line] : fooFunction.lines) {
                debugSubsection->addLineInfo(offset, LineInfo(line, line, true)); // Offset, Start, End, isStatement
            }
            module.addDebugSubsection(debugSubsection);
        }

        { // main
            auto debugSubsection = make_shared<DebugLinesSubsection>(*checksums, *strings);
            debugSubsection->createBlock(filename);
            debugSubsection->setCodeSize(75); // Function length (Total instruction count, including ret)
            debugSubsection->setRelocationAddress(1, 80); // Offset from the program base (?)

            for (const auto& [offset, line] : fooFunction.lines) {
                debugSubsection->addLineInfo(offset, LineInfo(line, line, true)); // Offset, Start, End, isStatement
            }
            module.addDebugSubsection(debugSubsection);
        }

        {
            auto sym = ObjNameSym();
            sym.Signature = 0;
            sym.Name = moduleName;
            AddSymbol(module, sym);
        }
        {
            auto cs = Compile3Sym();
            cs.Flags = CompileSym3Flags::None;
            cs.Machine = CPUType::Pentium3; // Assume. This may not matter?
            // The Frontend version can be whatever.
            cs.VersionFrontendMajor = 19;
            cs.VersionFrontendMinor = 23;
            cs.VersionFrontendBuild = 28016;
            cs.VersionFrontendQFE = 4;

            // The backend version must be a valid MSVC version. See LLD documentation:
            // https://github.com/llvm-mirror/lld/blob/master/COFF/PDB.cpp#L1395
            cs.VersionBackendMajor = 19;
            cs.VersionBackendMinor = 23;
            cs.VersionBackendBuild = 28016;
            cs.VersionBackendQFE = 4;
            cs.Version = "Microsoft (R) Optimizing Compiler";

            // cs.setLanguage(SourceLanguage::Link);
            AddSymbol(module, cs);
        }
        {
            auto sym = UsingNamespaceSym(SymbolRecordKind::UsingNamespaceSym);
            sym.Name = "std";
            AddSymbol(module, sym);
        }
        {
            auto sym = ProcSym(SymbolRecordKind::GlobalProcSym);
            sym.Parent = 0;
            sym.End = 240;
            sym.Next = 0;
            sym.CodeSize = 48;
            sym.DbgStart = 3;
            sym.DbgEnd = 46;
            sym.FunctionType = TypeIndex(0x1001);
            sym.CodeOffset = 32;
            sym.Segment = 1;
            sym.Flags = ProcSymFlags::HasFP;
            sym.Name = "foo";
            AddSymbol(module, sym);
        }
        {
            auto sym = FrameProcSym(SymbolRecordKind::FrameProcSym);
            sym.TotalFrameBytes = 0;
            sym.PaddingFrameBytes = 0;
            sym.OffsetToPadding = 0;
            sym.BytesOfCalleeSavedRegisters = 0;
            sym.OffsetOfExceptionHandler = 0;
            sym.SectionIdOfExceptionHandler = 0;
            sym.Flags = FrameProcedureOptions::AsynchronousExceptionHandling | FrameProcedureOptions::OptimizedForSpeed;
            AddSymbol(module, sym);
        }
        {
            auto sym = BPRelativeSym(SymbolRecordKind::BPRelativeSym);
            sym.Offset = 8;
            sym.Type = TypeIndex(SimpleTypeKind::Int32);
            sym.Name = "bar";
            AddSymbol(module, sym);
        }
        {
            auto sym = ScopeEndSym(SymbolRecordKind::ScopeEndSym);
            AddSymbol(module, sym);
        }
        {
            auto sym = ProcSym(SymbolRecordKind::GlobalProcSym);
            sym.Parent = 0;
            sym.End = 336;
            sym.Next = 0;
            sym.CodeSize = 75;
            sym.DbgStart = 4;
            sym.DbgEnd = 71;
            sym.FunctionType = TypeIndex(0x1003); 
            sym.CodeOffset = 80;
            sym.Segment = 1;
            sym.Flags = ProcSymFlags::HasFP;
            sym.Name = "main";
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
        {
            auto sym = BPRelativeSym(SymbolRecordKind::BPRelativeSym);
            sym.Offset = -4;
            sym.Type = TypeIndex(SimpleTypeKind::Int32);
            sym.Name = "a";
            AddSymbol(module, sym);
        }
        {
            auto sym = ScopeEndSym(SymbolRecordKind::ScopeEndSym);
            AddSymbol(module, sym);
        }
        {
            auto sym = BuildInfoSym(SymbolRecordKind::BuildInfoSym);
            sym.BuildId = TypeIndex(0x1009);
            AddSymbol(module, sym);
        }
    }
    { // Module: Linker
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo("* Linker *"));

        { // Foo thunk
            TrampolineSym sym(SymbolRecordKind::TrampolineSym);
            sym.Type = TrampolineType::TrampIncremental;
            sym.Size = 5;
            sym.ThunkOffset = 5; // The "thunk" is a jump redirect to a function. This "5" refers to 0x401005 -- 5 instructions off of the base.
            sym.ThunkSection = 1;
            sym.TargetOffset = 32;
            sym.TargetSection = 1;
            AddSymbol(module, sym);
        }
        { // Main thunk
            TrampolineSym sym(SymbolRecordKind::TrampolineSym);
            sym.Type = TrampolineType::TrampIncremental;
            sym.Size = 5;
            sym.ThunkOffset = 10;
            sym.ThunkSection = 1;
            sym.TargetOffset = 80;
            sym.TargetSection = 1;
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

    // Base addr is 0x4F1000
    {
        PublicSym32 sym(SymbolRecordKind::PublicSym32);
        sym.Flags = PublicSymFlags::Function;
        sym.Offset = 32;
        sym.Segment = 1;
        sym.Name = "?foo@@YAHH@Z";
        gsiBuilder.addPublicSymbol(sym);
    }
    {
        PublicSym32 sym(SymbolRecordKind::PublicSym32);
        sym.Flags = PublicSymFlags::Function;
        sym.Offset = 80;
        sym.Segment = 1;
        sym.Name = "_main";
        gsiBuilder.addPublicSymbol(sym);
    }
    {
        ProcRefSym sym(SymbolRecordKind::ProcRefSym);
        sym.Module = 2;
        sym.Name = "foo";
        sym.SymOffset = 148;
        sym.SumName = 0;
        gsiBuilder.addGlobalSymbol(sym);
    }
    {
        ProcRefSym sym(SymbolRecordKind::ProcRefSym);
        sym.Module = 2;
        sym.Name = "main";
        sym.SymOffset = 148;
        sym.SumName = 0;
        gsiBuilder.addGlobalSymbol(sym);
    }

    {
        {
            ProcedureRecord procedure(TypeRecordKind::Procedure);
            procedure.ReturnType = TypeIndex(SimpleTypeKind::Int32);
            procedure.CallConv = CallingConvention::NearC;
            procedure.Options = FunctionOptions::None;
            procedure.ParameterCount = 1;
            {
                ArgListRecord argList(TypeRecordKind::ArgList);
                argList.ArgIndices = {TypeIndex(SimpleTypeKind::Int32)};
                procedure.ArgumentList = typeBuilder->writeLeafType(argList);
                CVType cvt = typeBuilder->getType(procedure.ArgumentList);
                tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
            }
            CVType cvt = typeBuilder->getType(typeBuilder->writeLeafType(procedure));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
        {
            ProcedureRecord procedure(TypeRecordKind::Procedure);
            procedure.ReturnType = TypeIndex(SimpleTypeKind::Int32);
            procedure.CallConv = CallingConvention::NearC;
            procedure.Options = FunctionOptions::None;
            procedure.ParameterCount = 0;
            {
                ArgListRecord argList(TypeRecordKind::ArgList);
                argList.ArgIndices = {};
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
    fooFunction.lines = {
        {0x00, 6},
        {0x03, 7},
        {0x0C, 8},
        {0x13, 9},
        {0x1C, 10},
        {0x2B, 11},
        {0x2E, 12},
    };

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

    GeneratePDB("../Generated/PdbTest.pdb");
}
