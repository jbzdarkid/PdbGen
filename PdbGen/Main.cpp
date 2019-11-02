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

#include "Main.h"
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

// Returns {Segment index, offset}
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

template <typename SymType>
CVSymbol CreateSymbol(SymType& sym) {
    return SymbolSerializer::writeOneSymbol(sym, llvmAllocator, CodeViewContainer::Pdb);
}

void Main::AddFunction(const Function& function) {
    // Add line number <-> address associations
    auto debugSubsection = make_shared<DebugLinesSubsection>(*_checksums, *_strings);
    debugSubsection->createBlock(function.filename);
    debugSubsection->setCodeSize(function.length);
    debugSubsection->setRelocationAddress(function.segment, function.offset);
    for (const auto& [offset, line] : function.lines) {
        debugSubsection->addLineInfo(offset, LineInfo(line, line, true)); // Offset, Start, End, isStatement
    }
    _module->addDebugSubsection(debugSubsection);

    // Add symbols for the functions, locals, and thunks
    std::vector<CVSymbol> symbols;

    auto procSym = ProcSym(SymbolRecordKind::GlobalProcSym);
    // procSym.Parent = 0;
    procSym.End = _module->getNextSymbolOffset() - 4; // Offset of the symbol before this one
    // procSym.Next = 0;
    procSym.CodeSize = function.length;
    procSym.CodeOffset = function.offset;
    procSym.Segment = function.segment;
    procSym.Flags = ProcSymFlags::HasFP;
    procSym.Name = function.nickName;
    symbols.emplace_back(CreateSymbol(procSym));

    for (const Local& local : function.locals) {
        auto sym = BPRelativeSym(SymbolRecordKind::BPRelativeSym);
        sym.Offset = local.offset;
        sym.Type = local.type;
        sym.Name = local.name;
        symbols.emplace_back(CreateSymbol(sym));
    }
    {
        auto sym = ScopeEndSym(SymbolRecordKind::ScopeEndSym);
        symbols.emplace_back(CreateSymbol(sym));
    }

    // Update procSym.End to point to the symbol offset of the ScopeEndSym.
    for (const auto symbol : symbols) procSym.End += symbol.data().size();
    symbols[0] = CreateSymbol(procSym);
    for (const auto symbol : symbols) _module->addSymbol(symbol);

    TrampolineSym sym(SymbolRecordKind::TrampolineSym);
    sym.Type = TrampolineType::TrampIncremental;
    sym.Size = function.thunkLength;
    sym.ThunkOffset = function.thunkOffset; 
    sym.ThunkSection = function.thunkSegment;
    sym.TargetOffset = function.offset;
    sym.TargetSection = function.segment;
    _module->addSymbol(CreateSymbol(sym));

    // Add "Section Contributions", which mark certain parts of the binary to be interpreted in specific ways.
    {
        SectionContrib sc{};
        sc.Imod = _module->getModuleIndex();
        sc.ISect = function.thunkSegment;
        sc.Off = function.thunkOffset;
        sc.Size = function.thunkLength;
        sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        _dbiBuilder->addSectionContrib(sc);
    }
    {
        SectionContrib sc{};
        sc.Imod = _module->getModuleIndex();
        sc.ISect = function.segment;
        sc.Off = function.offset;
        sc.Size = function.length;
        sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        _dbiBuilder->addSectionContrib(sc);
    }

}

void Main::GeneratePDB(char const* outputFileName) {
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");
    // Name doesn't actually matter, since there is no real object file.
    const char* moduleName = "D:/dummy.obj";

    PDBFileBuilder* builder = new PDBFileBuilder(llvmAllocator);
    ExitOnErr(builder->initialize(4096)); // Blocksize
    MSFBuilder& msfBuilder = builder->getMsfBuilder();
    InfoStreamBuilder& infoBuilder = builder->getInfoBuilder();
    _dbiBuilder = &builder->getDbiBuilder();
    _strings = new DebugStringTableSubsection();
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
    _dbiBuilder->setSectionMap(sectionMap);
    ExitOnErr(_dbiBuilder->addDbgStream(
        DbgHeaderType::SectionHdr,
        {reinterpret_cast<const uint8_t*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

    _dbiBuilder->setVersionHeader(PdbDbiV70);
    _dbiBuilder->setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());
    
    tpiBuilder.setVersionHeader(PdbTpiV80);
    ipiBuilder.setVersionHeader(PdbTpiV80);

    _module = &ExitOnErr(_dbiBuilder->addModuleInfo(moduleName));
    _module->setObjFileName(moduleName);
    ExitOnErr(_dbiBuilder->addModuleSourceFile(*_module, fooFunction.filename));

    _checksums = make_shared<DebugChecksumsSubsection>(*_strings);
    _checksums->addChecksum(fooFunction.filename, FileChecksumKind::MD5, ::MD5::HashFile(fooFunction.filename));
    _module->addDebugSubsection(_checksums);

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
        _module->addSymbol(CreateSymbol(sym));
    }

    AddFunction(fooFunction);
    AddFunction(mainFunction);

    {
        PublicSym32 sym(SymbolRecordKind::PublicSym32);
        sym.Flags = PublicSymFlags::Function;
        sym.Offset = fooFunction.offset;
        sym.Segment = fooFunction.segment;
        sym.Name = fooFunction.properName;
        gsiBuilder.addPublicSymbol(sym);
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

    GUID ignoredOutGuid;
    // Also commits all other stream builders.
    ExitOnErr(builder->commit(outputFileName, &ignoredOutGuid));
}

int main(int argc, char** argv) {
    {
        auto [segment, offset] = ConvertRVA(0x401020);
        fooFunction.segment = segment;
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
    fooFunction.filename = "C:/Users/localhost/Documents/GitHub/PdbGen/Generated/Main.cpp";
    fooFunction.locals.emplace_back(Local{
        8,
        TypeIndex(SimpleTypeKind::Int32),
        "bar"
    });
    {
        auto [segment, offset] = ConvertRVA(0x401005);
        fooFunction.thunkSegment = segment;
        fooFunction.thunkOffset = offset;
    }
    fooFunction.thunkLength = 5;

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
    mainFunction.filename = "C:/Users/localhost/Documents/GitHub/PdbGen/Generated/Main.cpp";
    mainFunction.locals.emplace_back(Local{
        -4,
        TypeIndex(SimpleTypeKind::Int32),
        "a"
    });
    {
        auto [segment, offset] = ConvertRVA(0x40100A);
        mainFunction.thunkSegment = segment;
        mainFunction.thunkOffset = offset;
    }
    mainFunction.thunkLength = 5;

    Main main;
    main.GeneratePDB("../Generated/PdbTest.pdb");
}
