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

#include "Main.h"
#include "MD5.h"

using namespace std;
using namespace llvm;
using namespace llvm::codeview;
using namespace llvm::COFF;
using namespace llvm::object;
using namespace llvm::msf;
using namespace llvm::pdb;

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
    llvm::ExitOnError ExitOnErr;
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
bool ConvertRVA(uint64_t rva, uint16_t& segmentRef, uint32_t& offsetRef) {
    llvm::ExitOnError ExitOnErr;
    OwningBinary<Binary> binary = ExitOnErr(createBinary("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe"));
    assert(binary.getBinary()->isCOFF());
    const COFFObjectFile* obj = llvm::cast<COFFObjectFile>(binary.getBinary());

    rva -= obj->getImageBase();

    uint16_t index = 1;
    for (const SectionRef& sectionRef : obj->sections()) {
        const coff_section* section = obj->getCOFFSection(sectionRef);
        uint32_t s_va = section->VirtualAddress;
        if (s_va <= rva && rva <= s_va + section->VirtualSize) {
            segmentRef = index;
            offsetRef = static_cast<uint32_t>(rva - s_va);
            return true;
        }

        index++;
    }
    return false;
}

void Main::AddFunction(const Function& function) {
    ExitOnErr(_dbiBuilder->addModuleSourceFile(*_module, function.filename));
    _checksums->addChecksum(function.filename, FileChecksumKind::MD5, ::MD5::HashFile(function.filename));

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
    for (const auto symbol : symbols) procSym.End += static_cast<int32_t>(symbol.data().size());
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

    {
        PublicSym32 sym(SymbolRecordKind::PublicSym32);
        sym.Flags = PublicSymFlags::Function;
        sym.Offset = function.offset;
        sym.Segment = function.segment;
        sym.Name = function.properName;
        _gsiBuilder->addPublicSymbol(sym);
    }

    {
        ProcedureRecord procedure(TypeRecordKind::Procedure);
        procedure.ReturnType = function.returnType;
        procedure.CallConv = CallingConvention::NearC;
        procedure.Options = FunctionOptions::None;
        assert(function.arguments.size() <= 0xFFFF);
        procedure.ParameterCount = static_cast<uint16_t>(function.arguments.size());
        {
            ArgListRecord argList(TypeRecordKind::ArgList);
            argList.ArgIndices = function.arguments;
            procedure.ArgumentList = _typeBuilder->writeLeafType(argList);
            CVType cvt = _typeBuilder->getType(procedure.ArgumentList);
            _tpiBuilder->addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
        CVType cvt = _typeBuilder->getType(_typeBuilder->writeLeafType(procedure));
        _tpiBuilder->addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
    }

}

Main::Main(const std::string& inputExe) {
    _builder = new PDBFileBuilder(_allocator); // @Leak
    ExitOnErr(_builder->initialize(4096)); // Blocksize

    _msfBuilder = &_builder->getMsfBuilder();
    for (int i=0; i<kSpecialStreamCount; i++) ExitOnErr(_msfBuilder->addStream(0));

    _infoBuilder = &_builder->getInfoBuilder();
    ModuleInfo moduleInfo = ReadModuleInfo(inputExe);
    _infoBuilder->setAge(moduleInfo.age);
    _infoBuilder->setGuid(moduleInfo.guid);
    _infoBuilder->setSignature(moduleInfo.signature);
    _infoBuilder->addFeature(PdbRaw_FeatureSig::VC140);
    _infoBuilder->setVersion(PdbImplVC70);

    _gsiBuilder = &_builder->getGsiBuilder();

    _dbiBuilder = &_builder->getDbiBuilder();
    _dbiBuilder->setVersionHeader(PdbDbiV70);
    _dbiBuilder->setPublicsStreamIndex(_gsiBuilder->getPublicsStreamIndex());

    _tpiBuilder = &_builder->getTpiBuilder();
    _tpiBuilder->setVersionHeader(PdbTpiV80);

    _ipiBuilder = &_builder->getIpiBuilder();
    _ipiBuilder->setVersionHeader(PdbTpiV80);


    _typeBuilder = new GlobalTypeTableBuilder(_allocator); // @Leak

    _strings = new DebugStringTableSubsection(); // @Leak
    _checksums = make_shared<DebugChecksumsSubsection>(*_strings);
    _module = &ExitOnErr(_dbiBuilder->addModuleInfo("D:/dummy.obj"));
    _module->setObjFileName("D:/dummy.obj");
    _module->addDebugSubsection(_checksums);
}

void Main::GeneratePDB(const std::string& outputFileName, const Function& fooFunction, const Function& mainFunction) {
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");

    const vector<SecMapEntry> sectionMap = DbiStreamBuilder::createSectionMap(moduleInfo.sections);
    _dbiBuilder->setSectionMap(sectionMap);
    ExitOnErr(_dbiBuilder->addDbgStream(
        DbgHeaderType::SectionHdr,
        {reinterpret_cast<const uint8_t*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

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

    GUID ignoredOutGuid;
    // Also commits all other stream builders.
    ExitOnErr(_builder->commit(outputFileName, &ignoredOutGuid));
}

int main(int argc, char** argv) {
    Function fooFunction;
    ConvertRVA(0x401020, fooFunction.segment, fooFunction.offset);
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
    fooFunction.filename = "../Generated/Main.cpp";
    fooFunction.locals.emplace_back(Local{
        8,
        TypeIndex(SimpleTypeKind::Int32),
        "bar"
    });
    ConvertRVA(0x401005, fooFunction.thunkSegment, fooFunction.thunkOffset);
    fooFunction.thunkLength = 5;

    Function mainFunction;
    ConvertRVA(0x401050, mainFunction.segment, mainFunction.offset);
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
    mainFunction.filename = "../Generated/Main.cpp";
    mainFunction.locals.emplace_back(Local{
        -4,
        TypeIndex(SimpleTypeKind::Int32),
        "a"
    });
    ConvertRVA(0x40100A, mainFunction.thunkSegment, mainFunction.thunkOffset);
    mainFunction.thunkLength = 5;

    Main main("../PdbTest/Debug/PdbTest.exe");
    main.GeneratePDB("../Generated/PdbTest.pdb", fooFunction, mainFunction);
}
