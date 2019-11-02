#pragma warning(push)
#pragma warning(disable : 4146)
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#pragma warning(disable : 4624)
#pragma warning(disable : 4996)
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/Object/COFF.h>
#pragma warning(pop)

using namespace llvm::pdb;
using namespace llvm::COFF;
using namespace llvm::codeview;
using namespace llvm::sys::fs;

// I hate globals.
llvm::BumpPtrAllocator llvmAllocator;
llvm::ExitOnError ExitOnErr;

struct ModuleInfo
{
    bool is64Bit{};
    std::vector<llvm::object::coff_section> sections;
    GUID guid{};
    uint32_t age{};
    uint32_t signature{};
};

ModuleInfo ReadModuleInfo(const std::string& modulePath)
{
    using namespace llvm;
    using namespace llvm::object;

    ModuleInfo info;

    Expected<OwningBinary<Binary>> expectedBinary = createBinary(modulePath);
    if (!expectedBinary) {
        ExitOnErr(expectedBinary.takeError());
    }

    OwningBinary<Binary> binary = std::move(*expectedBinary);

    if (!binary.getBinary()->isCOFF()) {
        ExitOnErr(errorCodeToError(make_error_code(std::errc::not_supported)));
    }

    const auto obj = llvm::cast<COFFObjectFile>(binary.getBinary());
    for (const auto& sectionRef : obj->sections())
        info.sections.push_back(*obj->getCOFFSection(sectionRef));

    info.is64Bit = obj->is64();
    for (const auto& debugDir : obj->debug_directories()) {
        info.signature = debugDir.TimeDateStamp; // TODO: Timestamp.now()?
        if (debugDir.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
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

template <typename SymType>
void AddSymbol(llvm::pdb::DbiModuleDescriptorBuilder& modiBuilder, SymType& sym) {
    CVSymbol cvSym = SymbolSerializer::writeOneSymbol(sym, llvmAllocator, CodeViewContainer::Pdb);
    modiBuilder.addSymbol(cvSym);
}

void GeneratePDB(char const* outputPDB)
{
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");

    const char* filename = "C:/Users/localhost/Documents/Github/PdbGen/Generated/Main.cpp";

    PDBFileBuilder builder(llvmAllocator);
    ExitOnErr(builder.initialize(4096)); // Blocksize

    // Add each of the reserved streams. We may not put any data in them, but they at least have to be present.
    for (uint32_t i = 0; i < kSpecialStreamCount; ++i)
        ExitOnErr(builder.getMsfBuilder().addStream(0));

    InfoStreamBuilder& infoBuilder = builder.getInfoBuilder();
    infoBuilder.setAge(moduleInfo.age);
    infoBuilder.setGuid(moduleInfo.guid);
    infoBuilder.setSignature(moduleInfo.signature);
    infoBuilder.addFeature(PdbRaw_FeatureSig::VC140);
    infoBuilder.setVersion(PdbImplVC70);

    DbiStreamBuilder& dbiBuilder = builder.getDbiBuilder();
    dbiBuilder.setVersionHeader(PdbDbiV70);

    ExitOnErr(dbiBuilder.addModuleInfo("* Linker Generated Manifest RES *"));

    DebugStringTableSubsection strings; // Declared outside because this object crashes during the destructor
    auto checksums = std::make_shared<DebugChecksumsSubsection>(strings);

    DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo("D:/dummy.obj"));
    module.setObjFileName("D:/dummy.obj");
    ExitOnErr(dbiBuilder.addModuleSourceFile(module, filename));

    int FD;
    if (auto ec = openFileForRead(filename, FD, OpenFlags::OF_None))
        ExitOnErr(llvm::errorCodeToError(ec));
    auto result = md5_contents(FD);
    if (!result)
        ExitOnErr(llvm::errorCodeToError(result.getError()));
    checksums->addChecksum(filename, FileChecksumKind::MD5, result.get().Bytes);
    module.addDebugSubsection(checksums);

    {
        auto sym = ObjNameSym(SymbolRecordKind::ObjNameSym);
        sym.Name = "C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/asdf.obj"; // semi-immutable for some awful reason
        AddSymbol(module, sym);
    }
    {
        // The backend version must be a valid MSVC version. See LLD documentation:
        // https://github.com/llvm-mirror/lld/blob/master/COFF/PDB.cpp#L1395
        auto cs = Compile3Sym(SymbolRecordKind::Compile3Sym);
        cs.VersionBackendMajor = 19;
        cs.VersionBackendMinor = 23;
        cs.VersionBackendBuild = 28016;
        cs.VersionBackendQFE = 4;
        cs.Version = "Microsoft (R) Optimizing Compiler";
        cs.setLanguage(SourceLanguage::Cpp);
        AddSymbol(module, cs);
    }
    {
        auto sym = UsingNamespaceSym(SymbolRecordKind::UsingNamespaceSym);
        AddSymbol(module, sym);
    }

    GSIStreamBuilder& gsiBuilder = builder.getGsiBuilder();

    {
        // Base address is 0x4F1000
        int32_t funcStart = 0x20; // Offset from the base address
        int32_t funcLen = 48; // Function length (Total instruction count, including ret)

        // SectionContrib sc{};
        // sc.Imod = 1;
        // sc.ISect = 1;
        // sc.Off = funcStart;
        // sc.Size = funcLen;
        // sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        // dbiBuilder.addSectionContrib(sc);

        {
            auto debugSubsection = std::make_shared<DebugLinesSubsection>(*checksums, strings);
            debugSubsection->createBlock(filename);
            debugSubsection->setCodeSize(funcLen);
            debugSubsection->setRelocationAddress(1, funcStart);
            debugSubsection->setFlags(LineFlags::LF_None);

            debugSubsection->addLineInfo(0x00, LineInfo(6, 6, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(0x03, LineInfo(7, 7, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(0x0C, LineInfo(8, 8, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(0x13, LineInfo(9, 9, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(0x1C, LineInfo(10, 10, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(0x2B, LineInfo(11, 11, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(0x2E, LineInfo(12, 12, true)); // Offset, Start, End, isStatement
            module.addDebugSubsection(debugSubsection);

            {
                auto sym = ProcSym(SymbolRecordKind::GlobalProcSym);
                sym.Parent = 0;
                sym.End = 240;
                sym.Next = 0;
                sym.CodeSize = funcLen;
                sym.CodeOffset = funcStart;
                sym.Segment = 1;
                sym.Name = "foo";
                AddSymbol(module, sym);
            }
            {
                auto sym = FrameProcSym(SymbolRecordKind::FrameProcSym);
                sym.TotalFrameBytes = 4;
                AddSymbol(module, sym);
            }
            {
                auto sym = BPRelativeSym(SymbolRecordKind::BPRelativeSym);
                sym.Offset = -4;
                sym.Type = TypeIndex(SimpleTypeKind::Int16); // Mutable!
                sym.Name = "q"; // Mutable!
                AddSymbol(module, sym);
            }
            {
                auto sym = ScopeEndSym(SymbolRecordKind::ScopeEndSym);
                AddSymbol(module, sym);
            }
        }

        {
            ProcRefSym sym(SymbolRecordKind::ProcRefSym);
            sym.Module = 2;
            sym.Name = "foo";
            sym.SymOffset = 148; // Symbol offset in the module of the S_GPROC32.
            gsiBuilder.addGlobalSymbol(sym);
        }
        {
            PublicSym32 sym(SymbolRecordKind::PublicSym32);
            sym.Flags = PublicSymFlags::Function;
            sym.Offset = funcStart;
            sym.Segment = 1;
            sym.Name = "?foo@@YAHH@Z";
            gsiBuilder.addPublicSymbol(sym);
        }
    }

    {
        // Base address is 0x4F1000
        int32_t funcStart = 0x50; // Offset from the base address
        int32_t funcLen = 59; // Function length (Total instruction count, including ret)

        SectionContrib sc{};
        sc.Imod = 1;
        sc.ISect = 1;
        sc.Off = 0x20;
        sc.Size = 107;
        sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        dbiBuilder.addSectionContrib(sc);

        {
            auto debugSubsection = std::make_shared<DebugLinesSubsection>(*checksums, strings);
            debugSubsection->createBlock(filename);
            debugSubsection->setCodeSize(funcLen);
            debugSubsection->setRelocationAddress(1, funcStart);
            debugSubsection->setFlags(LineFlags::LF_None);

            debugSubsection->addLineInfo(0, LineInfo(10, 10, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(4, LineInfo(11, 11, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(11, LineInfo(12, 12, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(20, LineInfo(13, 13, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(28, LineInfo(14, 14, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(37, LineInfo(15, 15, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(52, LineInfo(16, 16, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(55, LineInfo(17, 17, true)); // Offset, Start, End, isStatement
            module.addDebugSubsection(debugSubsection);

            {
                auto sym = ProcSym(SymbolRecordKind::GlobalProcSym);
                sym.Parent = 0;
                sym.End = 240;
                sym.Next = 0;
                sym.CodeSize = funcLen;
                sym.CodeOffset = funcStart;
                sym.Segment = 1;
                sym.Name = "main"; // Immutable -- maybe because this is an entry point?
                AddSymbol(module, sym);
            }
            {
                auto sym = FrameProcSym(SymbolRecordKind::FrameProcSym);
                sym.TotalFrameBytes = 4;
                AddSymbol(module, sym);
            }
            {
                auto sym = BPRelativeSym(SymbolRecordKind::BPRelativeSym);
                sym.Offset = -4;
                sym.Type = TypeIndex(SimpleTypeKind::Int16); // Mutable!
                sym.Name = "b"; // Mutable!
                AddSymbol(module, sym);
            }
            {
                auto sym = ScopeEndSym(SymbolRecordKind::ScopeEndSym);
                AddSymbol(module, sym);
            }
        }

        {
            ProcRefSym sym(SymbolRecordKind::ProcRefSym);
            sym.Module = 2;
            sym.Name = "main";
            sym.SymOffset = 244;
            gsiBuilder.addGlobalSymbol(sym);
        }
        {
            PublicSym32 sym(SymbolRecordKind::PublicSym32);
            sym.Flags = PublicSymFlags::Function;
            sym.Offset = funcStart;
            sym.Segment = 1;
            sym.Name = "_main"; // Immutable -- decorated name
            gsiBuilder.addPublicSymbol(sym);
        }
    }

    ExitOnErr(dbiBuilder.addDbgStream(DbgHeaderType::SectionHdr, {
        reinterpret_cast<const uint8_t*>(moduleInfo.sections.data()),
        moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])
    }));

    // The TPI and IPI streams aren't strictly necessary... but pdbutil fails if they're not present.
    TpiStreamBuilder& tpiBuilder = builder.getTpiBuilder();
    tpiBuilder.setVersionHeader(PdbTpiV80);

    TpiStreamBuilder& ipiBuilder = builder.getIpiBuilder();
    ipiBuilder.setVersionHeader(PdbTpiV80);

    GUID ignoredOutGuid;
    // Also commits all other stream builders.
    ExitOnErr(builder.commit(outputPDB, &ignoredOutGuid));
    ::exit(0);
}

int main(int argc, char** argv) {
    GeneratePDB("../Generated/PdbTest.pdb");
}
