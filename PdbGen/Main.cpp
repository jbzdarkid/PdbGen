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

#include "MD5.h"

using namespace std;
using namespace llvm::pdb;
using namespace llvm::COFF;
using namespace llvm::codeview;

// I hate globals.
llvm::BumpPtrAllocator llvmAllocator;
llvm::ExitOnError ExitOnErr;

struct ModuleInfo
{
    bool is64Bit{};
    vector<llvm::object::coff_section> sections;
    llvm::codeview::GUID guid{};
    uint32_t age{};
    uint32_t signature{};
};

ModuleInfo ReadModuleInfo(const string& modulePath)
{
    using namespace llvm;
    using namespace llvm::object;

    ModuleInfo info;

    Expected<OwningBinary<Binary>> expectedBinary = createBinary(modulePath);
    if (!expectedBinary) {
        ExitOnErr(expectedBinary.takeError());
    }

    OwningBinary<Binary> binary = move(*expectedBinary);

    if (!binary.getBinary()->isCOFF()) {
        ExitOnErr(errorCodeToError(make_error_code(errc::not_supported)));
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

    const char* moduleName = R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\Main.obj)"; // Immutable
    const char* filename = R"(C:\Users\localhost\Documents\GitHub\PdbGen\Generated\Main.cpp)";

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
    dbiBuilder.setAge(moduleInfo.age);
    dbiBuilder.setBuildNumber(36375);
    dbiBuilder.setPdbDllVersion(28106);
    dbiBuilder.setPdbDllRbld(4);
    dbiBuilder.setFlags(1);
    dbiBuilder.setMachineType(moduleInfo.is64Bit ? PDB_Machine::Amd64 : PDB_Machine::x86);

    ExitOnErr(dbiBuilder.addModuleInfo("* Linker Generated Manifest RES *"));
    {
        SectionContrib sc;
        sc.Imod = 1;
        sc.ISect = 1;
        sc.Off = 16;
        sc.Size = 59;
        sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        dbiBuilder.addSectionContrib(sc);
    }

    DebugStringTableSubsection strings; // Declared outside because this object crashes during the destructor

    { // Module: Main.obj
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo(moduleName));
        module.setObjFileName(moduleName);
        // Add files to module (presumably necessary to associate source code lines)
        ExitOnErr(dbiBuilder.addModuleSourceFile(module, filename));

        auto checksums = make_shared<DebugChecksumsSubsection>(strings);
        int FD;
        if (auto ec = llvm::sys::fs::openFileForRead(filename, FD, llvm::sys::fs::OpenFlags::OF_None))
            ExitOnErr(llvm::errorCodeToError(ec));
        auto result = llvm::sys::fs::md5_contents(FD);
        if (!result)
            ExitOnErr(llvm::errorCodeToError(result.getError()));
        checksums->addChecksum(filename, FileChecksumKind::MD5, result.get().Bytes);
        module.addDebugSubsection(checksums);

        auto debugSubsection = make_shared<DebugLinesSubsection>(*checksums, strings);
        debugSubsection->createBlock(filename);
        debugSubsection->setCodeSize(59); // Function length (Total instruction count, including ret)
        debugSubsection->setRelocationAddress(1, 16); // Offset from the program base
        debugSubsection->setFlags(LineFlags::LF_None);

        debugSubsection->addLineInfo(0, LineInfo(1, 1, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(4, LineInfo(2, 2, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(11, LineInfo(3, 3, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(20, LineInfo(4, 4, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(28, LineInfo(5, 5, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(37, LineInfo(6, 6, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(52, LineInfo(7, 7, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(55, LineInfo(8, 8, true)); // Offset, Start, End, isStatement
        module.addDebugSubsection(debugSubsection);

        {
            auto sym = ObjNameSym(SymbolRecordKind::ObjNameSym);
            sym.Name = moduleName;
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
            sym.CodeSize = 59;
            // sym.DbgStart = 4;
            // sym.DbgEnd = 55;
            sym.CodeOffset = 16;
            sym.Segment = 1;
            // sym.Flags = ProcSymFlags::HasFP;
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
            sym.Type = TypeIndex(SimpleTypeKind::Int32); // Mutable!
            sym.Name = "b"; // Mutable! (good)
            AddSymbol(module, sym);
        }
    }

    ExitOnErr(dbiBuilder.addDbgStream(
        DbgHeaderType::SectionHdr,
        {reinterpret_cast<const uint8_t*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

    GSIStreamBuilder& gsiBuilder = builder.getGsiBuilder();
    // Base addr is 0x4F1000
    {
        PublicSym32 sym(SymbolRecordKind::PublicSym32);
        sym.Flags = PublicSymFlags::Function;
        sym.Offset = 16;
        sym.Segment = 1;
        sym.Name = "_main";
        gsiBuilder.addPublicSymbol(sym);
    }

    dbiBuilder.setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());

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
