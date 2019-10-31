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

// I hate globals.
llvm::BumpPtrAllocator llvmAllocator;
GlobalTypeTableBuilder ttb(llvmAllocator);
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

template <typename SymType>
void AddSymbol(llvm::pdb::DbiModuleDescriptorBuilder& modiBuilder, SymType& sym) {
    CVSymbol cvSym = SymbolSerializer::writeOneSymbol(sym, llvmAllocator, CodeViewContainer::Pdb);
    modiBuilder.addSymbol(cvSym);
}

void GeneratePDB(ModuleInfo const& moduleInfo, char const* outputFileName)
{
    // Name doesn't actually matter, since there is no real object file.
    const char* moduleName = R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\Main.obj)";
    // This one might matter. Unsure.
    const char* filename = R"(C:\Users\localhost\Documents\GitHub\PdbGen\Generated\Main.cpp)";
    // I really hope this one doesn't matter.
    const char* tmpFilename = R"(C:\Users\LOCALH~1\AppData\Local\Temp\lnk{CD77352F-E54C-4392-A458-0DE42662F1A3}.tmp)";

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

    DebugStringTableSubsection strings;

    ExitOnErr(dbiBuilder.addModuleInfo("* Linker Generated Manifest RES *"));

    { // Module: Main.obj
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo(moduleName));
        module.setObjFileName(moduleName);
        // Add files to module (presumably necessary to associate source code lines)
        ExitOnErr(dbiBuilder.addModuleSourceFile(module, filename));

        auto checksums = make_shared<DebugChecksumsSubsection>(strings);
        checksums->addChecksum(filename, FileChecksumKind::MD5, MD5::HashFile(filename));
        module.addDebugSubsection(checksums);

        // main func
        auto debugSubsection = make_shared<DebugLinesSubsection>(*checksums, strings);
        debugSubsection->createBlock(filename);
        debugSubsection->setCodeSize(59); // Function length (Total instruction count, including ret)
        debugSubsection->setRelocationAddress(1, 16); // Offset from the program base (?)
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
            cs.VersionFrontendBuild = 23;
            cs.VersionFrontendMinor = 28016;
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
            sym.CodeSize = 59;
            sym.DbgStart = 4;
            sym.DbgEnd = 55;
            sym.FunctionType = TypeIndex(TypeIndex::FirstNonSimpleIndex + 1);
            sym.CodeOffset = 16;
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
            sym.Type = TypeIndex(116);
            sym.Name = "a";
            AddSymbol(module, sym);
        }
    }

    {
        SectionContrib sc;
        sc.Imod = 1;
        sc.ISect = 1;
        sc.Off = 16;
        sc.Size = 59;
        sc.DataCrc = 804367154;
        sc.RelocCrc = 0;
        sc.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        dbiBuilder.addSectionContrib(sc);
    }
    {
        SectionContrib sc;
        sc.Imod = 2;
        sc.ISect = 2;
        sc.Off = 324;
        sc.Size = 93;
        sc.DataCrc = 0;
        sc.RelocCrc = 0;
        sc.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_MEM_READ;
        dbiBuilder.addSectionContrib(sc);
    }
    {
        SectionContrib sc;
        sc.Imod = 2;
        sc.ISect = 2;
        sc.Off = 420;
        sc.Size = 20;
        sc.DataCrc = 0;
        sc.RelocCrc = 0;
        sc.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_MEM_READ;
        dbiBuilder.addSectionContrib(sc);
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
    {
        ProcRefSym sym(SymbolRecordKind::ProcRefSym);
        sym.Module = 2;
        sym.Name = "main";
        sym.SymOffset = 148;
        sym.SumName = 0;
        gsiBuilder.addGlobalSymbol(sym);
    }

    dbiBuilder.setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());
    // dbiBuilder.setGlobalsStreamIndex(gsiBuilder.getGlobalsStreamIndex());
    // dbiBuilder.setSymbolRecordStreamIndex(gsiBuilder.getRecordStreamIdx());

    TpiStreamBuilder& tpiBuilder = builder.getTpiBuilder();
    tpiBuilder.setVersionHeader(PdbTpiV80);
    {
        {
            ArgListRecord record(TypeRecordKind::ArgList);
            record.ArgIndices = {};
            CVType cvt = ttb.getType(ttb.writeLeafType(record));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
        {
            ProcedureRecord record(TypeRecordKind::Procedure);
            record.ReturnType = TypeIndex(116);
            record.CallConv = CallingConvention::NearC;
            record.Options = FunctionOptions::None;
            record.ParameterCount = 0;
            record.ArgumentList = TypeIndex(TypeIndex::FirstNonSimpleIndex);
            CVType cvt = ttb.getType(ttb.writeLeafType(record));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
    }

    ExitOnErr(builder.addNamedStream("/src/headerblock", ""));

    TpiStreamBuilder& ipiBuilder = builder.getIpiBuilder();
    ipiBuilder.setVersionHeader(PdbTpiV80);

    GUID ignoredOutGuid;
    // Also commits all other stream builders.
    ExitOnErr(builder.commit(outputFileName, &ignoredOutGuid));
}

int main(int argc, char** argv) {
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");

    // sort(publics.begin(), publics.end(),
    //         [](auto const& l, auto const& r) { return l.Name < r.Name; });

    GeneratePDB(moduleInfo, "../Generated/PdbTest.pdb");
}
