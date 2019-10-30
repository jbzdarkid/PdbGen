#pragma warning(push)
#pragma warning(disable : 4141)
#pragma warning(disable : 4146)
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#pragma warning(disable : 4996)
#pragma warning(disable : 4624)
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/CodeView/SymbolSerializer.h>
#include <llvm/DebugInfo/CodeView/AppendingTypeTableBuilder.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>

#include <llvm/ObjectYAML/CodeViewYAMLTypes.h>

#pragma warning(pop)

#include "MD5.h"

namespace cv = llvm::codeview;
using namespace std;
using namespace llvm::pdb;

llvm::ExitOnError ExitOnErr;

struct ModuleInfo
{
    bool is64Bit{};
    vector<llvm::object::coff_section> sections;
    cv::GUID guid{};
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
            const cv::DebugInfo* debugInfo;
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

// TODO: in64_t? How else do we work with 64 bit processes?
cv::PublicSym32 CreatePublicSymbol(const char* name, int32_t offset) {
    using namespace llvm::codeview;
    PublicSym32 symbol(SymbolRecordKind::PublicSym32);
    symbol.Flags = PublicSymFlags::Function;
    symbol.Offset = offset;
    symbol.Segment = 1;
    symbol.Name = name;
    return symbol;
}

llvm::BumpPtrAllocator llvmAllocator;

template <typename SymType>
void AddSymbol(llvm::pdb::DbiModuleDescriptorBuilder& modiBuilder, SymType& sym) {
    cv::CVSymbol cvSym = cv::SymbolSerializer::writeOneSymbol(sym, llvmAllocator, cv::CodeViewContainer::Pdb);
    modiBuilder.addSymbol(cvSym);
}

void GeneratePDB(ModuleInfo const& moduleInfo, const vector<cv::PublicSym32>& publics, char const* outputFileName)
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

    cv::DebugStringTableSubsection strings;
    strings.insert("$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + = ");
    strings.insert(tmpFilename);
    strings.insert(filename);
    builder.getStringTableBuilder().setStrings(strings); // Must be after inserting strings. Should probably assert that this isn't resized at the end (i.e. nobody adds more strings)

    { // Module: Linker Manifest
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo("* Linker Generated Manifest RES *"));
        module.setObjFileName("");
        ExitOnErr(dbiBuilder.addModuleSourceFile(module, R"(C:\Users\LOCALH~1\AppData\Local\Temp\lnk{CD77352F-E54C-4392-A458-0DE42662F1A3}.tmp)"));

        auto checksums = make_shared<cv::DebugChecksumsSubsection>(strings);
        checksums->addChecksum(filename, cv::FileChecksumKind::MD5, {0xA3, 0x53, 0xD1, 0x2F, 0x29, 0x90, 0x19, 0x35, 0xF1, 0x7C, 0x81, 0x2B, 0xAE, 0x45, 0x1A, 0x23});
        module.addDebugSubsection(checksums);

        {
            cv::ObjNameSym sym;
            sym.Signature = 0;
            sym.Name = R"(C:\Users\LOCALH~1\AppData\Local\Temp\lnk{AFCB38A6-9747-485E-A123-A631A75FAE03}.tmp)"; // some other random temp file
            AddSymbol(module, sym);
        }
        {
            cv::Compile3Sym sym;
            sym.Flags = cv::CompileSym3Flags::NoDbgInfo;
            sym.Machine = cv::CPUType::Intel80386;
            sym.VersionFrontendMajor = 0;
            sym.VersionFrontendMinor = 0;
            sym.VersionFrontendBuild = 0;
            sym.VersionFrontendQFE = 0;
            sym.VersionBackendMajor = 14;
            sym.VersionBackendMinor = 23;
            sym.VersionBackendBuild = 28106;
            sym.VersionBackendQFE = 4;
            sym.Version = "Microsoft (R) CVTRES";
            AddSymbol(module, sym);
        }
        {
            cv::EnvBlockSym sym(cv::SymbolRecordKind::EnvBlockSym);
            sym.Fields = {
                "cwd",
                R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest)",
                "exe",
                R"##(C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.23.28105\bin\HostX86\x86\cvtres.exe)##"
                };
            AddSymbol(module, sym);
        }
    }
    { // Module: Main.obj
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo(moduleName));
        module.setObjFileName(moduleName);
        // Add files to module (presumably necessary to associate source code lines)
        ExitOnErr(dbiBuilder.addModuleSourceFile(module, filename));

        auto checksums = make_shared<cv::DebugChecksumsSubsection>(strings);
        checksums->addChecksum(filename, cv::FileChecksumKind::MD5, MD5::HashFile(filename));
        module.addDebugSubsection(checksums);

        // main func
        auto debugSubsection = make_shared<cv::DebugLinesSubsection>(*checksums, strings);
        debugSubsection->createBlock(filename);
        debugSubsection->setCodeSize(59); // Function length (Total instruction count, including ret)
        debugSubsection->setRelocationAddress(1, 16); // Offset from the program base (?)
        debugSubsection->setFlags(cv::LineFlags::LF_None);

        debugSubsection->addLineInfo(0, cv::LineInfo(1, 1, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(30, cv::LineInfo(2, 2, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(37, cv::LineInfo(3, 3, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(46, cv::LineInfo(4, 4, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(54, cv::LineInfo(5, 5, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(63, cv::LineInfo(6, 6, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(78, cv::LineInfo(7, 7, true)); // Offset, Start, End, isStatement
        debugSubsection->addLineInfo(81, cv::LineInfo(8, 8, true)); // Offset, Start, End, isStatement
        module.addDebugSubsection(debugSubsection);

        {
            auto sym = cv::ObjNameSym();
            sym.Signature = 0;
            sym.Name = moduleName;
            AddSymbol(module, sym);
        }
        {
            auto cs = cv::Compile3Sym();
            cs.Flags = cv::CompileSym3Flags::None;
            cs.Machine = cv::CPUType::Pentium3; // Assume. This may not matter?
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

            // cs.setLanguage(cv::SourceLanguage::Link);
            AddSymbol(module, cs);
        }
        {
            auto sym = cv::UsingNamespaceSym(cv::SymbolRecordKind::UsingNamespaceSym);
            sym.Name = "std";
            AddSymbol(module, sym);
        }
        {
            auto sym = cv::ProcSym(cv::SymbolRecordKind::GlobalProcSym);
            sym.Parent = 0;
            sym.End = 240;
            sym.Next = 0;
            sym.CodeSize = 59;
            sym.DbgStart = 4;
            sym.DbgEnd = 55;
            sym.FunctionType = cv::TypeIndex(cv::TypeIndex::FirstNonSimpleIndex + 1);
            sym.CodeOffset = 16;
            sym.Segment = 1;
            sym.Flags = cv::ProcSymFlags::HasFP;
            sym.Name = "main";
            AddSymbol(module, sym);
        }
        {
            auto sym = cv::FrameProcSym(cv::SymbolRecordKind::FrameProcSym);
            sym.TotalFrameBytes = 4;
            sym.PaddingFrameBytes = 0;
            sym.OffsetToPadding = 0;
            sym.BytesOfCalleeSavedRegisters = 0;
            sym.OffsetOfExceptionHandler = 0;
            sym.SectionIdOfExceptionHandler = 0;
            sym.Flags = cv::FrameProcedureOptions::AsynchronousExceptionHandling | cv::FrameProcedureOptions::OptimizedForSpeed;
            AddSymbol(module, sym);
        }
        {
            auto sym = cv::BPRelativeSym(cv::SymbolRecordKind::BPRelativeSym);
            sym.Offset = -4;
            sym.Type = cv::TypeIndex(116);
            sym.Name = "a";
            AddSymbol(module, sym);
        }
        {
            auto sym = cv::ScopeEndSym(cv::SymbolRecordKind::ScopeEndSym);
            AddSymbol(module, sym);
        }
        {
            auto sym = cv::BuildInfoSym(cv::SymbolRecordKind::BuildInfoSym);
            sym.BuildId = cv::TypeIndex(cv::TypeIndex::FirstNonSimpleIndex + 9);
            AddSymbol(module, sym);
        }
    }
    { // Module: Linker
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo("* Linker *"));
        module.setObjFileName("");
        {
            cv::ObjNameSym sym;
            sym.Signature = 0;
            sym.Name = " * Linker *";
            AddSymbol(module, sym);
        }
        {
            cv::Compile3Sym sym;
            sym.Flags = cv::CompileSym3Flags::None;
            sym.Machine = cv::CPUType::Intel80386;
            sym.VersionFrontendMajor = 0;
            sym.VersionFrontendMinor = 0;
            sym.VersionFrontendBuild = 0;
            sym.VersionFrontendQFE = 0;
            sym.VersionBackendMajor = 14;
            sym.VersionBackendMinor = 23;
            sym.VersionBackendBuild = 28106;
            sym.VersionBackendQFE = 4;
            sym.Version = "Microsoft (R) LINK";
            AddSymbol(module, sym);
        }
        {
            cv::EnvBlockSym sym(cv::SymbolRecordKind::EnvBlockSym);
            sym.Fields = {
                "cwd",
                R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest)",
                "exe",
                R"#(C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.23.28105\bin\HostX86\x86\link.exe)#",
                "pdb",
                R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.pdb)",
                "cmd",
                R"#( /ERRORREPORT:PROMPT /OUT:C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.exe /INCREMENTAL /NOLOGO /NODEFAULTLIB /MANIFEST "/MANIFESTUAC:level=''asInvoker'' uiAccess=''false''" /manifest:embed /DEBUG:FULL /PDB:C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.pdb /SUBSYSTEM:CONSOLE /TLBID:1 /ENTRY:main /DYNAMICBASE:NO /NXCOMPAT:NO /IMPLIB:C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.lib /MACHINE:X86)#"
            };
            AddSymbol(module, sym);
        }
        {
            cv::TrampolineSym sym(cv::SymbolRecordKind::TrampolineSym);
            sym.Type = cv::TrampolineType::TrampIncremental;
            sym.Size = 5;
            sym.ThunkOffset = 5;
            sym.TargetOffset = 16;
            sym.ThunkSection = 1;
            sym.TargetSection = 1;
            AddSymbol(module, sym);
        }
        {
            cv::SectionSym sym(cv::SymbolRecordKind::SectionSym);
            sym.SectionNumber = 1;
            sym.Alignment = 12;
            sym.Rva = 4096;
            sym.Length = 4189;
            sym.Characteristics = (1 << 30) | (1 << 29) | (1 << 5);
            sym.Name = ".text";
            AddSymbol(module, sym);
        }
        {
            cv::CoffGroupSym sym(cv::SymbolRecordKind::CoffGroupSym);
            sym.Size = 4189;
            sym.Characteristics = (1 << 30) | (1 << 29) | (1 << 5);
            sym.Offset = 0;
            sym.Segment = 1;
            sym.Name = ".text$mn";
            AddSymbol(module, sym);
        }
        {
            cv::SectionSym sym(cv::SymbolRecordKind::SectionSym);
            sym.SectionNumber = 2;
            sym.Alignment = 12;
            sym.Rva = 12288;
            sym.Length = 719;
            sym.Characteristics = (1 << 30) | (1 << 6);
            sym.Name = ".rdata";
            AddSymbol(module, sym);
        }
        {
            cv::CoffGroupSym sym(cv::SymbolRecordKind::CoffGroupSym);
            sym.Size = 324;
            sym.Characteristics = (1 << 30) | (1 << 6);

            sym.Offset = 0;
            sym.Segment = 2;
            sym.Name = ".rdata";
            AddSymbol(module, sym);
        }
        {
            cv::CoffGroupSym sym(cv::SymbolRecordKind::CoffGroupSym);
            sym.Size = 0;
            sym.Characteristics = (1 << 30) | (1 << 6);
            sym.Offset = 323;
            sym.Segment = 2;
            sym.Name = ".edata";
            AddSymbol(module, sym);
        }
        {
            cv::CoffGroupSym sym(cv::SymbolRecordKind::CoffGroupSym);
            sym.Size = 395;
            sym.Characteristics = (1 << 30) | (1 << 6);
            sym.Offset = 324;
            sym.Segment = 2;
            sym.Name = ".rdata$zzzdbg";
            AddSymbol(module, sym);
        }
        {
            cv::SectionSym sym(cv::SymbolRecordKind::SectionSym);
            sym.SectionNumber = 3;
            sym.Alignment = 12;
            sym.Rva = 16384;
            sym.Length = 1084;
            sym.Characteristics = (1 << 30) | (1 << 6);
            sym.Name = ".rsrc";
            AddSymbol(module, sym);
        }
        {
            cv::CoffGroupSym sym(cv::SymbolRecordKind::CoffGroupSym);
            sym.Size = 368;
            sym.Characteristics = (1 << 30) | (1 << 6);
            sym.Offset = 0;
            sym.Segment = 3;
            sym.Name = ".rsrc$01";
            AddSymbol(module, sym);
        }
        {
            cv::CoffGroupSym sym(cv::SymbolRecordKind::CoffGroupSym);
            sym.Size = 716;
            sym.Characteristics = (1 << 30) | (1 << 6);
            sym.Offset = 368;
            sym.Segment = 3;
            sym.Name = ".rsrc$02";
            AddSymbol(module, sym);
        }
    }

    const vector<SecMapEntry> sectionMap = DbiStreamBuilder::createSectionMap(moduleInfo.sections);
    dbiBuilder.setSectionMap(sectionMap);

    ExitOnErr(dbiBuilder.addDbgStream(
        DbgHeaderType::SectionHdr,
        {reinterpret_cast<const uint8_t*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

    GSIStreamBuilder& gsiBuilder = builder.getGsiBuilder();
    for (const cv::PublicSym32& pub : publics)
        gsiBuilder.addPublicSymbol(pub);
    dbiBuilder.setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());
    // dbiBuilder.setGlobalsStreamIndex(gsiBuilder.getGlobalsStreamIndex());
    // dbiBuilder.setSymbolRecordStreamIndex(gsiBuilder.getRecordStreamIdx());

    TpiStreamBuilder& tpiBuilder = builder.getTpiBuilder();
    tpiBuilder.setVersionHeader(PdbTpiV80);

    cv::AppendingTypeTableBuilder attb(llvmAllocator);
    {
        cv::ArgListRecord record(cv::TypeRecordKind::ArgList);
        record.ArgIndices = {};
        tpiBuilder.addTypeRecord(attb.getType(attb.writeLeafType(record)).RecordData, llvm::None);
    }
    {
        cv::ProcedureRecord record(cv::TypeRecordKind::Procedure);
        record.ReturnType = cv::TypeIndex(116);
        record.CallConv = cv::CallingConvention::NearC;
        record.Options = cv::FunctionOptions::None;
        record.ParameterCount = 0;
        record.ArgumentList = cv::TypeIndex(cv::TypeIndex::FirstNonSimpleIndex);
        tpiBuilder.addTypeRecord(attb.getType(attb.writeLeafType(record)).RecordData, llvm::None);
    }

    TpiStreamBuilder& ipiBuilder = builder.getIpiBuilder();
    ipiBuilder.setVersionHeader(PdbTpiV80);

    cv::FrameData frameData;
    frameData.RvaStart = 0x1010;
    frameData.CodeSize = 59;
    frameData.LocalSize = 4;
    frameData.ParamsSize = 0;
    frameData.MaxStackSize = 0;
    frameData.PrologSize = 4;
    frameData.SavedRegsSize = 0;
    frameData.Flags = !cv::FrameData::HasSEH | !cv::FrameData::HasEH | cv::FrameData::IsFunctionStart;
    frameData.FrameFunc = strings.getIdForString("$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + = ");
    dbiBuilder.addNewFpoData(frameData);

    /* Things that I'm potentially missing:
        505 bytes of DBI Stream
        1248 bytes of IPI Stream
        20 bytes of Symbol records

        Module: Linker Manifest
        Module: Linker

        (Unlikely)
        40 bytes of "Old MSF directory"
        25 bytes of PDB Stream
        12 bytes of Global Symbol Hash
        12 bytes of Public Symbol Hash
        8 bytes of TPI Hash
    */

    cv::GUID ignoredOutGuid;
    // Also commits all other stream builders.
    ExitOnErr(builder.commit(outputFileName, &ignoredOutGuid));
    ::exit(0);
}

int main(int argc, char** argv) {
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");

    // 0x4F1000
    vector<cv::PublicSym32> publics = {
        CreatePublicSymbol("_main", 16)
    };
    sort(publics.begin(), publics.end(),
            [](auto const& l, auto const& r) { return l.Name < r.Name; });

    GeneratePDB(moduleInfo, publics, "../Generated/PdbTest.pdb");
}
