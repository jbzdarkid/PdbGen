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

void GeneratePDB(ModuleInfo const& moduleInfo, char const* outputFileName)
{
    // Name doesn't actually matter, since there is no real object file.
    const char* moduleName = R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\Main.obj)";
    // This one might matter. Unsure.
    const char* filename = R"(C:\Users\localhost\Documents\GitHub\PdbGen\Generated\Main.cpp)";
    // I really hope this one doesn't matter.
    const char* tmpFilename = R"(C:\Users\LOCALH~1\AppData\Local\Temp\lnk{CD77352F-E54C-4392-A458-0DE42662F1A3}.tmp)";

    PDBFileBuilder* builder = new PDBFileBuilder(llvmAllocator);
    ExitOnErr(builder->initialize(4096)); // Blocksize

    // Add each of the reserved streams. We may not put any data in them, but they at least have to be present.
    for (uint32_t i = 0; i < kSpecialStreamCount; ++i)
        ExitOnErr(builder->getMsfBuilder().addStream(0));

    InfoStreamBuilder& infoBuilder = builder->getInfoBuilder();
    infoBuilder.setAge(moduleInfo.age);
    infoBuilder.setGuid(moduleInfo.guid);
    infoBuilder.setSignature(moduleInfo.signature);
    infoBuilder.addFeature(PdbRaw_FeatureSig::VC140);
    infoBuilder.setVersion(PdbImplVC70);

    DbiStreamBuilder& dbiBuilder = builder->getDbiBuilder();
    dbiBuilder.setVersionHeader(PdbDbiV70);
    dbiBuilder.setAge(moduleInfo.age);
    dbiBuilder.setBuildNumber(36375);
    dbiBuilder.setPdbDllVersion(28106);
    dbiBuilder.setPdbDllRbld(4);
    dbiBuilder.setFlags(1);
    dbiBuilder.setMachineType(moduleInfo.is64Bit ? PDB_Machine::Amd64 : PDB_Machine::x86);

    DebugStringTableSubsection* strings = new DebugStringTableSubsection();
    strings->insert("");
    strings->insert(tmpFilename);
    strings->insert(filename);
    strings->insert("$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + = ");
    builder->getStringTableBuilder().setStrings(*strings); // Must be after inserting strings. Should probably assert that this isn't resized at the end (i.e. nobody adds more strings)

    const vector<SecMapEntry> sectionMap = DbiStreamBuilder::createSectionMap(moduleInfo.sections);
    dbiBuilder.setSectionMap(sectionMap);
    ExitOnErr(dbiBuilder.addDbgStream(
        DbgHeaderType::SectionHdr,
        {reinterpret_cast<const uint8_t*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

    GSIStreamBuilder& gsiBuilder = builder->getGsiBuilder();

    { // Module: Linker Manifest
        DbiModuleDescriptorBuilder& module = ExitOnErr(dbiBuilder.addModuleInfo("* Linker Generated Manifest RES *"));
        module.setObjFileName("");
        ExitOnErr(dbiBuilder.addModuleSourceFile(module, R"(C:\Users\LOCALH~1\AppData\Local\Temp\lnk{CD77352F-E54C-4392-A458-0DE42662F1A3}.tmp)"));

        auto checksums = make_shared<DebugChecksumsSubsection>(*strings);
        checksums->addChecksum(tmpFilename, FileChecksumKind::MD5, {0xA3, 0x53, 0xD1, 0x2F, 0x29, 0x90, 0x19, 0x35, 0xF1, 0x7C, 0x81, 0x2B, 0xAE, 0x45, 0x1A, 0x23});
        module.addDebugSubsection(checksums);

        {
            ObjNameSym sym;
            sym.Signature = 0;
            sym.Name = R"(C:\Users\LOCALH~1\AppData\Local\Temp\lnk{AFCB38A6-9747-485E-A123-A631A75FAE03}.tmp)"; // some other random temp file
            AddSymbol(module, sym);
        }
        {
            Compile3Sym sym;
            sym.Flags = CompileSym3Flags::NoDbgInfo;
            sym.Machine = CPUType::Intel80386;
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
            EnvBlockSym sym(SymbolRecordKind::EnvBlockSym);
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

        auto checksums = make_shared<DebugChecksumsSubsection>(*strings);
        checksums->addChecksum(filename, FileChecksumKind::MD5, MD5::HashFile(filename));
        module.addDebugSubsection(checksums);

        { // foo
            auto debugSubsection = make_shared<DebugLinesSubsection>(*checksums, *strings);
            debugSubsection->createBlock(filename);
            debugSubsection->setCodeSize(48); // Function length (Total instruction count, including ret)
            debugSubsection->setRelocationAddress(1, 32); // Offset from the program base (?)
            debugSubsection->setFlags(LineFlags::LF_None);

            debugSubsection->addLineInfo(0, LineInfo(6, 6, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(3, LineInfo(7, 7, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(12, LineInfo(8, 8, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(19, LineInfo(9, 9, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(28, LineInfo(10, 10, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(43, LineInfo(11, 11, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(46, LineInfo(12, 12, true)); // Offset, Start, End, isStatement
            module.addDebugSubsection(debugSubsection);
        }

        { // main
            auto debugSubsection = make_shared<DebugLinesSubsection>(*checksums, *strings);
            debugSubsection->createBlock(filename);
            debugSubsection->setCodeSize(75); // Function length (Total instruction count, including ret)
            debugSubsection->setRelocationAddress(1, 80); // Offset from the program base (?)
            debugSubsection->setFlags(LineFlags::LF_None);

            debugSubsection->addLineInfo(0, LineInfo(14, 14, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(4, LineInfo(15, 15, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(11, LineInfo(16, 16, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(27, LineInfo(17, 17, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(36, LineInfo(18, 18, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(44, LineInfo(19, 19, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(53, LineInfo(20, 20, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(68, LineInfo(21, 21, true)); // Offset, Start, End, isStatement
            debugSubsection->addLineInfo(71, LineInfo(22, 22, true)); // Offset, Start, End, isStatement
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

        module.setObjFileName("");
        {
            ObjNameSym sym;
            sym.Signature = 0;
            sym.Name = " * Linker *";
            AddSymbol(module, sym);
        }
        {
            Compile3Sym sym;
            sym.Flags = CompileSym3Flags::None;
            sym.Machine = CPUType::Intel80386;
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
            EnvBlockSym sym(SymbolRecordKind::EnvBlockSym);
            sym.Fields = {
                "cwd",
                R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest)",
                "exe",
                R"#(C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.23.28105\bin\HostX86\x86\link.exe)#",
                "pdb",
                R"(C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.pdb)",
                "cmd",
                R"#( /ERRORREPORT:PROMPT /OUT:C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.exe /INCREMENTAL /NOLOGO /NODEFAULTLIB /MANIFEST "/MANIFESTUAC:level='asInvoker' uiAccess='false'" /manifest:embed /DEBUG:FULL /PDB:C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.pdb /SUBSYSTEM:CONSOLE /TLBID:1 /ENTRY:main /DYNAMICBASE:NO /NXCOMPAT:NO /IMPLIB:C:\Users\localhost\Documents\GitHub\PdbGen\PdbTest\Debug\PdbTest.lib /MACHINE:X86)#"
            };
            AddSymbol(module, sym);
        }
        {
            TrampolineSym sym(SymbolRecordKind::TrampolineSym);
            sym.Type = TrampolineType::TrampIncremental;
            sym.Size = 5;
            sym.ThunkOffset = 5;
            sym.TargetOffset = 32;
            sym.ThunkSection = 1;
            sym.TargetSection = 1;
            AddSymbol(module, sym);
        }
        {
            TrampolineSym sym(SymbolRecordKind::TrampolineSym);
            sym.Type = TrampolineType::TrampIncremental;
            sym.Size = 5;
            sym.ThunkOffset = 10;
            sym.TargetOffset = 80;
            sym.ThunkSection = 1;
            sym.TargetSection = 1;
            AddSymbol(module, sym);
        }
        {
            SectionSym sym(SymbolRecordKind::SectionSym);
            sym.SectionNumber = 1;
            sym.Alignment = 12;
            sym.Rva = 4096;
            sym.Length = 4289;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_MEM_EXECUTE | SectionCharacteristics::IMAGE_SCN_CNT_CODE;
            sym.Name = ".text";
            AddSymbol(module, sym);
        }
        {
            CoffGroupSym sym(SymbolRecordKind::CoffGroupSym);
            sym.Size = 4289;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_MEM_EXECUTE | SectionCharacteristics::IMAGE_SCN_CNT_CODE;
            sym.Offset = 0;
            sym.Segment = 1;
            sym.Name = ".text$mn";
            AddSymbol(module, sym);
        }
        {
            SectionSym sym(SymbolRecordKind::SectionSym);
            sym.SectionNumber = 2;
            sym.Alignment = 12;
            sym.Rva = 12288;
            sym.Length = 719;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_CNT_INITIALIZED_DATA;
            sym.Name = ".rdata";
            AddSymbol(module, sym);
        }
        {
            CoffGroupSym sym(SymbolRecordKind::CoffGroupSym);
            sym.Size = 324;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_CNT_INITIALIZED_DATA;
            sym.Offset = 0;
            sym.Segment = 2;
            sym.Name = ".rdata";
            AddSymbol(module, sym);
        }
        {
            CoffGroupSym sym(SymbolRecordKind::CoffGroupSym);
            sym.Size = 0;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_CNT_INITIALIZED_DATA;
            sym.Offset = 323;
            sym.Segment = 2;
            sym.Name = ".edata";
            AddSymbol(module, sym);
        }
        {
            CoffGroupSym sym(SymbolRecordKind::CoffGroupSym);
            sym.Size = 395;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_CNT_INITIALIZED_DATA;
            sym.Offset = 324;
            sym.Segment = 2;
            sym.Name = ".rdata$zzzdbg";
            AddSymbol(module, sym);
        }
        {
            SectionSym sym(SymbolRecordKind::SectionSym);
            sym.SectionNumber = 3;
            sym.Alignment = 12;
            sym.Rva = 16384;
            sym.Length = 1084;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_CNT_INITIALIZED_DATA;
            sym.Name = ".rsrc";
            AddSymbol(module, sym);
        }
        {
            CoffGroupSym sym(SymbolRecordKind::CoffGroupSym);
            sym.Size = 368;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_CNT_INITIALIZED_DATA;
            sym.Offset = 0;
            sym.Segment = 3;
            sym.Name = ".rsrc$01";
            AddSymbol(module, sym);
        }
        {
            CoffGroupSym sym(SymbolRecordKind::CoffGroupSym);
            sym.Size = 716;
            sym.Characteristics = SectionCharacteristics::IMAGE_SCN_MEM_READ | SectionCharacteristics::IMAGE_SCN_CNT_INITIALIZED_DATA;
            sym.Offset = 368;
            sym.Segment = 3;
            sym.Name = ".rsrc$02";
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
        sym.Name = "main";
        sym.SymOffset = 148;
        sym.SumName = 0;
        gsiBuilder.addGlobalSymbol(sym);
    }

    dbiBuilder.setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());
    // dbiBuilder.setGlobalsStreamIndex(gsiBuilder.getGlobalsStreamIndex());
    // dbiBuilder.setSymbolRecordStreamIndex(gsiBuilder.getRecordStreamIdx());

    TpiStreamBuilder& tpiBuilder = builder->getTpiBuilder();
    tpiBuilder.setVersionHeader(PdbTpiV80);
    {
        {
            ArgListRecord record(TypeRecordKind::ArgList);
            record.ArgIndices = {TypeIndex(SimpleTypeKind::Int32)};
            CVType cvt = ttb.getType(ttb.writeLeafType(record));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
        {
            ProcedureRecord record(TypeRecordKind::Procedure);
            record.ReturnType = TypeIndex(SimpleTypeKind::Int32);
            record.CallConv = CallingConvention::NearC;
            record.Options = FunctionOptions::None;
            record.ParameterCount = 1;
            record.ArgumentList = TypeIndex(0x1000);
            CVType cvt = ttb.getType(ttb.writeLeafType(record));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
        {
            ArgListRecord record(TypeRecordKind::ArgList);
            record.ArgIndices = {};
            CVType cvt = ttb.getType(ttb.writeLeafType(record));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
        {
            ProcedureRecord record(TypeRecordKind::Procedure);
            record.ReturnType = TypeIndex(SimpleTypeKind::Int32);
            record.CallConv = CallingConvention::NearC;
            record.Options = FunctionOptions::None;
            record.ParameterCount = 0;
            record.ArgumentList = TypeIndex(0x1002);
            CVType cvt = ttb.getType(ttb.writeLeafType(record));
            tpiBuilder.addTypeRecord(cvt.RecordData, ExitOnErr(hashTypeRecord(cvt)));
        }
    }

    FrameData frameData;
    frameData.RvaStart = 0x1010;
    frameData.CodeSize = 59;
    frameData.LocalSize = 4;
    frameData.ParamsSize = 0;
    frameData.MaxStackSize = 0;
    frameData.PrologSize = 4;
    frameData.SavedRegsSize = 0;
    frameData.Flags = !FrameData::HasSEH | !FrameData::HasEH | FrameData::IsFunctionStart;
    frameData.FrameFunc = strings->getIdForString("$T0 $ebp = $eip $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + = ");
    dbiBuilder.addNewFpoData(frameData);

    TpiStreamBuilder& ipiBuilder = builder->getIpiBuilder();
    ipiBuilder.setVersionHeader(PdbTpiV80);

    GUID ignoredOutGuid;
    // Also commits all other stream builders.
    ExitOnErr(builder->commit(outputFileName, &ignoredOutGuid));
    ::exit(0);
}

int main(int argc, char** argv) {
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PdbTest.exe");

    // sort(publics.begin(), publics.end(),
    //         [](auto const& l, auto const& r) { return l.Name < r.Name; });

    GeneratePDB(moduleInfo, "../Generated/PdbTest.pdb");
}
