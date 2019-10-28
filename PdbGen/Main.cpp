#pragma warning(push)
#pragma warning(disable : 4141)
#pragma warning(disable : 4146)
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#pragma warning(disable : 4996)
#pragma warning(disable : 4624)
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
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
    symbol.Segment = 2;
    symbol.Name = name;
    return symbol;
}

void GeneratePDB(ModuleInfo const& moduleInfo, const vector<cv::PublicSym32>& publics, char const* outputFileName)
{
    // Name doesn't actually matter, since there is no real object file.
    const char* moduleName = "d:\\dummy.obj";
    // This one might matter. Unsure.
    const char* filename = R"(C:\Users\localhost\Documents\GitHub\PdbGen\Generated\Main.cpp)";

    llvm::BumpPtrAllocator allocator;
    PDBFileBuilder builder(allocator);
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

    DbiModuleDescriptorBuilder& modiBuilder = ExitOnErr(dbiBuilder.addModuleInfo(moduleName));
    modiBuilder.setObjFileName(moduleName);
    // Add files to module (presumably necessary to associate source code lines)
    ExitOnErr(dbiBuilder.addModuleSourceFile(modiBuilder, filename));

    cv::DebugStringTableSubsection strings;
    builder.getStringTableBuilder().setStrings(strings);

    strings.insert("main"); // Presumably unnecessary; it looks like checksums / etc will auto-add strings when needed.

//     auto checksums = make_shared<cv::DebugChecksumsSubsection>(strings);
//     checksums->addChecksum(filename, cv::FileChecksumKind::MD5, MD5::HashFile(filename));
//     modiBuilder.addDebugSubsection(checksums);

       // Main
//     auto debugSubsection = make_shared<cv::DebugLinesSubsection>(*checksums, strings);
//     debugSubsection->createBlock(filename);
//     debugSubsection->setCodeSize(88); // Function length (Total instruction count, including ret)
//     debugSubsection->setRelocationAddress(2, 1744); // Offset from the program base (?)
//     debugSubsection->setFlags(cv::LineFlags::LF_None);
// 
//     debugSubsection->addLineInfo(0, cv::LineInfo(1, 1, true)); // Offset, Start, End, isStatement
//     debugSubsection->addLineInfo(30, cv::LineInfo(2, 2, true)); // Offset, Start, End, isStatement
//     debugSubsection->addLineInfo(37, cv::LineInfo(3, 3, true)); // Offset, Start, End, isStatement
//     debugSubsection->addLineInfo(46, cv::LineInfo(4, 4, true)); // Offset, Start, End, isStatement
//     debugSubsection->addLineInfo(54, cv::LineInfo(5, 5, true)); // Offset, Start, End, isStatement
//     debugSubsection->addLineInfo(63, cv::LineInfo(6, 6, true)); // Offset, Start, End, isStatement
//     debugSubsection->addLineInfo(78, cv::LineInfo(7, 7, true)); // Offset, Start, End, isStatement
//     debugSubsection->addLineInfo(81, cv::LineInfo(8, 8, true)); // Offset, Start, End, isStatement
//     modiBuilder.addDebugSubsection(debugSubsection);

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

    TpiStreamBuilder& ipiBuilder = builder.getIpiBuilder();
    ipiBuilder.setVersionHeader(PdbTpiV80);

    cv::GUID ignoredOutGuid;
    ExitOnErr(builder.commit(outputFileName, &ignoredOutGuid));
    exit(0);
}

int main(int argc, char** argv)
{
    ModuleInfo moduleInfo = ReadModuleInfo("C:/Users/localhost/Documents/GitHub/PdbGen/PdbTest/Debug/PDBTest.exe");

    // 0x4F1000
    vector<cv::PublicSym32> publics = {
        CreatePublicSymbol("main", 1712)
    };
    sort(publics.begin(), publics.end(),
            [](auto const& l, auto const& r) { return l.Name < r.Name; });

    GeneratePDB(moduleInfo, publics, "../Generated/PDBTest.pdb");
}