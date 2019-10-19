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

#include <charconv>
#include <fstream>
#include <sstream>

namespace cv = llvm::codeview;
using namespace std;

namespace
{
llvm::ExitOnError ExitOnErr;

struct ModuleInfo
{
    bool is64Bit;
    vector<llvm::object::coff_section> sections;
    cv::GUID guid;
    uint32_t age;
    uint32_t signature;
};

llvm::Error ReadModuleInfo(const string& modulePath, ModuleInfo& info)
{
    using namespace llvm;
    using namespace llvm::object;

    Expected<OwningBinary<Binary>> expectedBinary = createBinary(modulePath);
    if (!expectedBinary) return expectedBinary.takeError();

    OwningBinary<Binary> binary = move(*expectedBinary);

    if (!binary.getBinary()->isCOFF()) return errorCodeToError(make_error_code(errc::not_supported));

    const auto obj = llvm::cast<COFFObjectFile>(binary.getBinary());
    for (const auto& sectionRef : obj->sections())
        info.sections.push_back(*obj->getCOFFSection(sectionRef));

    info.is64Bit = obj->is64();
    for (const auto& debugDir : obj->debug_directories()) {
        // wait, why is this a loop?
        info.signature = debugDir.TimeDateStamp; // TODO: Timestamp.now()
        if (debugDir.Type == COFF::IMAGE_DEBUG_TYPE_CODEVIEW) {
            const cv::DebugInfo* debugInfo;
            StringRef pdbFileName;
            if (auto ec = obj->getDebugPDBInfo(&debugDir, debugInfo, pdbFileName))
                return errorCodeToError(ec);

            switch (debugInfo->Signature.CVSignature) {
                case OMF::Signature::PDB70:
                    info.age = debugInfo->PDB70.Age;
                    memcpy(&info.guid, debugInfo->PDB70.Signature, sizeof(info.guid));
                    break;
            }
        }
    }

    return Error::success();
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

void GeneratePDB(const ModuleInfo& moduleInfo, const vector<cv::PublicSym32>& publics, char const* outputFileName)
{
    llvm::BumpPtrAllocator allocator;
    llvm::pdb::PDBFileBuilder builder(allocator);

    uint32_t const blockSize = 4096;
    ExitOnErr(builder.initialize(blockSize));

    // Add each of the reserved streams.  We might not put any data in them,
    // but at least they have to be present.
    for (uint32_t i = 0; i < llvm::pdb::kSpecialStreamCount; ++i)
        ExitOnErr(builder.getMsfBuilder().addStream(0));

    auto& infoBuilder = builder.getInfoBuilder();
    infoBuilder.setAge(moduleInfo.age);
    infoBuilder.setGuid(moduleInfo.guid);
    infoBuilder.setSignature(moduleInfo.signature);
    infoBuilder.setVersion(llvm::pdb::PdbImplVC70);
    infoBuilder.addFeature(llvm::pdb::PdbRaw_FeatureSig::VC140);

    auto& dbiBuilder = builder.getDbiBuilder();
    dbiBuilder.setAge(moduleInfo.age);
    dbiBuilder.setBuildNumber(35584);
    dbiBuilder.setFlags(2);
    dbiBuilder.setMachineType(moduleInfo.is64Bit ? llvm::pdb::PDB_Machine::Amd64
                                                 : llvm::pdb::PDB_Machine::x86);
    dbiBuilder.setPdbDllRbld(1);
    dbiBuilder.setPdbDllVersion(1);
    dbiBuilder.setVersionHeader(llvm::pdb::PdbDbiV70);

    const auto sectionMap = llvm::pdb::DbiStreamBuilder::createSectionMap(moduleInfo.sections);
    dbiBuilder.setSectionMap(sectionMap);

    ExitOnErr(dbiBuilder.addDbgStream(
        llvm::pdb::DbgHeaderType::SectionHdr,
        {reinterpret_cast<uint8_t const*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

    const char* moduleName = "d:\\dummy.obj"; // Name doesn't actually matter, since there is no real object file.
    auto& modiBuilder = ExitOnErr(dbiBuilder.addModuleInfo(moduleName));
    modiBuilder.setObjFileName(moduleName);

    // Add files to module (presumably necessary to associate source code lines)
    for (auto file : {"main.c"})
        ExitOnErr(dbiBuilder.addModuleSourceFile(modiBuilder, file));

    // WIP: How do I make symbols? What even are symbols?
    // S_BPREL16 and S_BPREL32 are how we name "Symbols RELative to the Base Pointer"
    // See BPRelativeSym.
    //  Offset: Signed offset relative to base pointer (oh, does this include args, too?)
    //      If 0, variable was optimized away
    //  @type: ???
    //  name: Length-prefixed name of symbol
    // S_LDATA32 - Static variables (?)
    // S_LPROC32 - Local function (aka static or not-exported)
    // S_GPROC32 - Global function (aka class member). I expect to use this one exclusively. It's hard/impossible to decide if a function is local or not.
    //  Contains function length, as well as "when the stack is initialized", which seems helpful.
    // S_LOCAL - Only defined by llvm, seems to refer to arguments?
    vector<cv::CVSymbol> symbols;
    for (auto symbol : symbols) {
        modiBuilder.addSymbol(symbol);
    }

    // Apparently, I want a subsection of a module.
    cv::DebugSubsectionKind::Lines;





    auto& gsiBuilder = builder.getGsiBuilder();
    for (const cv::PublicSym32& pub : publics)
        gsiBuilder.addPublicSymbol(pub);

    auto& tpiBuilder = builder.getTpiBuilder();
    tpiBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);
    // This is where type information goes, I think. Idk.
    // cv::CVType type;
    // tpiBuilder.addTypeRecord(type.RecordData, llvm::None);


    auto& ipiBuilder = builder.getIpiBuilder();
    ipiBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);

    cv::StringsAndChecksums strings;
    strings.setStrings(make_shared<cv::DebugStringTableSubsection>());
    strings.strings()->insert("");
    builder.getStringTableBuilder().setStrings(*strings.strings());

    dbiBuilder.setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());
    // dbiBuilder.setGlobalsStreamIndex(gsiBuilder.getGlobalsStreamIndex());
    // dbiBuilder.setSymbolRecordStreamIndex(gsiBuilder.getRecordStreamIdx());

    cv::GUID ignoredOutGuid;
    ExitOnErr(builder.commit(outputFileName, &ignoredOutGuid));
}

} // namespace

int main(int argc, char** argv)
{
    ModuleInfo moduleInfo;
    ExitOnErr(ReadModuleInfo("PDBTest.exe", moduleInfo));

    vector<cv::PublicSym32> publics = {
        CreatePublicSymbol("foo", 0x0),
        CreatePublicSymbol("bar", 0x20),
        CreatePublicSymbol("main", 0x40)
    };
    sort(publics.begin(), publics.end(), [](const auto& l, const auto& r) { return l.Name < r.Name; });

    GeneratePDB(moduleInfo, publics, "PDBTest.pdb");
    return 0;
}
