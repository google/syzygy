// Copyright 2012 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Unittests for the Asan transform.

#include "syzygy/instrument/transforms/asan_transform.h"

#include <set>
#include <vector>

#include "base/scoped_native_library.h"
#include "base/scoped_temp_dir.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/win/pe_image.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "third_party/distorm/files/include/mnemonics.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockSubGraph;
using block_graph::BlockGraph;
typedef AsanBasicBlockTransform::MemoryAccessMode AsanMemoryAccessMode;
typedef AsanBasicBlockTransform::AsanHookMap HookMap;
typedef AsanBasicBlockTransform::AsanHookMapEntryKey HookMapEntryKey;

// A derived class to expose protected members for unit-testing.
class TestAsanBasicBlockTransform : public AsanBasicBlockTransform {
 public:
  using AsanBasicBlockTransform::InstrumentBasicBlock;

  explicit TestAsanBasicBlockTransform(AsanHookMap* hooks_check_access)
      : AsanBasicBlockTransform(hooks_check_access) {
  }
};

class AsanTransformTest : public testing::TestDllTransformTest {
 public:
  AsanTransformTest() :
      basic_block_("test block"),
      bb_asm_(basic_block_.instructions().begin(),
              &basic_block_.instructions()) {
  }

  void InitHooksRefs() {
    // Initialize the read access hooks.
    for (int access_size = 1; access_size <= 8; access_size *= 2) {
      std::string hook_name =
          base::StringPrintf("asan_check_%d_byte_read_access", access_size);
      HookMapEntryKey map_key =
          std::make_pair(AsanBasicBlockTransform::kReadAccess, access_size);
      hooks_check_access_[map_key] =
          block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 4, hook_name);
      // Set up the references to the hooks needed by SyzyAsan.
      hooks_check_access_ref_[map_key] =
          BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4,
                                hooks_check_access_[map_key], 0, 0);
    }
    // Initialize the write access hooks.
    for (int access_size = 1; access_size <= 8; access_size *= 2) {
      std::string hook_name =
          base::StringPrintf("asan_check_%d_byte_write_access", access_size);
      HookMapEntryKey map_key =
          std::make_pair(AsanBasicBlockTransform::kWriteAccess, access_size);
      hooks_check_access_[map_key] =
          block_graph_.AddBlock(BlockGraph::CODE_BLOCK, 4, hook_name);
      // Set up the references to the hooks needed by SyzyAsan.
      hooks_check_access_ref_[map_key] =
          BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4,
                                hooks_check_access_[map_key], 0, 0);
    }
  }

  bool AddInstructionFromBuffer(const uint8* data, size_t length) {
    DCHECK(data != NULL);
    DCHECK(length < core::AssemblerImpl::kMaxInstructionLength);

    block_graph::Instruction temp;
    if (!block_graph::Instruction::FromBuffer(data, length, &temp))
      return false;

    // Append this instruction to the basic block.
    basic_block_.instructions().push_back(temp);

    return true;
  }

  // Some handy constants we'll use throughout the tests.
  // @{
  static const BasicBlock::Size kDataSize;
  static const uint8 kBlockData[];
  // @}

 protected:
  ScopedTempDir temp_dir_;
  AsanTransform asan_transform_;
  HookMap hooks_check_access_ref_;
  std::map<HookMapEntryKey, BlockGraph::Block*> hooks_check_access_;
  BasicCodeBlock basic_block_;
  block_graph::BasicBlockAssembler bb_asm_;
};

const BasicBlock::Size AsanTransformTest::kDataSize = 32;
const uint8 AsanTransformTest::kBlockData[AsanTransformTest::kDataSize] = {};

}  // namespace

TEST_F(AsanTransformTest, SetInstrumentDLLName) {
  asan_transform_.set_instrument_dll_name("foo");
  ASSERT_EQ(strcmp(asan_transform_.instrument_dll_name(), "foo"), 0);
}

TEST_F(AsanTransformTest, ApplyAsanTransform) {
  ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());

  ASSERT_TRUE(block_graph::ApplyBlockGraphTransform(
      &asan_transform_, &block_graph_, dos_header_block_));

  // TODO(sebmarchand): Ensure that each memory access is instrumented by
  // decomposing each block of the new block-graph into basic blocks and walk
  // through their instructions. For now it's not possible due to an issue with
  // the labels in the new block-graph.
}

TEST_F(AsanTransformTest, InjectAsanHooks) {
  // Add a read access to the memory.
  bb_asm_.mov(core::eax, block_graph::Operand(core::ebx));
  // Add a write access to the memory.
  bb_asm_.mov(block_graph::Operand(core::ecx), core::edx);

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(&basic_block_));

  // Ensure that the basic block is instrumented.

  // We had 2 instructions initially, and for each of them we add 3
  // instructions, so we expect to have 2 + 3 * 2 = 8 instructions.
  ASSERT_EQ(basic_block_.instructions().size(), 8);

  // Walk through the instructions to ensure that the Asan hooks have been
  // injected.
  BasicBlock::Instructions::const_iterator iter_inst =
      basic_block_.instructions().begin();

  // First we check if the first memory access is instrumented as a 4 byte read
  // access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  HookMapEntryKey check_4_byte_read_key =
      std::make_pair(AsanBasicBlockTransform::kReadAccess, 4);
  ASSERT_TRUE(iter_inst->references().begin()->second.block()
      == hooks_check_access_[check_4_byte_read_key]);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  // Then we check if the second memory access is well instrumented as a 4 byte
  // write access.
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_PUSH);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_LEA);
  ASSERT_EQ(iter_inst->references().size(), 1);
  HookMapEntryKey check_4_byte_write_key =
      std::make_pair(AsanBasicBlockTransform::kWriteAccess, 4);
  ASSERT_TRUE(iter_inst->references().begin()->second.block()
      == hooks_check_access_[check_4_byte_write_key]);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_CALL);
  ASSERT_TRUE((iter_inst++)->representation().opcode == I_MOV);

  ASSERT_TRUE(iter_inst == basic_block_.instructions().end());
}

TEST_F(AsanTransformTest, InstrumentDifferentKindOfInstructions) {
  uint32 instrumentable_instructions = 0;

  // Generate a bunch of instrumentable and non instrumentable instructions.
  bb_asm_.mov(core::eax, block_graph::Operand(core::ebx));
  instrumentable_instructions++;
  bb_asm_.mov(block_graph::Operand(core::ecx), core::edx);
  instrumentable_instructions++;

  // Non-instrumentable.
  bb_asm_.call(block_graph::Operand(core::ecx));
  bb_asm_.push(block_graph::Operand(core::eax));
  instrumentable_instructions++;

  // Non-instrumentable.
  bb_asm_.lea(core::eax, block_graph::Operand(core::ecx));

  uint32 expected_instructions_count = basic_block_.instructions().size()
      + 3 * instrumentable_instructions;
  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(&basic_block_));
  ASSERT_EQ(basic_block_.instructions().size(), expected_instructions_count);
}

TEST_F(AsanTransformTest, NonInstrumentableStackBasedInstructions) {
  // DEC DWORD [EBP - 0x2830]
  static const uint8 kDec1[6] = { 0xff, 0x8d, 0xd0, 0xd7, 0xff, 0xff };
  // INC DWORD [EBP - 0x31c]
  static const uint8 kInc1[6] = { 0xff, 0x85, 0xe4, 0xfc, 0xff, 0xff };
  // INC DWORD [ESP + 0x1c]
  static const uint8 kInc2[4] = { 0xff, 0x44, 0x24, 0x1c };
  // NEG DWORD [EBP + 0x24]
  static const uint8 kNeg1[3] = { 0xf7, 0x5d, 0x24 };
  // FILD QWORD [EBP - 0x8]
  static const uint8 kFild1[3] = { 0xdf, 0x6d, 0xf8 };
  // FISTP QWORD [ESP + 0x28]
  static const uint8 kFistp1[4] = { 0xdf, 0x7c, 0x24, 0x28 };
  // MOV EDI, [EBP - 0x4]
  static const uint8 kMov1[3] = { 0x8b, 0x7d, 0xfc };
  // MOV EAX, [EBP - 0x104]
  static const uint8 kMov2[6] = { 0x8b, 0x85, 0xfc, 0xfe, 0xff, 0xff };

  EXPECT_TRUE(AddInstructionFromBuffer(kDec1, sizeof(kDec1)));
  EXPECT_TRUE(AddInstructionFromBuffer(kInc1, sizeof(kInc1)));
  EXPECT_TRUE(AddInstructionFromBuffer(kInc2, sizeof(kInc2)));
  EXPECT_TRUE(AddInstructionFromBuffer(kNeg1, sizeof(kNeg1)));
  EXPECT_TRUE(AddInstructionFromBuffer(kFild1, sizeof(kFild1)));
  EXPECT_TRUE(AddInstructionFromBuffer(kFistp1, sizeof(kFistp1)));
  EXPECT_TRUE(AddInstructionFromBuffer(kMov1, sizeof(kMov1)));
  EXPECT_TRUE(AddInstructionFromBuffer(kMov2, sizeof(kMov2)));

  // Keep track of the basic block size before Asan transform.
  uint32 basic_block_size = basic_block_.instructions().size();

  // Instrument this basic block.
  InitHooksRefs();
  TestAsanBasicBlockTransform bb_transform(&hooks_check_access_ref_);
  ASSERT_TRUE(bb_transform.InstrumentBasicBlock(&basic_block_));

  // Non-instrumentable instructions implies no change.
  ASSERT_EQ(basic_block_.instructions().size(), basic_block_size);
}

namespace {

using base::win::PEImage;
typedef std::set<std::string> StringSet;
typedef std::set<PVOID> FunctionsIATAddressSet;
typedef std::vector<std::string> StringVector;

const char kAsanRtlDll[] = "asan_rtl.dll";

bool EnumKernel32HeapImports(const PEImage &image, LPCSTR module,
                             DWORD ordinal, LPCSTR name, DWORD hint,
                             PIMAGE_THUNK_DATA iat, PVOID cookie) {
  DCHECK(module != NULL);
  DCHECK(cookie != NULL);

  StringVector* modules = reinterpret_cast<StringVector*>(cookie);

  if (_stricmp("kernel32.dll", module) == 0 && strncmp("Heap", name, 4) == 0) {
    DCHECK(name != NULL);
    modules->push_back(name);
  }

  return true;
}

bool EnumAsanImports(const PEImage &image, LPCSTR module,
                     DWORD ordinal, LPCSTR name, DWORD hint,
                     PIMAGE_THUNK_DATA iat, PVOID cookie) {
  DCHECK(module != NULL);
  DCHECK(cookie != NULL);

  StringSet* modules = reinterpret_cast<StringSet*>(cookie);

  if (strcmp(kAsanRtlDll, module) == 0) {
    DCHECK(name != NULL);
    modules->insert(name);
  }

  return true;
}

bool GetAsanHooksIATEntries(const PEImage &image,
                            LPCSTR module,
                            DWORD ordinal,
                            LPCSTR name,
                            DWORD hint,
                            PIMAGE_THUNK_DATA iat,
                            PVOID cookie) {
  DCHECK(module != NULL);
  DCHECK(cookie != NULL);

  FunctionsIATAddressSet* hooks_iat_entries =
      reinterpret_cast<FunctionsIATAddressSet*>(cookie);

  if (strcmp(kAsanRtlDll, module) != 0)
    return true;

  DCHECK(name != NULL);

  // Ensures that the function is an asan_check_access hook.
  if (StartsWithASCII(name, "asan_check_", true /* case sensitive */))
    hooks_iat_entries->insert(reinterpret_cast<PVOID>(iat->u1.Function));

  return true;
}

}  // namespace

TEST_F(AsanTransformTest, ImportsAreRedirected) {
  FilePath asan_instrumented_dll = testing::GetExeTestDataRelativePath(
      testing::kAsanInstrumentedTestDllName);

  // Load the transformed module without resolving its dependencies.
  base::NativeLibrary lib =
      ::LoadLibraryEx(asan_instrumented_dll.value().c_str(),
                      NULL,
                      DONT_RESOLVE_DLL_REFERENCES);
  ASSERT_TRUE(lib != NULL);
  // Make sure it's unloaded on failure.
  base::ScopedNativeLibrary lib_keeper(lib);

  PEImage image(lib);
  ASSERT_TRUE(image.VerifyMagic());
  StringSet imports;
  ASSERT_TRUE(image.EnumAllImports(&EnumAsanImports, &imports));

  StringVector heap_imports;
  ASSERT_TRUE(image.EnumAllImports(&EnumKernel32HeapImports, &heap_imports));

  // This isn't strictly speaking a full test, as we only check that the new
  // imports have been added. It's however more trouble than it's worth to
  // test this fully for now.
  StringSet expected;
  for (size_t i = 0; i < heap_imports.size(); ++i) {
    std::string asan_import = "asan_";
    asan_import.append(heap_imports[i]);
    expected.insert(asan_import);
  }
  expected.insert("asan_check_1_byte_read_access");
  expected.insert("asan_check_2_byte_read_access");
  expected.insert("asan_check_4_byte_read_access");
  expected.insert("asan_check_8_byte_read_access");
  expected.insert("asan_check_10_byte_read_access");
  expected.insert("asan_check_16_byte_read_access");
  expected.insert("asan_check_32_byte_read_access");
  expected.insert("asan_check_1_byte_write_access");
  expected.insert("asan_check_2_byte_write_access");
  expected.insert("asan_check_4_byte_write_access");
  expected.insert("asan_check_8_byte_write_access");
  expected.insert("asan_check_10_byte_write_access");
  expected.insert("asan_check_16_byte_write_access");
  expected.insert("asan_check_32_byte_write_access");

  EXPECT_EQ(expected, imports);
}

TEST_F(AsanTransformTest, AsanHooksAreStubbed) {
  FilePath asan_instrumented_dll = testing::GetExeTestDataRelativePath(
      testing::kAsanInstrumentedTestDllName);

  // Load the transformed module without resolving its dependencies.
  base::NativeLibrary lib =
      ::LoadLibraryEx(asan_instrumented_dll.value().c_str(),
                      NULL,
                      DONT_RESOLVE_DLL_REFERENCES);
  ASSERT_TRUE(lib != NULL);
  // Make sure it's unloaded on failure.
  base::ScopedNativeLibrary lib_keeper(lib);

  PEImage image(lib);
  ASSERT_TRUE(image.VerifyMagic());

  // Iterate over the image import descriptors. We want to make sure the
  // one for asan_rtl.dll is bound.
  DWORD size = image.GetImageDirectoryEntrySize(IMAGE_DIRECTORY_ENTRY_IMPORT);
  PIMAGE_IMPORT_DESCRIPTOR iid = image.GetFirstImportChunk();
  ASSERT_TRUE(iid != NULL);
  ASSERT_GE(size, sizeof(IMAGE_IMPORT_DESCRIPTOR));
  for (; iid->FirstThunk; ++iid) {
    std::string module_name(reinterpret_cast<LPCSTR>(
        image.RVAToAddr(iid->Name)));
    if (module_name == kAsanRtlDll)
      ASSERT_NE(0u, iid->TimeDateStamp);
  }

  // As all the hooks refer to the same stub, we expect to have only one entry
  // in the set.
  FunctionsIATAddressSet hooks_iat_set;
  ASSERT_TRUE(image.EnumAllImports(&GetAsanHooksIATEntries, &hooks_iat_set));
  ASSERT_EQ(hooks_iat_set.size(), 1U);

  PVOID stub_address = *hooks_iat_set.begin();

  // Ensures that the stub is in the thunks section.
  PIMAGE_SECTION_HEADER stub_sec = image.GetImageSectionFromAddr(stub_address);
  ASSERT_STREQ(common::kThunkSectionName,
               reinterpret_cast<const char*>(stub_sec->Name));
}

}  // namespace transforms
}  // namespace instrument
