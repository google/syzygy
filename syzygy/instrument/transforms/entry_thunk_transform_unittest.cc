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
// Unittests for iteration primitives.

#include "syzygy/instrument/transforms/entry_thunk_transform.h"

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/block_graph/unittest_util.h"
#include "syzygy/common/defs.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using block_graph::ConstBlockVector;
using block_graph::Immediate;
using block_graph::TypedBlock;
using core::AbsoluteAddress;
using testing::_;
using testing::Return;

// This defines the memory layout for the thunks that are created by the
// transform.
#pragma pack(push)
#pragma pack(1)
struct Thunk {
  BYTE push;
  DWORD func_addr;  // The real function to invoke.
  WORD indirect_jmp;
  DWORD hook_addr;  // The instrumentation hook that gets called indirectly.
};
struct ParamThunk {
  BYTE push1;
  DWORD param;  // The parameter for the instrumentation hook.
  BYTE push2;
  DWORD func_addr;  // The real function to invoke.
  WORD indirect_jmp;
  DWORD hook_addr;  // The instrumentation hook that gets called indirectly.
};
#pragma pack(pop)

class EntryThunkTransformTest : public testing::Test {
 public:
  EntryThunkTransformTest()
      : num_sections_pre_transform_(0),
        dos_header_block_(NULL),
        nt_headers_block_(NULL),
        foo_(NULL),
        bar_(NULL),
        array_(NULL) {
  }

  virtual void SetUp() {
    // TODO(siggi): We have a lot of code that does this sort of thing, maybe
    //     it should be concentrated in a test fixture in pe someplace.
    bg_.set_image_format(BlockGraph::PE_IMAGE);
    // Create the DOS/NT headers.
    dos_header_block_ = bg_.AddBlock(BlockGraph::DATA_BLOCK,
                                     sizeof(IMAGE_DOS_HEADER),
                                     "DOS Header");
    ASSERT_TRUE(
        dos_header_block_->AllocateData(dos_header_block_->size()) != NULL);

    nt_headers_block_ = bg_.AddBlock(BlockGraph::DATA_BLOCK,
                                     sizeof(IMAGE_NT_HEADERS),
                                     "NT Headers");

    ASSERT_TRUE(
        nt_headers_block_->AllocateData(nt_headers_block_->size()) != NULL);
    TypedBlock<IMAGE_NT_HEADERS> nt_headers;
    ASSERT_TRUE(nt_headers.Init(0, nt_headers_block_));
    nt_headers->Signature = IMAGE_NT_SIGNATURE;
    nt_headers->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    nt_headers->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;

    TypedBlock<IMAGE_DOS_HEADER> dos_header;
    ASSERT_TRUE(dos_header.Init(0, dos_header_block_));
    ASSERT_TRUE(dos_header.SetReference(BlockGraph::RELATIVE_REF,
                                        dos_header->e_lfanew,
                                        nt_headers));

    // Make the DOS header valid just for giggles.
    ASSERT_TRUE(pe::UpdateDosHeader(dos_header_block_));

    // Get the .text section.
    BlockGraph::Section* text =
        bg_.FindOrAddSection(pe::kCodeSectionName, pe::kCodeCharacteristics);

    // Create a couple of code blocks for "functions".
    foo_ = bg_.AddBlock(BlockGraph::CODE_BLOCK, 20, "foo");
    foo_->set_section(text->id());
    foo_->source_ranges().Push(BlockGraph::Block::DataRange(0, 20),
        BlockGraph::Block::SourceRange(core::RelativeAddress(0x1000), 20));

    bar_ = bg_.AddBlock(BlockGraph::CODE_BLOCK, 20, "bar");
    bar_->set_section(text->id());
    bar_->source_ranges().Push(BlockGraph::Block::DataRange(0, 20),
        BlockGraph::Block::SourceRange(core::RelativeAddress(0x1020), 20));

    // Get the .rdata section.
    BlockGraph::Section* rdata =
        bg_.FindOrAddSection(pe::kReadOnlyDataSectionName,
                             pe::kReadOnlyDataCharacteristics);

    // Create a data array block.
    array_ = bg_.AddBlock(BlockGraph::DATA_BLOCK,
                          30 * sizeof(AbsoluteAddress),
                          "array");
    array_->set_section(rdata->id());

    // foo() refers to the start of bar() with a PC-relative reference.
    foo_->SetReference(5, BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF,
                                                sizeof(AbsoluteAddress),
                                                bar_,
                                                0, 0));
    // foo() is self-referential.
    foo_->SetReference(10, BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF,
                                                 sizeof(AbsoluteAddress),
                                                 foo_,
                                                 0, 0));

    // bar() refers to foo() five bytes in.
    bar_->SetReference(5, BlockGraph::Reference(BlockGraph::PC_RELATIVE_REF,
                                                sizeof(AbsoluteAddress),
                                                foo_,
                                                5, 5));

    // The array refers to the start of both foo() and bar().
    array_->SetReference(0, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                                  sizeof(AbsoluteAddress),
                                                  foo_,
                                                  0, 0));

    array_->SetReference(4, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                                  sizeof(AbsoluteAddress),
                                                  bar_,
                                                  0, 0));

    // And the array refers 5 bytes into foo().
    array_->SetReference(8, BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                                  sizeof(AbsoluteAddress),
                                                  foo_,
                                                  5, 5));

    num_sections_pre_transform_ = bg_.sections().size();

    // No thunks so far.
    ASSERT_NO_FATAL_FAILURE(VerifyThunks(0, 0, 0, 0));
  }

  // Retrieves the thunks.
  void FindThunks(ConstBlockVector* ret, int* param_thunks) {
    ASSERT_TRUE(ret != NULL);
    EXPECT_TRUE(ret->empty());
    ASSERT_TRUE(param_thunks != NULL);

    *param_thunks = 0;

    BlockGraph::Section* thunk_section =
        bg_.FindSection(common::kThunkSectionName);
    if (thunk_section == NULL)
      return;

    BlockGraph::BlockMap::const_iterator it = bg_.blocks().begin();
    for (; it != bg_.blocks().end(); ++it) {
      const BlockGraph::Block& block = it->second;
      if (block.section() == thunk_section->id()) {
        EXPECT_EQ(BlockGraph::CODE_BLOCK, block.type());
        EXPECT_EQ(2, block.references().size());
        EXPECT_TRUE(block.size() == sizeof(Thunk) ||
                    block.size() == sizeof(ParamThunk));

        if (block.size() == sizeof(ParamThunk))
          ++(*param_thunks);

        // It's a thunk.
        ret->push_back(&block);
      }
    }
  }

  size_t CountDestinations(const ConstBlockVector& blocks) {
    typedef std::set<std::pair<BlockGraph::Block*, BlockGraph::Offset>>
        ReferenceMap;
    ReferenceMap destinations;
    for (size_t i = 0; i < blocks.size(); ++i) {
      size_t func_addr_offset = offsetof(Thunk, func_addr);
      if (blocks[i]->size() == sizeof(ParamThunk))
        func_addr_offset = offsetof(ParamThunk, func_addr);

      // Lookup and record the destination.
      BlockGraph::Reference ref;
      EXPECT_TRUE(blocks[i]->GetReference(func_addr_offset, &ref));
      EXPECT_EQ(BlockGraph::ABSOLUTE_REF, ref.type());
      destinations.insert(std::make_pair(ref.referenced(), ref.offset()));
    }
    return destinations.size();
  }

  size_t CountEntryPoints(const ConstBlockVector& blocks) {
    typedef std::set<std::pair<BlockGraph::Block*, BlockGraph::Offset>>
        ReferenceMap;
    ReferenceMap entrypoints;
    for (size_t i = 0; i < blocks.size(); ++i) {
      size_t hook_addr_offset = offsetof(Thunk, hook_addr);
      if (blocks[i]->size() == sizeof(ParamThunk))
        hook_addr_offset = offsetof(ParamThunk, hook_addr);

      // Lookup and record the entrypoint.
      BlockGraph::Reference ref;
      EXPECT_TRUE(blocks[i]->GetReference(
          hook_addr_offset, &ref));
      EXPECT_EQ(BlockGraph::ABSOLUTE_REF, ref.type());
      entrypoints.insert(std::make_pair(ref.referenced(), ref.offset()));
    }
    return entrypoints.size();
  }

  void VerifySourceRanges(const ConstBlockVector& thunks) {
    for (size_t i = 0; i < thunks.size(); ++i) {
      // Test the source ranges on the thunk.
      ASSERT_EQ(1, thunks[i]->source_ranges().size());
      BlockGraph::Block::SourceRanges::RangePair r =
          thunks[i]->source_ranges().range_pairs()[0];
      ASSERT_EQ(0, r.first.start());

      ASSERT_TRUE(r.first.size() == sizeof(Thunk) ||
                  r.first.size() == sizeof(ParamThunk));

      BlockGraph::Reference ref;
      EXPECT_TRUE(thunks[i]->GetReference(
          offsetof(Thunk, func_addr), &ref));

      // Retrieve the referenced block's source ranges to calculate
      // the destination start address.
      EXPECT_EQ(1, ref.referenced()->source_ranges().size());
      BlockGraph::Block::SourceRanges::RangePair o =
          ref.referenced()->source_ranges().range_pairs()[0];

      // The thunk's destination should be the block's start, plus the
      // reference offset.
      EXPECT_EQ(o.second.start() + ref.offset(), r.second.start());
      EXPECT_TRUE(r.second.size() == sizeof(Thunk) ||
                  r.second.size() == sizeof(ParamThunk));
    }
  }

  // Verifies that there are num_thunks thunks in the image, and that they
  // have the expected properties.
  void VerifyThunks(size_t expected_total_thunks,
                    size_t expected_param_thunks,
                    size_t expected_destinations,
                    size_t expected_entrypoints) {
    ConstBlockVector thunks;
    int param_thunks = 0;
    ASSERT_NO_FATAL_FAILURE(FindThunks(&thunks, &param_thunks));

    EXPECT_EQ(expected_total_thunks, thunks.size());
    EXPECT_EQ(expected_param_thunks, param_thunks);
    EXPECT_EQ(expected_destinations, CountDestinations(thunks));
    EXPECT_EQ(expected_entrypoints, CountEntryPoints(thunks));
  }

  enum ImageType {
    DLL_IMAGE,
    EXE_IMAGE,
  };

  void SetEmptyDllEntryPoint() {
    TypedBlock<IMAGE_NT_HEADERS> nt_headers;
    ASSERT_TRUE(nt_headers.Init(0, nt_headers_block_));
    nt_headers->FileHeader.Characteristics |= IMAGE_FILE_DLL;
  }

  // Sets the image entrypoint and sets or clears the DLL flag
  // in the NT headers.
  void SetEntryPoint(BlockGraph::Block* entrypoint, ImageType image_type) {
    // Set the image entrypoint.
    TypedBlock<IMAGE_NT_HEADERS> nt_headers;
    ASSERT_TRUE(nt_headers.Init(0, nt_headers_block_));
    ASSERT_TRUE(
        nt_headers.SetReference(
            BlockGraph::RELATIVE_REF,
            nt_headers->OptionalHeader.AddressOfEntryPoint,
            entrypoint,
            0, 0));

    // Set or clear the DLL flag.
    if (image_type == DLL_IMAGE)
      nt_headers->FileHeader.Characteristics |= IMAGE_FILE_DLL;
    else
      nt_headers->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;
  }

  // Creates a TLS directory with the given block for entrypoint, and sets or
  // clears the DLL flag in the NT headers.
  void SetTLSEntryPoint(BlockGraph::Block* entrypoint, ImageType image_type) {
    // Set the image entrypoint.
    TypedBlock<IMAGE_NT_HEADERS> nt_headers;
    ASSERT_TRUE(nt_headers.Init(0, nt_headers_block_));
    IMAGE_DATA_DIRECTORY& data_dir =
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    ASSERT_EQ(0, data_dir.Size);

    // Create the TLS directory block.
    BlockGraph::Block* tls_dir_block = bg_.AddBlock(BlockGraph::DATA_BLOCK,
                                                    sizeof(IMAGE_TLS_DIRECTORY),
                                                    "TLS Directory");
    ASSERT_TRUE(tls_dir_block != NULL);
    ASSERT_TRUE(tls_dir_block->AllocateData(tls_dir_block->size()));

    // Hook the TLS dir up to the NT headers.
    ASSERT_TRUE(nt_headers.SetReference(BlockGraph::ABSOLUTE_REF,
                                        data_dir.VirtualAddress,
                                        tls_dir_block,
                                        0, 0));
    data_dir.Size = tls_dir_block->size();

    TypedBlock<IMAGE_TLS_DIRECTORY> tls_dir;
    ASSERT_TRUE(tls_dir.Init(0, tls_dir_block));

    BlockGraph::Block* tls_callbacks = bg_.AddBlock(BlockGraph::DATA_BLOCK,
                                                    2 * sizeof(AbsoluteAddress),
                                                    "TLS Callbacks");
    ASSERT_TRUE(tls_callbacks != NULL);
    ASSERT_TRUE(tls_callbacks->AllocateData(tls_callbacks->size()) != NULL);
    ASSERT_TRUE(tls_dir.SetReference(BlockGraph::ABSOLUTE_REF,
                                     tls_dir->AddressOfCallBacks,
                                     tls_callbacks,
                                     0, 0));

    ASSERT_TRUE(tls_callbacks->SetReference(0,
                    BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                                          sizeof(AbsoluteAddress),
                                          entrypoint,
                                          0, 0)));

    // Set or clear the DLL flag.
    if (image_type == DLL_IMAGE)
      nt_headers->FileHeader.Characteristics |= IMAGE_FILE_DLL;
    else
      nt_headers->FileHeader.Characteristics &= ~IMAGE_FILE_DLL;
  }

 protected:
  size_t num_sections_pre_transform_;

  testing::DummyTransformPolicy policy_;

  BlockGraph bg_;
  BlockGraph::Block* dos_header_block_;
  BlockGraph::Block* nt_headers_block_;

  BlockGraph::Block* foo_;
  BlockGraph::Block* bar_;
  BlockGraph::Block* array_;
};

}  // namespace

TEST_F(EntryThunkTransformTest, AccessorsAndMutators) {
  EntryThunkTransform tx;

  EXPECT_TRUE(tx.instrument_unsafe_references());
  EXPECT_FALSE(tx.src_ranges_for_thunks());
  EXPECT_FALSE(tx.only_instrument_module_entry());

  tx.set_instrument_unsafe_references(false);
  tx.set_src_ranges_for_thunks(true);
  tx.set_only_instrument_module_entry(true);

  EXPECT_FALSE(tx.instrument_unsafe_references());
  EXPECT_TRUE(tx.src_ranges_for_thunks());
  EXPECT_TRUE(tx.only_instrument_module_entry());
}

TEST_F(EntryThunkTransformTest, ParameterizedThunks) {
  EntryThunkTransform tx;

  EXPECT_FALSE(tx.EntryThunkIsParameterized());
  EXPECT_FALSE(tx.FunctionThunkIsParameterized());
  EXPECT_EQ(core::kSizeNone, tx.entry_thunk_parameter().size());
  EXPECT_EQ(core::kSizeNone, tx.function_thunk_parameter().size());

  // We shouldn't be allowed to set an 8-bit parameter.
  Immediate imm8(43, core::kSize8Bit);
  EXPECT_FALSE(tx.SetEntryThunkParameter(imm8));
  EXPECT_FALSE(tx.SetFunctionThunkParameter(imm8));

  EXPECT_FALSE(tx.EntryThunkIsParameterized());
  EXPECT_FALSE(tx.FunctionThunkIsParameterized());
  EXPECT_EQ(core::kSizeNone, tx.entry_thunk_parameter().size());
  EXPECT_EQ(core::kSizeNone, tx.function_thunk_parameter().size());

  // A 32-bit parameter should be accepted just fine.
  Immediate imm32(static_cast<int32>(0x11223344));
  EXPECT_TRUE(tx.SetEntryThunkParameter(imm32));
  EXPECT_TRUE(tx.SetFunctionThunkParameter(imm32));

  EXPECT_TRUE(tx.EntryThunkIsParameterized());
  EXPECT_TRUE(tx.FunctionThunkIsParameterized());
  EXPECT_EQ(imm32, tx.entry_thunk_parameter());
  EXPECT_EQ(imm32, tx.function_thunk_parameter());

  // A default contructured (with no size) parameter should be accepted.
  EXPECT_TRUE(tx.SetEntryThunkParameter(Immediate()));
  EXPECT_TRUE(tx.SetFunctionThunkParameter(Immediate()));

  EXPECT_FALSE(tx.EntryThunkIsParameterized());
  EXPECT_FALSE(tx.FunctionThunkIsParameterized());
  EXPECT_EQ(core::kSizeNone, tx.entry_thunk_parameter().size());
  EXPECT_EQ(core::kSizeNone, tx.function_thunk_parameter().size());
}

TEST_F(EntryThunkTransformTest, InstrumentAll) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEmptyDllEntryPoint());

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have three thunks - one each for the start of foo() and bar(),
  // and one for the middle of foo().
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(3, 0, 3, 1));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentAllWithParam) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEmptyDllEntryPoint());
  transform.SetEntryThunkParameter(Immediate(0x11223344));
  transform.SetFunctionThunkParameter(Immediate(0x11223344));

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have three thunks - one each for the start of foo() and bar(),
  // and one for the middle of foo().
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(3, 3, 3, 1));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentModuleEntriesOnlyNone) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEmptyDllEntryPoint());
  transform.set_only_instrument_module_entry(true);

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have no thunks.
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(0, 0, 0, 0));

  // The .thunks section should not have been added, as there are no hooks
  // added.
  EXPECT_EQ(num_sections_pre_transform_, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentModuleEntriesOnlyDllMainOnly) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, DLL_IMAGE));
  transform.set_only_instrument_module_entry(true);

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have one thunk, for the DLL main entry point to the start of
  // foo_.
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(1, 0, 1, 1));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentOnlyDllMainWithParamThunk) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, DLL_IMAGE));
  transform.set_only_instrument_module_entry(true);
  transform.SetEntryThunkParameter(Immediate(0x11223344));

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have one thunk, for the DLL main entry point to the start of
  // foo_ and it should be parameterized.
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(1, 1, 1, 1));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentModuleEntriesOnlyDllMainAndTls) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, DLL_IMAGE));
  ASSERT_NO_FATAL_FAILURE(SetTLSEntryPoint(bar_, DLL_IMAGE));
  transform.set_only_instrument_module_entry(true);

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have two thunk, for the DLL main entry point and another for the
  // TLS. One is to foo_ and one is to bar_.
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(2, 0, 2, 1));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentModuleEntriesOnlyExeMainAndTls) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, EXE_IMAGE));
  ASSERT_NO_FATAL_FAILURE(SetTLSEntryPoint(bar_, EXE_IMAGE));
  transform.set_only_instrument_module_entry(true);

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have one TLS thunk and an EXE entry thunk.
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(2, 0, 2, 2));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentAllDebugFriendly) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, EXE_IMAGE));
  transform.set_src_ranges_for_thunks(true);

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // Verify the source ranges on the thunks.
  ConstBlockVector thunks;
  int param_thunks = 0;
  ASSERT_NO_FATAL_FAILURE(FindThunks(&thunks, &param_thunks));
  EXPECT_EQ(0u, param_thunks);
  ASSERT_NO_FATAL_FAILURE(VerifySourceRanges(thunks));
}

TEST_F(EntryThunkTransformTest, InstrumentNoUnsafe) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEmptyDllEntryPoint());

  // No unsafe reference instrumentation.
  transform.set_instrument_unsafe_references(false);

  // Tag both foo and bar with unsafe attributes.
  foo_->set_attribute(BlockGraph::HAS_INLINE_ASSEMBLY);
  bar_->set_attribute(BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have two thunks - one each for the start of foo() and bar().
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(2, 0, 2, 1));

  // The foo->bar reference should not have been thunked.
  BlockGraph::Reference ref;
  ASSERT_TRUE(foo_->GetReference(5, &ref));
  ASSERT_EQ(bar_, ref.referenced());

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentDllEntrypoint) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, DLL_IMAGE));

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have three thunks - one each for the start of foo() and bar().
  // One of the thunks should use the DllMain entrypoint.
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(3, 0, 3, 2));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentExeEntrypoint) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, EXE_IMAGE));

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have three thunks - one each for the start of foo() and bar().
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(3, 0, 3, 2));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentDllTLSEntrypoint) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, DLL_IMAGE));
  ASSERT_NO_FATAL_FAILURE(SetTLSEntryPoint(bar_, DLL_IMAGE));

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have three thunks - one each for the start of foo() and bar().
  // One of the thunks should use the DllMain entrypoint.
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(3, 0, 3, 2));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

TEST_F(EntryThunkTransformTest, InstrumentExeTLSEntrypoint) {
  EntryThunkTransform transform;
  ASSERT_NO_FATAL_FAILURE(SetEntryPoint(foo_, EXE_IMAGE));
  ASSERT_NO_FATAL_FAILURE(SetTLSEntryPoint(bar_, EXE_IMAGE));

  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, &policy_, &bg_, dos_header_block_));

  // We should have three thunks - one each for the start of foo() and bar().
  ASSERT_NO_FATAL_FAILURE(VerifyThunks(3, 0, 3, 3));

  // The .thunks section should have been added.
  EXPECT_EQ(num_sections_pre_transform_ + 1, bg_.sections().size());
}

}  // namespace transforms
}  // namespace instrument
