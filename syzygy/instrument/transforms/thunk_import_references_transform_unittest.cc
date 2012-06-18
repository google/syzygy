// Copyright 2012 Google Inc.
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
// Unittests for ThunkImportReferencesTransform.

#include "syzygy/instrument/transforms/thunk_import_references_transform.h"

#include <vector>

#include "base/scoped_temp_dir.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/transforms/add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;
using core::AbsoluteAddress;
using pe::transforms::AddImportsTransform;

typedef BlockGraph::Block::ReferrerSet ReferrerSet;

// Expose protected members for testing.
class TestThunkImportReferencesTransform
    : public ThunkImportReferencesTransform {
 public:
  using ThunkImportReferencesTransform::Thunk;

  AddImportsTransform& add_imports_transform() {
    return ThunkImportReferencesTransform::add_imports_transform();
  }
};

class ThunkImportReferencesTransformTest : public testing::Test {
 public:
  ThunkImportReferencesTransformTest()
      : input_image_layout_(&block_graph_), dos_header_block_(NULL) {
  }

  virtual void SetUp() {
    tmp_dir_.CreateUniqueTempDir();
    ASSERT_TRUE(input_pe_file_.Init(
        testing::GetOutputRelativePath(L"test_dll.dll")));
    ASSERT_NO_FATAL_FAILURE(Decompose());
  }

  void Decompose() {
    // Decompose the input image.
    pe::Decomposer decomposer(input_pe_file_);
    decomposer.set_pdb_path(
        FilePath(testing::GetOutputRelativePath(L"test_dll.pdb")));
    ASSERT_TRUE(decomposer.Decompose(&input_image_layout_))
        << "Unable to decompose module: "
        << input_pe_file_.path().value();

    // Get the DOS header block.
    dos_header_block_ =
        input_image_layout_.blocks.GetBlockByAddress(
            BlockGraph::RelativeAddress(0));
    ASSERT_TRUE(dos_header_block_ != NULL)
        << "Unable to find the DOS header block.";
  }

 protected:
  pe::PEFile input_pe_file_;
  pe::ImageLayout input_image_layout_;
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;
  ScopedTempDir tmp_dir_;
};

}  // namespace

TEST_F(ThunkImportReferencesTransformTest, TestImports) {
  // Check that we don't have a thunks section yet.
  BlockGraph::Section* null_thunks_section =
      block_graph_.FindSection(".thunks");
  EXPECT_EQ(NULL, null_thunks_section);

  TestThunkImportReferencesTransform transform;
  ASSERT_TRUE(ApplyTransform(&transform, &block_graph_, dos_header_block_));

  // Check that we now have a thunks section.
  BlockGraph::Section* thunks_section = block_graph_.FindSection(".thunks");
  ASSERT_TRUE(thunks_section != NULL);

  BlockGraph::SectionId thunks_section_id = thunks_section->id();

  // The only CODE_BLOCK referrers to the IAT should be in the thunk section.
  AddImportsTransform& ait = transform.add_imports_transform();
  const ReferrerSet& referrers  =
      ait.import_address_table_block()->referrers();
  ReferrerSet::const_iterator ref_iter(referrers.begin()),
                              ref_end(referrers.end());
  for (; ref_iter != ref_end; ++ref_iter) {
    // Use this check to exclude the NT headers and the IDT blocks.
    if (ref_iter->first->type() == BlockGraph::CODE_BLOCK)
      EXPECT_EQ(thunks_section_id, ref_iter->first->section());
  }
}

}  // namespace transforms
}  // namespace instrument
