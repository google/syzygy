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
// Unittests for ThunkImportReferencesTransform.

#include "syzygy/instrument/transforms/thunk_import_references_transform.h"

#include <vector>

#include "base/files/scoped_temp_dir.h"
#include "base/strings/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/instrument/transforms/unittest_util.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"

namespace instrument {
namespace transforms {

namespace {

using block_graph::BlockGraph;
using block_graph::TypedBlock;
using core::AbsoluteAddress;
using pe::transforms::PEAddImportsTransform;

typedef BlockGraph::Block::ReferrerSet ReferrerSet;

// Expose protected members for testing.
class TestThunkImportReferencesTransform
    : public ThunkImportReferencesTransform {
 public:
  // Make data members public for testing.
  using ThunkImportReferencesTransform::add_imports_transform;
  using ThunkImportReferencesTransform::modules_to_exclude_;

  // Make member types public for testing.
  using ThunkImportReferencesTransform::BlockSet;
  using ThunkImportReferencesTransform::ImportAddressLocation;
  using ThunkImportReferencesTransform::ImportAddressLocationNameMap;
  using ThunkImportReferencesTransform::ModuleNameSet;

  // Make member functions public for testing.
  using ThunkImportReferencesTransform::GetImportBlocks;
  using ThunkImportReferencesTransform::LookupImportLocations;
  using ThunkImportReferencesTransform::LookupDelayImportLocations;
};

class ThunkImportReferencesTransformTest
    : public testing::TestDllTransformTest {
 public:
  typedef TestThunkImportReferencesTransform::BlockSet BlockSet;
  typedef TestThunkImportReferencesTransform::ModuleNameSet ModuleNameSet;
  typedef TestThunkImportReferencesTransform::ImportAddressLocation
      ImportAddressLocation;
  typedef TestThunkImportReferencesTransform::ImportAddressLocationNameMap
      ImportAddressLocationNameMap;

  ThunkImportReferencesTransformTest() : input_image_layout_(&block_graph_) {
  }

  virtual void SetUp() {
    ASSERT_NO_FATAL_FAILURE(DecomposeTestDll());
  }

 protected:
  pe::ImageLayout input_image_layout_;
};

}  // namespace

TEST_F(ThunkImportReferencesTransformTest, Initialization) {
  TestThunkImportReferencesTransform transform;

  EXPECT_STREQ(TestThunkImportReferencesTransform::kDefaultInstrumentDll,
               transform.instrument_dll_name());
  EXPECT_TRUE(transform.modules_to_exclude_.empty());
}

TEST_F(ThunkImportReferencesTransformTest, LookupImportLocations) {
  ImportAddressLocationNameMap all_import_locations;
  // This should enumerate all imports.
  ASSERT_TRUE(
      TestThunkImportReferencesTransform::LookupImportLocations(
          ModuleNameSet(), header_block_, &all_import_locations));

  // Check that we found all the functions imported from export_dll.dll.
  std::set<std::string> export_dll_imports;
  ImportAddressLocationNameMap::const_iterator it =
      all_import_locations.begin();
  static const char kExportDLLPrefix[] = "export_dll.dll:";

  for (; it != all_import_locations.end(); ++it) {
    if (StartsWithASCII(it->second, kExportDLLPrefix, false))
      export_dll_imports.insert(it->second);
  }

  EXPECT_THAT(export_dll_imports,
      testing::ElementsAre("export_dll.dll:#7",
                           "export_dll.dll:function1",
                           "export_dll.dll:function3",
                           "export_dll.dll:kExportedData"));
}

TEST_F(ThunkImportReferencesTransformTest, LookupDelayImportLocations) {
  ImportAddressLocationNameMap all_import_locations;
  // This should enumerate all delay imports.
  ASSERT_TRUE(
      TestThunkImportReferencesTransform::LookupDelayImportLocations(
          ModuleNameSet(), header_block_, &all_import_locations));

  // There should be precisely one ole32.dll import.
  ASSERT_EQ(1, all_import_locations.size());

  ASSERT_STRCASEEQ("ole32.dll:CoCreateGuid",
                   all_import_locations.begin()->second.c_str());
}

TEST_F(ThunkImportReferencesTransformTest, ExcludeModule) {
  TestThunkImportReferencesTransform transform;

  EXPECT_TRUE(transform.modules_to_exclude_.empty());
  transform.ExcludeModule("kernel32.dll");
  EXPECT_THAT(transform.modules_to_exclude_,
              testing::ElementsAre("kernel32.dll"));

  // Make sure case is ignored.
  transform.ExcludeModule("KERNEL32.DLL");
  EXPECT_THAT(transform.modules_to_exclude_,
              testing::ElementsAre("kernel32.dll"));

  // Add another exclusion.
  transform.ExcludeModule("export_dll.dll");
  EXPECT_THAT(transform.modules_to_exclude_,
              testing::ElementsAre("export_dll.dll", "kernel32.dll"));
}

TEST_F(ThunkImportReferencesTransformTest, TestInstrumentation) {
  // Check that we don't have a thunks section yet.
  EXPECT_EQ(NULL, block_graph_.FindSection(common::kThunkSectionName));

  TestThunkImportReferencesTransform transform;
  // Exclude kernel32.dll.
  transform.ExcludeModule("kernel32.dll");

  // Run the transform.
  ASSERT_TRUE(ApplyBlockGraphTransform(
      &transform, policy_, &block_graph_, header_block_));

  // Check that we now have a thunks section.
  BlockGraph::Section* thunks_section =
      block_graph_.FindSection(common::kThunkSectionName);
  ASSERT_TRUE(thunks_section != NULL);

  BlockGraph::SectionId thunks_section_id = thunks_section->id();

  // From here it gets a little tricky. We use the import/delay import lookups
  // to find where the import entries are, and what their names are. We then
  // use that information to make sure that only non-thunks reference
  // kernel32.dll imports, and that only thunks reference other imports.
  ImportAddressLocationNameMap all_import_locations;
  ASSERT_TRUE(TestThunkImportReferencesTransform::LookupImportLocations(
      ModuleNameSet(), header_block_, &all_import_locations));
  ASSERT_TRUE(TestThunkImportReferencesTransform::LookupDelayImportLocations(
      ModuleNameSet(), header_block_, &all_import_locations));

  // Retrieve the import blocks.
  BlockSet import_blocks;
  ASSERT_TRUE(TestThunkImportReferencesTransform::GetImportBlocks(
      all_import_locations, &import_blocks));
  // There should be two import blocks, the IAT and the delay IAT.
  ASSERT_EQ(2, import_blocks.size());

  BlockSet::const_iterator block_it = import_blocks.begin();
  for (; block_it != import_blocks.end(); ++block_it) {
    const ReferrerSet& referrers = (*block_it)->referrers();
    ReferrerSet::const_iterator ref_iter(referrers.begin()),
                                ref_end(referrers.end());
    for (; ref_iter != ref_end; ++ref_iter) {
      const BlockGraph::Block* referring_block = ref_iter->first;
      BlockGraph::Offset referring_offset = ref_iter->second;

      if (referring_block->type() != BlockGraph::CODE_BLOCK)
        continue;

      BlockGraph::Reference ref;
      ASSERT_TRUE(referring_block->GetReference(referring_offset, &ref));

      ImportAddressLocation location(
          std::make_pair(ref.referenced(), ref.offset()));
      ImportAddressLocationNameMap::const_iterator location_it(
          all_import_locations.find(location));

      ASSERT_TRUE(location_it != all_import_locations.end());

      // Compare on the import name prefix case-insensitively to determine
      // whether this is an eligible or excluded import.
      if (StartsWithASCII(location_it->second, "kernel32.dll:", false)) {
        // Excluded import, the referring block must not be in
        // the thunks section.
        EXPECT_NE(thunks_section_id, referring_block->section());
      } else {
        // Eligible import, if the referring block is not itself a thunk (such
        // as a linker-generated import or delay import thunk), it must be in
        // the thunks section.
        if ((referring_block->attributes() & BlockGraph::THUNK) == 0) {
          EXPECT_EQ(thunks_section_id, referring_block->section());
        }
      }
    }
  }
}

}  // namespace transforms
}  // namespace instrument
