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

#include "syzygy/pe/pe_relinker.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

class PERelinkerTest : public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  void SetUp() {
    Super::SetUp();

    input_dll_ = testing::GetExeRelativePath(kDllName);
    input_pdb_ = testing::GetExeRelativePath(kDllPdbName);

    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
    temp_dll_ = temp_dir_.Append(kDllName);
    temp_pdb_ = temp_dir_.Append(kDllPdbName);
  }

  FilePath input_dll_;
  FilePath input_pdb_;
  FilePath temp_dir_;
  FilePath temp_dll_;
  FilePath temp_pdb_;
};

}  // namespace

TEST_F(PERelinkerTest, Properties) {
  PERelinker relinker;

  EXPECT_EQ(FilePath(), relinker.input_path());
  EXPECT_EQ(FilePath(), relinker.input_pdb_path());
  EXPECT_EQ(FilePath(), relinker.output_path());
  EXPECT_EQ(FilePath(), relinker.output_pdb_path());
  EXPECT_EQ(true, relinker.add_metadata());
  EXPECT_EQ(false, relinker.allow_overwrite());
  EXPECT_EQ(0u, relinker.padding());

  FilePath dummy_path(L"foo");

  relinker.set_input_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.input_path());

  relinker.set_output_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.output_path());

  relinker.set_output_pdb_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.output_pdb_path());

  relinker.set_add_metadata(false);
  EXPECT_EQ(false, relinker.add_metadata());

  relinker.set_allow_overwrite(true);
  EXPECT_EQ(true, relinker.allow_overwrite());

  relinker.set_padding(10);
  EXPECT_EQ(10u, relinker.padding());
}

TEST_F(PERelinkerTest, InitFailsOnUnspecifiedInput) {
  PERelinker relinker;

  relinker.set_output_path(temp_dll_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitFailsOnUnspecifiedOutput) {
  PERelinker relinker;

  relinker.set_input_path(input_dll_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitFailsOnNonexistentInput) {
  PERelinker relinker;

  relinker.set_input_path(temp_dir_.Append(L"nonexistent.dll"));
  relinker.set_output_path(temp_dll_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitFailsOnDisallowedOverwrite) {
  PERelinker relinker;

  // Copy the image in case the test actually does overwrite the input; this
  // way we don't accidentally turf our test data.
  file_util::CopyFile(input_dll_, temp_dll_);

  relinker.set_input_path(temp_dll_);
  relinker.set_output_path(temp_dll_);

  relinker.set_allow_overwrite(false);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitSucceeds) {
  PERelinker relinker;

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);

  EXPECT_TRUE(relinker.Init());
}

TEST_F(PERelinkerTest, IntermediateAccessors) {
  PERelinker relinker;

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);

  EXPECT_TRUE(relinker.Init());

  EXPECT_EQ(input_dll_, relinker.input_pe_file().path());
  EXPECT_TRUE(relinker.dos_header_block() != NULL);
}

TEST_F(PERelinkerTest, IdentityRelink) {
  PERelinker relinker;

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);

  // We let the relinker infer the PDB output. The mechanism should cause it
  // to produce a PDB file in the temporary directory with the same basename
  // as the input PDB.
  EXPECT_TRUE(relinker.Init());
  EXPECT_TRUE(relinker.Relink());
  EXPECT_EQ(temp_pdb_, relinker.output_pdb_path());

  EXPECT_TRUE(file_util::PathExists(relinker.output_path()));
  EXPECT_TRUE(file_util::PathExists(relinker.output_pdb_path()));

  ASSERT_NO_FATAL_FAILURE(CheckTestDll(relinker.output_path()));

  PEFile orig_pe_file;
  PEFile::Signature orig_pe_sig;
  ASSERT_TRUE(orig_pe_file.Init(input_dll_));
  orig_pe_file.GetSignature(&orig_pe_sig);

  // Ensure that the produced binary contains a metadata section. This
  // confirms that the AddMetadataTransform has run.
  PEFile new_pe_file;
  ASSERT_TRUE(new_pe_file.Init(temp_dll_));
  ASSERT_NE(kInvalidSection,
            new_pe_file.GetSectionIndex(common::kSyzygyMetadataSectionName));
  Metadata metadata;
  ASSERT_TRUE(metadata.LoadFromPE(new_pe_file));
  EXPECT_TRUE(metadata.IsConsistent(orig_pe_sig));

  // Ensure that the PDB file can be found from the module. This confirms that
  // the AddPdbInfoTransform has run.

  PdbInfo pdb_info;
  ASSERT_TRUE(pdb_info.Init(relinker.output_path()));
  EXPECT_EQ(pdb_info.pdb_file_name(), relinker.output_pdb_path());

  FilePath pdb_path;
  ASSERT_TRUE(FindPdbForModule(relinker.output_path(), &pdb_path));
  EXPECT_EQ(pdb_path, relinker.output_pdb_path());
}

TEST_F(PERelinkerTest, BlockGraphStreamIsCreated) {
  PERelinker relinker;

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);
  relinker.set_augment_pdb(true);
  EXPECT_EQ(true, relinker.augment_pdb());

  EXPECT_TRUE(relinker.Init());
  EXPECT_TRUE(relinker.Relink());
  EXPECT_EQ(temp_pdb_, relinker.output_pdb_path());

  // Ensure that the block-graph stream has been written to the PDB. The
  // content of the stream is not validated, we only check that the named
  // stream exists in the generated PDB file.
  pdb::PdbFile pdb_file;
  pdb::PdbReader pdb_reader;
  EXPECT_TRUE(pdb_reader.Read(temp_pdb_, &pdb_file));
  pdb::PdbInfoHeader70 pdb_header = {0};
  pdb::NameStreamMap name_stream_map;
  EXPECT_TRUE(ReadHeaderInfoStream(
      pdb_file.GetStream(pdb::kPdbHeaderInfoStream),
      &pdb_header,
      &name_stream_map));
  pdb::NameStreamMap::const_iterator name_it = name_stream_map.find(
      pdb::kSyzygyBlockGraphStreamName);
  ASSERT_TRUE(name_it != name_stream_map.end());
  scoped_refptr<pdb::PdbStream> stream = pdb_file.GetStream(name_it->second);
  ASSERT_TRUE(stream.get() != NULL);
  ASSERT_GT(stream->length(), 0u);
}

}  // namespace pe
