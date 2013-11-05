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

#include "syzygy/pe/pe_relinker.h"

#include "base/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/serialization.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using block_graph::BlockGraphOrdererInterface;
using block_graph::BlockGraphTransformInterface;
using block_graph::OrderedBlockGraph;
using block_graph::TransformPolicyInterface;
using pdb::PdbFile;
using pdb::PdbMutatorInterface;
using testing::_;
using testing::Return;
using testing::StrictMock;

class TestPERelinker : public PERelinker {
 public:
  explicit TestPERelinker(const PETransformPolicy* transform_policy)
      : PERelinker(transform_policy) {
  }

  using PERelinker::transforms_;
  using PERelinker::orderers_;
  using PERelinker::pdb_mutators_;
};

class PERelinkerTest : public testing::PELibUnitTest {
  typedef testing::PELibUnitTest Super;

 public:
  void SetUp() {
    Super::SetUp();

    input_dll_ = testing::GetExeRelativePath(testing::kTestDllName);
    input_pdb_ = testing::GetExeRelativePath(testing::kTestDllPdbName);

    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));
    temp_dll_ = temp_dir_.Append(testing::kTestDllName);
    temp_pdb_ = temp_dir_.Append(testing::kTestDllPdbName);
  }

  PETransformPolicy policy_;
  base::FilePath input_dll_;
  base::FilePath input_pdb_;
  base::FilePath temp_dir_;
  base::FilePath temp_dll_;
  base::FilePath temp_pdb_;
};

class MockTransform : public BlockGraphTransformInterface {
 public:
  const char* name() const { return "MockTransform"; }
  MOCK_METHOD3(TransformBlockGraph,
               bool(const TransformPolicyInterface*,
                    BlockGraph*,
                    BlockGraph::Block*));
};

class MockOrderer : public BlockGraphOrdererInterface {
 public:
  const char* name() const { return "MockOrderer"; }
  MOCK_METHOD2(OrderBlockGraph, bool(OrderedBlockGraph*, BlockGraph::Block*));
};

class MockPdbMutator : public PdbMutatorInterface {
 public:
  const char* name() const { return "MockPdbMutator"; }
  MOCK_METHOD1(MutatePdb, bool(PdbFile*));
};

}  // namespace

TEST_F(PERelinkerTest, Properties) {
  TestPERelinker relinker(&policy_);
  base::FilePath dummy_path(L"foo");

  EXPECT_EQ(base::FilePath(), relinker.input_path());
  relinker.set_input_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.input_path());

  EXPECT_EQ(base::FilePath(), relinker.input_pdb_path());
  relinker.set_input_pdb_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.input_pdb_path());

  EXPECT_EQ(base::FilePath(), relinker.output_path());
  relinker.set_output_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.output_path());

  EXPECT_EQ(base::FilePath(), relinker.output_pdb_path());
  relinker.set_output_pdb_path(dummy_path);
  EXPECT_EQ(dummy_path, relinker.output_pdb_path());

  EXPECT_TRUE(relinker.add_metadata());
  relinker.set_add_metadata(false);
  EXPECT_FALSE(relinker.add_metadata());
  relinker.set_add_metadata(TRUE);
  EXPECT_TRUE(relinker.add_metadata());

  EXPECT_FALSE(relinker.allow_overwrite());
  relinker.set_allow_overwrite(true);
  EXPECT_TRUE(relinker.allow_overwrite());
  relinker.set_allow_overwrite(false);
  EXPECT_FALSE(relinker.allow_overwrite());

  EXPECT_TRUE(relinker.augment_pdb());
  relinker.set_augment_pdb(false);
  EXPECT_FALSE(relinker.augment_pdb());
  relinker.set_augment_pdb(true);
  EXPECT_TRUE(relinker.augment_pdb());

  EXPECT_FALSE(relinker.compress_pdb());
  relinker.set_compress_pdb(true);
  EXPECT_TRUE(relinker.compress_pdb());
  relinker.set_compress_pdb(false);
  EXPECT_FALSE(relinker.compress_pdb());

  EXPECT_FALSE(relinker.strip_strings());
  relinker.set_strip_strings(true);
  EXPECT_TRUE(relinker.strip_strings());
  relinker.set_strip_strings(false);
  EXPECT_FALSE(relinker.strip_strings());

  EXPECT_FALSE(relinker.use_new_decomposer());
  relinker.set_use_new_decomposer(true);
  EXPECT_TRUE(relinker.use_new_decomposer());
  relinker.set_use_new_decomposer(false);
  EXPECT_FALSE(relinker.use_new_decomposer());

  EXPECT_EQ(0u, relinker.padding());
  relinker.set_padding(10);
  EXPECT_EQ(10u, relinker.padding());
  relinker.set_padding(0);
  EXPECT_EQ(0u, relinker.padding());

  EXPECT_EQ(1u, relinker.code_alignment());
  relinker.set_code_alignment(10);
  EXPECT_EQ(10u, relinker.code_alignment());
  relinker.set_code_alignment(1);
  EXPECT_EQ(1u, relinker.code_alignment());
}

TEST_F(PERelinkerTest, AppendPdbMutators) {
  TestPERelinker relinker(&policy_);

  MockPdbMutator pdb_mutator1, pdb_mutator2;
  std::vector<PdbMutatorInterface*> pdb_mutators;
  pdb_mutators.push_back(&pdb_mutator2);

  relinker.AppendPdbMutator(&pdb_mutator1);
  relinker.AppendPdbMutators(pdb_mutators);

  std::vector<PdbMutatorInterface*> expected;
  expected.push_back(&pdb_mutator1);
  expected.push_back(&pdb_mutator2);

  EXPECT_EQ(expected, relinker.pdb_mutators_);
}

TEST_F(PERelinkerTest, InitFailsOnUnspecifiedInput) {
  TestPERelinker relinker(&policy_);

  relinker.set_output_path(temp_dll_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitFailsOnUnspecifiedOutput) {
  TestPERelinker relinker(&policy_);

  relinker.set_input_path(input_dll_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitFailsOnNonexistentInput) {
  TestPERelinker relinker(&policy_);

  relinker.set_input_path(temp_dir_.Append(L"nonexistent.dll"));
  relinker.set_output_path(temp_dll_);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitFailsOnDisallowedOverwrite) {
  TestPERelinker relinker(&policy_);

  // Copy the image in case the test actually does overwrite the input; this
  // way we don't accidentally turf our test data.
  file_util::CopyFile(input_dll_, temp_dll_);

  relinker.set_input_path(temp_dll_);
  relinker.set_output_path(temp_dll_);

  relinker.set_allow_overwrite(false);
  EXPECT_FALSE(relinker.Init());
}

TEST_F(PERelinkerTest, InitSucceeds) {
  TestPERelinker relinker(&policy_);

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);

  EXPECT_TRUE(relinker.Init());
}

TEST_F(PERelinkerTest, IntermediateAccessors) {
  TestPERelinker relinker(&policy_);

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);

  EXPECT_TRUE(relinker.Init());

  EXPECT_EQ(input_dll_, relinker.input_pe_file().path());
  EXPECT_TRUE(relinker.headers_block() != NULL);
}

TEST_F(PERelinkerTest, FailsWhenTransformFails) {
  TestPERelinker relinker(&policy_);
  StrictMock<MockTransform> transform;

  EXPECT_CALL(transform, TransformBlockGraph(_, _, _)).WillOnce(Return(false));

  relinker.AppendTransform(&transform);
  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);
  EXPECT_TRUE(relinker.Init());
  EXPECT_FALSE(relinker.Relink());
}

TEST_F(PERelinkerTest, FailsWhenOrdererFails) {
  TestPERelinker relinker(&policy_);
  StrictMock<MockOrderer> orderer;

  EXPECT_CALL(orderer, OrderBlockGraph(_, _)).WillOnce(Return(false));

  relinker.AppendOrderer(&orderer);
  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);
  EXPECT_TRUE(relinker.Init());
  EXPECT_FALSE(relinker.Relink());
}

TEST_F(PERelinkerTest, FailsWhenPdbMutatorFails) {
  TestPERelinker relinker(&policy_);
  StrictMock<MockPdbMutator> pdb_mutator;

  EXPECT_CALL(pdb_mutator, MutatePdb(_)).WillOnce(Return(false));

  relinker.AppendPdbMutator(&pdb_mutator);
  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);
  EXPECT_TRUE(relinker.Init());
  EXPECT_FALSE(relinker.Relink());
}

TEST_F(PERelinkerTest, Success) {
  TestPERelinker relinker(&policy_);
  StrictMock<MockTransform> transform;
  StrictMock<MockOrderer> orderer;
  StrictMock<MockPdbMutator> pdb_mutator;

  EXPECT_CALL(transform, TransformBlockGraph(_, _, _)).WillOnce(Return(true));
  EXPECT_CALL(orderer, OrderBlockGraph(_, _)).WillOnce(Return(true));
  EXPECT_CALL(pdb_mutator, MutatePdb(_)).WillOnce(Return(true));

  relinker.AppendTransform(&transform);
  relinker.AppendOrderer(&orderer);
  relinker.AppendPdbMutator(&pdb_mutator);

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);

  EXPECT_TRUE(relinker.Init());
  EXPECT_TRUE(relinker.Relink());
}

TEST_F(PERelinkerTest, IdentityRelink) {
  TestPERelinker relinker(&policy_);

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

  base::FilePath pdb_path;
  ASSERT_TRUE(FindPdbForModule(relinker.output_path(), &pdb_path));
  EXPECT_EQ(pdb_path, relinker.output_pdb_path());
}

TEST_F(PERelinkerTest, IdentityRelinkNewDecomposer) {
  TestPERelinker relinker(&policy_);

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);
  relinker.set_use_new_decomposer(true);

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

  base::FilePath pdb_path;
  ASSERT_TRUE(FindPdbForModule(relinker.output_path(), &pdb_path));
  EXPECT_EQ(pdb_path, relinker.output_pdb_path());
}

TEST_F(PERelinkerTest, BlockGraphStreamIsCreated) {
  TestPERelinker relinker(&policy_);

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);
  relinker.set_augment_pdb(true);
  EXPECT_TRUE(relinker.augment_pdb());

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

TEST_F(PERelinkerTest, BlockGraphStreamVersionIsTheCurrentOne) {
  TestPERelinker relinker(&policy_);

  relinker.set_input_path(input_dll_);
  relinker.set_output_path(temp_dll_);
  relinker.set_augment_pdb(true);
  EXPECT_TRUE(relinker.augment_pdb());

  EXPECT_TRUE(relinker.Init());
  EXPECT_TRUE(relinker.Relink());
  EXPECT_EQ(temp_pdb_, relinker.output_pdb_path());

  // Looks for the block-graph stream in the PDB.
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
  ASSERT_LT(0U, stream->length());

  scoped_refptr<pdb::PdbByteStream> byte_stream = new pdb::PdbByteStream();
  EXPECT_TRUE(byte_stream->Init(stream.get()));
  EXPECT_TRUE(byte_stream.get() != NULL);
  core::ScopedInStreamPtr in_stream;
  in_stream.reset(core::CreateByteInStream(byte_stream->data(),
                  byte_stream->data() + byte_stream->length()));
  core::NativeBinaryInArchive in_archive(in_stream.get());

  // Ensure that the version of the stream is the current one.
  uint32 stream_version = 0;
  EXPECT_TRUE(in_archive.Load(&stream_version));
  ASSERT_EQ(stream_version, pdb::kSyzygyBlockGraphStreamVersion);
}

}  // namespace pe
