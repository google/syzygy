// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/type_propagator_analyzer.h"

#include <string>

#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/minidump/minidump.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_namer.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

namespace {

const Address kAddress = 0x0000CAFE;  // Fits 32-bit.
const Size kSize = 42U;
const uint32 kChecksum = 11U;
const uint32 kTimestamp = 22U;
const wchar_t kPath[] = L"c:\\path\\ModuleName";

class MockSymbolProvider : public SymbolProvider {
 public:
  MOCK_METHOD2(FindOrCreateTypeRepository,
               bool(const pe::PEFile::Signature& signature,
                    scoped_refptr<TypeRepository>* type_repo));
};

}  // namespace

class TypePropagatorAnalyzerTest : public testing::Test {
 public:
  TypePropagatorAnalyzerTest()
      : variable_(42),
        variable_ptr_(&variable_),
        expected_sig_(kPath,
                      core::AbsoluteAddress(0U),
                      kSize,
                      kChecksum,
                      kTimestamp),
        repo_(new TypeRepository(expected_sig_)),
        type_namer_(true) {
    // Create a basic type and a pointer type to it.
    basic_type_ = new BasicType(L"int32_t", sizeof(int32_t));
    repo_->AddType(basic_type_);

    ptr_type_ = new PointerType(sizeof(int32_t*), PointerType::PTR_MODE_PTR);
    repo_->AddType(ptr_type_);
    ptr_type_->Finalize(kNoTypeFlags, basic_type_->type_id());
    CHECK(type_namer_.EnsureTypeName(ptr_type_));
  }

 protected:
  // Data for the test.
  int32_t variable_;
  int32_t* variable_ptr_;

  TypePtr basic_type_;
  PointerTypePtr ptr_type_;

  pe::PEFile::Signature expected_sig_;
  scoped_refptr<TypeRepository> repo_;
  TypeNamer type_namer_;
};

TEST_F(TypePropagatorAnalyzerTest, AnalyzeMinidump) {
  ProcessState process_state;

  // Populate the bytes layer with the contents of variable_ptr_.
  BytesLayerPtr bytes_layer;
  process_state.FindOrCreateLayer(&bytes_layer);

  AddressRange range(reinterpret_cast<Address>(&variable_ptr_),
                     sizeof(variable_ptr_));
  BytesRecordPtr bytes_record;
  bytes_layer->CreateRecord(range, &bytes_record);

  Bytes* bytes_proto = bytes_record->mutable_data();
  std::string* buffer = bytes_proto->mutable_data();
  memcpy(base::WriteInto(buffer, sizeof(variable_ptr_) + 1), &variable_ptr_,
         sizeof(variable_ptr_));

  // Populate the module layer with a module and get its id.
  ModuleLayerAccessor accessor(&process_state);
  accessor.AddModuleRecord(AddressRange(kAddress, kSize), kChecksum, kTimestamp,
                           kPath);
  ModuleId module_id = accessor.GetModuleId(kAddress);
  ASSERT_NE(kNoModuleId, module_id);

  // Populate the typed block layer with knowledge of variable_ptr_.
  ASSERT_TRUE(AddTypedBlockRecord(range, L"variable_ptr_", module_id,
                                  ptr_type_->type_id(), &process_state));
  TypedBlockLayerPtr typedblock_layer;
  ASSERT_TRUE(process_state.FindLayer(&typedblock_layer));
  ASSERT_EQ(1, typedblock_layer->size());

  // Run the analyzer.
  scoped_refptr<MockSymbolProvider> mock_provider(new MockSymbolProvider());
  EXPECT_CALL(*mock_provider, FindOrCreateTypeRepository(expected_sig_, _))
      .Times(1)
      .WillOnce(DoAll(SetArgPointee<1>(repo_), Return(true)));
  TypePropagatorAnalyzer analyzer(mock_provider);
  minidump::Minidump dummy_minidump;
  ASSERT_EQ(Analyzer::ANALYSIS_COMPLETE,
            analyzer.Analyze(dummy_minidump, &process_state));

  // Validate the new typed block.
  ASSERT_EQ(2, typedblock_layer->size());

  // First reinterpret_cast to an unsigned type, to avoid sign extension.
  Address expected_addr =
      static_cast<Address>(reinterpret_cast<uintptr_t>(variable_ptr_));

  TypedBlockRecordPtr typed_record;
  ASSERT_TRUE(process_state.FindSingleRecord(expected_addr, &typed_record));

  ASSERT_EQ(expected_addr, typed_record->range().addr());
  ASSERT_EQ(basic_type_->size(), typed_record->range().size());
  const TypedBlock& typedblock = typed_record->data();
  ASSERT_EQ(module_id, typedblock.module_id());
  ASSERT_EQ(basic_type_->type_id(), typedblock.type_id());
  ASSERT_EQ("", typedblock.data_name());
}

}  // namespace refinery
