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
#include "syzygy/refinery/analyzers/analyzer_util.h"
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
const uint32_t kChecksum = 11U;
const uint32_t kTimestamp = 22U;
const wchar_t kPath[] = L"c:\\path\\ModuleName";

// TODO(manzagop): remove this.
template<typename type>
Address ToAddress(type* addr) {
  // First reinterpret_cast to an unsigned type, to avoid sign extension.
  return static_cast<Address>(reinterpret_cast<uintptr_t>(addr));
}

class MockSymbolProvider : public SymbolProvider {
 public:
  MOCK_METHOD2(FindOrCreateTypeRepository,
               bool(const pe::PEFile::Signature& signature,
                    scoped_refptr<TypeRepository>* type_repo));
};

// Add the bytes backing a pointer to the bytes layer.
void AddPointerBytesRecord(ProcessState* process_state, int32_t** addr) {
  BytesLayerPtr bytes_layer;
  process_state->FindOrCreateLayer(&bytes_layer);

  BytesRecordPtr bytes_record;
  bytes_layer->CreateRecord(AddressRange(ToAddress(addr), sizeof(*addr)),
                            &bytes_record);

  Bytes* bytes_proto = bytes_record->mutable_data();
  std::string* buffer = bytes_proto->mutable_data();
  memcpy(base::WriteInto(buffer, sizeof(*addr) + 1), addr, sizeof(*addr));
}

void ValidateTypedBlockLayerEntry(Address expected_addr,
                                  Size expected_size,
                                  ModuleId expected_module_id,
                                  TypeId expected_type_id,
                                  const std::string& expected_name,
                                  ProcessState* process_state) {
  TypedBlockRecordPtr typed_record;
  ASSERT_TRUE(process_state->FindSingleRecord(expected_addr, &typed_record));

  ASSERT_EQ(expected_addr, typed_record->range().start());
  ASSERT_EQ(expected_size, typed_record->range().size());

  const TypedBlock& typedblock = typed_record->data();
  ASSERT_EQ(expected_module_id, typedblock.module_id());
  ASSERT_EQ(expected_type_id, typedblock.type_id());
  ASSERT_EQ(expected_name, typedblock.data_name());
}

struct SimpleUDT {
  int32_t* pointer;
};

}  // namespace

class TypePropagatorAnalyzerTest : public testing::Test {
 public:
  TypePropagatorAnalyzerTest()
      : variable_(42),
        variable_ptr_(&variable_),
        expected_variable_address_(ToAddress(&variable_)),
        variable_ptr_range_(ToAddress(&variable_ptr_), sizeof(variable_ptr_)),
        expected_sig_(kPath,
                      core::AbsoluteAddress(0U),
                      kSize,
                      kChecksum,
                      kTimestamp),
        repo_(new TypeRepository(expected_sig_)) {
    // Create a basic type and a pointer type to it.
    basic_type_ = new BasicType(L"int32_t", sizeof(int32_t));
    repo_->AddType(basic_type_);

    ptr_type_ = new PointerType(sizeof(int32_t*), PointerType::PTR_MODE_PTR);
    repo_->AddType(ptr_type_);
    ptr_type_->Finalize(kNoTypeFlags, basic_type_->type_id());

    // Populate the bytes layer with the contents of variable_ptr_. This is
    // needed to be able to dereference it.
    AddPointerBytesRecord(&process_state_, &variable_ptr_);

    // Populate the module layer with a module and get its id.
    ModuleLayerAccessor accessor(&process_state_);
    accessor.AddModuleRecord(AddressRange(kAddress, kSize), kChecksum,
                             kTimestamp, kPath);
    module_id_ = accessor.GetModuleId(kAddress);
    CHECK_NE(kNoModuleId, module_id_);
  }

  bool Analyze() {
    scoped_refptr<MockSymbolProvider> mock_provider(new MockSymbolProvider());
    EXPECT_CALL(*mock_provider, FindOrCreateTypeRepository(expected_sig_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(repo_), Return(true)));

    SimpleProcessAnalysis analysis(&process_state_);
    analysis.set_symbol_provider(mock_provider);

    TypePropagatorAnalyzer analyzer;
    minidump::FileMinidump dummy_minidump;
    return analyzer.Analyze(dummy_minidump, analysis) ==
           Analyzer::ANALYSIS_COMPLETE;
  }

  void Validate() {
    ValidateTypedBlockLayerEntry(expected_variable_address_,
                                 basic_type_->size(), module_id_,
                                 basic_type_->type_id(), "", &process_state_);
  }

 protected:
  // Data for the test.
  int32_t variable_;
  int32_t* variable_ptr_;

  Address expected_variable_address_;
  AddressRange variable_ptr_range_;

  TypePtr basic_type_;
  PointerTypePtr ptr_type_;

  pe::PEFile::Signature expected_sig_;
  scoped_refptr<TypeRepository> repo_;

  ModuleId module_id_;
  ProcessState process_state_;
};

TEST_F(TypePropagatorAnalyzerTest, AnalyzeMinidumpPointer) {
  // Populate the typed block layer with knowledge of variable_ptr_.
  ASSERT_TRUE(AddTypedBlockRecord(variable_ptr_range_, L"variable_ptr_",
                                  module_id_, ptr_type_->type_id(),
                                  &process_state_));
  TypedBlockLayerPtr typedblock_layer;
  ASSERT_TRUE(process_state_.FindLayer(&typedblock_layer));
  ASSERT_EQ(1, typedblock_layer->size());

  // Run the analyzer and validate the pointed to block was picked up.
  ASSERT_TRUE(Analyze());
  ASSERT_EQ(2, typedblock_layer->size());
  ASSERT_NO_FATAL_FAILURE(Validate());
}

TEST_F(TypePropagatorAnalyzerTest, AnalyzeMinidumpArray) {
  // Create an array type.
  ArrayTypePtr array_type = new ArrayType(3 * ptr_type_->size());
  repo_->AddType(array_type);
  array_type->Finalize(kNoTypeFlags, basic_type_->type_id(), 3,
                       ptr_type_->type_id());

  // The array.
  int32_t* array[3];
  array[1] = &variable_;

  // Make only array[1] known to the bytes layer.
  AddPointerBytesRecord(&process_state_, &array[1]);

  // Populate the typed block layer with knowledge of the array.
  AddressRange array_range(ToAddress(array), sizeof(array));
  ASSERT_TRUE(AddTypedBlockRecord(array_range, L"array",
                                  module_id_, array_type->type_id(),
                                  &process_state_));
  TypedBlockLayerPtr typedblock_layer;
  ASSERT_TRUE(process_state_.FindLayer(&typedblock_layer));
  ASSERT_EQ(1, typedblock_layer->size());

  // Run the analyzer and validate the pointed to block was picked up.
  ASSERT_TRUE(Analyze());
  ASSERT_EQ(2, typedblock_layer->size());
  ASSERT_NO_FATAL_FAILURE(Validate());
}

TEST_F(TypePropagatorAnalyzerTest, AnalyzeMinidumpUDT) {
  // Create a udt.
  UserDefinedTypePtr udt_type = new UserDefinedType(
      L"udt", ptr_type_->size(), UserDefinedType::UDT_STRUCT);
  repo_->AddType(udt_type);
  UserDefinedType::Fields fields;
  fields.push_back(new UserDefinedType::MemberField(
      L"pointer", 0, kNoTypeFlags, 0, 0, ptr_type_->type_id(), repo_.get()));
  UserDefinedType::Functions functions;
  udt_type->Finalize(&fields, &functions);

  // The UDT.
  SimpleUDT udt;
  udt.pointer = &variable_;

  // Populate the bytes layer.
  AddPointerBytesRecord(&process_state_, &udt.pointer);

  // Populate the typed block layer with knowledge of the udt.
  AddressRange udt_range(ToAddress(&udt), sizeof(udt));
  ASSERT_TRUE(AddTypedBlockRecord(udt_range, L"udt", module_id_,
                                  udt_type->type_id(), &process_state_));
  TypedBlockLayerPtr typedblock_layer;
  ASSERT_TRUE(process_state_.FindLayer(&typedblock_layer));
  ASSERT_EQ(1, typedblock_layer->size());

  // Run the analyzer and validate the pointed to block was picked up.
  ASSERT_TRUE(Analyze());
  ASSERT_EQ(2, typedblock_layer->size());
  ASSERT_NO_FATAL_FAILURE(Validate());
}

}  // namespace refinery
