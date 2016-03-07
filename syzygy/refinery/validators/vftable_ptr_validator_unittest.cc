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

#include "syzygy/refinery/validators/vftable_ptr_validator.h"

#include <string>

#include "base/containers/hash_tables.h"
#include "base/strings/string_util.h"
#include "base/win/scoped_comptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

namespace {

const Address kAddress = 1000ULL;       // Fits 32-bit.
const Address kAddressOther = 2000ULL;  // Fits 32-bit.
const Address kUdtAddress = 9000ULL;    // Fits 32-bit.
const Size kSize = 42U;
const Size kSizeOther = 43U;
const uint32_t kChecksum = 11U;
const uint32_t kChecksumOther = 12U;
const uint32_t kTimestamp = 22U;
const wchar_t kPath[] = L"c:\\path\\ModuleName";
const wchar_t kPathOther[] = L"c:\\path\\ModuleNameOther";

class MockSymbolProvider : public SymbolProvider {
 public:
  MOCK_METHOD2(FindOrCreateTypeRepository,
               bool(const pe::PEFile::Signature& signature,
                    scoped_refptr<TypeRepository>* type_repo));
  MOCK_METHOD2(GetVFTableRVAs,
               bool(const pe::PEFile::Signature& signature,
                    base::hash_set<RelativeAddress>* vftable_rvas));
};

class TestVftablePtrValidator : public VftablePtrValidator {
 public:
  using VftablePtrValidator::GetVFTableVAs;
};

void AddBytesRecord(ProcessState* state, Address address, uintptr_t value) {
  DCHECK(state);

  BytesLayerPtr bytes_layer;
  state->FindOrCreateLayer(&bytes_layer);
  BytesRecordPtr bytes_record;
  bytes_layer->CreateRecord(AddressRange(address, sizeof(value)),
                            &bytes_record);
  Bytes* bytes_proto = bytes_record->mutable_data();
  std::string* buffer = bytes_proto->mutable_data();
  memcpy(base::WriteInto(buffer, sizeof(value) + 1), &value, sizeof(value));
}

}  // namespace

// Sets up a process state with a single typed block. The bytes layer is empty
// and up to the specific tests.
class VftablePtrValidatorSyntheticTest : public testing::Test {
 protected:
  void SetUp() override {
    testing::Test::SetUp();

    // Add a module to the process state.
    ModuleLayerAccessor accessor(&state_);
    accessor.AddModuleRecord(AddressRange(kAddress, kSize), kChecksum,
                             kTimestamp, kPath);
    ModuleId module_id = accessor.GetModuleId(kAddress);
    pe::PEFile::Signature module_signature;
    ASSERT_TRUE(accessor.GetModuleSignature(module_id, &module_signature));

    // Create a type repository for the module, then a UDT.
    repository_ = new TypeRepository(module_signature);
    UserDefinedTypePtr udt = AddSimpleUDTWithVfptr(repository_.get());

    // Add a typed block.
    udt_range_ = AddressRange(kUdtAddress, udt->size());
    AddTypedBlockRecord(udt_range_, L"udt", module_id, udt->type_id(), &state_);

    // Build the allowed set of vfptr rvas and set the expected vfptr value.
    const Address kVfptrRva = 10U;
    ASSERT_LT(kVfptrRva, kSize);
    base::hash_set<RelativeAddress> rvas;
    rvas.insert(kVfptrRva);
    expected_vfptr_ = kAddress + kVfptrRva;

    // Ensure the bytes layer exists.
    BytesLayerPtr bytes_layer;
    state_.FindOrCreateLayer(&bytes_layer);

    // Create the symbol provider and set expectations.
    mock_provider_ = new MockSymbolProvider();
    EXPECT_CALL(*mock_provider_, GetVFTableRVAs(module_signature, testing::_))
        .WillOnce(DoAll(SetArgPointee<1>(rvas), Return(true)));
    EXPECT_CALL(*mock_provider_,
                FindOrCreateTypeRepository(module_signature, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(repository_), Return(true)));
  }

  UserDefinedTypePtr AddSimpleUDTWithVfptr(TypeRepository* repo) {
    DCHECK(repo);

    // Create a vfptr type: a pointer to a vtshape type.
    // TODO(manzagop): update this to a vtshape type once it exists.
    TypePtr vtshape_type = new WildcardType(L"vtshape", 4U);
    repo->AddType(vtshape_type);

    PointerTypePtr vfptr_type =
        new PointerType(sizeof(uintptr_t), PointerType::PTR_MODE_PTR);
    vfptr_type->Finalize(kNoTypeFlags, vtshape_type->type_id());
    repo->AddType(vfptr_type);

    // Create a UDT. It (artificially) only has a vftptr.
    UserDefinedTypePtr other_udt =
        new UserDefinedType(L"other", L"decorated_other", vfptr_type->size(),
                            UserDefinedType::UDT_CLASS);
    repo->AddType(other_udt);
    {
      UserDefinedType::Fields fields;
      fields.push_back(
          new UserDefinedType::VfptrField(0, vfptr_type->type_id(), repo));
      UserDefinedType::Functions functions;
      other_udt->Finalize(&fields, &functions);
    }

    // Create another UDT. This also is an artificial type: it has the other UDT
    // as both base class and member, as well as a vfptr (yet not virtual
    // function).
    UserDefinedTypePtr udt;
    {
      UserDefinedType::Fields fields;
      UserDefinedType::Functions functions;
      ptrdiff_t size = 0;

      base_field_ =
          new UserDefinedType::BaseClassField(size, other_udt->type_id(), repo);
      fields.push_back(base_field_);
      size += other_udt->size();

      member_field_ = new UserDefinedType::MemberField(
          L"member", size, kNoTypeFlags, 0, 0, other_udt->type_id(), repo);
      fields.push_back(member_field_);
      size += other_udt->size();

      vfptr_field_ =
          new UserDefinedType::VfptrField(size, vfptr_type->type_id(), repo);
      fields.push_back(vfptr_field_);
      size += vfptr_type->size();

      udt = new UserDefinedType(L"foo", L"decorated_foo", size,
                                UserDefinedType::UDT_CLASS);
      repo->AddType(udt);
      udt->Finalize(&fields, &functions);
    }

    return udt;
  }

  void Validate(bool expect_error) {
    VftablePtrValidator validator(mock_provider_);
    ValidationReport report;
    ASSERT_EQ(Validator::VALIDATION_COMPLETE,
              validator.Validate(&state_, &report));

    if (expect_error) {
      ASSERT_EQ(1, report.error_size());
      ASSERT_EQ(VIOLATION_VFPTR, report.error(0).type());
    } else {
      ASSERT_EQ(0, report.error_size());
    }
  }

  ProcessState state_;
  scoped_refptr<TypeRepository> repository_;
  scoped_refptr<MockSymbolProvider> mock_provider_;

  BaseClassFieldPtr base_field_;
  MemberFieldPtr member_field_;
  VfptrFieldPtr vfptr_field_;

  AddressRange udt_range_;
  Address expected_vfptr_;
};

TEST_F(VftablePtrValidatorSyntheticTest, NoBytesCase) {
  // No bytes to validate against. Expect no error.
  ASSERT_NO_FATAL_FAILURE(Validate(false));
}

TEST_F(VftablePtrValidatorSyntheticTest, ValidBytesCase) {
  // Valid bytes. Expect no error.
  AddBytesRecord(&state_, kUdtAddress + vfptr_field_->offset(),
                 expected_vfptr_);
  ASSERT_NO_FATAL_FAILURE(Validate(false));
}

TEST_F(VftablePtrValidatorSyntheticTest, InvalidBytesCase) {
  // Invalid bytes. Expect an error.
  AddBytesRecord(&state_, kUdtAddress + vfptr_field_->offset(),
                 expected_vfptr_ + 1);
  ASSERT_NO_FATAL_FAILURE(Validate(true));
}

TEST_F(VftablePtrValidatorSyntheticTest, BaseClassValidBytesCase) {
  // Valid bytes. Expect no error.
  AddBytesRecord(&state_, kUdtAddress + base_field_->offset(),
                 expected_vfptr_);
  ASSERT_NO_FATAL_FAILURE(Validate(false));
}

TEST_F(VftablePtrValidatorSyntheticTest, BaseClassInvalidBytesCase) {
  // Invalid bytes. Expect an error.
  AddBytesRecord(&state_, kUdtAddress + base_field_->offset(),
                 expected_vfptr_ + 1);
  ASSERT_NO_FATAL_FAILURE(Validate(true));
}

TEST_F(VftablePtrValidatorSyntheticTest, MemberValidBytesCase) {
  // Valid bytes. Expect no error.
  AddBytesRecord(&state_, kUdtAddress + member_field_->offset(),
                 expected_vfptr_);
  ASSERT_NO_FATAL_FAILURE(Validate(false));
}

TEST_F(VftablePtrValidatorSyntheticTest, MemberInvalidBytesCase) {
  // Invalid bytes. Expect an error.
  AddBytesRecord(&state_, kUdtAddress + member_field_->offset(),
                 expected_vfptr_ + 1);
  ASSERT_NO_FATAL_FAILURE(Validate(true));
}

TEST(VftablePtrValidatorTest, GetVFTableVAs) {
  // Create a process state with 2 modules.
  ProcessState state;
  ModuleLayerAccessor accessor(&state);
  accessor.AddModuleRecord(AddressRange(kAddress, kSize), kChecksum, kTimestamp,
                           kPath);
  accessor.AddModuleRecord(AddressRange(kAddressOther, kSizeOther),
                           kChecksumOther, kTimestamp, kPathOther);

  // Set up the symbol provider.
  scoped_refptr<MockSymbolProvider> provider = new MockSymbolProvider();

  pe::PEFile::Signature signature;
  ASSERT_TRUE(accessor.GetModuleSignature(kAddress, &signature));
  signature.base_address = core::AbsoluteAddress(0U);
  base::hash_set<RelativeAddress> rvas;
  rvas.insert(1ULL);
  rvas.insert(2ULL);
  EXPECT_CALL(*provider, GetVFTableRVAs(signature, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rvas), Return(true)));

  pe::PEFile::Signature signature_other;
  ASSERT_TRUE(accessor.GetModuleSignature(kAddressOther, &signature_other));
  signature_other.base_address = core::AbsoluteAddress(0U);
  base::hash_set<RelativeAddress> rvas_other;
  rvas_other.insert(3ULL);
  rvas_other.insert(4ULL);
  EXPECT_CALL(*provider, GetVFTableRVAs(signature_other, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rvas_other), Return(true)));

  // Retrieve VAs and validate.
  base::hash_set<RelativeAddress> vftable_vas;
  ASSERT_TRUE(TestVftablePtrValidator::GetVFTableVAs(&state, provider.get(),
                                                     &vftable_vas));

  base::hash_set<RelativeAddress> expected_vftable_vas;
  expected_vftable_vas.insert(kAddress + 1ULL);
  expected_vftable_vas.insert(kAddress + 2ULL);
  expected_vftable_vas.insert(kAddressOther + 3ULL);
  expected_vftable_vas.insert(kAddressOther + 4ULL);

  ASSERT_EQ(expected_vftable_vas, vftable_vas);
}

}  // namespace refinery
