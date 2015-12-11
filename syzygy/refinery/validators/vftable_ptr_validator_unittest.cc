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

#include <dia2.h>

#include "base/containers/hash_tables.h"
#include "base/win/scoped_comptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

namespace {

const Address kAddress = 1000ULL;  // Fits 32-bit.
const Address kAddressOther = 2000ULL;  // Fits 32-bit.
const Size kSize = 42U;
const Size kSizeOther = 43U;
const uint32 kChecksum = 11U;
const uint32 kChecksumOther = 12U;
const uint32 kTimestamp = 22U;
const wchar_t kPath[] = L"c:\\path\\ModuleName";
const wchar_t kPathOther[] = L"c:\\path\\ModuleNameOther";

class MockDiaSymbolProvider : public DiaSymbolProvider {
 public:
  MOCK_METHOD2(FindOrCreateDiaSession,
               bool(const pe::PEFile::Signature& signature,
                    base::win::ScopedComPtr<IDiaSession>* session));
  MOCK_METHOD2(GetVFTableRVAs,
               bool(const pe::PEFile::Signature& signature,
                    base::hash_set<Address>* vftable_rvas));
};

class TestVftablePtrValidator : public VftablePtrValidator {
 public:
  using VftablePtrValidator::GetVFTableVAs;
};

}  // namespace

TEST(VftablePtrValidatorTest, BasicTest) {
  // TODO(manzagop): implement.
}

TEST(VftablePtrValidatorTest, GetVFTableVAs) {
  using testing::_;
  using testing::DoAll;
  using testing::Return;
  using testing::SetArgPointee;

  // Create a process state with 2 modules.
  ProcessState state;
  ModuleLayerAccessor accessor(&state);
  accessor.AddModuleRecord(AddressRange(kAddress, kSize), kChecksum, kTimestamp,
                           kPath);
  accessor.AddModuleRecord(AddressRange(kAddressOther, kSizeOther),
                           kChecksumOther, kTimestamp, kPathOther);

  // Set up the symbol provider.
  scoped_refptr<MockDiaSymbolProvider> provider = new MockDiaSymbolProvider();

  pe::PEFile::Signature signature;
  ASSERT_TRUE(accessor.GetModuleSignature(kAddress, &signature));
  signature.base_address = core::AbsoluteAddress(0U);
  base::hash_set<Address> rvas;
  rvas.insert(1ULL);
  rvas.insert(2ULL);
  EXPECT_CALL(*provider, GetVFTableRVAs(signature, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rvas), Return(true)));

  pe::PEFile::Signature signature_other;
  ASSERT_TRUE(accessor.GetModuleSignature(kAddressOther, &signature_other));
  signature_other.base_address = core::AbsoluteAddress(0U);
  base::hash_set<Address> rvas_other;
  rvas_other.insert(3ULL);
  rvas_other.insert(4ULL);
  EXPECT_CALL(*provider, GetVFTableRVAs(signature_other, testing::_))
      .WillOnce(DoAll(SetArgPointee<1>(rvas_other), Return(true)));

  // Retrieve VAs and validate.
  base::hash_set<Address> vftable_vas;
  ASSERT_TRUE(
      TestVftablePtrValidator::GetVFTableVAs(&state, provider, &vftable_vas));

  base::hash_set<Address> expected_vftable_vas;
  expected_vftable_vas.insert(kAddress + 1ULL);
  expected_vftable_vas.insert(kAddress + 2ULL);
  expected_vftable_vas.insert(kAddressOther + 3ULL);
  expected_vftable_vas.insert(kAddressOther + 4ULL);

  ASSERT_EQ(expected_vftable_vas, vftable_vas);
}

}  // namespace refinery
