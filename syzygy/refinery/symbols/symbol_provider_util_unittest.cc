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

#include "syzygy/refinery/symbols/symbol_provider_util.h"

#include <string>

#include "gtest/gtest.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

namespace {

const Address kAddress = 0x0000CAFE;  // Fits 32-bit.
const Size kSize = 42U;
const uint32 kChecksum = 11U;
const uint32 kTimestamp = 22U;
const char kPath[] = "c:\\path\\ModuleName";
const wchar_t kPathWide[] = L"c:\\path\\ModuleName";

}  // namespace

TEST(GetModuleSignatureTest, BasicTest) {
  ProcessState state;
  pe::PEFile::Signature signature;

  // Fails when VA doesn't correspond to a module.
  ASSERT_FALSE(GetModuleSignature(kAddress, &state, &signature));

  // Add a module.
  AddModuleRecord(AddressRange(kAddress, kSize), kChecksum, kTimestamp, kPath,
                  &state);

  // Fails outside the module's range.
  ASSERT_FALSE(GetModuleSignature(kAddress - 1, &state, &signature));
  ASSERT_FALSE(GetModuleSignature(kAddress + kSize, &state, &signature));

  // Succeeds within the module's range.
  ASSERT_TRUE(GetModuleSignature(kAddress, &state, &signature));
  ASSERT_TRUE(GetModuleSignature(kAddress + kSize - 1, &state, &signature));

  // Validate signature on the last hit.
  ASSERT_EQ(kAddress, signature.base_address.value());
  ASSERT_EQ(kSize, signature.module_size);
  ASSERT_EQ(kChecksum, signature.module_checksum);
  ASSERT_EQ(kTimestamp, signature.module_time_date_stamp);
  ASSERT_EQ(kPathWide, signature.path);
}

}  // namespace refinery
