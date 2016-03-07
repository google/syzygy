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

#include "syzygy/refinery/symbols/symbol_provider.h"

#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/strings/utf_string_conversions.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

const Address kAddress = 0x0000CAFE;  // Fits 32-bit.
const Size kSize = 42U;
const uint32_t kChecksum = 11U;
const uint32_t kTimestamp = 22U;

}  // namespace

TEST(SymbolProviderTest, FindOrCreateTypeRepository) {
  ProcessState process_state;
  scoped_refptr<SymbolProvider> provider = new SymbolProvider();

  // Get the signature for test_types.dll.
  const base::FilePath module_path(testing::GetSrcRelativePath(
      L"syzygy\\refinery\\test_data\\test_types.dll"));
  pe::PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(module_path));
  pe::PEFile::Signature module_signature;
  pe_file.GetSignature(&module_signature);

  // Successfully retrieve the repository.
  scoped_refptr<TypeRepository> repository;
  ASSERT_TRUE(
      provider->FindOrCreateTypeRepository(module_signature, &repository));
  ASSERT_TRUE(repository != nullptr);
  ASSERT_GT(repository->size(), 0);

  // Ensure a second call retrieves the same object.
  scoped_refptr<TypeRepository> second_repository;
  ASSERT_TRUE(provider->FindOrCreateTypeRepository(module_signature,
                                                   &second_repository));
  ASSERT_EQ(repository.get(), second_repository.get());
}

TEST(SymbolProviderTest, FindOrCreateTypeNameIndex) {
  ProcessState process_state;
  scoped_refptr<SymbolProvider> provider = new SymbolProvider();

  // Get the signature for test_types.dll.
  const base::FilePath module_path(testing::GetSrcRelativePath(
      L"syzygy\\refinery\\test_data\\test_types.dll"));
  pe::PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(module_path));
  pe::PEFile::Signature module_signature;
  pe_file.GetSignature(&module_signature);

  // Successfully retrieve the type name index.
  scoped_refptr<TypeNameIndex> index;
  ASSERT_TRUE(provider->FindOrCreateTypeNameIndex(module_signature, &index));
  ASSERT_TRUE(index != nullptr);
  std::vector<TypePtr> matching_types;
  index->GetTypes(L"testing::TestSimpleUDT", &matching_types);
  ASSERT_EQ(1, matching_types.size());
}

}  // namespace refinery
