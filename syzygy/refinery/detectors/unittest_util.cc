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

#include "syzygy/refinery/detectors/unittest_util.h"

#include "base/environment.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/types/dia_crawler.h"

namespace testing {

namespace {

// TODO(siggi): Remove dupes of this function.
bool GetNtdllTypes(refinery::TypeRepository* repo) {
  // As of 28/10/2015 the symbol file for ntdll.dll on Win7 is missing the
  // crucial symbols for heap enumeration. This code deserves to either die
  // in a fire, or else be updated to find symbols that are close to the
  // system in version and bitness.
  pe::PEFile::Signature ntdll_sig(L"ntdll.dll", core::AbsoluteAddress(0),
                                  0x141000, 0, 0x560D708C);

  std::unique_ptr<base::Environment> env(base::Environment::Create());
  std::string search_path;
  if (!env->GetVar("_NT_SYMBOL_PATH", &search_path)) {
    // TODO(siggi): Set a default when it's missing.
    LOG(ERROR) << "Missing symbol path.";
    return false;
  }

  base::FilePath ntdll_path;
  if (!pe::FindModuleBySignature(ntdll_sig, base::UTF8ToUTF16(search_path),
                                 &ntdll_path)) {
    LOG(ERROR) << "Failed to locate NTDLL.";
    return false;
  }

  refinery::DiaCrawler crawler;
  if (!crawler.InitializeForFile(base::FilePath(ntdll_path)) ||
      !crawler.GetTypes(repo)) {
    LOG(ERROR) << "Failed to get ntdll types.";
    return false;
  }

  return true;
}

}  // namespace

LFHDetectorTest::LFHDetectorTest() {
}

void LFHDetectorTest::SetUp() {
  ASSERT_TRUE(scoped_symbol_path_.Setup());

  repo_ = new refinery::TypeRepository;
  ASSERT_TRUE(scoped_heap_.Create());
  ASSERT_TRUE(testing::GetNtdllTypes(repo_.get()));
}

void LFHDetectorTest::TearDown() {
}

refinery::Address LFHDetectorTest::AllocateLFHBucket(size_t block_size) {
  for (size_t i = 0; i < 10000; ++i) {
    void* ptr = scoped_heap_.Allocate(block_size);

    if (scoped_heap_.IsLFHBlock(ptr))
      return reinterpret_cast<refinery::Address>(ptr);
  }

  return 0;
}

}  // namespace testing
