// Copyright 2013 Google Inc. All Rights Reserved.
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
// Functions below are used to test basic block counting in the end to end
// unittest. We assume the compiler won't simplify any calls.
#ifndef SYZYGY_INTEGRATION_TESTS_BB_ENTRY_TESTS_H_
#define SYZYGY_INTEGRATION_TESTS_BB_ENTRY_TESTS_H_

// Those function need to be declared as "extern "C"" because we want to be able
// to find them by name in the integration tests.

extern "C" unsigned int BBEntryCallOnce();

extern "C" unsigned int BBEntryFunction1();

extern "C" unsigned int BBEntryFunction2();

extern "C" unsigned int BBEntryFunction3();

extern "C" unsigned int BBEntryCallTree();

extern "C" unsigned int BBEntryFunctionRecursive(int n);

extern "C" unsigned int BBEntryCallRecursive();

#endif  // SYZYGY_INTEGRATION_TESTS_BB_ENTRY_TESTS_H_
