// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/direct_allocation.h"

#include "windows.h"

#include "base/basictypes.h"
#include "base/debug/alias.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {

namespace {

// Frequently used constants.
const DirectAllocation::Justification kAutoJustification =
    DirectAllocation::kAutoJustification;
const DirectAllocation::Justification kLeftJustification =
    DirectAllocation::kLeftJustification;
const DirectAllocation::Justification kRightJustification =
    DirectAllocation::kRightJustification;

class TestDirectAllocation : public DirectAllocation {
 public:
  using DirectAllocation::FinalizeParameters;
  using DirectAllocation::ToNoPages;
  using DirectAllocation::ToReservedPages;
  using DirectAllocation::ToAllocatedPages;
  using DirectAllocation::ProtectNoPages;
  using DirectAllocation::ProtectGuardPages;
  using DirectAllocation::ProtectAllPages;
};

struct Configuration {
  size_t size;
  size_t alignment;
  bool left_guard;
  bool right_guard;
  size_t left_redzone;
  size_t right_redzone;
  TestDirectAllocation::Justification justification;
};

// Helper function for setting all DirectAllocation parameters at once.
void Configure(const Configuration& configuration, TestDirectAllocation* da) {
  ASSERT_TRUE(da != NULL);
  da->set_size(configuration.size);
  da->set_alignment(configuration.alignment);
  da->set_left_guard_page(configuration.left_guard);
  da->set_right_guard_page(configuration.right_guard);
  da->set_left_redzone_size(configuration.left_redzone);
  da->set_right_redzone_size(configuration.right_redzone);
  da->set_justification(configuration.justification);
}

// Validates that the given configuration matches the direct allocation.
// Intended to be wrapped in EXPECT_/ASSERT_NO_FATAL_FAILURE.
void CheckConfiguration(const Configuration& configuration,
                        const TestDirectAllocation& da) {
  EXPECT_EQ(configuration.size, da.size());
  EXPECT_EQ(configuration.alignment, da.alignment());
  EXPECT_EQ(configuration.left_guard, da.left_guard_page());
  EXPECT_EQ(configuration.right_guard, da.right_guard_page());
  EXPECT_EQ(configuration.left_redzone, da.left_redzone_size());
  EXPECT_EQ(configuration.right_redzone, da.right_redzone_size());
  EXPECT_EQ(configuration.justification, da.justification());
}

}  // namespace

TEST(DirectAllocationTest, ConstructionSettersAndGetters) {
  TestDirectAllocation da;

  // Check default values after construction.
  EXPECT_EQ(0u, da.size());
  EXPECT_EQ(DirectAllocation::kDefaultAlignment, da.alignment());
  EXPECT_FALSE(da.left_guard_page());
  EXPECT_FALSE(da.right_guard_page());
  EXPECT_EQ(0u, da.left_redzone_size());
  EXPECT_EQ(0u, da.right_redzone_size());
  EXPECT_EQ(kAutoJustification, da.justification());
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da.protection_state());;
  EXPECT_EQ(NULL, da.pages());

  // Modify the allocation parameters.
  da.set_size(100);
  da.set_alignment(16u);
  da.set_left_guard_page(true);
  da.set_right_guard_page(true);
  da.set_left_redzone_size(100);
  da.set_right_redzone_size(100);
  da.set_justification(DirectAllocation::kRightJustification);

  // Check values after they've been modified.
  EXPECT_EQ(100u, da.size());
  EXPECT_EQ(16u, da.alignment());
  EXPECT_TRUE(da.left_guard_page());
  EXPECT_TRUE(da.right_guard_page());
  EXPECT_EQ(100u, da.left_redzone_size());
  EXPECT_EQ(100u, da.right_redzone_size());
  EXPECT_EQ(DirectAllocation::kRightJustification, da.justification());
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da.protection_state());;
  EXPECT_EQ(NULL, da.pages());
}

TEST(DirectAllocationTest, FinalizeParameters) {
  // Pairs of inputs and expected outputs.
  static const std::pair<Configuration, Configuration> kConfigurations[] = {
    // The left and right redzone sizes should grow to reflect the page size,
    // and the allocation should be right-justified.
    { { 100, 8, true, true, 100, 100, kAutoJustification },
      { 100, 8, true, true, 8088, 4100, kRightJustification } },
    // The left and right redzone sizes should grow to reflect the alignment,
    // the guard pages should remain deactivated, and the allocation should be
    // right-justified.
    { { 100, 8, false, false, 100, 100, kAutoJustification },
      { 100, 8, false, false, 3888, 108, kRightJustification } },
    // The left and right redzone sizes should grow to reflect the alignment,
    // the right guard page should be automatically activated, and the
    // allocation should be right-justified.
    { { 100, 8, false, false, 100, 5000, kAutoJustification },
       { 100, 8, false, true, 3088, 5004, kRightJustification } },

    // The left and right redzone sizes should grow to reflect the page size.
    { { 100, 8, true, true, 100, 100, kLeftJustification },
      { 100, 8, true, true, 4096, 8092, kLeftJustification } },
    // The left and right redzone sizes should grow to reflect the alignment,
    // the guard pages should remain deactivated.
    { { 100, 8, false, false, 100, 100, kLeftJustification },
      { 100, 8, false, false, 104, 3892, kLeftJustification } },
    // The left and right redzone sizes should grow to reflect the alignment,
    // the right guard page should be automatically activated.
    { { 100, 8, false, false, 100, 5000, kLeftJustification },
      { 100, 8, false, true, 104, 7988, kLeftJustification } },

    // Everything should stay the same, but the guard pages should be auto
    // activated.
    { { 4096, 16, false, false, 4096, 4096, kLeftJustification },
      { 4096, 16, true, true, 4096, 4096, kLeftJustification } },
    // The justification should default to right justification.
    { { 4096, 16, true, true, 4096, 4096, kAutoJustification },
      { 4096, 16, true, true, 4096, 4096, kRightJustification } },
    // Everything should stay exactly the same.
    { { 4096, 16, true, true, 4096, 4096, kLeftJustification },
      { 4096, 16, true, true, 4096, 4096, kLeftJustification } },
    { { 4096, 16, true, true, 4096, 4096, kRightJustification },
      { 4096, 16, true, true, 4096, 4096, kRightJustification } },
  };

  // Loop through the set of configurations, finalize parameters, and ensure
  // that the calculated layout matches what is expected.
  for (size_t i = 0; i < arraysize(kConfigurations); ++i) {
    const Configuration& input = kConfigurations[i].first;
    const Configuration& output = kConfigurations[i].second;
    TestDirectAllocation da;
    Configure(input, &da);
    da.FinalizeParameters();
    EXPECT_NO_FATAL_FAILURE(CheckConfiguration(output, da));
  }
}

namespace {

// An exception filter that grabs and sets an exception pointer, and
// triggers only for access violations.
DWORD AccessViolationFilter(EXCEPTION_POINTERS* e,
                            EXCEPTION_POINTERS** pe) {
  *pe = e;
  if (e->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    return EXCEPTION_EXECUTE_HANDLER;
  return EXCEPTION_CONTINUE_SEARCH;
}

// Tries to access the given address, validating whether or not an
// access violation occurs.
bool TestAccess(void* address, bool expect_access_violation) {
  uint8* m = reinterpret_cast<uint8*>(address);
  ULONG_PTR p = reinterpret_cast<ULONG_PTR>(address);

  // Try a read.
  uint8 value = 0;
  EXCEPTION_POINTERS* e = NULL;
  __try {
    value = m[0];
    if (expect_access_violation)
      return false;
  } __except (AccessViolationFilter(GetExceptionInformation(), &e)) {
    if (!expect_access_violation)
      return false;
    if (e->ExceptionRecord == NULL ||
        e->ExceptionRecord->NumberParameters < 2 ||
        e->ExceptionRecord->ExceptionInformation[1] != p) {
      return false;
    }
    return true;
  }

  // Try a write.
  __try {
    m[0] = 0;
    if (expect_access_violation)
      return false;
  } __except (AccessViolationFilter(GetExceptionInformation(), &e)) {
    if (!expect_access_violation)
      return false;
    if (e->ExceptionRecord == NULL ||
        e->ExceptionRecord->NumberParameters < 2 ||
        e->ExceptionRecord->ExceptionInformation[1] != p) {
      return false;
    }
  }

  // Ensure that |value| doesn't get optimized away. If so, the attempted
  // read never occurs.
  base::debug::Alias(&value);

  return true;
}

// Readable wrappers to TestAccess.
bool IsAccessible(void* address) {
  return TestAccess(address, false);
}
bool IsNotAccessible(void* address) {
  return TestAccess(address, true);
}

// Transitions to the reserved state, and tests all protection state changes.
void TestToReserved(TestDirectAllocation* da) {
  ASSERT_TRUE(da != NULL);

  // Reserve the pages, and try all protection settings.
  EXPECT_TRUE(da->ToReservedPages());
  EXPECT_EQ(DirectAllocation::kReservedPages, da->memory_state());
  EXPECT_EQ(DirectAllocation::kAllPagesProtected, da->protection_state());
  EXPECT_TRUE(IsNotAccessible(da->GetAllocation()));
  if (da->left_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetLeftGuardPage()));
  if (da->right_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetRightGuardPage()));
  EXPECT_FALSE(da->ProtectNoPages());
  EXPECT_EQ(DirectAllocation::kAllPagesProtected, da->protection_state());
  EXPECT_FALSE(da->ProtectGuardPages());
  EXPECT_EQ(DirectAllocation::kAllPagesProtected, da->protection_state());
}

// Transitions to the allocated state, and tests all protection state changes.
void TestToAllocated(TestDirectAllocation* da) {
  ASSERT_TRUE(da != NULL);

  // Reserve the pages, and try all protection settings.
  EXPECT_TRUE(da->ToAllocatedPages());
  EXPECT_EQ(DirectAllocation::kAllocatedPages, da->memory_state());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
  EXPECT_TRUE(IsAccessible(da->GetAllocation()));
  if (da->left_guard_page())
    EXPECT_TRUE(IsAccessible(da->GetLeftGuardPage()));
  if (da->right_guard_page())
    EXPECT_TRUE(IsAccessible(da->GetRightGuardPage()));

  EXPECT_TRUE(da->ProtectGuardPages());
  if (da->left_guard_page() || da->right_guard_page()) {
    EXPECT_EQ(DirectAllocation::kGuardPagesProtected, da->protection_state());
    EXPECT_TRUE(IsAccessible(da->GetAllocation()));
    if (da->left_guard_page())
      EXPECT_TRUE(IsNotAccessible(da->GetLeftGuardPage()));
    if (da->right_guard_page())
      EXPECT_TRUE(IsNotAccessible(da->GetRightGuardPage()));
  } else {
    EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
  }

  EXPECT_TRUE(da->ProtectAllPages());
  EXPECT_EQ(DirectAllocation::kAllPagesProtected, da->protection_state());
  EXPECT_TRUE(IsNotAccessible(da->GetAllocation()));
  if (da->left_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetLeftGuardPage()));
  if (da->right_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetRightGuardPage()));

  // Leave ourselves at no page protections, same as when we entered. This
  // facilitates running TestToAllocated back-to-back.
  EXPECT_TRUE(da->ProtectNoPages());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
  EXPECT_TRUE(IsAccessible(da->GetAllocation()));
  if (da->left_guard_page())
    EXPECT_TRUE(IsAccessible(da->GetLeftGuardPage()));
  if (da->right_guard_page())
    EXPECT_TRUE(IsAccessible(da->GetRightGuardPage()));
}

// Transitions to the free state, and tests all protection state changes.
void TestToFree(TestDirectAllocation* da) {
  ASSERT_TRUE(da != NULL);

  // Free the pages, and try all protection settings.
  EXPECT_TRUE(da->ToNoPages());
  EXPECT_EQ(DirectAllocation::kNoPages, da->memory_state());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
  EXPECT_FALSE(da->ProtectNoPages());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
  EXPECT_FALSE(da->ProtectGuardPages());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
  EXPECT_FALSE(da->ProtectAllPages());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
}

// Tests all possible state changes of a DirectAllocation object. Incidentally
// tests all of the accessors at the same time.
void TestAllStateChanges(TestDirectAllocation* da) {
  ASSERT_TRUE(da != NULL);

  // We test every possible state transition (self-transitions too).
  // Within each of these tests we test every possible protection state
  // transition, and actually test that the protections work as expected.
  EXPECT_NO_FATAL_FAILURE(TestToReserved(da));
  EXPECT_NO_FATAL_FAILURE(TestToAllocated(da));
  EXPECT_NO_FATAL_FAILURE(TestToAllocated(da));
  EXPECT_NO_FATAL_FAILURE(TestToReserved(da));
  EXPECT_NO_FATAL_FAILURE(TestToReserved(da));
  EXPECT_NO_FATAL_FAILURE(TestToFree(da));
  EXPECT_NO_FATAL_FAILURE(TestToFree(da));
  EXPECT_NO_FATAL_FAILURE(TestToAllocated(da));
  EXPECT_NO_FATAL_FAILURE(TestToFree(da));
}

}  // namespace

TEST(DirectAllocationTest, AllStateChangesNoGuards) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(da.GetPageSize());
  EXPECT_NO_FATAL_FAILURE(TestAllStateChanges(&da));
}

TEST(DirectAllocationTest, AllStateChangesLeftGuard) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(da.GetPageSize());
  da.set_left_guard_page(true);
  EXPECT_NO_FATAL_FAILURE(TestAllStateChanges(&da));
}

TEST(DirectAllocationTest, AllStateChangesRightGuard) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(da.GetPageSize());
  da.set_right_guard_page(true);
  EXPECT_NO_FATAL_FAILURE(TestAllStateChanges(&da));
}

TEST(DirectAllocationTest, AllStateChangesBothGuards) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(1024 * 1024);
  da.set_left_guard_page(true);
  da.set_right_guard_page(true);
  EXPECT_NO_FATAL_FAILURE(TestAllStateChanges(&da));
}

namespace {

// Tests the typical ASAN use of the allocation, using only external
// state transition functions.
void TestAsanUse(TestDirectAllocation* da) {
  ASSERT_TRUE(da != NULL);

  EXPECT_TRUE(da->Allocate());
  EXPECT_EQ(DirectAllocation::kAllocatedPages, da->memory_state());
  if (da->HasGuardPages()) {
    EXPECT_EQ(DirectAllocation::kGuardPagesProtected, da->protection_state());
    if (da->left_guard_page())
      EXPECT_TRUE(IsNotAccessible(da->GetLeftGuardPage()));
    if (da->right_guard_page())
      EXPECT_TRUE(IsNotAccessible(da->GetRightGuardPage()));
    EXPECT_TRUE(IsAccessible(da->GetAllocation()));
  } else {
    EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
    EXPECT_TRUE(IsAccessible(da->GetAllocation()));
  }

  EXPECT_TRUE(da->QuarantineKeepContents());
  EXPECT_EQ(DirectAllocation::kAllocatedPages, da->memory_state());
  EXPECT_EQ(DirectAllocation::kAllPagesProtected, da->protection_state());
  if (da->left_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetLeftGuardPage()));
  if (da->right_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetRightGuardPage()));
  EXPECT_TRUE(IsNotAccessible(da->GetAllocation()));

  EXPECT_TRUE(da->QuarantineDiscardContents());
  EXPECT_EQ(DirectAllocation::kReservedPages, da->memory_state());
  EXPECT_EQ(DirectAllocation::kAllPagesProtected, da->protection_state());
  if (da->left_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetLeftGuardPage()));
  if (da->right_guard_page())
    EXPECT_TRUE(IsNotAccessible(da->GetRightGuardPage()));
  EXPECT_TRUE(IsNotAccessible(da->GetAllocation()));

  EXPECT_TRUE(da->Free());
  EXPECT_EQ(DirectAllocation::kNoPages, da->memory_state());
  EXPECT_EQ(DirectAllocation::kNoPagesProtected, da->protection_state());
}

}  // namespace

TEST(DirectAllocationTest, AsanUseNoGuards) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(da.GetPageSize());
  EXPECT_NO_FATAL_FAILURE(TestAsanUse(&da));
}

TEST(DirectAllocationTest, AsanUseLeftGuard) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(da.GetPageSize());
  da.set_left_guard_page(true);
  EXPECT_NO_FATAL_FAILURE(TestAsanUse(&da));
}

TEST(DirectAllocationTest, AsanUseRightGuard) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(da.GetPageSize());
  da.set_right_guard_page(true);
  EXPECT_NO_FATAL_FAILURE(TestAsanUse(&da));
}

TEST(DirectAllocationTest, AsanUseBothGuards) {
  TestDirectAllocation da;
  EXPECT_EQ(DirectAllocation::kNoPages, da.memory_state());
  da.set_size(1024 * 1024);
  da.set_left_guard_page(true);
  da.set_right_guard_page(true);
  EXPECT_NO_FATAL_FAILURE(TestAsanUse(&da));
}

}  // namespace asan
}  // namespace agent
