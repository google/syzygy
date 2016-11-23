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

#include "syzygy/agent/asan/shadow_marker.h"

#include "base/macros.h"
#include "gtest/gtest.h"

namespace agent {
namespace asan {

namespace {

// A list of all of the defined enumeration values.
#define EXTRACT_ENUM_NAME_MACRO(x, y)  x,
static const ShadowMarker kValidShadowMarkers[] = {
  SHADOW_MARKER_GENERATOR(EXTRACT_ENUM_NAME_MACRO)
};
#undef EXTRACT_ENUM_NAME_MACRO

static const ShadowMarker kRedzoneShadowMarkers[] = {
    kHeapHistoricBlockStartMarker0,
    kHeapHistoricBlockStartMarker1,
    kHeapHistoricBlockStartMarker2,
    kHeapHistoricBlockStartMarker3,
    kHeapHistoricBlockStartMarker4,
    kHeapHistoricBlockStartMarker5,
    kHeapHistoricBlockStartMarker6,
    kHeapHistoricBlockStartMarker7,
    kHeapHistoricBlockEndMarker,
    kHeapHistoricLeftPaddingMarker,
    kHeapHistoricRightPaddingMarker,
    kHeapHistoricFreedMarker,
    kHeapBlockStartMarker0,
    kHeapBlockStartMarker1,
    kHeapBlockStartMarker2,
    kHeapBlockStartMarker3,
    kHeapBlockStartMarker4,
    kHeapBlockStartMarker5,
    kHeapBlockStartMarker6,
    kHeapBlockStartMarker7,
    kAsanMemoryMarker,
    kInvalidAddressMarker,
    kUserRedzoneMarker,
    kHeapBlockEndMarker,
    kHeapLeftPaddingMarker,
    kHeapRightPaddingMarker,
    kAsanReservedMarker,
    kHeapFreedMarker,
};

static const ShadowMarker kActiveBlockShadowMarkers[] = {
    kHeapBlockStartMarker0,
    kHeapBlockStartMarker1,
    kHeapBlockStartMarker2,
    kHeapBlockStartMarker3,
    kHeapBlockStartMarker4,
    kHeapBlockStartMarker5,
    kHeapBlockStartMarker6,
    kHeapBlockStartMarker7,
    kHeapBlockEndMarker,
    kHeapLeftPaddingMarker,
    kHeapRightPaddingMarker,
    kHeapFreedMarker,
};

static const ShadowMarker kHistoricBlockShadowMarkers[] = {
    kHeapHistoricBlockStartMarker0,
    kHeapHistoricBlockStartMarker1,
    kHeapHistoricBlockStartMarker2,
    kHeapHistoricBlockStartMarker3,
    kHeapHistoricBlockStartMarker4,
    kHeapHistoricBlockStartMarker5,
    kHeapHistoricBlockStartMarker6,
    kHeapHistoricBlockStartMarker7,
    kHeapHistoricBlockEndMarker,
    kHeapHistoricLeftPaddingMarker,
    kHeapHistoricRightPaddingMarker,
    kHeapHistoricFreedMarker,
};

static const ShadowMarker kBlockShadowMarkers[] = {
    kHeapHistoricBlockStartMarker0,
    kHeapHistoricBlockStartMarker1,
    kHeapHistoricBlockStartMarker2,
    kHeapHistoricBlockStartMarker3,
    kHeapHistoricBlockStartMarker4,
    kHeapHistoricBlockStartMarker5,
    kHeapHistoricBlockStartMarker6,
    kHeapHistoricBlockStartMarker7,
    kHeapHistoricBlockEndMarker,
    kHeapHistoricLeftPaddingMarker,
    kHeapHistoricRightPaddingMarker,
    kHeapHistoricFreedMarker,
    kHeapBlockStartMarker0,
    kHeapBlockStartMarker1,
    kHeapBlockStartMarker2,
    kHeapBlockStartMarker3,
    kHeapBlockStartMarker4,
    kHeapBlockStartMarker5,
    kHeapBlockStartMarker6,
    kHeapBlockStartMarker7,
    kHeapBlockEndMarker,
    kHeapLeftPaddingMarker,
    kHeapRightPaddingMarker,
    kHeapFreedMarker,
};

static const ShadowMarker kActiveBlockStartShadowMarkers[] = {
    kHeapBlockStartMarker0,
    kHeapBlockStartMarker1,
    kHeapBlockStartMarker2,
    kHeapBlockStartMarker3,
    kHeapBlockStartMarker4,
    kHeapBlockStartMarker5,
    kHeapBlockStartMarker6,
    kHeapBlockStartMarker7,
};

static const ShadowMarker kHistoricBlockStartShadowMarkers[] = {
    kHeapHistoricBlockStartMarker0,
    kHeapHistoricBlockStartMarker1,
    kHeapHistoricBlockStartMarker2,
    kHeapHistoricBlockStartMarker3,
    kHeapHistoricBlockStartMarker4,
    kHeapHistoricBlockStartMarker5,
    kHeapHistoricBlockStartMarker6,
    kHeapHistoricBlockStartMarker7,
};

static const ShadowMarker kBlockStartShadowMarkers[] = {
    kHeapBlockStartMarker0,
    kHeapBlockStartMarker1,
    kHeapBlockStartMarker2,
    kHeapBlockStartMarker3,
    kHeapBlockStartMarker4,
    kHeapBlockStartMarker5,
    kHeapBlockStartMarker6,
    kHeapBlockStartMarker7,
    kHeapHistoricBlockStartMarker0,
    kHeapHistoricBlockStartMarker1,
    kHeapHistoricBlockStartMarker2,
    kHeapHistoricBlockStartMarker3,
    kHeapHistoricBlockStartMarker4,
    kHeapHistoricBlockStartMarker5,
    kHeapHistoricBlockStartMarker6,
    kHeapHistoricBlockStartMarker7,
};

static const ShadowMarker kActiveBlockEndShadowMarkers[] = {
  kHeapBlockEndMarker,
};

static const ShadowMarker kHistoricBlockEndShadowMarkers[] = {
  kHeapHistoricBlockEndMarker,
};

static const ShadowMarker kBlockEndShadowMarkers[] = {
  kHeapHistoricBlockEndMarker,
  kHeapBlockEndMarker,
};

static const ShadowMarker kHistoricLeftRedzoneShadowMarkers[] = {
    kHeapHistoricBlockStartMarker0,
    kHeapHistoricBlockStartMarker1,
    kHeapHistoricBlockStartMarker2,
    kHeapHistoricBlockStartMarker3,
    kHeapHistoricBlockStartMarker4,
    kHeapHistoricBlockStartMarker5,
    kHeapHistoricBlockStartMarker6,
    kHeapHistoricBlockStartMarker7,
    kHeapHistoricLeftPaddingMarker,
};

static const ShadowMarker kActiveLeftRedzoneShadowMarkers[] = {
    kHeapBlockStartMarker0,
    kHeapBlockStartMarker1,
    kHeapBlockStartMarker2,
    kHeapBlockStartMarker3,
    kHeapBlockStartMarker4,
    kHeapBlockStartMarker5,
    kHeapBlockStartMarker6,
    kHeapBlockStartMarker7,
    kHeapLeftPaddingMarker,
};

static const ShadowMarker kLeftRedzoneShadowMarkers[] = {
    kHeapHistoricBlockStartMarker0,
    kHeapHistoricBlockStartMarker1,
    kHeapHistoricBlockStartMarker2,
    kHeapHistoricBlockStartMarker3,
    kHeapHistoricBlockStartMarker4,
    kHeapHistoricBlockStartMarker5,
    kHeapHistoricBlockStartMarker6,
    kHeapHistoricBlockStartMarker7,
    kHeapHistoricLeftPaddingMarker,
    kHeapBlockStartMarker0,
    kHeapBlockStartMarker1,
    kHeapBlockStartMarker2,
    kHeapBlockStartMarker3,
    kHeapBlockStartMarker4,
    kHeapBlockStartMarker5,
    kHeapBlockStartMarker6,
    kHeapBlockStartMarker7,
    kHeapLeftPaddingMarker,
};

static const ShadowMarker kHistoricRightRedzoneShadowMarkers[] = {
  kHeapHistoricBlockEndMarker,
  kHeapHistoricRightPaddingMarker,
};

static const ShadowMarker kActiveRightRedzoneShadowMarkers[] = {
  kHeapBlockEndMarker,
  kHeapRightPaddingMarker,
};

static const ShadowMarker kRightRedzoneShadowMarkers[] = {
  kHeapHistoricBlockEndMarker,
  kHeapHistoricRightPaddingMarker,
  kHeapBlockEndMarker,
  kHeapRightPaddingMarker,
};

// Pointer to a query function.
typedef bool (*ShadowMarkerQueryFunctionPtr)(ShadowMarkerValue marker);

// Tests a shadow marker query function. Iterates over all markers defined in
// both |shadow_markers_to_test| and |passing_shadow_markers|. Expects the
// function to return true if the marker is in |passing_shadow_markers|, false
// otherwise. Markers may be defined in both lists.
//
// Meant to be called via EXPECT_NO_FATAL_FAILURES or ASSERT_NO_FATAL_FAILURES.
void TestShadowMarkerQueryFunction(
    const char* function_name,
    const ShadowMarker* shadow_markers_to_test,
    size_t num_shadow_markers_to_test,
    const ShadowMarker* passing_shadow_markers,
    size_t num_passing_shadow_markers,
    ShadowMarkerQueryFunctionPtr function) {
  std::set<ShadowMarker> expect_fail(
      shadow_markers_to_test,
      shadow_markers_to_test + num_shadow_markers_to_test);

  char buffer[5] = {};
  for (size_t i = 0; i < num_passing_shadow_markers; ++i) {
    ShadowMarker marker = passing_shadow_markers[i];
    if (!(*function)(marker)) {
      ::_snprintf(buffer, arraysize(buffer), "0x%02X", marker);
      ADD_FAILURE() << function_name << "(" << kShadowMarkerNames[marker]
                    << " = " << buffer << ") returned false, expected true.";
    }
    expect_fail.erase(marker);
  }

  std::set<ShadowMarker>::const_iterator it = expect_fail.begin();
  for (; it != expect_fail.end(); ++it) {
    if ((*function)(*it)) {
      ::_snprintf(buffer, arraysize(buffer), "0x%02X", *it);
      ADD_FAILURE() << function_name << "(" << kShadowMarkerNames[*it]
                    << " = " << buffer << ") returned true, expected false.";
    }
  }
}

// A version of the function that explicitly tests against all shadow markers.
void TestShadowMarkerQueryFunction(
    const char* function_name,
    const ShadowMarker* passing_shadow_markers,
    size_t num_passing_shadow_markers,
    ShadowMarkerQueryFunctionPtr function) {
  TestShadowMarkerQueryFunction(function_name,
                                kValidShadowMarkers,
                                arraysize(kValidShadowMarkers),
                                passing_shadow_markers,
                                num_passing_shadow_markers,
                                function);
}

}  // namespace

#define TEST_SHADOW_MARKER_FUNCTION_COMPLETE(Name)  \
    TEST(ShadowMarkerHelperTest, Is ## Name) {  \
      EXPECT_NO_FATAL_FAILURE(TestShadowMarkerQueryFunction(  \
          "ShadowMarkerHerlp::Is" _STRINGIZE(Name),  \
          k ## Name ## ShadowMarkers,  \
          arraysize(k  ## Name ## ShadowMarkers),  \
          &ShadowMarkerHelper::Is ## Name));  \
    }

// This tests the various shadow marker querying functions.
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(Redzone);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(ActiveBlock);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(HistoricBlock);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(Block);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(ActiveBlockStart);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(HistoricBlockStart);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(BlockStart);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(ActiveBlockEnd);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(HistoricBlockEnd);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(BlockEnd);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(HistoricLeftRedzone);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(ActiveLeftRedzone);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(LeftRedzone);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(HistoricRightRedzone);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(ActiveRightRedzone);
TEST_SHADOW_MARKER_FUNCTION_COMPLETE(RightRedzone);
#undef TEST_SHADOW_MARKER_FUNCTION_COMPLETE

TEST(ShadowMarkerHelperTest, GetBlockStartData) {
  EXPECT_EQ(0u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker0));
  EXPECT_EQ(1u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker1));
  EXPECT_EQ(2u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker2));
  EXPECT_EQ(3u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker3));
  EXPECT_EQ(4u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker4));
  EXPECT_EQ(5u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker5));
  EXPECT_EQ(6u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker6));
  EXPECT_EQ(7u, ShadowMarkerHelper::GetBlockStartData(
      kHeapHistoricBlockStartMarker7));
  EXPECT_EQ(0u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker0));
  EXPECT_EQ(1u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker1));
  EXPECT_EQ(2u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker2));
  EXPECT_EQ(3u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker3));
  EXPECT_EQ(4u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker4));
  EXPECT_EQ(5u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker5));
  EXPECT_EQ(6u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker6));
  EXPECT_EQ(7u, ShadowMarkerHelper::GetBlockStartData(
      kHeapBlockStartMarker7));
}

TEST(ShadowMarkerHelper, ToHistoric) {
  EXPECT_EQ(kHeapHistoricBlockStartMarker0,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker0));
  EXPECT_EQ(kHeapHistoricBlockStartMarker1,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker1));
  EXPECT_EQ(kHeapHistoricBlockStartMarker2,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker2));
  EXPECT_EQ(kHeapHistoricBlockStartMarker3,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker3));
  EXPECT_EQ(kHeapHistoricBlockStartMarker4,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker4));
  EXPECT_EQ(kHeapHistoricBlockStartMarker5,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker5));
  EXPECT_EQ(kHeapHistoricBlockStartMarker6,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker6));
  EXPECT_EQ(kHeapHistoricBlockStartMarker7,
            ShadowMarkerHelper::ToHistoric(kHeapBlockStartMarker7));
  EXPECT_EQ(kHeapHistoricBlockEndMarker,
            ShadowMarkerHelper::ToHistoric(kHeapBlockEndMarker));
  EXPECT_EQ(kHeapHistoricLeftPaddingMarker,
            ShadowMarkerHelper::ToHistoric(kHeapLeftPaddingMarker));
  EXPECT_EQ(kHeapHistoricRightPaddingMarker,
            ShadowMarkerHelper::ToHistoric(kHeapRightPaddingMarker));
  EXPECT_EQ(kHeapHistoricFreedMarker,
            ShadowMarkerHelper::ToHistoric(kHeapFreedMarker));
}

TEST(ShadowMarkerHelper, BuildBlockStart) {
  EXPECT_EQ(kHeapHistoricBlockStartMarker0,
            ShadowMarkerHelper::BuildBlockStart(false, 0));
  EXPECT_EQ(kHeapHistoricBlockStartMarker1,
            ShadowMarkerHelper::BuildBlockStart(false, 1));
  EXPECT_EQ(kHeapHistoricBlockStartMarker2,
            ShadowMarkerHelper::BuildBlockStart(false, 2));
  EXPECT_EQ(kHeapHistoricBlockStartMarker3,
            ShadowMarkerHelper::BuildBlockStart(false, 3));
  EXPECT_EQ(kHeapHistoricBlockStartMarker4,
            ShadowMarkerHelper::BuildBlockStart(false, 4));
  EXPECT_EQ(kHeapHistoricBlockStartMarker5,
            ShadowMarkerHelper::BuildBlockStart(false, 5));
  EXPECT_EQ(kHeapHistoricBlockStartMarker6,
            ShadowMarkerHelper::BuildBlockStart(false, 6));
  EXPECT_EQ(kHeapHistoricBlockStartMarker7,
            ShadowMarkerHelper::BuildBlockStart(false, 7));

  EXPECT_EQ(kHeapBlockStartMarker0,
            ShadowMarkerHelper::BuildBlockStart(true, 0));
  EXPECT_EQ(kHeapBlockStartMarker1,
            ShadowMarkerHelper::BuildBlockStart(true, 1));
  EXPECT_EQ(kHeapBlockStartMarker2,
            ShadowMarkerHelper::BuildBlockStart(true, 2));
  EXPECT_EQ(kHeapBlockStartMarker3,
            ShadowMarkerHelper::BuildBlockStart(true, 3));
  EXPECT_EQ(kHeapBlockStartMarker4,
            ShadowMarkerHelper::BuildBlockStart(true, 4));
  EXPECT_EQ(kHeapBlockStartMarker5,
            ShadowMarkerHelper::BuildBlockStart(true, 5));
  EXPECT_EQ(kHeapBlockStartMarker6,
            ShadowMarkerHelper::BuildBlockStart(true, 6));
  EXPECT_EQ(kHeapBlockStartMarker7,
            ShadowMarkerHelper::BuildBlockStart(true, 7));
}

TEST(ShadowMarkerHelper, BuildBlockEnd) {
  EXPECT_EQ(kHeapHistoricBlockEndMarker,
            ShadowMarkerHelper::BuildBlockEnd(false));
  EXPECT_EQ(kHeapBlockEndMarker, ShadowMarkerHelper::BuildBlockEnd(true));
}

}  // namespace asan
}  // namespace agent
