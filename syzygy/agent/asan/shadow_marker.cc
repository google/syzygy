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

#include "base/logging.h"

namespace agent {
namespace asan {

namespace {

// Some constants related to the structure of shadow marker values.
static const uint8 kActiveBit = 0x20;
static const uint8 kBlockEndNestedBit = 0x01;
static const uint8 kBlockStartDataMask = 0x7;
static const uint8 kBlockStartNestedBit = 0x08;
static const uint8 kFirstNibble = 0xF0;
static const uint8 kRedzoneBit = 0x80;

// ShadowMarker name generator. This maps an enumeration value to a name via
// template specialization.
template<size_t kIndex> struct ShadowMarkerNameGenerator {
  static const uintptr_t kName = 0;
};
#define SHADOW_MARKER_NAME_GENERATOR_MACRO(name, value)  \
    template<> struct ShadowMarkerNameGenerator<value> {  \
      static const char* kName;  \
    };  \
    const char* ShadowMarkerNameGenerator<value>::kName =  \
        _STRINGIZE(name);
SHADOW_MARKER_GENERATOR(SHADOW_MARKER_NAME_GENERATOR_MACRO)
#undef SHADOW_MARKER_NAME_GENERATOR_MACRO

}  // namespace

// This generates an array of shadow marker names, populating valid markers
// with their names as defined by the template specialization above. Invalid
// markers map to NULL as defined by the base template.
#define ITERATE_2(F, base)  F(base) F(base + 1)
#define ITERATE_4(F, base)  ITERATE_2(F, base) ITERATE_2(F, base + 2)
#define ITERATE_8(F, base)  ITERATE_4(F, base) ITERATE_4(F, base + 4)
#define ITERATE_16(F, base)  ITERATE_8(F, base) ITERATE_8(F, base + 8)
#define ITERATE_32(F, base)  ITERATE_16(F, base) ITERATE_16(F, base + 16)
#define ITERATE_64(F, base)  ITERATE_32(F, base) ITERATE_32(F, base + 32)
#define ITERATE_128(F, base)  ITERATE_64(F, base) ITERATE_64(F, base + 64)
#define ITERATE_256(F)  ITERATE_128(F, 0) ITERATE_128(F, 128)
#define GET_SHADOW_MARKER_STRING_PTR(index)  \
    reinterpret_cast<const char*>(ShadowMarkerNameGenerator<index>::kName),
const char* kShadowMarkerNames[256] = {
    ITERATE_256(GET_SHADOW_MARKER_STRING_PTR)
};
#undef GET_SHADOW_MARKER_STRING_PTR
#undef ITERATE_256
#undef ITERATE_128
#undef ITERATE_64
#undef ITERATE_32
#undef ITERATE_16
#undef ITERATE_8
#undef ITERATE_4
#undef ITERATE_2

bool ShadowMarkerHelper::IsRedzone(ShadowMarkerValue marker) {
  return (marker.value & kRedzoneBit) == kRedzoneBit;
}

bool ShadowMarkerHelper::IsActiveBlock(ShadowMarkerValue marker) {
  return marker.value == kHeapLeftPaddingMarker ||
      marker.value == kHeapRightPaddingMarker ||
      marker.value == kHeapFreedMarker ||
      IsActiveBlockStart(marker) ||
      IsActiveBlockEnd(marker);
}

bool ShadowMarkerHelper::IsHistoricBlock(ShadowMarkerValue marker) {
return marker.value == kHeapHistoricLeftPaddingMarker ||
      marker.value == kHeapHistoricRightPaddingMarker ||
      marker.value == kHeapHistoricFreedMarker ||
      IsHistoricBlockStart(marker) ||
      IsHistoricBlockEnd(marker);
}

bool ShadowMarkerHelper::IsBlock(ShadowMarkerValue marker) {
  return IsActiveBlock(marker) || IsHistoricBlock(marker);
}

bool ShadowMarkerHelper::IsActiveBlockStart(ShadowMarkerValue marker) {
  return (marker.value & kFirstNibble) == kHeapBlockStartMarker0;
}

bool ShadowMarkerHelper::IsHistoricBlockStart(ShadowMarkerValue marker) {
  return (marker.value & kFirstNibble) == kHeapHistoricBlockStartMarker0;
}

bool ShadowMarkerHelper::IsBlockStart(ShadowMarkerValue marker) {
  static const uint8 kMask = kFirstNibble ^ kActiveBit;
  return (marker.value & kMask) == kHeapHistoricBlockStartMarker0;
}

bool ShadowMarkerHelper::IsNestedBlockStart(ShadowMarkerValue marker) {
  if (!IsBlockStart(marker))
    return false;
  return (marker.value & kBlockStartNestedBit) == kBlockStartNestedBit;
}

uint8 ShadowMarkerHelper::GetBlockStartData(ShadowMarkerValue marker) {
  return marker.value & kBlockStartDataMask;
}

bool ShadowMarkerHelper::IsActiveBlockEnd(ShadowMarkerValue marker) {
  return (marker.value & ~kBlockEndNestedBit) ==
      kHeapBlockEndMarker;
}

bool ShadowMarkerHelper::IsHistoricBlockEnd(ShadowMarkerValue marker) {
  return (marker.value & ~kBlockEndNestedBit) ==
      kHeapHistoricBlockEndMarker;
}

bool ShadowMarkerHelper::IsBlockEnd(ShadowMarkerValue marker) {
  // Block end markers have arbitrary values for the active bit
  // and the block end nested bit.
  static const uint8 kMask = ~(kActiveBit | kBlockEndNestedBit);
  return (marker.value & kMask) == kHeapHistoricBlockEndMarker;
}

bool ShadowMarkerHelper::IsNestedBlockEnd(ShadowMarkerValue marker) {
  if (!IsBlockEnd(marker))
    return false;
  return (marker.value & kBlockEndNestedBit) == kBlockEndNestedBit;
}

bool ShadowMarkerHelper::IsHistoricLeftRedzone(ShadowMarkerValue marker) {
  return marker.value == kHeapHistoricLeftPaddingMarker ||
      IsHistoricBlockStart(marker);
}

bool ShadowMarkerHelper::IsActiveLeftRedzone(ShadowMarkerValue marker) {
  return marker.value == kHeapLeftPaddingMarker ||
      IsActiveBlockStart(marker);
}

bool ShadowMarkerHelper::IsLeftRedzone(ShadowMarkerValue marker) {
  return (marker.value & ~kActiveBit) == kHeapHistoricLeftPaddingMarker ||
      IsBlockStart(marker);
}

bool ShadowMarkerHelper::IsHistoricRightRedzone(ShadowMarkerValue marker) {
  return marker.value == kHeapHistoricRightPaddingMarker ||
      IsHistoricBlockEnd(marker);
}

bool ShadowMarkerHelper::IsActiveRightRedzone(ShadowMarkerValue marker) {
  return marker.value == kHeapRightPaddingMarker ||
      IsActiveBlockEnd(marker);
}

bool ShadowMarkerHelper::IsRightRedzone(ShadowMarkerValue marker) {
  return (marker.value & ~kActiveBit) == kHeapHistoricRightPaddingMarker ||
      IsBlockEnd(marker);
}

ShadowMarker ShadowMarkerHelper::ToHistoric(ShadowMarkerValue marker) {
  DCHECK(IsActiveBlock(marker));
  return static_cast<ShadowMarker>(marker.value & ~kActiveBit);
}

ShadowMarker ShadowMarkerHelper::BuildBlockStart(
    bool active, bool nested, uint8 data) {
  DCHECK_EQ(0, data & ~kBlockStartDataMask);
  uint8 marker = kHeapHistoricBlockStartMarker0;
  if (active)
    marker |= kActiveBit;
  if (nested)
    marker |= kBlockStartNestedBit;
  marker |= data;
  return static_cast<ShadowMarker>(marker);
}

ShadowMarker ShadowMarkerHelper::BuildBlockEnd(bool active, bool nested) {
  uint8 marker = kHeapHistoricBlockEndMarker;
  if (active)
    marker |= kActiveBit;
  if (nested)
    marker |= kBlockEndNestedBit;
  return static_cast<ShadowMarker>(marker);
}

}  // namespace asan
}  // namespace agent
