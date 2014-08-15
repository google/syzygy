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
//
// Declares the ShadowMarker enumeration, and a utility class for querying the
// component parts of a shadow byte.

#ifndef SYZYGY_AGENT_ASAN_SHADOW_MARKER_H_
#define SYZYGY_AGENT_ASAN_SHADOW_MARKER_H_

#include "base/basictypes.h"

namespace agent {
namespace asan {

// Defines the various distinct values that are used to mark shadow memory. At
// the highest level this is split into 2 classes: accessible memory (leading
// bit is 0), and inaccessible, or redzoned, memory (leading bit is 1). The
// fast path ASan error checking code relies on the fact that the leading bit
// is 1 for redzoned memory.
//
// The redzoned memory is broken into various distinct types. A lot of the
// codespace of this enum is dedicated to describing blocks, with sufficient
// detail to reconstruct the layout of the block from an inspection of shadow
// memory alone.
//
// All block markers have 'historic' variants which are used for marking old
// blocks that have since fallen out of the quarantine. This serves as a
// persistent record of the block that *used* to be located at a specific spot
// in memory, at least until the owning heap reuses the memory.
//
// Since the code space is quite convoluted (it has strictly been added to, and
// was initially a clone of ASan's far simpler marker types) a helper class
// (ShadowMarkerHelper) has been defined for making queries about marker
// properties.
//
// NOTE: If this grows any more complex then it would be relatively simple to
//     define a 32-bit 'ShadowMarkerProperties' struct, and simply map each
//     marker type to its properties. The properties could then be trivially
//     inspected via masks.
#define SHADOW_MARKER_GENERATOR(F)  \
    /* ADDRESSABLE BYTES. */  \
    /* This is either a range of bytes that we know nothing about, or is */  \
    /* an allocated byte that is explicitly accessible. */  \
    F(kHeapAddressableMarker, 0x00)  \
    /* Values 0x01 through 0x07 indicate that a range of bytes is */  \
    /* partially accessible, and partially inaccessible. */  \
    F(kHeapPartiallyAddressableByte1, 0x01)  \
    F(kHeapPartiallyAddressableByte2, 0x02)  \
    F(kHeapPartiallyAddressableByte3, 0x03)  \
    F(kHeapPartiallyAddressableByte4, 0x04)  \
    F(kHeapPartiallyAddressableByte5, 0x05)  \
    F(kHeapPartiallyAddressableByte6, 0x06)  \
    F(kHeapPartiallyAddressableByte7, 0x07)  \
    /* NON-ADDRESSABLE BYTES. */  \
    /* These are 'historic' block start bytes. They are equivalent to */  \
    /* other block markers, but mark blocks that have since fallen out of */  \
    /* the quarantine. They are kept around to provide extra data, but */  \
    /* through memory reuse may end up being incomplete. The values are */  \
    /* the same as 'active' block markers, but with the 'active' bit */  \
    /* (0x20) disabled. Thus any marker starting with 0xc0 is a historic */  \
    /* block start marker. */  \
    F(kHeapHistoricBlockStartMarker0, 0xC0)  \
    F(kHeapHistoricBlockStartMarker1, 0xC1)  \
    F(kHeapHistoricBlockStartMarker2, 0xC2)  \
    F(kHeapHistoricBlockStartMarker3, 0xC3)  \
    F(kHeapHistoricBlockStartMarker4, 0xC4)  \
    F(kHeapHistoricBlockStartMarker5, 0xC5)  \
    F(kHeapHistoricBlockStartMarker6, 0xC6)  \
    F(kHeapHistoricBlockStartMarker7, 0xC7)  \
    /* Nested block start bytes have the bit 0x80 set. */  \
    F(kHeapHistoricNestedBlockStartMarker0, 0xC8)  \
    F(kHeapHistoricNestedBlockStartMarker1, 0xC9)  \
    F(kHeapHistoricNestedBlockStartMarker2, 0xCA)  \
    F(kHeapHistoricNestedBlockStartMarker3, 0xCB)  \
    F(kHeapHistoricNestedBlockStartMarker4, 0xCC)  \
    F(kHeapHistoricNestedBlockStartMarker5, 0xCD)  \
    F(kHeapHistoricNestedBlockStartMarker6, 0xCE)  \
    F(kHeapHistoricNestedBlockStartMarker7, 0xCF)  \
    /* These are 'historic' markers associated with block left/right */  \
    /* redzones and freed data. They consist of the same values as the */  \
    /* active markers, minus the active block bit. */  \
    F(kHeapHistoricBlockEndMarker, 0xD4)  \
    F(kHeapHistoricNestedBlockEndMarker, 0xD5)  \
    F(kHeapHistoricLeftPaddingMarker, 0xDA)  \
    F(kHeapHistoricRightPaddingMarker, 0xDB)  \
    F(kHeapHistoricFreedMarker, 0xDD)  \
    /* Any marker starting with 0xe0 marks the beginning of a block. The */  \
    /* trailing 4 bits of the marker are used to encode additional */  \
    /* metadata about the block itself. This is necessary to allow */  \
    /* full introspection of blocks via the shadow. All 'active' block */  \
    /* start bytes have the bit 0x20 set. */  \
    F(kHeapBlockStartMarker0, 0xE0)  \
    F(kHeapBlockStartMarker1, 0xE1)  \
    F(kHeapBlockStartMarker2, 0xE2)  \
    F(kHeapBlockStartMarker3, 0xE3)  \
    F(kHeapBlockStartMarker4, 0xE4)  \
    F(kHeapBlockStartMarker5, 0xE5)  \
    F(kHeapBlockStartMarker6, 0xE6)  \
    F(kHeapBlockStartMarker7, 0xE7)  \
    /* Nested block start bytes have the bit 0x80 set. */  \
    F(kHeapNestedBlockStartMarker0, 0xE8)  \
    F(kHeapNestedBlockStartMarker1, 0xE9)  \
    F(kHeapNestedBlockStartMarker2, 0xEA)  \
    F(kHeapNestedBlockStartMarker3, 0xEB)  \
    F(kHeapNestedBlockStartMarker4, 0xEC)  \
    F(kHeapNestedBlockStartMarker5, 0xED)  \
    F(kHeapNestedBlockStartMarker6, 0xEE)  \
    F(kHeapNestedBlockStartMarker7, 0xEF)  \
    /* The data in this block maps to internal memory structures. */  \
    F(kAsanMemoryMarker, 0xF1)  \
    /* The address covered by this byte are simply invalid and unable to */  \
    /* be accessed by user code. */  \
    F(kInvalidAddressMarker, 0xF2)  \
    /* The bytes are part of a block that has been allocated by the */  \
    /* instrumented code, but subsequently redzoned via the runtime API. */  \
    F(kUserRedzoneMarker, 0xF3)  \
    /* This marker marks the end of a block in memory, and is part of a */  \
    /* right redzone. */  \
    F(kHeapBlockEndMarker, 0xF4)  \
    F(kHeapNestedBlockEndMarker, 0xF5)  \
    /* The bytes are part of a left redzone (block header padding). */  \
    /* This is the same value as used by ASan itself. */  \
    F(kHeapLeftPaddingMarker, 0xFA)  \
    /* The bytes are part of a right redzone (block trailer and padding). */  \
    /* This is the same value as used by ASan itself. */  \
    F(kHeapRightPaddingMarker, 0xFB)  \
    /* These bytes are part of memory that is destined to be used by the */  \
    /* heap, has been reserved from the OS, but not yet handed out to */  \
    /* the code under test. */  \
    F(kAsanReservedMarker, 0xFC)  \
    /* The bytes are part of the body of a block that has been allocated */  \
    /* and subsequently freed by instrumented code. */  \
    /* This is the same value as used by ASan itself. */  \
    F(kHeapFreedMarker, 0xFD)

// Any non-accessible marker will have these bits set.
static const uint8 kHeapNonAccessibleMarkerMask = 0x80;

// Generate the enum using the generator. This keeps it such that we only need
// to maintain a single list.
#define SHADOW_MARKER_ENUM_FUNCTION(x, y)  x = y,
enum ShadowMarker {
  SHADOW_MARKER_GENERATOR(SHADOW_MARKER_ENUM_FUNCTION)
};
#undef SHADOW_MARKER_ENUM_FUNCTION

// Maps from a shadow marker ID to its name. Invalid enumeration values are
// mapped to a NULL string.
extern const char* kShadowMarkerNames[256];

// A convenience class that automatically accepts either a uint8 or a
// ShadowMarker enum.
struct ShadowMarkerValue {
  // These are deliberately left as implicit typecasts.
  ShadowMarkerValue(ShadowMarker marker) : value(marker) {  // NOLINT
  }
  ShadowMarkerValue(uint8 marker)  // NOLINT
      : value(static_cast<ShadowMarker>(marker)) {
  }
  ShadowMarkerValue(const ShadowMarkerValue& rhs)  // NOLINT
      : value(rhs.value) {
  }
  ShadowMarker value;
};

// A simple helper for querying and building ShadowMarker values.
struct ShadowMarkerHelper {
  // @name For querying shadow markers.
  // @{

  // @param marker The shadow marker to query.
  // @returns true if the marker is a redzone (inaccessible) marker, false
  //     otherwise.
  static bool IsRedzone(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes an active block.
  static bool IsActiveBlock(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a historic block.
  static bool IsHistoricBlock(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes memory pertaining to a block,
  //     historic or otherwise.
  static bool IsBlock(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes an active block start marker.
  static bool IsActiveBlockStart(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a historic block start marker.
  static bool IsHistoricBlockStart(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a block header marker, historic or
  //     active.
  static bool IsBlockStart(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the markers describes a nested block start marker,
  //     historic or active.
  static bool IsNestedBlockStart(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns the extra data encoded in a block start marker.
  // @note This should only be called for block start markers.
  static uint8 GetBlockStartData(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes an active block start marker.
  static bool IsActiveBlockEnd(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a historic block start marker.
  static bool IsHistoricBlockEnd(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a block header marker, historic or
  //     active.
  static bool IsBlockEnd(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the markers describes a nested block end marker,
  //     historic or active.
  static bool IsNestedBlockEnd(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a historic left redzone.
  //     Note that block start markers are part of a left redzone.
  static bool IsHistoricLeftRedzone(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes an active left redzone.
  //     Note that block start markers are part of a left redzone.
  static bool IsActiveLeftRedzone(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a left redzone, historic or active.
  //     Note that block start markers are part of a left redzone.
  static bool IsLeftRedzone(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a historic right redzone.
  //     Note that block end markers are part of a right redzone.
  static bool IsHistoricRightRedzone(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes an active right redzone.
  //     Note that block end markers are part of a right redzone.
  static bool IsActiveRightRedzone(ShadowMarkerValue marker);

  // @param marker The shadow marker to query.
  // @returns true if the marker describes a right redzone, historic or active.
  //     Note that block end markers are part of a left redzone.
  static bool IsRightRedzone(ShadowMarkerValue marker);

  // @}

  // @name For modifying shadow markers.
  // @{

  // @param marker The shadow marker to modify.
  // @returns the historic version of the input marker.
  // @note The input marker must be an active block marker that has an
  //     equivalent historic type.
   static ShadowMarker ToHistoric(ShadowMarkerValue marker);

  // @}

  // @name For building shadow markers.
  // @{

  // Builds a block start marker.
  // @param active True if the block is active, false if its historic.
  // @param nested True if the block is nested, false otherwise.
  // @param data The data to be appended to the marker. This can only consist
  //     of 3 bits of data.
  // @returns the generated block start marker.
  static ShadowMarker BuildBlockStart(bool active, bool nested, uint8 data);

  // Builds a block end marker.
  // @param active True if the block is active, false if its historic.
  // @param nested True if the block is nested, false otherwise.
  // @returns the generated block end marker.
  static ShadowMarker BuildBlockEnd(bool active, bool nested);

  // @}
};

}  // namespace asan
}  // namespace agent

#endif  // SYZYGY_AGENT_ASAN_SHADOW_MARKER_H_
