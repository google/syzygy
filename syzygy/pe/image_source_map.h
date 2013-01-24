// Copyright 2011 Google Inc. All Rights Reserved.
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
// Declares utility functions for generating a combined source range map for
// an ImageLayout.

#ifndef SYZYGY_PE_IMAGE_SOURCE_MAP_H_
#define SYZYGY_PE_IMAGE_SOURCE_MAP_H_

#include <windows.h>  // NOLINT
#include <dbghelp.h>

#include "syzygy/pe/image_layout.h"

namespace pe {

// An ImageSourceMap is a mapping from bytes in a modifed image to bytes in the
// original image from which it was created.
typedef core::AddressRange<core::RelativeAddress, size_t> RelativeAddressRange;
typedef core::AddressRangeMap<RelativeAddressRange,
                              RelativeAddressRange> ImageSourceMap;

// This is used for representing an invalid address in a source range map that
// is converted to an OMAP. Since the OMAP format only implicitly encodes
// lengths we have to encode unmapped ranges by mapping to invalid addresses.
// We do this for completeness, making the OMAP vector more useful as a
// debugging tool, although it is not strictly necessary.
extern const ULONG kInvalidOmapRvaTo;

// Given an ImageLayout representing an image that has been derived from exactly
// one non-transformed image, returns the combined ImageSourceMap for all of the
// data in the image.
//
// @param image_layout the ImageLayout whose source information to extract.
// @param image_source_map the AddressRangeMap mapping relative addresses in the
//     new image to relative addresses in the source image.
void BuildImageSourceMap(const ImageLayout& image_layout,
                         ImageSourceMap* new_to_old);

// Given an ImageSourceMap, converts it to an equivalent OMAP vector. The OMAP
// vector is constructed such that source addresses with no equivalent address
// in the destination address space are mapped to an invalid address that is
// greater than or equal to kInvalidOmapRvaTo.
//
// Mappings whose destination range is shorter than its source range are broken
// into multiple OMAP entries, each mapping a portion of the larger source
// range. This ensures that any address in the source range will be mapped to
// some address in the destination range, and not any address outside of it.
//
// This transformation is not lossless, with the OMAP inherently encoding less
// information about the image than does the ImageSourceMap.
//
// @param range the range which the OMAP vector should cover.
// @param source_map the source map to be translated to an OMAP vector.
// @param omaps the OMAP vector be populated.
void BuildOmapVectorFromImageSourceMap(const RelativeAddressRange& range,
                                       const ImageSourceMap& source_map,
                                       std::vector<OMAP>* omaps);

}  // namespace pe

#endif  // SYZYGY_PE_IMAGE_SOURCE_MAP_H_
