// Copyright 2011 Google Inc.
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

#ifndef SYZYGY_PDB_OMAP_H_
#define SYZYGY_PDB_OMAP_H_

#include <windows.h>  // NOLINT
#include <dbghelp.h>

#include <vector>

#include "syzygy/core/address.h"

namespace pdb {

// Builds an anonymous intialized OMAP object.
//
// @param rva the relative address this entry maps.
// @param rvaTo the relative address that @p rva is mapped to.
OMAP CreateOmap(ULONG rva, ULONG rvaTo);

// A comparison functor, for comparing two OMAP entries based on 'rva'.
//
// @param omap1 the first omap object to compare.
// @param omap2 the second omap object to comapre.
// @returns true if omap1.rva < omap2.rva, false otherwise.
bool OmapLess(const OMAP& omap1, const OMAP& omap2);

// Determines if the given OMAP vector is valid. That is, for every i in
// [1, omaps.size() - 1], OmapLess(omaps[i - 1], omaps[i]) is true.
//
// @params omaps the vector of OMAPs to validate.
// @returns true if omaps is valid, false otherwise.
bool OmapVectorIsValid(const std::vector<OMAP>& omaps);

// Maps an address through the given OMAP information.
//
// @param omaps the vector of OMAPs to apply.
// @param address the address to map.
// @returns the mapped address.
// @pre OmapIsValid(omaps) is true.
core::RelativeAddress TranslateAddressViaOmap(const std::vector<OMAP>& omaps,
                                              core::RelativeAddress address);

}  // namespace pdb

#endif  // SYZYGY_PDB_OMAP_H_
