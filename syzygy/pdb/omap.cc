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

#include "syzygy/pdb/omap.h"

#include <algorithm>

namespace pdb {

OMAP CreateOmap(ULONG rva, ULONG rvaTo) {
  OMAP omap = { rva, rvaTo };
  return omap;
}

bool OmapLess(const OMAP& omap1, const OMAP& omap2) {
    return omap1.rva < omap2.rva;
}

bool OmapVectorIsValid(const std::vector<OMAP>& omaps) {
  for (size_t i = 1; i < omaps.size(); ++i) {
    if (!OmapLess(omaps[i - 1], omaps[i]))
      return false;
  }
  return true;
}

core::RelativeAddress TranslateAddressViaOmap(const std::vector<OMAP>& omaps,
                                              core::RelativeAddress address) {
  OMAP omap_address = CreateOmap(address.value(), 0);

  // Find the first element that is > than omap_address.
  std::vector<OMAP>::const_iterator it =
      std::upper_bound(omaps.begin(), omaps.end(), omap_address,
                       OmapLess);

  // If we are at the first OMAP entry, the address is before any addresses
  // that are OMAPped. Thus, we return the same address.
  if (it == omaps.begin())
    return address;

  // Otherwise, the previous OMAP entry tells us where we lie.
  --it;
  return core::RelativeAddress(it->rvaTo) +
      (address - core::RelativeAddress(it->rva));
}

}  // namespace pdb
