// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_util.h"

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

bool ReadOmapsFromPdbFile(const PdbFile& pdb_file,
                          std::vector<OMAP>* omap_to,
                          std::vector<OMAP>* omap_from) {
  PdbStream* dbi_stream = pdb_file.GetStream(kDbiStream);
  if (dbi_stream == NULL)
    return false;

  DbiHeader dbi_header = {};
  if (!dbi_stream->Read(&dbi_header, 1))
    return false;

  DbiDbgHeader dbg_header = {};
  if (!dbi_stream->Seek(GetDbiDbgHeaderOffset(dbi_header)))
    return false;
  if (!dbi_stream->Read(&dbg_header, 1))
    return false;

  // We expect both the OMAP stream IDs to exist.
  if (dbg_header.omap_to_src < 0 || dbg_header.omap_from_src < 0)
    return false;

  // We expect both streams to exist.
  PdbStream* omap_to_stream = pdb_file.GetStream(dbg_header.omap_to_src);
  PdbStream* omap_from_stream = pdb_file.GetStream(dbg_header.omap_from_src);
  if (omap_to_stream == NULL || omap_from_stream == NULL)
    return false;

  // Read the streams if need be.
  if (omap_to != NULL && !omap_to_stream->Read(omap_to))
    return false;
  if (omap_from != NULL && !omap_from_stream->Read(omap_from))
    return false;

  return true;
}

bool ReadOmapsFromPdbFile(const FilePath& pdb_path,
                          std::vector<OMAP>* omap_to,
                          std::vector<OMAP>* omap_from) {
  PdbReader pdb_reader;
  PdbFile pdb_file;
  if (!pdb_reader.Read(pdb_path, &pdb_file))
    return false;
  return ReadOmapsFromPdbFile(pdb_file, omap_to, omap_from);
}

}  // namespace pdb
