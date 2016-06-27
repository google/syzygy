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

#include "syzygy/pdb/pdb_file.h"
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
  PdbStream* dbi_stream = pdb_file.GetStream(kDbiStream).get();
  if (dbi_stream == NULL)
    return false;

  DbiHeader dbi_header = {};
  if (!dbi_stream->ReadBytesAt(0, sizeof(dbi_header), &dbi_header))
    return false;

  DbiDbgHeader dbg_header = {};
  size_t offset = GetDbiDbgHeaderOffset(dbi_header);
  if (!dbi_stream->ReadBytesAt(offset, sizeof(dbg_header), &dbg_header))
    return false;

  // We expect both the OMAP stream IDs to exist.
  if (dbg_header.omap_to_src < 0 || dbg_header.omap_from_src < 0)
    return false;

  // We expect both streams to exist.
  scoped_refptr<PdbStream> omap_to_stream =
      pdb_file.GetStream(dbg_header.omap_to_src);
  scoped_refptr<PdbStream> omap_from_stream =
      pdb_file.GetStream(dbg_header.omap_from_src);
  if (omap_to_stream == nullptr || omap_from_stream == nullptr)
    return false;

  DCHECK(omap_to_stream != nullptr && omap_from_stream != nullptr);
  // Read the streams if need be.
  size_t num_to = omap_to_stream->length() / sizeof(OMAP);
  if (omap_to != nullptr) {
    omap_to->resize(num_to);
    if (num_to &&
        !omap_to_stream->ReadBytesAt(0, num_to * sizeof(OMAP),
                                     &omap_to->at(0))) {
      omap_to->clear();
      return false;
    }
  }

  if (omap_from != nullptr) {
    size_t num_from = omap_from_stream->length() / sizeof(OMAP);
    omap_from->resize(num_from);
    if (num_from &&
        !omap_from_stream->ReadBytesAt(0, num_from * sizeof(OMAP),
                                       &omap_from->at(0))) {
      omap_from->clear();
      return false;
    }
  }

  return true;
}

bool ReadOmapsFromPdbFile(const base::FilePath& pdb_path,
                          std::vector<OMAP>* omap_to,
                          std::vector<OMAP>* omap_from) {
  PdbReader pdb_reader;
  PdbFile pdb_file;
  if (!pdb_reader.Read(pdb_path, &pdb_file))
    return false;
  return ReadOmapsFromPdbFile(pdb_file, omap_to, omap_from);
}

}  // namespace pdb
