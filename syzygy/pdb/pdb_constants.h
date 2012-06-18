// Copyright 2012 Google Inc.
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
#ifndef SYZYGY_PDB_PDB_CONSTANTS_H_
#define SYZYGY_PDB_PDB_CONSTANTS_H_

#include "base/basictypes.h"

namespace pdb {

// The index of the Pdb info header stream.
const size_t kPdbHeaderInfoStream = 1;

// The version we've observed in the Pdb info header.
const uint32 kPdbCurrentVersion = 20000404;

// The signature we've observed in the section contribs substream of the Pdb Dbi
// stream.
const uint32 kPdbDbiSectionContribsSignature = 0xF12EBA2D;

// The signature we've observed in the EC info substream of the Pdb Dbi stream.
const uint32 kPdbDbiEcInfoSignature = 0xEFFEEFFE;

// The version we've observed in the EC info substream of the Pdb Dbi stream.
const uint32 kPdbDbiEcInfoVersion = 1;

// The index of the Tpi (Type info) stream.
const size_t kTpiStream = 2;

// The index of the Dbi info stream.
const size_t kDbiStream = 3;

// This is the magic value found at the start of all MSF v7.00 files.
extern const uint8 kPdbHeaderMagicString[32];

// The maximum number of root pages in the Multi-Stream Format (MSF) header.
// See http://code.google.com/p/pdbparser/wiki/MSF_Format
extern const uint32 kPdbMaxDirPages;

// This is the Multi-Stream Format (MSF) page size generally used for PDB
// files. Check bytes 32 through 35 (little endian) of any PDB file.
const uint32 kPdbPageSize = 1024;

// The named PDB stream containing the history of Syzygy transformations applied
// to an image. This consists of a sequence of Metadata objects.
extern const char kSyzygyHistoryStreamName[];

// The version of the Syzygy history stream. This needs to be incremented
// whenever the format of the stream has changed.
const uint32 kSyzygyHistoryStreamVersion = 0;

// The named PDB stream containing the serialized BlockGraph of an image.
extern const char kSyzygyBlockGraphStreamName[];

// The version of the Syzygy BlockGraph data stream. This needs to be
// incremented whenever the format of the stream has changed.
const uint32 kSyzygyBlockGraphStreamVersion = 0;

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_CONSTANTS_H_
