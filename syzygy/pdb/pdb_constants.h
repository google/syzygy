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
#ifndef SYZYGY_PDB_PDB_CONSTANTS_H_
#define SYZYGY_PDB_PDB_CONSTANTS_H_

#include <stdint.h>

namespace pdb {

// The index of the Pdb old directory stream.
const size_t kPdbOldDirectoryStream = 0;

// The index of the Pdb info header stream.
const size_t kPdbHeaderInfoStream = 1;

// The version we've observed in the Pdb info header.
const uint32_t kPdbCurrentVersion = 20000404;

// The signature we've observed in the section contribs substream of the Pdb Dbi
// stream.
const uint32_t kPdbDbiSectionContribsSignature = 0xF12EBA2D;

// The signature we've observed for the string tables of the Pdb.
const uint32_t kPdbStringTableSignature = 0xEFFEEFFE;

// The version we've observed for the string tables of the Pdb.
const uint32_t kPdbStringTableVersion = 1;

// The index of the Tpi (Type info) stream.
const size_t kTpiStream = 2;

// The index of the Ipi (ID info) stream. This is of the same layout as the
// Tpi stream.
const size_t kIpiStream = 4;

// The version we've observed for the Tpi stream.
const uint32_t kTpiStreamVersion = 0x0131CA0B;

// The index of the first user-defined type.
// Indexes in range 0x0-0xFFF are reserved.
// See http://www.openwatcom.org/ftp/devel/docs/CodeView.pdf, section 5.
const uint32_t kTpiStreamFirstUserTypeIndex = 0x1000;

// The values we've observed for the hash key and hash buckets fields in the
// header of an empty Tpi stream. See the pdb::TypeInfoHashHeader struct.
const uint32_t kTpiStreamEmptyHashKey = 0x4;
const uint32_t kTpiStreamEmptyHashBuckets = 0x8003;

// The index of the Dbi info stream.
const size_t kDbiStream = 3;

// The version we've observed for the Dbi stream.
const uint32_t kDbiStreamVersion = 0x01310977;

// The signature we've observed in the header of the public stream.
const uint32_t kPublicStreamSignature = 0xF12F091A;

// The named PDB stream containing the history of Syzygy transformations applied
// to an image. This consists of a sequence of Metadata objects.
extern const char kSyzygyHistoryStreamName[];

// The version of the Syzygy history stream. This needs to be incremented
// whenever the format of the stream has changed.
const uint32_t kSyzygyHistoryStreamVersion = 0;

// The named PDB stream containing the serialized BlockGraph of an image.
extern const char kSyzygyBlockGraphStreamName[];

// The version of the Syzygy BlockGraph data stream. This needs to be
// incremented whenever the format of the stream has changed.
const uint32_t kSyzygyBlockGraphStreamVersion = 1;

}  // namespace pdb

#endif  // SYZYGY_PDB_PDB_CONSTANTS_H_
