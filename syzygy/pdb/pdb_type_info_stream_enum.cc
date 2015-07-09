// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_type_info_stream_enum.h"

#include "base/strings/stringprintf.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

TypeInfoEnumerator::TypeInfoEnumerator(PdbStream* stream)
    : stream_(stream),
      start_position_(0),
      data_end_(0),
      len_(0),
      type_(0),
      type_id_(0),
      type_id_max_(0),
      type_id_min_(0) {
  DCHECK(stream_ != NULL);
}

bool TypeInfoEnumerator::EndOfStream() {
  DCHECK(stream_ != NULL);
  return stream_->pos() >= data_end_;
}

bool TypeInfoEnumerator::ReadTypeInfoHeader(TypeInfoHeader* type_info_header) {
  DCHECK(stream_ != NULL);
  DCHECK(type_info_header != NULL);

  // Reads the header of the stream.
  if (!stream_->Seek(0) || !stream_->Read(type_info_header, 1)) {
    LOG(ERROR) << "Unable to read the type info stream header.";
    return false;
  }

  if (stream_->pos() != type_info_header->len) {
    LOG(ERROR) << "Unexpected length for the type info stream header (expected "
               << type_info_header->len << ", read " << stream_->pos() << ").";
    return false;
  }

  data_end_ = type_info_header->len + type_info_header->type_info_data_size;

  if (data_end_ != stream_->length()) {
    LOG(ERROR) << "The type info stream is not valid.";
    return false;
  }

  // The type ID of each entry is not present in the stream, instead of that we
  // know the first and the last type ID and we know that the type records are
  // ordered in increasing order in the stream.
  type_id_ = type_info_header->type_min - 1;
  type_id_min_ = type_id_;
  type_id_max_ = type_info_header->type_max;
  return true;
}

bool TypeInfoEnumerator::NextTypeInfoRecord() {
  if (stream_->pos() >= data_end_)
    return false;

  // Right now we are interested only in the length, the starting position and
  // the type of the record.
  if (!stream_->Read(&len_, 1)) {
    LOG(ERROR) << "Unable to read a type info record length.";
    return false;
  }
  if (!stream_->Read(&type_, 1)) {
    LOG(ERROR) << "Unable to read a type info record type.";
    return false;
  }

  start_position_ = stream_->pos();
  len_ -= sizeof(type_);

  if (!stream_->Seek(start_position_ + len_)) {
    LOG(ERROR) << "Unable to seek to the end of the type info record.";
    return false;
  }

  ++type_id_;
  if (stream_->pos() >= data_end_ && (type_id_ + 1) != type_id_max_) {
    LOG(ERROR) << "Unexpected number of type info records in the type info "
               << "stream (expected " << type_id_max_ - type_id_min_
               << ", read " << type_id_ - type_id_min_ + 1 << ").";
    return false;
  }
  return true;
}

}  // namespace pdb
