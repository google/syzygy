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
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

TypeInfoEnumerator::TypeInfoEnumerator()
    : stream_(nullptr),
      start_position_(0),
      data_end_(0),
      data_stream_(new PdbByteStream()),
      len_(0),
      type_(0),
      type_id_(0),
      type_id_max_(0),
      type_id_min_(0),
      largest_encountered_id_(0) {
  memset(&type_info_header_, 0, sizeof(type_info_header_));
}

bool TypeInfoEnumerator::EndOfStream() {
  DCHECK(stream_ != nullptr);
  return stream_->pos() >= data_end_;
}

bool TypeInfoEnumerator::Init(PdbStream* stream) {
  DCHECK(stream != nullptr);
  DCHECK(stream_ == nullptr);

  // We are making in memory copy of the whole stream.
  scoped_refptr<PdbByteStream> byte_stream = new PdbByteStream();
  byte_stream->Init(stream);
  stream_ = byte_stream.get();

  // Reads the header of the stream.
  if (!stream_->Seek(0) || !stream_->Read(&type_info_header_, 1)) {
    LOG(ERROR) << "Unable to read the type info stream header.";
    return false;
  }

  if (stream_->pos() != type_info_header_.len) {
    LOG(ERROR) << "Unexpected length for the type info stream header (expected "
               << type_info_header_.len << ", read " << stream_->pos() << ").";
    return false;
  }

  data_end_ = type_info_header_.len + type_info_header_.type_info_data_size;

  if (data_end_ != stream_->length()) {
    LOG(ERROR) << "The type info stream is not valid.";
    return false;
  }

  // The type ID of each entry is not present in the stream, instead of that we
  // know the first and the last type ID and we know that the indices of all the
  // records are consecutive numbers.
  type_id_ = type_info_header_.type_min - 1;
  type_id_min_ = type_info_header_.type_min;
  type_id_max_ = type_info_header_.type_max;

  // Save the location of the first type record in the map.
  start_positions_.insert(std::make_pair(type_id_min_, stream_->pos()));
  largest_encountered_id_ = type_id_min_;
  return true;
}

bool TypeInfoEnumerator::NextTypeInfoRecord() {
  DCHECK(stream_ != nullptr);

  if (stream_->pos() >= data_end_)
    return false;

  ++type_id_;
  largest_encountered_id_ = std::max(largest_encountered_id_, type_id_);

  // Save the location of this record in the map.
  start_positions_.insert(std::make_pair(type_id_, stream_->pos()));

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

  // TODO(siggi): Hoist this to a method, then replace the implementation.
  if (!data_stream_->Init(stream_.get(), len_)) {
    LOG(ERROR) << "Unable to read data of the type info record.";
    return false;
  }
  data_stream_->Seek(0);

  if (stream_->pos() >= data_end_ && type_id_ >= type_id_max_) {
    LOG(ERROR) << "Unexpected number of type info records in the type info "
               << "stream (expected " << type_id_max_ - type_id_min_
               << ", read " << type_id_ - type_id_min_ + 1 << ").";
    return false;
  }
  return true;
}

bool TypeInfoEnumerator::SeekRecord(uint32_t type_id) {
  DCHECK(stream_ != nullptr);

  if (type_id >= type_id_max_ || type_id < type_id_min_)
    return false;

  if (type_id > largest_encountered_id_) {
    stream_->Seek(start_positions_[largest_encountered_id_]);
    type_id_ = largest_encountered_id_ - 1;
    while (type_id_ < type_id) {
      if (!NextTypeInfoRecord())
        return false;
    }
    return type_id == type_id_;
  } else {
    stream_->Seek(start_positions_[type_id]);
    type_id_ = type_id - 1;
    return NextTypeInfoRecord();
  }
}

bool TypeInfoEnumerator::ResetStream() {
  DCHECK(stream_ != nullptr);

  return SeekRecord(type_id_min_);
}

}  // namespace pdb
