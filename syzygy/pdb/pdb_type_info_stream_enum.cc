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

TypeInfoEnumerator::TypeInfoEnumerator(PdbStream* stream)
    : stream_(stream),
      reader_(stream),
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

bool TypeInfoEnumerator::Init() {
  DCHECK(stream_ != nullptr);

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

  largest_encountered_id_ = type_id_min_ - 1;
  // Save the location of the first type record in the map.
  bool added = AddStartPosition(type_id_min_, stream_->pos());
  DCHECK(added);

  // Position our parsing reader at the start of the first type record.
  reader_.Consume(stream_->pos());

  return true;
}

bool TypeInfoEnumerator::NextTypeInfoRecord() {
  DCHECK(stream_ != nullptr);

  if (!EnsureTypeLocated(type_id_ + 1))
    return false;
  size_t position = 0;
  bool found = FindStartPosition(type_id_ + 1, &position);
  if (!found) {
    LOG(ERROR) << "Can't locate record " << type_id_ + 1;
    return false;
  }

  if (!stream_->Seek(position)) {
    LOG(ERROR) << "Can't seek to record " << type_id_ + 1;
    return false;
  }

  // Right now we are interested only in the length, the starting position and
  // the type of the record.
  uint16_t len = 0;
  uint16_t type = 0;
  if (!stream_->Read(&len, 1)) {
    LOG(ERROR) << "Unable to read a type info record length.";
    return false;
  }
  if (!stream_->Read(&type, 1)) {
    LOG(ERROR) << "Unable to read a type info record type.";
    return false;
  }

  ++type_id_;
  start_position_ = position;
  len_ = len - sizeof(type_);
  type_ = type;

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

  if (!EnsureTypeLocated(type_id))
    return false;

  // Set the type id cursor one back and advance it.
  type_id_ = type_id - 1;
  return NextTypeInfoRecord();
}

bool TypeInfoEnumerator::ResetStream() {
  DCHECK(stream_ != nullptr);
  return SeekRecord(type_id_min_);
}

bool TypeInfoEnumerator::EnsureTypeLocated(uint32_t type_id) {
  DCHECK(stream_ != nullptr);

  if (type_id >= type_id_max_ || type_id < type_id_min_)
    return false;
  if (type_id <= largest_encountered_id_)
    return true;

  size_t position = 0;
  bool found = FindStartPosition(largest_encountered_id_, &position);
  DCHECK(found);
  DCHECK_EQ(position, reader_.Position());

  uint32_t current_type_id = largest_encountered_id_;
  common::BinaryStreamParser parser(&reader_);
  while (current_type_id < type_id) {
    uint16_t len = 0;
    uint16_t type = 0;
    if (!parser.Read(&len)) {
      LOG(ERROR) << "Unable to read a type info record length.";
      return false;
    }
    if (!parser.Read(&type)) {
      LOG(ERROR) << "Unable to read a type info record type.";
      return false;
    }
    if (!reader_.Consume(len - sizeof(type))) {
      LOG(ERROR) << "Unable consume type body.";
      return false;
    }

    ++current_type_id;
    bool added = AddStartPosition(current_type_id, reader_.Position());
    DCHECK(added);
  }

  return type_id == current_type_id;
}

bool TypeInfoEnumerator::AddStartPosition(uint32_t type_id, size_t position) {
  if (type_id >= type_id_max_ || type_id < type_id_min_)
    return false;

  DCHECK_EQ(largest_encountered_id_ + 1, type_id);
  DCHECK_EQ(start_positions_.size(),
            largest_encountered_id_ - type_id_min_ + 1);

  start_positions_.push_back(position);
  largest_encountered_id_ = type_id;

  return true;
}

bool TypeInfoEnumerator::FindStartPosition(uint32_t type_id, size_t* position) {
  DCHECK(position);
  if (type_id >= type_id_max_ || type_id < type_id_min_)
    return false;

  DCHECK_GT(start_positions_.size(), type_id - type_id_min_);
  *position = start_positions_[type_id - type_id_min_];
  return true;
}

}  // namespace pdb
