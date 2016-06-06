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
      data_end_(0),
      current_record_{},
      type_id_(0),
      type_id_max_(0),
      type_id_min_(0),
      largest_located_id_(0) {
  memset(&type_info_header_, 0, sizeof(type_info_header_));
}

bool TypeInfoEnumerator::EndOfStream() {
  if (type_id_ + 1 == type_id_max_)
    return true;

  return false;
}

bool TypeInfoEnumerator::Init() {
  DCHECK(stream_ != nullptr);

  common::BinaryStreamParser parser(&reader_);
  // Reads the header of the stream.
  if (!parser.Read(&type_info_header_)) {
    LOG(ERROR) << "Unable to read the type info stream header.";
    return false;
  }

  if (reader_.Position() != type_info_header_.len) {
    LOG(ERROR) << "Unexpected length for the type info stream header (expected "
               << type_info_header_.len << ", read " << reader_.Position()
               << ").";
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

  largest_located_id_ = type_id_min_ - 1;
  // Locate the first type info record - note that this may fail if the
  // stream is invalid or empty.
  return EnsureTypeLocated(type_id_min_);
}

bool TypeInfoEnumerator::NextTypeInfoRecord() {
  DCHECK(stream_ != nullptr);

  if (!EnsureTypeLocated(type_id_ + 1))
    return false;
  TypeRecordInfo info = {};
  bool found = FindRecordInfo(type_id_ + 1, &info);
  if (!found) {
    LOG(ERROR) << "Can't locate record " << type_id_ + 1;
    return false;
  }

  ++type_id_;
  current_record_ = info;

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

TypeInfoEnumerator::BinaryTypeRecordReader
TypeInfoEnumerator::CreateRecordReader() {
  return BinaryTypeRecordReader(start_position(), len(), stream_.get());
}

bool TypeInfoEnumerator::EnsureTypeLocated(uint32_t type_id) {
  DCHECK(stream_ != nullptr);

  if (type_id >= type_id_max_ || type_id < type_id_min_)
    return false;
  if (type_id <= largest_located_id_)
    return true;

#ifndef NDEBUG
  if (type_id > type_id_min_) {
    TypeRecordInfo info = {};
    bool found = FindRecordInfo(largest_located_id_, &info);
    DCHECK(found);
    DCHECK_EQ(info.start + info.length + sizeof(info.length),
              reader_.Position());
  }
#endif

  uint32_t current_type_id = largest_located_id_;
  common::BinaryStreamParser parser(&reader_);
  while (current_type_id < type_id) {
    TypeRecordInfo next_info = {};
    next_info.start = reader_.Position();
    if (!parser.Read(&next_info.length)) {
      LOG(ERROR) << "Unable to read a type info record length.";
      return false;
    }
    if (!parser.Read(&next_info.type)) {
      LOG(ERROR) << "Unable to read a type info record type.";
      return false;
    }
    if (!reader_.Consume(next_info.length - sizeof(next_info.type))) {
      LOG(ERROR) << "Unable to consume type body.";
      return false;
    }

    ++current_type_id;
    bool added = AddRecordInfo(current_type_id, next_info);
    DCHECK(added);
  }

  return type_id == current_type_id;
}

bool TypeInfoEnumerator::AddRecordInfo(uint32_t type_id,
                                       const TypeRecordInfo& info) {
  if (type_id >= type_id_max_ || type_id < type_id_min_)
    return false;

  DCHECK_EQ(largest_located_id_ + 1, type_id);
  DCHECK_EQ(located_records_.size(), largest_located_id_ - type_id_min_ + 1);

  located_records_.push_back(info);
  largest_located_id_ = type_id;

  return true;
}

bool TypeInfoEnumerator::FindRecordInfo(uint32_t type_id,
                                        TypeRecordInfo* info) {
  DCHECK(info);
  if (type_id >= type_id_max_ || type_id < type_id_min_)
    return false;

  DCHECK_GT(located_records_.size(), type_id - type_id_min_);
  *info = located_records_[type_id - type_id_min_];
  return true;
}

TypeInfoEnumerator::BinaryTypeRecordReader::BinaryTypeRecordReader(
    size_t start_offset,
    size_t len,
    PdbStream* stream)
    : PdbStreamReaderWithPosition(start_offset, len, stream) {
}

}  // namespace pdb
