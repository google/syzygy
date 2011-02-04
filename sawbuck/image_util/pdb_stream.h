// Copyright 2010 Google Inc.
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
#ifndef SAWBUCK_IMAGE_UTIL_PDB_STREAM_H_
#define SAWBUCK_IMAGE_UTIL_PDB_STREAM_H_

#include <vector>
#include "base/basictypes.h"
#include "base/ref_counted.h"
#include "base/scoped_ptr.h"

class PdbStream : public base::RefCounted<PdbStream> {
 public:
  PdbStream(uint8* stream, uint32 size);
  ~PdbStream();

  uint8* stream() const { return stream_.get(); }
  uint32 size() const { return size_; }

 private:
  friend base::RefCounted<PdbStream>;

  scoped_array<uint8> stream_;
  uint32 size_;
};

typedef std::vector<scoped_refptr<PdbStream> > PdbStreamList;

#endif  // SAWBUCK_IMAGE_UTIL_PDB_STREAM_H_
