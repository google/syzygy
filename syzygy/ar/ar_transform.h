// Copyright 2014 Google Inc. All Rights Reserved.
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
//
// Declares a utility class for iterating over all of the files in an
// archive and transforming them, before putting them back into a new
// archive. Work is performed via callbacks that the client registers.

#ifndef SYZYGY_AR_AR_TRANSFORM_H_
#define SYZYGY_AR_AR_TRANSFORM_H_

#include "base/callback.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "syzygy/ar/ar_common.h"

namespace ar {

// A class for transforming all of the object files contained in an
// archive, and repackaging them into an archive.
class ArTransform {
 public:
  // The type of callback that will be invoked for each object file
  // in the archive. If this returns true then the transform will
  // continue. If it returns false then the transform will terminate
  // with an error. Transforms modify the values in place.
  // |header| The header of the file.
  // |contents| The contents of the file.
  // |remove| If set to true then indicates that the file should be
  //     removed from the archive.
  typedef base::Callback<bool(ParsedArFileHeader* /* header */,
                              DataBuffer* /* contents */,
                              bool* /* remove */)>
      TransformFileCallback;

  // Constructor.
  ArTransform() { }

  // Applies the transform. The transform must already have been configured.
  // @returns true on success, false otherwise.
  bool Transform();

  // @name Mutators.
  // @{
  // Sets the input archive path.
  // @param input_archive The archive to be processed.
  void set_input_archive(const base::FilePath& input_archive) {
    DCHECK(!input_archive.empty());
    input_archive_ = input_archive;
  }

  // Sets the output archive path.
  // @param output_archive The archive to be produced.
  void set_output_archive(const base::FilePath& output_archive) {
    DCHECK(!output_archive.empty());
    output_archive_ = output_archive;
  }

  // Sets the callback.
  // @param callback The callback to be invoked.
  void set_callback(TransformFileCallback callback) {
    DCHECK(!callback.is_null());
    callback_ = callback;
  }
  // @}

  // @name Accessors.
  // @{
  // @returns the input archive path.
  const base::FilePath& input_archive() const { return input_archive_; }

  // @returns the output archive path.
  const base::FilePath& output_archive() const { return input_archive_; }

  // @returns the callback.
  TransformFileCallback callback() const { return callback_; }
  // @}

 private:
  base::FilePath input_archive_;
  base::FilePath output_archive_;
  TransformFileCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(ArTransform);
};

// A callback adapter that allows transforms to modify the files
// on disk rather than in memory. This is not thread safe.
class OnDiskArTransformAdapter {
 public:
  typedef ArTransform::TransformFileCallback TransformFileCallback;

  // The type of callback that will be invoked for each object file
  // in the archive. If this returns true then the transform will
  // continue. If it returns false then the transform will terminate
  // with an error. Transforms work on temporary files on disk.
  // |input_path| The path of the original file on disk.
  // |output_path| The path where the transformed file should be written.
  // |header| The header of the file.
  // |remove| If set to true then indicates that the file should be
  //     removed from the archive.
  typedef base::Callback<bool(const base::FilePath& /* input_path */,
                              const base::FilePath& /* output_path */,
                              ParsedArFileHeader* /* header */,
                              bool* /* remove */)>
      TransformFileOnDiskCallback;

  // Constructor.
  // @param inner_callback The callback that will be invoked by the adapter.
  explicit OnDiskArTransformAdapter(
      TransformFileOnDiskCallback inner_callback);

  // Destructor.
  ~OnDiskArTransformAdapter();

  // @name Accessors.
  // @{
  TransformFileOnDiskCallback& inner_callback() {
    return inner_callback_;
  }
  TransformFileCallback& outer_callback() {
    return outer_callback_;
  }
  // @}

 private:
  // The function that will be bound as the wrapped callback
  bool Transform(ParsedArFileHeader* header,
                 DataBuffer* contents,
                 bool* remove);

  // Wrapped and unwrapped callbacks.
  TransformFileOnDiskCallback inner_callback_;
  TransformFileCallback outer_callback_;

  // Temporary directory where files are produced.
  base::FilePath temp_dir_;
  size_t index_;
};

}  // namespace ar

#endif  // SYZYGY_AR_AR_TRANSFORM_H_
