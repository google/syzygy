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

#include "syzygy/ar/ar_transform.h"

#include "base/bind.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/memory/scoped_vector.h"
#include "base/strings/stringprintf.h"
#include "syzygy/ar/ar_reader.h"
#include "syzygy/ar/ar_writer.h"

namespace ar {

namespace {

// Helper struct to delete a file when this object goes out of scope.
struct FileDeleter {
  explicit FileDeleter(const base::FilePath& path) : path_(path) {
  }

  ~FileDeleter() {
    if (!base::DeleteFile(path_, false))
      LOG(WARNING) << "Unable to delete file: " << path_.value();
  }

  const base::FilePath& path_;
};

}  // namespace

bool ArTransform::Transform() {
  DCHECK(!input_archive_.empty());
  DCHECK(!output_archive_.empty());
  DCHECK(!callback_.is_null());

  ArReader reader;
  if (!reader.Init(input_archive_))
    return false;
  LOG(INFO) << "Read " << reader.symbols().size() << " symbols.";

  // This collection of buffers must outlive the ArWriter below.
  ScopedVector<DataBuffer> buffers;

  // Iterate over the files in the archive.
  ArWriter writer;
  for (size_t i = 0; i < reader.offsets().size(); ++i) {
    // Extract the next file.
    ParsedArFileHeader header;
    scoped_ptr<DataBuffer> buffer(new DataBuffer());
    if (!reader.ExtractNext(&header, buffer.get()))
      return false;

    LOG(INFO) << "Processing file " << (i + 1) << " of "
              << reader.offsets().size() << ": " << header.name;

    // Apply the transform to this file.
    bool remove = false;
    if (!callback_.Run(&header, buffer.get(), &remove))
      return false;

    if (remove)
      continue;

    // Add the transformed file to the output archive.
    if (!writer.AddFile(header.name, header.timestamp, header.mode,
                        buffer.get())) {
      return false;
    }

    // Save the buffer so we keep it around until the writer has finished.
    buffers.push_back(buffer.release());
  }

  if (!writer.Write(output_archive_))
    return false;
  LOG(INFO) << "Wrote " << writer.symbols().size() << " symbols.";

  return true;
}

OnDiskArTransformAdapter::OnDiskArTransformAdapter(
    TransformFileOnDiskCallback inner_callback)
    : inner_callback_(inner_callback),
      outer_callback_(base::Bind(&OnDiskArTransformAdapter::Transform,
                                 base::Unretained(this))),
      index_(0) {
}

OnDiskArTransformAdapter::~OnDiskArTransformAdapter() {
  if (!base::DeleteFile(temp_dir_, true)) {
    LOG(WARNING) << "Unable to delete temporary directory: "
                 << temp_dir_.value();
  }
}

bool OnDiskArTransformAdapter::Transform(ParsedArFileHeader* header,
                                         DataBuffer* contents,
                                         bool* remove) {
  if (temp_dir_.empty()) {
    if (!base::CreateNewTempDirectory(L"OnDiskArTransformAdapter",
                                           &temp_dir_)) {
      LOG(ERROR) << "Unable to create temporary directory.";
      return false;
    }
  }

  // Create input and output file names.
  base::FilePath input_path = temp_dir_.Append(
      base::StringPrintf(L"input-%04d.obj", index_));
  base::FilePath output_path = temp_dir_.Append(
      base::StringPrintf(L"output-%04d.obj", index_));
  ++index_;

  // Set up deleters for these files.
  FileDeleter input_deleter(input_path);
  FileDeleter output_deleter(output_path);

  if (base::WriteFile(input_path,
                      reinterpret_cast<const char*>(contents->data()),
                      contents->size()) !=
          static_cast<int>(contents->size())) {
    LOG(ERROR) << "Unable to write file: " << input_path.value();
    return false;
  }

  // Delegate to the wrapped callback.
  if (!inner_callback_.Run(input_path, output_path, header, remove))
    return false;

  // If the file is being removed we don't need to bother reading it.
  if (*remove)
    return true;

  // GetFileSize and ReadFile will both fail in this case, but we can provide
  // a more meaningful error message by first doing this check.
  if (!base::PathExists(output_path)) {
    LOG(ERROR) << "File does not exist: " << output_path.value();
    return false;
  }

  // Read the transformed file from disk.
  int64 size = 0;
  if (!base::GetFileSize(output_path, &size)) {
    LOG(ERROR) << "Unable to read size of file: " << output_path.value();
    return false;
  }
  contents->resize(size);
  if (base::ReadFile(output_path,
                           reinterpret_cast<char*>(contents->data()),
                           contents->size()) !=
          static_cast<int>(contents->size())) {
    LOG(ERROR) << "Unable to read file: " << output_path.value();
    return false;
  }

  return true;
}

}  // namespace ar
