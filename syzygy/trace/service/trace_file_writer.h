// Copyright 2013 Google Inc. All Rights Reserved.
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
// This file declares the TraceFileWriter class, which encapsulates
// functionality for writing buffers of data to a trace file. This uses raw
// unbuffered writing to disk, and as such only writes multiples of the disk
// sector size.
//
// Intended use:
//
//   TraceFileWriter w;
//   if (!w.Open(path))
//     ...
//
//   // Use w.block_size() to make sure we are getting data with the appropriate
//   // block size.
//
//   if (!w.WriteHeader(process_info))
//     ...
//   while (...) {
//     if (!w.WriteRecord(buffer, length))
//       ...
//   }
//
//   if (!w.Close())
//     ...

#ifndef SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_H_
#define SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_H_

#include "base/files/file_path.h"
#include "base/win/scoped_handle.h"
#include "syzygy/trace/service/process_info.h"

namespace trace {
namespace service {

// A trace file writer encapsulates the bare minimum functionality necessary for
// writing a trace file. It is not thread-safe.
class TraceFileWriter {
 public:
  // Constructor.
  TraceFileWriter();

  // Destructor.
  ~TraceFileWriter();

  // Given information about a process, generates a suggested base filename for
  // a trace.
  // @param process_info Information about the process for which we are creating
  //     a trace file.
  // @returns A suggested basename for the trace file.
  static base::FilePath GenerateTraceFileBaseName(
      const ProcessInfo& process_info);

  // Opens a trace file at the given path.
  // @param path The path of the trace file to write.
  // @returns true on success, false otherwise.
  bool Open(const base::FilePath& path);

  // Writes the header to the trace file. A trace file is associated with a
  // single running process, so we require a populated process-info struct.
  // @param process_info Information about the process to which this trace file
  //     pertains.
  // @returns true on success, false otherwise.
  bool WriteHeader(const ProcessInfo& process_info);

  // Writes a record of data to disk.
  // @param data The record to be written. This must contain a RecordPrefix.
  //     This currently only supports records that contain a
  //     TraceFileSegmenHeader.
  // @param length The maximum length of continuous data that may be
  //     contained in the record. The actual length is stored in the header, but
  //     this is necessary to ensure that the header is valid.
  // @returns true on success, false otherwise.
  bool WriteRecord(const void* data, size_t length);

  // Closes the trace file.
  // @returns true on success, false otherwise.
  // @note If this is not called manually the trace-file will close itself when
  //     the writer goes out of scope.
  bool Close();

  // @returns the path to the trace file.
  // @note This is only valid after Open has returned successfully.
  base::FilePath path() const { return path_; }

  // @returns the block size.
  // @note This is only valid after Open has returned successfully.
  size_t block_size() const { return block_size_; }

 protected:
  // The path to the trace file being written.
  base::FilePath path_;

  // The handle to the file that's being written to.
  base::win::ScopedHandle handle_;

  // The block size being used by the trace file writer.
  size_t block_size_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TraceFileWriter);
};

}  // namespace service
}  // namespace trace

#endif  // SYZYGY_TRACE_SERVICE_TRACE_FILE_WRITER_H_
