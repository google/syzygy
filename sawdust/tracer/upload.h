// Copyright 2011 Google Inc.
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
// The tool for uploading tracer's result to the crash server.

#ifndef SAWDUST_TRACER_UPLOAD_H_
#define SAWDUST_TRACER_UPLOAD_H_

#include <windows.h>
#include <iostream>  // NOLINT - streams used as abstracts, without formatting.

#include "base/file_path.h"

// A single entry corresponding to a file in the target archive. The purpose of
// istream masquerade is to have consistent interface to binary files (logs) and
// whatever other content we might want to write. These streams are never used
// through operators and serve only as carriers of buffers.
class IReportContentEntry {
 public:
  virtual ~IReportContentEntry() {}

  // A data stream. The client should hold and read the reference until it is
  // done and then call 'MarkCompleted'.
  virtual std::istream& Data() = 0;

  // The file name that should be associated with the stream when it is sent to
  // its destination.
  virtual const char * Title() const = 0;

  // Signals to the object that the client who requested the data stream (Data
  // call) is done with it. Implementation is now free to do whatever it feels
  // appropriate with data underlying the stream returned by Data.
  virtual void MarkCompleted() = 0;
};

// Iterator-container serving subsequent streams. The protocol of GetNextEntry
// is as follows: (1) if there is a stream wrapper yet unserved, assign it to
// *entry and return S_OK; (b) if there is no more data, return S_FALSE and
// assign NULL to entry; (3) in case of an error, return the error code leaving
// *entry alone.
class IReportContent {
 public:
  virtual ~IReportContent() {}

  // An implementation of IReportContent retains the ownership of *|entry|.
  virtual HRESULT GetNextEntry(IReportContentEntry** entry) = 0;
};

class ReportUploader {
 public:
  ReportUploader(const std::wstring& target, bool local);
  virtual ~ReportUploader();

  // This should take a list of streams (or 'stream factories' to archive)
  HRESULT Upload(IReportContent* content);

  // UploadArchive is invoked by Upload, but it is left public to permit GUI-
  // driven re-tries.
  virtual HRESULT UploadArchive();

  // Retrieve the archive path (valid only after the process has started).
  bool GetArchivePath(FilePath* archive_path) const;

  // Sets the 'abort' flag and returns immediately.
  void SignalAbort();

 protected:
  // Write the entire |content| into zip file at temp_archive_path_.
  HRESULT ZipContent(IReportContent* content);

  // Remove the temporary archive from the local drive.
  void ClearTemporaryData();

  // Upload the file under |file_path| to a remote server (HTTP POST request).
  static HRESULT UploadToCrashServer(const wchar_t* file_path,
                                     const wchar_t* url,
                                     std::wstring* response);

  // A test seam.
  virtual bool MakeTemporaryPath(FilePath* tmp_file_path) const;

 private:
  HRESULT WriteEntryIntoZip(void* zip_handle, IReportContentEntry* entry);

  std::wstring uri_target_;  // Upload target path.
  bool remote_upload_;  // Is uri_target_ a HTTP location or a local path.
  FilePath temp_archive_path_;  // Points at the zip archive while created.
  bool abort_;  // Signals that compression and upload is to be abandoned.

  DISALLOW_COPY_AND_ASSIGN(ReportUploader);
};

#endif  // SAWDUST_TRACER_UPLOAD_H_
