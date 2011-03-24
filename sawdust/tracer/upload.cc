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
// Upload result logs to the crash server.

#include "sawdust/tracer/upload.h"

#include <atlstr.h>
#include <msxml.h>
#include <wininet.h>  // For win32 http error code.

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "third_party/zlib/contrib/minizip/zip.h"
#include "third_party/zlib/contrib/minizip/iowin32.h"

#include "sawdust/tracer/com_utils.h"

namespace {
// This function is derived from third_party/minizip/iowin32.c.
// Its only difference is that it treats the char* as UTF8 and
// uses the Unicode version of CreateFile.
// This version has been copied from chrome/common/zip.cc
typedef struct {
  HANDLE hf;
  int error;
} WIN32FILE_IOWIN;

const unsigned kZipBufferSize = 8192;

// A custom zip file-open function (see zipOpen2 in minizip/zip.h). Note that
// the allocated structure is owned by the caller (minizip library, that is).
// This a bit opaque, but: the return value is always treated as a stream handle
// (see struct layout), but released by free in win32_close_file_func.
void* ZipOpenFunc(void* opaque, const char* filename, int mode) {
  HANDLE file = 0;
  void* ret = NULL;
  const ReportUploader* invocation_origin =
      reinterpret_cast<const ReportUploader*>(opaque);
  FilePath path_obj;
  if (invocation_origin == NULL ||
      !invocation_origin->GetArchivePath(&path_obj)) {
    NOTREACHED() << "Failed to retrieve target file name.";
    return NULL;
  }

  DWORD desired_access = 0;
  DWORD creation_disposition = GENERIC_READ;
  DWORD share_mode = 0;
  DWORD flags_and_attributes = 0;

  if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER) == ZLIB_FILEFUNC_MODE_READ) {
    desired_access = GENERIC_READ;
    creation_disposition = OPEN_EXISTING;
    share_mode = FILE_SHARE_READ;
  } else if (mode & ZLIB_FILEFUNC_MODE_EXISTING) {
    desired_access = GENERIC_WRITE | GENERIC_READ;
    creation_disposition = OPEN_EXISTING;
  } else if (mode & ZLIB_FILEFUNC_MODE_CREATE) {
    desired_access = GENERIC_WRITE | GENERIC_READ;
    creation_disposition = CREATE_ALWAYS;
  }

  if ((!path_obj.empty()) && (desired_access != 0)) {
    file = CreateFile(path_obj.value().c_str(), desired_access, share_mode,
                      NULL, creation_disposition, flags_and_attributes, NULL);
  }

  if (file == INVALID_HANDLE_VALUE)
    file = NULL;

  if (file != NULL) {
    WIN32FILE_IOWIN file_ret;
    file_ret.hf = file;
    file_ret.error = 0;
    ret = malloc(sizeof(WIN32FILE_IOWIN));
    if (ret == NULL)
      CloseHandle(file);
    else
      *(static_cast<WIN32FILE_IOWIN*>(ret)) = file_ret;
  }
  return ret;
}
}

ReportUploader::ReportUploader(const std::wstring& target, bool local)
    : uri_target_(target),
      remote_upload_(!local),
      abort_(false) {
}

// The destructor will remove the temporary archive.
ReportUploader::~ReportUploader() {
  ClearTemporaryData();
}

HRESULT ReportUploader::Upload(IReportContent* content) {
  DCHECK(content != NULL);
  if (!MakeTemporaryPath(&temp_archive_path_))
    return E_ACCESSDENIED;

  HRESULT hr = ZipContent(content);  // Always into temp_archive_path_.

  if (FAILED(hr)) {
    // Try to remove the invalid file.
    LOG(ERROR) << "Failed to create the archive. The file will be deleted.";
    ClearTemporaryData();
    temp_archive_path_.clear();
    return hr;
  }

  hr = UploadArchive();

  if (SUCCEEDED(hr))  // If upload failed data is retained to allow a retry.
    ClearTemporaryData();

  return hr;
}

HRESULT ReportUploader::ZipContent(IReportContent* content) {
  // Create the zip file. Note we use custom file open operation.
  zlib_filefunc_def zip_funcs;
  fill_win32_filefunc(&zip_funcs);
  zip_funcs.zopen_file = ZipOpenFunc;
  zip_funcs.opaque = reinterpret_cast<void*>(this);

  abort_ = false;
  zipFile archive_handle = zipOpen2("fake name", APPEND_STATUS_CREATE,
                                    NULL, &zip_funcs);
  if (archive_handle == NULL) {
    LOG(ERROR) << "couldn't create file " << temp_archive_path_.value();
    return false;
  }

  IReportContentEntry* entry = NULL;
  HRESULT hr = content->GetNextEntry(&entry);

  while (SUCCEEDED(hr) && entry) {
    if (abort_)
      hr = E_ABORT;
    else
      hr = WriteEntryIntoZip(archive_handle, entry);

    if (SUCCEEDED(hr)) {
      entry->MarkCompleted();
      hr = content->GetNextEntry(&entry);
    }
  }

  // Regardless the result, close the archive.
  int close_file_code = zipClose(archive_handle, NULL);
  if (close_file_code != ZIP_OK) {
    LOG(ERROR) << "Failed to properly close the zip archive. Code=" <<
        close_file_code;

    if (SUCCEEDED(hr))
      hr = E_UNEXPECTED;
  }
  return hr;
}

HRESULT ReportUploader::UploadArchive() {
  if (remote_upload_) {
    std::wstring reponse;
    HRESULT hr = UploadToCrashServer(temp_archive_path_.value().c_str(),
                                     uri_target_.c_str(), &reponse);
    LOG_IF(ERROR, FAILED(hr)) << "Upload failed. " << com::LogHr(hr);
    LOG_IF(INFO, !reponse.empty()) << "Server response: " << reponse;
    return hr;
  } else {
    // A simple file move will do.
    FilePath tgt_file(uri_target_);
    if (!file_util::Move(temp_archive_path_, tgt_file)) {
      NOTREACHED() << "Failed to move file to its target.";
      return E_ACCESSDENIED;
    }
    return S_OK;
  }
}

bool ReportUploader::GetArchivePath(FilePath* archive_path) const {
  if (!temp_archive_path_.empty() && archive_path != NULL)
    *archive_path = temp_archive_path_;
  return !temp_archive_path_.empty();
}


HRESULT ReportUploader::WriteEntryIntoZip(void* zip_vhandle,
                                          IReportContentEntry* entry) {
  // The purpose of shenanigans with the parameter type here is to avoid
  // including a third_party header into upload.h.
  zipFile zip_file = zip_vhandle;
  if (ZIP_OK != zipOpenNewFileInZip(zip_file,
                                    entry->Title(),
                                    NULL,  // No file info.
                                    NULL,  // No extrafield_local.
                                    0u,    // Size of extrafield_local (none).
                                    NULL,  // No extrafield_global.
                                    0u,    // Size of extrafield_global (none).
                                    NULL,  // No comment.
                                    Z_DEFLATED,  // Compression method.
                                    Z_DEFAULT_COMPRESSION)) {  // Level.
    LOG(ERROR) << "Could not open zip file entry " << entry->Title();
    return E_FAIL;
  }

  HRESULT hr = S_OK;
  // Write the content using provided stream.
  std::istream& data = entry->Data();

  char buffer[kZipBufferSize];

  bool keep_zipping = true;
  do {
    std::streamsize bytes_read = data.read(buffer, sizeof(buffer)).gcount();

    if (data.bad()) {
      LOG(ERROR) << "Reading from source stream " << entry->Title()
          << " failed.";
      hr = E_FAIL;
      keep_zipping = false;
    } else if (abort_) {
      keep_zipping = false;
      hr = E_ABORT;
    } else {
      if (ZIP_OK != zipWriteInFileInZip(zip_file, buffer, bytes_read)) {
        LOG(ERROR) << "Could not write data to zip for path " << entry->Title();
        hr = E_FAIL;
        keep_zipping = false;
      } else {
        keep_zipping = !data.eof();
      }
    }
  } while (keep_zipping);

  if (ZIP_OK != zipCloseFileInZip(zip_file)) {
    LOG(ERROR) << "Could not close zip file entry " << entry->Title();
    return E_FAIL;
  }

  return hr;
}

// The function executes POST to the specified crash server.
HRESULT ReportUploader::UploadToCrashServer(const wchar_t* file_path,
                                            const wchar_t* url,
                                            std::wstring* response) {
  DCHECK(file_path != NULL);
  DCHECK(url != NULL);
  DCHECK(response != NULL);

  HRESULT hr = ::CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  DCHECK(SUCCEEDED(hr));

  CComPtr<IXMLHttpRequest> request;

  // Create the http request object.
  hr = request.CoCreateInstance(CLSID_XMLHTTPRequest);

  if (FAILED(hr))
    return hr;

  // Open a stream to the file.
  CComPtr<IStream> stream;
  hr = SHCreateStreamOnFile(file_path, STGM_READ, &stream);

  if (FAILED(hr))
    return hr;

  // Open the request.
  CComVariant empty;
  CComVariant var_false(false);
  hr = request->open(CComBSTR("POST"), CComBSTR(url), var_false, empty, empty);

  if (FAILED(hr))
    return hr;

  request->setRequestHeader(CComBSTR("Content-Type"),
                            CComBSTR("application/zip"));
  int64 file_size = 0;
  if (file_util::GetFileSize(FilePath(file_path), &file_size) &&
      file_size > 0) {
    request->setRequestHeader(CComBSTR("Content-Length"),
                              CComBSTR(base::Int64ToString(file_size).c_str()));
  }

  // Send the file.
  hr = request->send(CComVariant(stream));

  if (FAILED(hr))
    return hr;

  long response_code = 0;  // NOLINT - used as in interface declaration.
  hr = request->get_status(&response_code);

  if (FAILED(hr))
    return hr;
  if (response_code < 200 || response_code >= 300)
    return AtlHresultFromWin32(ERROR_HTTP_INVALID_SERVER_RESPONSE);
  CComBSTR bresponse;
  hr = request->get_responseText(&bresponse);

  if (SUCCEEDED(hr) && NULL != response)
    *response = static_cast<const wchar_t*>(bresponse);

  return hr;
}

void ReportUploader::ClearTemporaryData() {
  if (!temp_archive_path_.empty() &&
      file_util::PathExists(temp_archive_path_)) {
    if (!file_util::Delete(temp_archive_path_, false))
      LOG(ERROR) << "Cannot delete file " << temp_archive_path_.value();
  }
}

void ReportUploader::SignalAbort() {
  abort_ = true;
}

// Delegate to file_util.
bool ReportUploader::MakeTemporaryPath(FilePath* tmp_file_path) const {
  return file_util::CreateTemporaryFile(tmp_file_path);
}
