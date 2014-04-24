// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/core/file_util.h"

#include "base/file_util.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/com_utils.h"

namespace core {

namespace {

enum FileInformationResult {
  kFileNotFound,
  kSuccess,
  kFailure
};

// Gets a handle to a file, and the file information for it. Leaves the handle
// open.
FileInformationResult GetFileInformation(
    const base::FilePath& path,
    base::win::ScopedHandle* handle,
    BY_HANDLE_FILE_INFORMATION* file_info) {
  // Open the file in the least restrictive possible way.
  handle->Set(
      ::CreateFile(path.value().c_str(),
                   SYNCHRONIZE,
                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                   NULL,
                   OPEN_EXISTING,
                   FILE_ATTRIBUTE_NORMAL,
                   NULL));
  if (!handle->IsValid()) {
    // The file not being found is a special case.
    DWORD error = ::GetLastError();
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
      return kFileNotFound;

    LOG(ERROR) << "Unable to open \"" << path.value() << "\": "
               << common::LogWe(error);
    return kFailure;
  }

  if (!::GetFileInformationByHandle(handle->Get(), file_info)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "GetFileInformationByHandle failed for \"" << path.value()
               << "\": " << common::LogWe(error);
    return kFailure;
  }

  return kSuccess;
}

}  // namespace

FilePathCompareResult CompareFilePaths(const base::FilePath& path1,
                                       const base::FilePath& path2) {
  // Now we try opening both files for reading to see if they point to the same
  // underlying volume and file index. We open both files simultaneously to
  // avoid a race condition whereby the file could be moved/removed in between
  // the two calls to GetFileInformation.

  base::win::ScopedHandle handle1;
  BY_HANDLE_FILE_INFORMATION info1 = {};
  FileInformationResult result1 = GetFileInformation(path1, &handle1, &info1);
  if (result1 == kFailure)
    return kFilePathCompareError;

  base::win::ScopedHandle handle2;
  BY_HANDLE_FILE_INFORMATION info2 = {};
  FileInformationResult result2 = GetFileInformation(path2, &handle2, &info2);
  if (result2 == kFailure)
    return kFilePathCompareError;

  // If neither file exists we can't really compare them based on anything
  // other than the path itself.
  if (result1 == kFileNotFound && result2 == kFileNotFound) {
    base::FilePath abs1(MakeAbsoluteFilePath(path1));
    base::FilePath abs2(MakeAbsoluteFilePath(path2));

    if (abs1.empty() || abs2.empty())
      return kUnableToCompareFilePaths;

    if (abs1 == abs2)
      return kEquivalentFilePaths;

    return kUnableToCompareFilePaths;
  }

  // If only one of them exists, then they can't possibly be the same file.
  if (result1 == kFileNotFound || result2 == kFileNotFound)
    return kDistinctFilePaths;

  // If they both exist we compare the details of where they live on disk.
  bool identical = info1.dwVolumeSerialNumber == info2.dwVolumeSerialNumber &&
      info1.nFileIndexLow == info2.nFileIndexLow &&
      info1.nFileIndexHigh == info2.nFileIndexHigh;

  return identical ? kEquivalentFilePaths : kDistinctFilePaths;
}

namespace {

// A struct for storing magic signatures for a given file type.
struct FileMagic {
  FileType file_type;
  size_t magic_size;
  const uint8* magic;
};

// Macros for defining magic signatures for files.
#define DEFINE_BINARY_MAGIC(type, bin)  \
    { type, arraysize(bin), bin }
#define DEFINE_STRING_MAGIC(type, str)  \
    { type, arraysize(str) - 1, str }  // Ignores the trailing NUL.

// Magic signatures used by various file types.
// Archive (.lib) files begin with a simple string.
const uint8 kArchiveFileMagic[] = "!<arch>";
// Machine independent COFF files begin with 0x00 0x00, and then two bytes
// that aren't 0xFF 0xFF. LTCG object files (unsupported) are followed by
// 0xFF 0xFF.
const uint8 kCoffFileMagic1[] = { 0x00, 0x00, 0xFF, 0xFF };
const uint8 kCoffFileMagic2[] = { 0x00, 0x00 };
// X86 COFF files begin with 0x4c 0x01.
const uint8 kCoffFileMagic3[] = { 0x4C, 0x01 };
const uint8 kPdbFileMagic[] = "Microsoft C/C++ MSF ";
// PE files all contain DOS stubs, and the first two bytes of 16-bit DOS
// exectuables are always "MZ".
const uint8 kPeFileMagic[] = "MZ";
// This is a dummy resource file entry that also reads as an invalid 16-bit
// resource. This allows MS tools to distinguish between 16-bit and 32-bit
// resources. We only care about 32-bit resources, and this is sufficient for
// us to distinguish between a resource file and a COFF object file.
const uint8 kResourceFileMagic[] = {
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Simple magic signatures for files.
const FileMagic kFileMagics[] = {
  DEFINE_BINARY_MAGIC(kResourceFileType, kResourceFileMagic),
  DEFINE_STRING_MAGIC(kPdbFileType, kPdbFileMagic),
  DEFINE_STRING_MAGIC(kArchiveFileType, kArchiveFileMagic),
  // This effectively emulates a more complicated if-then-else expression,
  // by mapping some COFF files to an unknown file type.
  DEFINE_BINARY_MAGIC(kUnknownFileType, kCoffFileMagic1),
  DEFINE_BINARY_MAGIC(kCoffFileType, kCoffFileMagic2),
  DEFINE_BINARY_MAGIC(kCoffFileType, kCoffFileMagic3),
  DEFINE_STRING_MAGIC(kPeFileType, kPeFileMagic),
};

#undef DEFINE_BINARY_MAGIC
#undef DEFINE_STRING_MAGIC

}  // namespace

bool GuessFileType(const base::FilePath& path, FileType* file_type) {
  DCHECK(!path.empty());
  DCHECK(file_type != NULL);

  *file_type = kUnknownFileType;

  if (!file_util::PathExists(path)) {
    LOG(ERROR) << "File does not exist: " << path.value();
    return false;
  }

  size_t file_size = 0;
  {
    int64 temp_file_size = 0;
    if (!file_util::GetFileSize(path, &temp_file_size)) {
      LOG(ERROR) << "Unable to get file size: " << path.value();
      return false;
    }
    DCHECK_LE(0, temp_file_size);
    file_size = static_cast<size_t>(temp_file_size);
  }

  // No point trying to identify an empty file.
  if (file_size == 0)
    return true;

  file_util::ScopedFILE file(file_util::OpenFile(path, "rb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open file for reading: " << path.value();
    return false;
  }

  // Check all of the magic signatures.
  std::vector<uint8> magic;
  for (size_t i = 0; i < arraysize(kFileMagics); ++i) {
    const FileMagic& file_magic = kFileMagics[i];

    // Try to read sufficient data for the current signature, bounded by the
    // available data in the file.
    if (magic.size() < file_size && magic.size() < file_magic.magic_size) {
      size_t old_size = magic.size();
      size_t new_size = std::min(file_size, file_magic.magic_size);
      DCHECK_LT(old_size, new_size);
      magic.resize(new_size);
      size_t missing = new_size - old_size;
      size_t read = ::fread(magic.data() + old_size, 1, missing, file.get());
      if (read != missing) {
        LOG(ERROR) << "Failed to read magic bytes from file: " << path.value();
        return false;
      }
    }

    // There is insufficient data to compare with this signature.
    if (magic.size() < file_magic.magic_size)
      continue;

    // If the signature matches then we can return the recognized type.
    if (::memcmp(magic.data(), file_magic.magic, file_magic.magic_size) == 0) {
      *file_type = file_magic.file_type;
      return true;
    }
  }

  DCHECK_EQ(kUnknownFileType, *file_type);
  return true;
}

}  // namespace core
