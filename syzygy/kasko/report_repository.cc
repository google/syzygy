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
// -----------------
// Repository Format
// -----------------
//
// This file implements a repository for crash reports that are pending upload.
// The repository has a single root directory and creates several subdirectories
// beneath it:
//
// <root>/Incoming
// <root>/Retry
// <root>/Retry 2
//
// Reports are stored in the repository by creating a minidump file and passing
// its path, along with a dictionary of crash keys to StoreReport. The minidump
// will be moved into Incoming and its crash keys serialized alongside it. The
// minidump will be given a .dmp extension (if it doesn't already have one) and
// the crash keys will be in a file having the same basename and a '.kys'
// extension.
//
// After a successful upload, the minidump and crash keys files are deleted.
// After a failed upload, a report in "Incoming" will be moved to "Retry", a
// report in "Retry" to "Retry 2", and a report from "Retry 2" will be processed
// using the configured PermanentFailureHandler.
//
// When the repository receives or attempts to upload a report the report file
// timestamps are updated. While files in "Incoming" are always eligible for
// upload, those in "Retry" and "Retry 2" are eligible when their last-modified
// date is older than the configured retry interval.
//
// Orphaned report files (minidumps without crash keys and vice-versa) may be
// detected during upload attempts. When receiving new minidumps, we first write
// the crash keys to "Incoming" before moving the minidump file in. As a result,
// an orphaned minidump file is always an error condition and will be deleted
// immediately upon detection. An orphaned crash keys file may occur normally in
// the interval before the minidump file is moved. These files are only deleted
// when their timestamp is more than a day in the past.

#include "syzygy/kasko/report_repository.h"

#include "base/logging.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_util.h"
#include "syzygy/kasko/crash_keys_serialization.h"

namespace kasko {

namespace {

// The extension used when serializing crash keys.
const base::char16 kCrashKeysFileExtension[] = L".kys";
// The extension used to identify minidump files.
const base::char16 kDumpFileExtension[] = L".dmp";
// The subdirectory where new reports (minidumps and crash keys) are initially
// stored.
const base::char16 kIncomingReportsSubdir[] = L"Incoming";
// The subdirectory where reports that have failed once are stored.
const base::char16 kFailedOnceSubdir[] = L"Retry";
// The subdirectory where reports that have failed twice are stored.
const base::char16 kFailedTwiceSubdir[] = L"Retry 2";

// Deletes a path non-recursively and logs an error in case of failure.
// @param path The path to delete.
// @returns true if the operation succeeds.
bool LoggedDeleteFile(const base::FilePath& path) {
  bool result = base::DeleteFile(path, false);
  LOG_IF(ERROR, !result) << "Failed to delete " << path.value();
  return result;
}

// Takes ownership of a FilePath. The owned path will be deleted when the
// ScopedReportFile is destroyed.
class ScopedReportFile {
 public:
  explicit ScopedReportFile(const base::FilePath& path) : path_(path) {}

  ~ScopedReportFile() {
    if (!path_.empty())
      LoggedDeleteFile(path_);
  }

  // Provides access to the owned value.
  // @returns the owned path.
  base::FilePath Get() const { return path_; }

  // Releases ownership of the owned path.
  // @returns the owned path.
  base::FilePath Take() {
    base::FilePath temp = path_;
    path_ = base::FilePath();
    return temp;
  }

  // Moves the file pointed to by the owned path, and updates the owned path
  // to the new path.
  // @param new_path The full destination path.
  // @returns true if the operation succeeds.
  bool Move(const base::FilePath& new_path) {
    bool result = base::Move(path_, new_path);
    LOG_IF(ERROR, !result) << "Failed to move " << path_.value() << " to "
                           << new_path.value();
    if (result)
      path_ = new_path;
    return result;
  }

  // Sets the last-modified timestamp of the file pointed to by the owned path.
  // @param value The desired timestamp.
  // @returns true if the operation succeeds.
  bool UpdateTimestamp(const base::Time& value) {
    bool result = false;
    if (!path_.empty()) {
      result = base::TouchFile(path_, value, value);
      LOG_IF(ERROR, !result) << "Failed to update timestamp for "
                             << path_.value();
    }
    return result;
  }

 private:
  base::FilePath path_;

  DISALLOW_COPY_AND_ASSIGN(ScopedReportFile);
};

// Returns the crash keys file path corresponding to the supplied minidump file
// path.
// @param minidump_path The path to a minidump file.
// @returns The path where the corresponding crash keys file should be stored.
base::FilePath GetCrashKeysFileForDumpFile(
    const base::FilePath& minidump_path) {
  return minidump_path.ReplaceExtension(kCrashKeysFileExtension);
}

// Returns the minidump file path corresponding to the supplied crash keys file
// path.
// @param crash_keys_path The path to a crash keys file.
// @returns The path where the corresponding minidump file should be stored.
base::FilePath GetDumpFileForCrashKeysFile(
    const base::FilePath& crash_keys_path) {
  return crash_keys_path.ReplaceExtension(kDumpFileExtension);
}

// Returns a minidump that is eligible for upload from the given directory, if
// any are.
// @param directory The directory to scan.
// @param maximum_timestamp_for_retries The cutoff for the most most recent
//     upload attempt of eligible minidumps. If null, there is no cutoff.
// @returns The path to a minidump that is eligible for upload, if any.
base::FilePath GetPendingReportFromDirectory(
    const base::FilePath& directory,
    const base::Time& maximum_timestamp_for_retries) {
  base::FileEnumerator file_enumerator(
      directory, false, base::FileEnumerator::FILES,
      base::string16(L"*") + kDumpFileExtension);
  // Visit all files in this directory until we find an eligible one.
  for (base::FilePath candidate = file_enumerator.Next(); !candidate.empty();
       candidate = file_enumerator.Next()) {
    // Skip dumps with missing crash keys.
    if (!base::PathExists(GetCrashKeysFileForDumpFile(candidate))) {
      LOG(ERROR) << "Deleting a minidump file with missing crash keys: "
                 << candidate.value();
      LoggedDeleteFile(candidate);
      continue;
    }
    if (maximum_timestamp_for_retries.is_null())
      return candidate;

    // Check if this file is eligible for retry.
    base::FileEnumerator::FileInfo file_info = file_enumerator.GetInfo();
    if (file_info.GetLastModifiedTime() <= maximum_timestamp_for_retries)
      return candidate;
  }
  return base::FilePath();
}

void CleanOrphanedCrashKeysFiles(
    const base::FilePath& repository_path,
    const base::Time& now) {
  base::Time one_day_ago(now - base::TimeDelta::FromDays(1));
  const base::char16* subdirs[] = {
      kIncomingReportsSubdir, kFailedOnceSubdir, kFailedTwiceSubdir};

  for (size_t i = 0; i < arraysize(subdirs); ++i) {
    base::FileEnumerator file_enumerator(
        repository_path.Append(subdirs[i]), false, base::FileEnumerator::FILES,
        base::string16(L"*") + kCrashKeysFileExtension);
    for (base::FilePath candidate = file_enumerator.Next(); !candidate.empty();
         candidate = file_enumerator.Next()) {
      if (base::PathExists(GetDumpFileForCrashKeysFile(candidate)))
        continue;

      // We write crash keys files before moving dump files, so there is a brief
      // period where an orphan might be expected. Only delete orphans that are
      // more than a day old.
      if (file_enumerator.GetInfo().GetLastModifiedTime() >= one_day_ago)
        continue;

      LOG(ERROR) << "Deleting a crash keys file with missing minidump: "
                 << candidate.value();
      LoggedDeleteFile(candidate);
    }
  }
}

// Returns a minidump that is eligible for upload, if any are.
// @param repository_path The directory where this repository stores reports.
// @param now The current time.
// @param retry_interval The minimum interval between upload attempts for a
//     given report.
// @returns A pair of mindump path (empty if none) and failure destination
//     (empty if the next failure is permanent).
std::pair<base::FilePath, base::FilePath> GetPendingReport(
    const base::FilePath& repository_path,
    const base::Time& now,
    const base::TimeDelta& retry_interval) {
  struct {
    const base::char16* subdir;
    const base::char16* failure_subdir;
    base::Time retry_cutoff;
  } directories[] = {
      {kIncomingReportsSubdir, kFailedOnceSubdir, base::Time()},
      {kFailedOnceSubdir, kFailedTwiceSubdir, now - retry_interval},
      {kFailedTwiceSubdir, nullptr, now - retry_interval}};

  for (size_t i = 0; i < arraysize(directories); ++i) {
    base::FilePath result = GetPendingReportFromDirectory(
        repository_path.Append(directories[i].subdir),
        directories[i].retry_cutoff);
    if (!result.empty()) {
      if (!directories[i].failure_subdir)
        return std::make_pair(result, base::FilePath());
      return std::make_pair(
          result, repository_path.Append(directories[i].failure_subdir));
    }
  }
  return std::pair<base::FilePath, base::FilePath>();
}

// Handles a non-permanent failure by moving the report files to a new queue.
// @param minidump_file The minidump file. This method calls Take() on success.
// @param crash_keys_file The crash keys file. This method calls Take() on
//     success.
// @param destination_directory The directory where the files should be moved
//     to.
void HandleNonpermanentFailure(ScopedReportFile* minidump_file,
                               ScopedReportFile* crash_keys_file,
                               const base::FilePath& destination_directory) {
  bool result = base::CreateDirectory(destination_directory);
  LOG_IF(ERROR, !result) << "Failed to create destination directory "
                         << destination_directory.value();
  if (result) {
    if (minidump_file->Move(
            destination_directory.Append(minidump_file->Get().BaseName()))) {
      if (crash_keys_file->Move(destination_directory.Append(
              crash_keys_file->Get().BaseName()))) {
        minidump_file->Take();
        crash_keys_file->Take();
      }
    }
  }
}

// Handles a permanent failure by invoking the PermanentFailureHandler. Ensures
// that the report files are removed from the repository.
// @param minidump_path The path to the minidump file.
// @param crash_keys_path The path to the crash keys file.
// @param permanent_failure_handler The PermanentFailureHandler to invoke.
void HandlePermanentFailure(const base::FilePath& minidump_path,
                            const base::FilePath& crash_keys_path,
                            const ReportRepository::PermanentFailureHandler&
                                permanent_failure_handler) {
  permanent_failure_handler.Run(minidump_path, crash_keys_path);

  // In case the handler didn't delete the files, we will.
  if (base::PathExists(minidump_path))
    LoggedDeleteFile(minidump_path);
  if (base::PathExists(crash_keys_path))
    LoggedDeleteFile(crash_keys_path);
}

}  // namespace

ReportRepository::ReportRepository(
    const base::FilePath& repository_path,
    const base::TimeDelta& retry_interval,
    const TimeSource& time_source,
    const Uploader& uploader,
    const PermanentFailureHandler& permanent_failure_handler)
    : repository_path_(repository_path),
      retry_interval_(retry_interval),
      time_source_(time_source),
      uploader_(uploader),
      permanent_failure_handler_(permanent_failure_handler) {
}

ReportRepository::~ReportRepository() {
}

void ReportRepository::StoreReport(
    const base::FilePath& minidump_path,
    const std::map<base::string16, base::string16>& crash_keys) {
  ScopedReportFile minidump_file(minidump_path);

  base::FilePath destination_directory(
      repository_path_.Append(kIncomingReportsSubdir));
  bool result = base::CreateDirectory(destination_directory);
  LOG_IF(ERROR, !result) << "Failed to create destination directory "
                         << destination_directory.value();
  if (result) {
    // Choose the location and extension where the minidump will be stored.
    base::FilePath minidump_target_path = destination_directory.Append(
        minidump_path.BaseName().ReplaceExtension(kDumpFileExtension));
    base::FilePath crash_keys_path =
        GetCrashKeysFileForDumpFile(minidump_target_path);

    if (WriteCrashKeysToFile(crash_keys_path, crash_keys)) {
      ScopedReportFile crash_keys_file(crash_keys_path);

      if (minidump_file.Move(minidump_target_path)) {
        base::Time now = time_source_.Run();
        if (minidump_file.UpdateTimestamp(now)) {
          if (crash_keys_file.UpdateTimestamp(now)) {
            // Prevent the files from being deleted.
            minidump_file.Take();
            crash_keys_file.Take();
          }
        }
      }
    }
  }
}

bool ReportRepository::UploadPendingReport() {
  base::Time now = time_source_.Run();

  // Do a bit of opportunistic cleanup.
  CleanOrphanedCrashKeysFiles(repository_path_, now);

  std::pair<base::FilePath, base::FilePath> entry =
      GetPendingReport(repository_path_, now, retry_interval_);
  ScopedReportFile minidump_file(entry.first);
  base::FilePath failure_destination = entry.second;

  if (minidump_file.Get().empty())
    return true;  // Successful no-op.

  ScopedReportFile crash_keys_file(
      GetCrashKeysFileForDumpFile(minidump_file.Get()));

  // Renew the file timestamps before attempting upload. If we are unable to do
  // this, make no upload attempt (since that would potentially lead to a hot
  // loop of upload attempts).
  if (minidump_file.UpdateTimestamp(now)) {
    if (crash_keys_file.UpdateTimestamp(now)) {
      // Attempt the upload.
      std::map<base::string16, base::string16> crash_keys;
      if (ReadCrashKeysFromFile(crash_keys_file.Get(), &crash_keys)) {
        if (uploader_.Run(minidump_file.Get(), crash_keys))
          return true;
      }

      // We failed.
      if (!failure_destination.empty()) {
        HandleNonpermanentFailure(&minidump_file, &crash_keys_file,
                                  failure_destination);
      } else {
        HandlePermanentFailure(minidump_file.Take(), crash_keys_file.Take(),
                               permanent_failure_handler_);
      }
    }
  }

  return false;
}

bool ReportRepository::HasPendingReports() {
  return !GetPendingReport(repository_path_, time_source_.Run(),
                           retry_interval_).first.empty();
}

}  // namespace kasko
