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

#include "syzygy/kasko/report_repository.h"

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include "base/bind.h"
#include "base/macros.h"
#include "base/rand_util.h"
#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/strings/string16.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/time/time.h"
#include "gtest/gtest.h"
#include "syzygy/kasko/crash_keys_serialization.h"

namespace kasko {

namespace {

// This test harness allows us to generate reports and mock the results of
// upload attempts for them. A report may be configured to succeed immediately,
// succeed after 1 or 2 retries, or fail permanently.
// The test harness will log failures if the permanent failure or upload
// handler is invoked inappropriately or not invoked when expected.
// A mock TimeSource is used to simulate the passage of time for retry
// intervals.
// Each test should call repository()->UploadPendingReport() enough times to
// empty the repository. The harness expects it to be empty at the end of the
// test.
class ReportRepositoryTest : public testing::Test {
 public:
  static const uint16_t kHalfRetryIntervalInSeconds;
  static const uint16_t kRetryIntervalInSeconds;

  // The mock time must not start at 0, as we cannot update a file timestamp to
  // that value.
  ReportRepositoryTest()
      : remainder_expected_(false), time_(base::Time::Now()) {}

 protected:
  typedef std::pair<std::string, std::map<base::string16, base::string16>>
      Report;

  // testing::Test implementation
  void SetUp() override {
    repository_temp_dir_.CreateUniqueTempDir();
    repository_.reset(new ReportRepository(
        repository_temp_dir_.path(),
        base::TimeDelta::FromSeconds(kRetryIntervalInSeconds),
        base::Bind(&ReportRepositoryTest::GetTime, base::Unretained(this)),
        base::Bind(&ReportRepositoryTest::Upload, base::Unretained(this)),
        base::Bind(&ReportRepositoryTest::HandlePermanentFailure,
                   base::Unretained(this))));
  }
  void TearDown() override { Validate(); }

  // Validates that all injected reports have been handled as expected, and that
  // the repository directory does not contain any leftover files.
  // This is automatically called by TearDown but may also be invoked mid-test.
  void Validate() {
    // There should not be anything left over.
    EXPECT_EQ(base::FilePath(),
              base::FileEnumerator(repository_temp_dir_.path(), true,
                                   base::FileEnumerator::FILES).Next());

    // If |remainder_expected_| is true, we allow exactly one report to not be
    // processed (due to corruption).
    for (size_t i = 0; i < arraysize(successful_reports_); ++i) {
      if (remainder_expected_ && successful_reports_[i].size() == 1) {
        remainder_expected_ = false;
        successful_reports_[i].clear();
        continue;
      }
      EXPECT_TRUE(successful_reports_[i].empty());
    }
    for (size_t i = 0; i < arraysize(failing_reports_); ++i) {
      if (remainder_expected_ && failing_reports_[i].size() == 1) {
        remainder_expected_ = false;
        failing_reports_[i].clear();
        continue;
      }
      EXPECT_TRUE(failing_reports_[i].empty());
    }

    // |remainder_expected_| should have been reset during the above loops.
    EXPECT_FALSE(remainder_expected_);
  }

  // Indicates that one report has been intentionally corrupted. This will be
  // checked during Validate().
  void SetRemainderExpected() { remainder_expected_ = true; }

  // Randomly deletes a report file (either crash keys or minidump) from the
  // repository.
  void OrphanAReport() {
    base::FilePath to_delete;
    size_t count = 0;
    base::FileEnumerator file_enumerator(repository_temp_dir_.path(), true,
                                         base::FileEnumerator::FILES);
    for (base::FilePath candidate = file_enumerator.Next(); !candidate.empty();
         candidate = file_enumerator.Next()) {
      ++count;
      if (base::RandDouble() < 1.0 / count)
        to_delete = candidate;
    }
    ASSERT_FALSE(to_delete.empty());
    ASSERT_TRUE(base::DeleteFile(to_delete, false));
  }

  // Implements the TimeSource.
  base::Time GetTime() { return time_; }

  // Increments the simulated clock.
  void IncrementTime(const base::TimeDelta& time_delta) { time_ += time_delta; }

  // Creates a report that will succeed after the specified number of retries
  // (0, 1, or 2).
  void InjectForSuccessAfterRetries(size_t retries) {
    Report report = GenerateReport();
    AllowReportToSucceedAfterRetries(report, retries);
    StoreReport(report);
  }

  // Creates a report that will never succeed in uploading.
  void InjectForFailure() {
    Report report = GenerateReport();
    PermanentlyFailReport(report);
    StoreReport(report);
  }

  // Returns the instance under test.
  ReportRepository* repository() { return repository_.get(); }

 private:
  // Writes a report to disk and stores it in the repository.
  void StoreReport(const Report& report) {
    base::FilePath minidump_file;
    ASSERT_TRUE(base::CreateTemporaryFileInDir(repository_temp_dir_.path(),
                                               &minidump_file));
    ASSERT_TRUE(base::WriteFile(minidump_file, report.first.data(),
                                report.first.length()));
    repository_->StoreReport(minidump_file, report.second);
  }

  // Sets up the mock behaviour for a report that will succeed after the
  // specified number of retries.
  void AllowReportToSucceedAfterRetries(const Report& report, size_t retries) {
    ASSERT_LT(retries, arraysize(successful_reports_));
    successful_reports_[retries].push_back(report);
  }

  // Sets up the mock behaviour for a report that will always fail to upload.
  void PermanentlyFailReport(const Report& report) {
    failing_reports_[3].push_back(report);
  }

  // Generates a unique report.
  Report GenerateReport() {
    static size_t id = 0;
    Report report;
    report.first = base::UintToString(id);
    report.second[L"id"] = base::ASCIIToUTF16(report.first);
    ++id;
    return report;
  }

  // Implements the UploadHandler.
  bool Upload(const base::FilePath& minidump_path,
              const std::map<base::string16, base::string16>& crash_keys) {
    Report report;
    bool success = base::ReadFileToString(minidump_path, &report.first);
    EXPECT_TRUE(success);
    if (!success)
      return false;

    report.second = crash_keys;

    // Check to see if this report is destined to eventually succeed. If it's in
    // successful_reports_[0] it succeeds this round. If it's in [1] or higher
    // it will fail this round but be advanced to a lower index to eventually
    // succeed.
    for (size_t i = 0; i < arraysize(successful_reports_); ++i) {
      std::vector<Report>::iterator entry = std::find(
          successful_reports_[i].begin(), successful_reports_[i].end(), report);
      if (entry == successful_reports_[i].end())
        continue;

      // Remove it from whence it was found.
      successful_reports_[i].erase(entry);
      // Advance it, if necessary.
      if (i > 0) {
        successful_reports_[i-1].push_back(report);
        return false;
      }
      return true;
    }

    // Check to see if this report is destined for permanent failure.
    // Start at [1] because the elements in [0] are ready for
    // HandlePermanentFailure.
    for (size_t i = 1; i < arraysize(failing_reports_); ++i) {
      std::vector<Report>::iterator entry = std::find(
          failing_reports_[i].begin(), failing_reports_[i].end(), report);
      if (entry == failing_reports_[i].end())
        continue;
      // Remove it from whence it was found.
      failing_reports_[i].erase(entry);
      // Advance towards later permanent failure.
      failing_reports_[i - 1].push_back(report);
      return false;
    }
    ADD_FAILURE() << "Unexpected report. Minidump: " << report.first;
    return false;
  }

  // Implements the PermanentFailureHandler.
  void HandlePermanentFailure(const base::FilePath& minidump_path,
                              const base::FilePath& crash_keys_path) {
    Report report;
    EXPECT_TRUE(ReadCrashKeysFromFile(crash_keys_path, &report.second));
    ASSERT_TRUE(base::ReadFileToString(minidump_path, &report.first));

    std::vector<Report>::iterator entry = std::find(
        failing_reports_[0].begin(), failing_reports_[0].end(), report);
    if (entry == failing_reports_[0].end()) {
      ADD_FAILURE() << "Unexpected permanently failed report. Minidump: "
                    << report.first;
    } else {
      failing_reports_[0].erase(entry);
    }
  }

  // If true, exactly one report should never have been sent (because we
  // corrupted it).
  bool remainder_expected_;

  // Vectors of reports that should succeed after 0, 1, or 2 failures according
  // to their index in this array.
  std::vector<Report> successful_reports_[3];

  // Vectors of reports that should permanently fail after 1, 2, or 3 more
  // failures according to their index in this array. Index [0] is reports that
  // have just failed upload and should now be handed to the
  // PermanentFailureHandler.
  std::vector<Report> failing_reports_[4];

  // The repository directory.
  base::ScopedTempDir repository_temp_dir_;

  // The mock time.
  base::Time time_;

  // The instance under test.
  std::unique_ptr<ReportRepository> repository_;

  DISALLOW_COPY_AND_ASSIGN(ReportRepositoryTest);
};

const uint16_t ReportRepositoryTest::kHalfRetryIntervalInSeconds = 10;
const uint16_t ReportRepositoryTest::kRetryIntervalInSeconds =
    ReportRepositoryTest::kHalfRetryIntervalInSeconds * 2;

}  // namespace

TEST_F(ReportRepositoryTest, BasicTest) {
  EXPECT_FALSE(repository()->HasPendingReports());

  InjectForSuccessAfterRetries(2);
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Fails
  EXPECT_FALSE(repository()->HasPendingReports());

  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op

  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Fails
  EXPECT_FALSE(repository()->HasPendingReports());

  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // Succeeds
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op

  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op
}

TEST_F(ReportRepositoryTest, SuccessTest) {
  EXPECT_FALSE(repository()->HasPendingReports());

  InjectForSuccessAfterRetries(0);
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // Succeeds
  EXPECT_FALSE(repository()->HasPendingReports());

  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op

  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op
}

TEST_F(ReportRepositoryTest, PermanentFailureTest) {
  EXPECT_FALSE(repository()->HasPendingReports());

  InjectForFailure();
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Fails
  EXPECT_FALSE(repository()->HasPendingReports());

  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Fails
  EXPECT_FALSE(repository()->HasPendingReports());

  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Fails
  EXPECT_FALSE(repository()->HasPendingReports());
}

TEST_F(ReportRepositoryTest, MultipleReportsTest) {
  EXPECT_FALSE(repository()->HasPendingReports());

  InjectForSuccessAfterRetries(0);
  InjectForSuccessAfterRetries(0);
  InjectForSuccessAfterRetries(0);

  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // Succeeds
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // Succeeds
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // Succeeds
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op

  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op
}

TEST_F(ReportRepositoryTest, MultipleReportsTestWithFailures) {
  EXPECT_FALSE(repository()->HasPendingReports());

  InjectForSuccessAfterRetries(0);
  InjectForSuccessAfterRetries(1);
  InjectForSuccessAfterRetries(2);
  InjectForFailure();

  // 3 will fail, 1 will succeed.
  size_t successes = 0;
  for (size_t i = 0; i < 4; ++i) {
    EXPECT_TRUE(repository()->HasPendingReports());
    if (repository()->UploadPendingReport())
      successes++;
  }
  EXPECT_EQ(1, successes);
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());
  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));

  // 2 will fail, 1 will succeed.
  successes = 0;
  for (size_t i = 0; i < 3; ++i) {
    EXPECT_TRUE(repository()->HasPendingReports());
    if (repository()->UploadPendingReport())
      successes++;
  }
  EXPECT_EQ(1, successes);
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());
  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));

  // 1 will permanently fail, 1 will succeed.
  successes = 0;
  for (size_t i = 0; i < 2; ++i) {
    EXPECT_TRUE(repository()->HasPendingReports());
    if (repository()->UploadPendingReport())
      successes++;
  }
  EXPECT_EQ(1, successes);
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());
  IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));

  // None left.
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());
}

TEST_F(ReportRepositoryTest, MultipleInterleavedReports) {
  EXPECT_FALSE(repository()->HasPendingReports());

  // 1st generation
  InjectForSuccessAfterRetries(1);
  InjectForSuccessAfterRetries(2);

  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Failure
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Failure
  EXPECT_FALSE(repository()->HasPendingReports());

  // Increment a half interval.
  IncrementTime(base::TimeDelta::FromSeconds(kHalfRetryIntervalInSeconds));
  EXPECT_FALSE(repository()->HasPendingReports());
  // 2nd generation
  InjectForSuccessAfterRetries(1);
  InjectForSuccessAfterRetries(2);
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Failure
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_FALSE(repository()->UploadPendingReport());  // Failure
  EXPECT_FALSE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());  // No-op

  // Increment another half interval. Now only the first generation are eligible
  // for retry. One will succeed.
  IncrementTime(base::TimeDelta::FromSeconds(kHalfRetryIntervalInSeconds));
  size_t successes = 0;
  for (size_t i = 0; i < 2; ++i) {
    EXPECT_TRUE(repository()->HasPendingReports());
    if (repository()->UploadPendingReport())
      successes++;
  }
  EXPECT_EQ(1, successes);
  EXPECT_FALSE(repository()->HasPendingReports());

  // Increment another half interval. This is the second generation, one will
  // succeed.
  IncrementTime(base::TimeDelta::FromSeconds(kHalfRetryIntervalInSeconds));
  successes = 0;
  for (size_t i = 0; i < 2; ++i) {
    EXPECT_TRUE(repository()->HasPendingReports());
    if (repository()->UploadPendingReport())
      successes++;
  }
  EXPECT_EQ(1, successes);
  EXPECT_FALSE(repository()->HasPendingReports());

  // Increment another half interval. This is the first generation, only one
  // element left (it will succeed).
  IncrementTime(base::TimeDelta::FromSeconds(kHalfRetryIntervalInSeconds));
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());
  EXPECT_FALSE(repository()->HasPendingReports());

  // Increment another half interval. This is the second generation, only one
  // element left (it will succeed).
  IncrementTime(base::TimeDelta::FromSeconds(kHalfRetryIntervalInSeconds));
  EXPECT_TRUE(repository()->HasPendingReports());
  EXPECT_TRUE(repository()->UploadPendingReport());
  EXPECT_FALSE(repository()->HasPendingReports());
}

TEST_F(ReportRepositoryTest, CorruptionTest) {
  // In order to avoid hard-coding extensions/paths, and having a bunch of
  // permutations, let's run this test a bunch of times and probabilistically
  // cover all the cases of a file being missing.
  for (size_t i = 0; i< 100; ++i) {
    // This sequence will put one report each in the different states.
    InjectForSuccessAfterRetries(2); // one in Incoming
    InjectForSuccessAfterRetries(2); // two in Incoming
    repository()->UploadPendingReport(); // one in Retry
    repository()->UploadPendingReport(); // two in Retry
    IncrementTime(base::TimeDelta::FromSeconds(kRetryIntervalInSeconds));
    repository()->UploadPendingReport(); // one in Retry 2
    InjectForSuccessAfterRetries(2); // one in Incoming

    // Randomly delete one file.
    OrphanAReport();

    // Wait 36 hours.
    base::Time start = GetTime();
    while (GetTime() - start < base::TimeDelta::FromHours(36)) {
      IncrementTime(base::TimeDelta::FromMinutes(30));
      repository()->UploadPendingReport();
    }

    SetRemainderExpected();
    // Validate that exactly one of the injected reports didn't come out and
    // that there are no files left over.
    Validate();
  }
}

}  // namespace kasko
