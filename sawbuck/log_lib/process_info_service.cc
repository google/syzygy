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
//
// Symbol information service implementation.
#include "sawbuck/log_lib/process_info_service.h"

#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"

bool IProcessInfoService::ProcessInfo::operator == (
    const ProcessInfo& other) const {
  return started_ == other.started_ &&
         ended_ == other.ended_ &&
         process_id_ == other.process_id_ &&
         parent_process_id_ == other.parent_process_id_ &&
         session_id_ == other.session_id_ &&
         command_line_ == other.command_line_ &&
         exit_code_ == other.exit_code_;
}

ProcessInfoService::ProcessInfoService() {
}

ProcessInfoService::~ProcessInfoService() {
}

ProcessInfoService::ProcessInfoMap::iterator ProcessInfoService::FindProcess(
    DWORD process_id, const base::Time& time) {
  lock_.AssertAcquired();
  ProcessKey key = std::make_pair(process_id, time);
  ProcessInfoMap::iterator it(process_info_.lower_bound(key));

  // We have two success cases here - either an exact match on {PID, time}, or
  // else time > process start time, but < process end time, in which case
  // lower bound will have returned us the next largest {PID, time} key,
  // and we need to back up one.
  if (it == process_info_.end() || it->first != key) {
    // Are we at the beginning of the list, can't back up in that case.
    if (it == process_info_.begin())
      return process_info_.end();

    --it;
  }

  // Are we pointing to relevant process info now? Need a match on pid,
  // and (start <= time < end) - where zero end time means infinity.
  if (it->first.first == process_id && it->second.started_ <= time &&
      (it->second.ended_ == base::Time() || time < it->second.ended_)) {
    return it;
  }

  return process_info_.end();
}

bool ProcessInfoService::GetProcessInfo(DWORD process_id,
    const base::Time& time, IProcessInfoService::ProcessInfo* info) {
  base::AutoLock lock(lock_);

  DCHECK(info != NULL);
  ProcessInfoMap::iterator it(FindProcess(process_id, time));

  if (it != process_info_.end()) {
    *info = it->second;
    return true;
  }

  return false;
}

void ProcessInfoService::OnProcessIsRunning(const base::Time& time,
      const KernelProcessEvents::ProcessInfo& process_info) {
  // Record it as started at epoch.
  OnProcessStarted(base::Time(), process_info);
}

void ProcessInfoService::OnProcessStarted(const base::Time& time,
      const KernelProcessEvents::ProcessInfo& process_info) {
  base::AutoLock lock(lock_);

   // See whether we have a record of this pid/time already.
  ProcessInfoMap::iterator it(
      FindProcess(process_info.process_id, time));
  if (it == process_info_.end()) {
    // Repack the kernel event to our notion of a process info.
    IProcessInfoService::ProcessInfo to_insert = {
        time,  // started_
        base::Time(),  // ended_
        process_info.process_id,
        process_info.parent_id,
        process_info.session_id,
        L"",
        STILL_ACTIVE,
      };
    if (process_info.command_line.empty()) {
      to_insert.command_line_ = base::UTF8ToWide(process_info.image_name);
    } else {
      to_insert.command_line_ = process_info.command_line;
    }

    ProcessKey key(process_info.process_id, time);
    process_info_.insert(std::make_pair(key, to_insert));
  } else {
    // Make a copy of the process info.
    IProcessInfoService::ProcessInfo copy = it->second;

    // We should have had an end time in the previous callback.
    DCHECK(base::Time() == copy.started_);
    DCHECK(base::Time() != copy.ended_);

    // Verify that we're seeing the same process info.
    DCHECK_EQ(process_info.process_id, copy.process_id_);
    DCHECK_EQ(process_info.parent_id, copy.parent_process_id_);
    DCHECK_EQ(process_info.session_id, copy.session_id_);

    // Drop the old entry, fix up the start time and reinsert it.
    process_info_.erase(it);

    copy.started_ = time;
    ProcessKey key(process_info.process_id, time);
    process_info_.insert(std::make_pair(key, copy));
  }
}

void ProcessInfoService::OnProcessEnded(const base::Time& time,
      const KernelProcessEvents::ProcessInfo& process_info,
      ULONG exit_status) {
  base::AutoLock lock(lock_);

  // See whether we have a record of this pid/time already.
  ProcessInfoMap::iterator it(
      FindProcess(process_info.process_id, time));
  if (it == process_info_.end()) {
    // Repack the kernel event to our notion of a process info.
    IProcessInfoService::ProcessInfo to_insert = {
        base::Time(),  // started_
        time,  // ended_
        process_info.process_id,
        process_info.parent_id,
        process_info.session_id,
        L"",
        exit_status,
      };
    if (process_info.command_line.empty()) {
      to_insert.command_line_ = base::UTF8ToWide(process_info.image_name);
    } else {
      to_insert.command_line_ = process_info.command_line;
    }

    ProcessKey key(process_info.process_id, base::Time());
    process_info_.insert(std::make_pair(key, to_insert));
  } else {
    // We should not have had an end time in the previous callback.
    DCHECK(base::Time() == it->second.ended_);
    // Verify that we're seeing the same process info.
    DCHECK_EQ(process_info.process_id, it->second.process_id_);
    DCHECK_EQ(process_info.parent_id, it->second.parent_process_id_);
    DCHECK_EQ(process_info.session_id, it->second.session_id_);

    it->second.ended_ = time;
    it->second.exit_code_ = exit_status;
  }
}
