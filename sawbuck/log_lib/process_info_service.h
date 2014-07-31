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
// Symbol information service declaration.
#ifndef SAWBUCK_LOG_LIB_PROCESS_INFO_SERVICE_H_
#define SAWBUCK_LOG_LIB_PROCESS_INFO_SERVICE_H_

#include <map>
#include "base/synchronization/lock.h"
#include "sawbuck/log_lib/kernel_log_consumer.h"

class IProcessInfoService {
 public:
  struct ProcessInfo {
    base::Time started_;
    base::Time ended_;
    DWORD process_id_;
    DWORD parent_process_id_;
    DWORD session_id_;
    std::wstring command_line_;
    DWORD exit_code_;

    bool operator == (const ProcessInfo& other) const;
  };

  // Retrieve info about @p process_id at @p time.
  // @returns true iff info is available, false otherwise.
  virtual bool GetProcessInfo(DWORD process_id, const base::Time& time,
      ProcessInfo* info) = 0;
};

// Fwd.
namespace base {
class MessageLoop;
}  // namespace base

// The process info service class sinks process events from a kernel log
// parser, and stores away the process information for later retrieval.
class ProcessInfoService
    : public IProcessInfoService,
      public KernelProcessEvents {
 public:
  ProcessInfoService();
  ~ProcessInfoService();

  // IProcessInfoService implementation.
  virtual bool GetProcessInfo(DWORD process_id, const base::Time& time,
      IProcessInfoService::ProcessInfo* info);

  // KernelProcessEvents implementation.
  virtual void OnProcessIsRunning(const base::Time& time,
      const KernelProcessEvents::ProcessInfo& process_info);
  virtual void OnProcessStarted(const base::Time& time,
      const KernelProcessEvents::ProcessInfo& process_info);
  virtual void OnProcessEnded(const base::Time& time,
      const KernelProcessEvents::ProcessInfo& process_info,
      ULONG exit_status);

 private:
  typedef std::pair<DWORD, base::Time> ProcessKey;
  typedef std::map<ProcessKey, IProcessInfoService::ProcessInfo>
      ProcessInfoMap;
  ProcessInfoMap::iterator FindProcess(DWORD process_id,
      const base::Time& time);

  base::Lock lock_;
  ProcessInfoMap process_info_;  // Under lock_.
};

#endif  // SAWBUCK_LOG_LIB_PROCESS_INFO_SERVICE_H_
