// Copyright 2012 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/asan_runtime.h"

#include "base/bind.h"
#include "base/command_line.h"
#include "base/environment.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "base/sys_string_conversions.h"
#include "base/utf_string_conversions.h"
#include "syzygy/agent/asan/asan_logger.h"
#include "syzygy/agent/asan/stack_capture_cache.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {
namespace asan {

namespace {

using agent::asan::AsanLogger;
using agent::asan::HeapProxy;
using agent::asan::StackCaptureCache;

// The default error handler.
void OnAsanError() {
  ::DebugBreak();
  ::RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
}

// Try to update the value of a size_t variable from a command-line.
// @param cmd_line The command line who might contain a given parameter.
// @param param_name The parameter that we want to read.
// @param cmd_line A pointer to the size_t variable where we want to store the
//     value of the parameter if it's present.
// @returns true on success, false otherwise.
bool UpdateSizetFromCommandLine(const CommandLine& cmd_line,
                                const std::string& param_name,
                                size_t* value) {
  if (cmd_line.HasSwitch(param_name)) {
    std::string value_str = cmd_line.GetSwitchValueASCII(param_name);
    size_t new_value = 0;
    if (!base::StringToSizeT(value_str, &new_value))
      return false;
    *value = new_value;
  }
  return true;
}

// A helper function to find if an intrusive list contains a given entry.
// @param list The list in which we want to look for the entry.
// @param item The entry we want to look for.
// @returns true if the list contains this entry, false otherwise.
bool HeapListContainsEntry(const LIST_ENTRY* list, const LIST_ENTRY* item) {
  LIST_ENTRY* current = list->Flink;
  while (current != NULL) {
    LIST_ENTRY* next_item = NULL;
    if (current->Flink != list) {
      next_item = current->Flink;
    }

    if (current == item) {
      return true;
    }

    current = next_item;
  }
  return false;
}

}  // namespace

const char AsanRuntime::kSyzyAsanEnvVar[] = "ASAN_OPTIONS";

const char AsanRuntime::kBottomFramesToSkip[] =
    "bottom_frames_to_skip";
const char AsanRuntime::kQuarantineSize[] = "quarantine_size";
const char AsanRuntime::kCompressionReportingPeriod[] =
    "compression_reporting_period";
const wchar_t AsanRuntime::kSyzyAsanDll[] = L"asan_rtl.dll";

AsanRuntime::AsanRuntime() : logger_(NULL), stack_cache_(NULL) {
}

AsanRuntime::~AsanRuntime() {
}

void AsanRuntime::SetUp(const std::wstring& flags_command_line) {
  // Initialize the command-line structures. This is needed so that
  // SetUpLogger() can include the command-line in the message announcing
  // this process. Note: this is mostly for debugging purposes.
  CommandLine::Init(0, NULL);

  InitializeListHead(&heap_proxy_dlist_);

  // Setup the "global" state.
  SetUpLogger();
  SetUpStackCache();
  if (!ParseFlagsFromString(flags_command_line)) {
    LOG(ERROR) << "Unable to parse the flags from the input string (\""
               << flags_command_line.c_str() << "\").";
  }
  // Propagates the flags values to the different modules.
  PropagateFlagsValues();

  // Use the default callback.
  SetErrorCallBack(&OnAsanError);
}

void AsanRuntime::TearDown() {
  TearDownStackCache();
  TearDownLogger();
  DCHECK(asan_error_callback_.is_null() == FALSE);
  asan_error_callback_.Reset();
  // In principle, we should also check that all the heaps have been destroyed
  // but this is not guaranteed to be the case in Chrome, so the heap list may
  // not be empty here.
}

void AsanRuntime::OnError() {
  // Call the callback to handle this error.
  DCHECK_EQ(false, asan_error_callback_.is_null());
  asan_error_callback_.Run();
}

void AsanRuntime::SetErrorCallBack(void (*callback)()) {
  asan_error_callback_ = base::Bind(callback);
}

void AsanRuntime::SetUpLogger() {
  // Setup variables we're going to use.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  scoped_ptr<AsanLogger> client(new AsanLogger);
  CHECK(env.get() != NULL);
  CHECK(client.get() != NULL);

  // Initialize the client.
  std::string instance_id;
  if (env->GetVar(kSyzygyRpcInstanceIdEnvVar, &instance_id))
    client->set_instance_id(UTF8ToWide(instance_id));
  client->Init();

  // Register the client singleton instance.
  logger_.reset(client.release());
}

void AsanRuntime::TearDownLogger() {
  logger_.reset();
}

void AsanRuntime::SetUpStackCache() {
  DCHECK(stack_cache_.get() == NULL);
  DCHECK(logger_.get() != NULL);
  stack_cache_.reset(new StackCaptureCache(logger_.get()));
}

void AsanRuntime::TearDownStackCache() {
  DCHECK(stack_cache_.get() != NULL);
  stack_cache_->LogCompressionRatio();
  stack_cache_.reset();
}

bool AsanRuntime::ParseFlagsFromString(std::wstring str) {
  // Prepends the flags with the agent name. We need to do this because the
  // command-line constructor expect the process name to be the first value of
  // the command-line string.
  // Start by inserting a space at the beginning of the flags to separate the
  // flags from the agent name.
  str.insert(0, L" ");
  // Insert the agent name.
  str.insert(0, kSyzyAsanDll);

  CommandLine cmd_line = CommandLine::FromString(str);

  // Parse the quarantine size flag.
  flags_.quarantine_size = HeapProxy::GetDefaultQuarantineMaxSize();
  if (!UpdateSizetFromCommandLine(cmd_line, kQuarantineSize,
                                  &flags_.quarantine_size)) {
    LOG(ERROR) << "Unable to read " << kQuarantineSize << " from the argument "
               << "list.";
    return false;
  }

  // Parse the reporting period flag.
  flags_.reporting_period =
      StackCaptureCache::GetDefaultCompressionReportingPeriod();
  if (!UpdateSizetFromCommandLine(cmd_line, kCompressionReportingPeriod,
                                  &flags_.reporting_period)) {
    LOG(ERROR) << "Unable to read " << kCompressionReportingPeriod
               << " from the argument list.";
    return false;
  }

  // Parse the bottom frames to skip flag.
  flags_.bottom_frames_to_skip = StackCapture::bottom_frames_to_skip();
  if (!UpdateSizetFromCommandLine(cmd_line, kBottomFramesToSkip,
                                  &flags_.bottom_frames_to_skip)) {
    LOG(ERROR) << "Unable to read " << kBottomFramesToSkip << " from the "
               << "argument list.";
    return false;
  }

  return true;
}

bool AsanRuntime::GetAsanFlagsEnvVar(std::wstring* env_var_wstr) {
  scoped_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL) {
    LOG(ERROR) << "base::Environment::Create returned NULL.";
    return false;
  }

  // If this fails, the environment variable simply does not exist.
  std::string env_var_str;
  if (!env->GetVar(kSyzyAsanEnvVar, &env_var_str)) {
    return true;
  }

  *env_var_wstr = base::SysUTF8ToWide(env_var_str);

  return true;
}

void AsanRuntime::PropagateFlagsValues() const {
  // TODO(sebmarchand): Look into edit-free ways to expose new flags to the
  //     different modules.
  HeapProxy::SetDefaultQuarantineMaxSize(flags_.quarantine_size);
  StackCapture::SetBottomFramesToSkip(flags_.bottom_frames_to_skip);
  StackCaptureCache::SetCompressionReportingPeriod(flags_.reporting_period);
}

void AsanRuntime::set_flags(const AsanFlags* flags) {
  DCHECK(flags != NULL);
  flags_ = *flags;
}

void AsanRuntime::AddHeap(HeapProxy* heap) {
  base::AutoLock lock(heap_proxy_dlist_lock_);
  InsertTailList(&heap_proxy_dlist_, HeapProxy::ToListEntry(heap));
}

void AsanRuntime::RemoveHeap(HeapProxy* heap) {
  base::AutoLock lock(heap_proxy_dlist_lock_);
  DCHECK(HeapListContainsEntry(&heap_proxy_dlist_,
                               HeapProxy::ToListEntry(heap)));
  RemoveEntryList(HeapProxy::ToListEntry(heap));
}

void AsanRuntime::ReportAsanErrorDetails(const void* addr,
                                         const CONTEXT& context,
                                         const StackCapture& stack,
                                         HeapProxy::AccessMode access_mode,
                                         size_t access_size) {
  base::AutoLock lock(heap_proxy_dlist_lock_);
  // Iterates over the HeapProxy list to find the memory block containing this
  // address. We expect that there is at least one heap proxy extant.
  HeapProxy* proxy = NULL;
  LIST_ENTRY* item = heap_proxy_dlist_.Flink;
  CHECK(item != NULL);
  while (item != NULL) {
    LIST_ENTRY* next_item = NULL;
    if (item->Flink != &heap_proxy_dlist_) {
      next_item = item->Flink;
    }

    proxy = HeapProxy::FromListEntry(item);
    if (proxy->OnBadAccess(addr, context, stack, access_mode, access_size)) {
      break;
    }

    item = next_item;
  }

  // If item is NULL then we went through the list without finding the heap
  // from which this address was allocated. We can just reuse the logger of
  // the last heap proxy we saw to report an "unknown" error.
  if (item == NULL) {
    CHECK(proxy != NULL);
    proxy->ReportUnknownError(addr, context, stack, access_mode,
                              access_size);
  }
}

}  // namespace asan
}  // namespace agent
