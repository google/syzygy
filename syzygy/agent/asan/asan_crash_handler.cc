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

#include "syzygy/agent/asan/asan_crash_handler.h"

#include "base/logging.h"

namespace agent {
namespace asan {

// Static member variables.
base::Lock AsanCrashHandler::lock_;
bool AsanCrashHandler::unhandled_exception_filter_registered_ = false;
LPTOP_LEVEL_EXCEPTION_FILTER
    AsanCrashHandler::previous_unhandled_exception_filter_ = NULL;
AsanCrashHandler::OnExceptionCallback AsanCrashHandler::on_exception_callback_;
std::set<DWORD> AsanCrashHandler::disabled_thread_ids_;

LONG WINAPI AsanCrashHandler::UnhandledExceptionFilter(
    struct _EXCEPTION_POINTERS* exception) {
  // This ensures that we don't have multiple colliding crashes being processed
  // simultaneously.
  base::AutoLock auto_lock(lock_);

  // Invoke the filter unless its been disabled on this thread.
  if (disabled_thread_ids_.count(::GetCurrentThreadId()) == 0 &&
      !on_exception_callback_.is_null()) {
    on_exception_callback_.Run(&exception);
  }

  // Pass the buck to the next exception handler.
  if (previous_unhandled_exception_filter_ != NULL)
    return (*previous_unhandled_exception_filter_)(exception);

  // We can't do anything with this, so let the system deal with it.
  return EXCEPTION_EXECUTE_HANDLER;
}

void AsanCrashHandler::Initialize() {
  base::AutoLock auto_lock(lock_);
  if (unhandled_exception_filter_registered_)
    return;
  unhandled_exception_filter_registered_ = true;
  previous_unhandled_exception_filter_ = ::SetUnhandledExceptionFilter(
      &UnhandledExceptionFilter);
}

void AsanCrashHandler::DisableForCurrentThread() {
  base::AutoLock auto_lock(lock_);
  disabled_thread_ids_.insert(::GetCurrentThreadId());
}

void AsanCrashHandler::EnableForCurrentThread() {
  base::AutoLock auto_lock(lock_);
  DCHECK(disabled_thread_ids_.count(::GetCurrentThreadId()));
  disabled_thread_ids_.erase(::GetCurrentThreadId());
}

void AsanCrashHandler::SetOnExceptionCallback(OnExceptionCallback callback) {
  base::AutoLock auto_lock(lock_);
  on_exception_callback_ = callback;
}

}  // namespace asan
}  // namespace agent
