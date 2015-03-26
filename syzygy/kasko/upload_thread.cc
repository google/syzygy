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

#include "syzygy/kasko/upload_thread.h"

#include <windows.h>
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/strings/string16.h"
#include "base/strings/string_util.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/kasko/waitable_timer.h"

namespace kasko {

// static
scoped_ptr<UploadThread> UploadThread::Create(
    const base::FilePath& exclusive_path,
    scoped_ptr<WaitableTimer> waitable_timer,
    const base::Closure& uploader) {
  // '\' is the only character not permitted in mutex names.
  base::string16 escaped_path;
  base::ReplaceChars(exclusive_path.value(), L"\\", L"/", &escaped_path);
  base::string16 mutex_name = L"Local\\kasko_uploader_mutex_" + escaped_path;
  base::string16 wake_event_name =
      L"Local\\kasko_uploader_wake_event_" + escaped_path;
  base::win::ScopedHandle mutex(::CreateMutex(NULL, FALSE, mutex_name.c_str()));
  if (!mutex) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create a mutex named " << mutex_name << ": "
               << ::common::LogWe(error);
    return scoped_ptr<UploadThread>();
  }
  base::win::ScopedHandle stop_event(::CreateEvent(NULL, TRUE, FALSE, NULL));
  if (!stop_event) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create an event: " << ::common::LogWe(error);
    return scoped_ptr<UploadThread>();
  }
  base::win::ScopedHandle wake_event(
      ::CreateEvent(NULL, FALSE, FALSE, wake_event_name.c_str()));
  if (!wake_event) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create an event named '" << wake_event_name
               << "': " << ::common::LogWe(error);
    return scoped_ptr<UploadThread>();
  }
  return make_scoped_ptr(new UploadThread(mutex.Pass(), stop_event.Pass(),
                                          wake_event.Pass(),
                                          waitable_timer.Pass(), uploader));
}

UploadThread::~UploadThread() {
  // It's a bad idea to shut down without stopping the service. It's also a bad
  // idea to block unexpectedly in our destructor.
  CHECK(!thread_impl_.HasBeenStarted() || thread_impl_.HasBeenJoined());
}

void UploadThread::Start() {
  thread_impl_.Start();
}

void UploadThread::Stop() {
  if (!::SetEvent(stop_event_)) {
    DWORD error = ::GetLastError();
    LOG(FATAL) << "Failed to signal stop event. Terminating to avoid deadlock: "
               << ::common::LogWe(error);
  }
}

void UploadThread::Join() {
  Stop();
  thread_impl_.Join();
}

void UploadThread::UploadOneNowAsync() {
  if (!::SetEvent(wake_event_)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to signal wake event: " << ::common::LogWe(error);
  }
}

UploadThread::ThreadImpl::ThreadImpl(UploadThread* owner)
    : base::SimpleThread("upload_thread"), owner_(owner) {
}

UploadThread::ThreadImpl::~ThreadImpl(){}

void UploadThread::ThreadImpl::Run() {
  HANDLE handles_pre_mutex[] = {owner_->mutex_, owner_->stop_event_};
  DWORD wait_result = ::WaitForMultipleObjects(
      arraysize(handles_pre_mutex), handles_pre_mutex, FALSE, INFINITE);
  switch (wait_result) {
    case WAIT_OBJECT_0:
    case WAIT_ABANDONED_0:
      // mutex_
      break;
    case WAIT_OBJECT_0 + 1:
      // stop_event_
      return;
    default:
      DWORD error = ::GetLastError();
      LOG(ERROR) << "WaitForMultipleObjects failed: " << ::common::LogWe(error);
      return;
  }

  // We have the mutex now. We will wait on the wake event, the stop event, and
  // the timer.
  HANDLE handles_post_mutex[] = {owner_->wake_event_,
                                 owner_->stop_event_,
                                 owner_->waitable_timer_->GetHANDLE()};

  while (true) {
    owner_->waitable_timer_->Start();
    wait_result = ::WaitForMultipleObjects(arraysize(handles_post_mutex),
                                           handles_post_mutex, FALSE, INFINITE);
    switch (wait_result) {
      case WAIT_OBJECT_0:
        // wake_event_
        break;
      case WAIT_OBJECT_0 + 1:
        // stop_event_
        return;
      case WAIT_OBJECT_0 + 2:
        // waitable_timer_
        break;
      default:
        DWORD error = ::GetLastError();
        LOG(ERROR) << "WaitForMultipleObjects failed: "
                   << ::common::LogWe(error);
        return;
    }
    owner_->uploader_.Run();
  }
}

UploadThread::UploadThread(base::win::ScopedHandle mutex,
                           base::win::ScopedHandle stop_event,
                           base::win::ScopedHandle wake_event,
                           scoped_ptr<WaitableTimer> waitable_timer,
                           const base::Closure& uploader)
    : mutex_(mutex.Take()),
      stop_event_(stop_event.Take()),
      wake_event_(wake_event.Take()),
      waitable_timer_(waitable_timer.Pass()),
      uploader_(uploader),
      thread_impl_(this) {
}

}  // namespace kasko
