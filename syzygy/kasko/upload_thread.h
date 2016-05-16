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

#ifndef SYZYGY_KASKO_UPLOAD_THREAD_H_
#define SYZYGY_KASKO_UPLOAD_THREAD_H_

#include <memory>

#include "base/callback.h"
#include "base/macros.h"
#include "base/threading/simple_thread.h"
#include "base/win/scoped_handle.h"

namespace base {
class FilePath;
}  // namespace base

namespace kasko {

class WaitableTimer;

// Establishes a background thread that uploads crash reports. Each instance has
// a configured "exclusive path". Although multiple instances of this class may
// have the same exclusive path simultaneously in one or more processes, only
// one will be active (and perform uploads) at any time. Any other instances
// will wait in the background until the active instance is terminated by
// invoking Stop() or via process termination. At that time, one of the waiting
// instances will become the active instance.
class UploadThread {
 public:
  // Creates an UploadThread instance. Returns NULL if an error prevents
  // instantiation.
  // @param exclusive_path The path for which exclusive access is sought.
  // @param waitable_timer A timer implementation that defines the interval
  //     between upload operations. At least one interval will pass before the
  //     first upload and between any two consecutive uploads.
  // @param uploader A callback that will be invoked periodically to upload
  //     crash reports, if any.
  // @returns an UploadThread instance if successful.
  static std::unique_ptr<UploadThread> Create(
      const base::FilePath& exclusive_path,
      std::unique_ptr<WaitableTimer> waitable_timer,
      const base::Closure& uploader);

  ~UploadThread();

  // Starts the background uploading process. If another instance is currently
  // active with the same exclusive path the new background process simply waits
  // until it becomes active.
  // After calling Start() you _must_ call Join() before destroying the
  // UploadThread.
  void Start();

  // Signals the background uploading process to stop. Returns immediately. You
  // must call Join() to wait for the background process to terminate.
  void Stop();

  // Signals the background uploading process to stop. Blocks until the current
  // invocation of the uploader terminates (if any) and the background process
  // has completely shut down.
  void Join();

  // Immediately initiates a single upload attempt. The attempt will be serviced
  // by the active UploadThread instance, whether this one or another (possibly
  // in a separate process). This method returns immediately without waiting for
  // the upload attempt to complete.
  //
  // The upload attempt is guaranteed to take place, regardless of any
  // subsequent calls to UploadThread::Stop(), as long as this instance has
  // previously been started via UploadThread::Start.
  //
  // If an upload attempt is already active, the requested upload attempt will
  // take place imediately after its completion. If a previously requested
  // upload attempt has not yet started, this method has no effect.
  void UploadOneNowAsync();

 private:
  class ThreadImpl : public base::SimpleThread {
   public:
    explicit ThreadImpl(UploadThread* owner);
    ~ThreadImpl() override;

    // base::SimpleThread implementation.
    void Run() override;

   private:
    UploadThread* owner_;

    DISALLOW_COPY_AND_ASSIGN(ThreadImpl);
  };

  UploadThread(base::win::ScopedHandle mutex,
               base::win::ScopedHandle stop_event,
               base::win::ScopedHandle wake_event,
               std::unique_ptr<WaitableTimer> waitable_timer,
               const base::Closure& uploader);

  base::win::ScopedHandle mutex_;
  base::win::ScopedHandle stop_event_;
  base::win::ScopedHandle wake_event_;
  std::unique_ptr<WaitableTimer> waitable_timer_;
  base::Closure uploader_;
  ThreadImpl thread_impl_;

  DISALLOW_COPY_AND_ASSIGN(UploadThread);
};

}  // namespace kasko

#endif  // SYZYGY_KASKO_UPLOAD_THREAD_H_
