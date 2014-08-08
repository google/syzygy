// Copyright 2013 Google Inc. All Rights Reserved.
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
// Describes a service, which is a persistent background process that uses
// named events and mutexes to communicate and synchronize itself, and presents
// an external API via RPC.

#ifndef SYZYGY_TRACE_COMMON_SERVICE_H_
#define SYZYGY_TRACE_COMMON_SERVICE_H_

#include "base/callback.h"
#include "base/strings/string_piece.h"
#include "base/threading/platform_thread.h"

namespace trace {
namespace common {

class Service {
 public:
  typedef base::Callback<bool(Service*)> ServiceCallback;

  enum State {
    // This is the starting state for a Service. Once any call to Start, Stop or
    // Join has successfully returned it can not return to this state.
    kUnused,
    kInitialized,
    kRunning,
    kStopping,
    kStopped,
    kErrored,
  };

  // Constructor.
  // @param name The name of this service. Should be a short name, like
  //     'call-trace' or 'logger'.
  explicit Service(const base::StringPiece16& name);

  // Destructor.
  virtual ~Service();

  // @name Mutators. These are not thread-safe.
  // @{
  void set_instance_id(const base::StringPiece16& instance_id);
  void set_started_callback(ServiceCallback callback);
  void set_interrupted_callback(ServiceCallback callback);
  void set_stopped_callback(ServiceCallback callback);
  // @}

  // @name Accessors.
  // @{
  // These are not thread-safe.
  const std::wstring& name() const { return name_; }
  const std::wstring& instance_id() const { return instance_id_; }
  const ServiceCallback& started_callback() const { return started_callback_; }
  const ServiceCallback& interrupted_callback() const {
    return interrupted_callback_;
  }
  const ServiceCallback& stopped_callback() const { return stopped_callback_; }
  // This is thread-safe. As such it requires use of a lock and is not const.
  State state();
  // @}

  // Launch this service. This method may only be called by the thread that
  // created the service. This call is non-blocking and not thread-safe.
  // @returns true on success, false otherwise. Logs verbosely.
  bool Start();

  // Stops this service. This method may be called by any thread once the
  // service has started. This call is non-blocking and thread-safe.
  // @returns true on success, false otherwise. Logs verbosely.
  bool Stop();

  // Joins the thread on which the service is running, and returns when the
  // service has terminated (cleanly, or otherwise). This is a blocking call and
  // is thread-safe.
  // @returns true on success, false otherwise. Logs verbosely.
  bool Join();

 protected:
  // Progress callbacks to be used by non-blocking implementations. These
  // invoke any external callbacks and transition the state of the service.
  // These are thread-safe.
  bool OnInitialized();
  bool OnStarted();
  bool OnInterrupted();
  bool OnStopped();

  // @name Functions for derived class to implement.
  // @{
  // This must be non-blocking. This will only be called by the thread that
  // created this service instance. This should indicate progress via the
  // 'initialized' and 'started' callbacks.
  virtual bool StartImpl() = 0;
  // This must be non-blocking. This should indicate progress via the
  // 'stopped' callback.
  virtual bool StopImpl() = 0;
  // This should be blocking and should only return when the service has
  // terminated. This will only be called by the thread that created this
  // service.
  virtual bool JoinImpl() = 0;
  // @}

  // Testing seam for state transitions.
  virtual void OnStateChange(State old_state, State new_state) { }

 private:
  // Sets the current state. This grabs lock_, so must not be called while it is
  // already held.
  // @param state The new state to be set.
  void set_state(State state);

  std::wstring name_;
  std::wstring instance_id_;

  // Service callbacks.
  ServiceCallback started_callback_;
  ServiceCallback interrupted_callback_;
  ServiceCallback stopped_callback_;

  // The ID of the thread that created this logger. Because of the intricacies
  // of RPC some operations may only be performed by the owning thread and we
  // enforce that using this. This is only used for DCHECKs.
  base::PlatformThreadId owning_thread_id_;

  // The current state of the service instance.
  State state_;

  DISALLOW_COPY_AND_ASSIGN(Service);
};

}  // namespace common
}  // namespace trace

#endif  // SYZYGY_TRACE_COMMON_SERVICE_H_
