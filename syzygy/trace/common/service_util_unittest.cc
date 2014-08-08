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

#include "syzygy/trace/common/service_util.h"

#include "base/bind.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/condition_variable.h"
#include "base/threading/thread.h"
#include "gtest/gtest.h"

namespace trace {
namespace common {

namespace {

typedef base::Callback<bool()> BoolCallback;

void InvokeOnAnotherThreadTask(BoolCallback task,
                               base::Lock* lock,
                               base::ConditionVariable* cv,
                               bool* result,
                               bool* finished) {
  DCHECK(lock != NULL);
  DCHECK(cv != NULL);
  DCHECK(result != NULL);

  *result = task.Run();

  {
    base::AutoLock auto_lock(*lock);
    *finished = true;
    cv->Signal();
  }
}

bool InvokeOnAnotherThread(BoolCallback task) {
  base::Lock lock;
  base::ConditionVariable cv(&lock);
  bool result = false;
  bool finished = false;

  base::Thread worker("worker");
  worker.Start();
  worker.message_loop()->PostTask(
      FROM_HERE,
      base::Bind(&InvokeOnAnotherThreadTask,
                 task,
                 base::Unretained(&lock),
                 base::Unretained(&cv),
                 base::Unretained(&result),
                 base::Unretained(&finished)));

  base::AutoLock hold(lock);
  while (!finished)
    cv.Wait();

  worker.Stop();

  return result;
}

}  // namespace

TEST(ServiceUtilTest, AcquireMutex) {
  // We generate a mutex name that will be unique to this process so that
  // running multiple copies of the unittest doesn't cause problems.
  std::wstring mutex_name = base::StringPrintf(
      L"ServiceUtilTest-AcquireMutex-%08X", ::GetCurrentProcessId());

  // We should be able to acquire the mutex.
  base::win::ScopedHandle mutex1;
  EXPECT_TRUE(AcquireMutex(mutex_name, &mutex1));

  // We should not be able to acquire the mutex, as it is already held.
  base::win::ScopedHandle mutex2;
  EXPECT_FALSE(InvokeOnAnotherThread(base::Bind(&AcquireMutex,
                                                mutex_name,
                                                base::Unretained(&mutex2))));

  // Releasing the mutex should make us be able to acquire it once again.
  ::ReleaseMutex(mutex1.Get());
  mutex1.Close();
  EXPECT_TRUE(AcquireMutex(mutex_name, &mutex2));
}

TEST(ServiceUtilTest, InitEvent) {
  std::wstring event_name = base::StringPrintf(
      L"ServiceUtilTest-InitEvent-%08X", ::GetCurrentProcessId());

  base::win::ScopedHandle named_event;
  EXPECT_TRUE(InitEvent(event_name, &named_event));

  ::SetEvent(named_event.Get());

  ::WaitForSingleObject(named_event.Get(), INFINITE);
}

}  // namespace common
}  // namespace trace
