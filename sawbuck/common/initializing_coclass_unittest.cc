// Copyright 2011 Google Inc.
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
// Unit tests for InitializingCoClass template mixin.
#include "sawbuck/common/initializing_coclass.h"

#include <atlbase.h>
#include <atlcom.h>
#include "gtest/gtest.h"

namespace {

// A test class to exercise initializing coclass functionality
// We inherit from two interfaces just to play devil's advocate
class CoClassTesterBase: public CComObjectRootEx<CComSingleThreadModel>,
        public IObjectWithSiteImpl<CoClassTesterBase>,
        public IDispatchImpl<IDispatch> {
 public:
  CoClassTesterBase() {
    instances_++;
    last_initializer_called_ = 0;
  }

  ~CoClassTesterBase() {
    instances_--;
  }

  BEGIN_COM_MAP(CoClassTesterBase)
    COM_INTERFACE_ENTRY(IObjectWithSite)
    COM_INTERFACE_ENTRY(IDispatch)
  END_COM_MAP()

 public:
  static int last_initializer_called_;

  // tally of our instances
  static int instances_;
};

int CoClassTesterBase::last_initializer_called_ = 0;
int CoClassTesterBase::instances_ = 0;

#define DECLARE_INIT_FUNCTION(args, num, result) \
HRESULT Initialize args { \
  last_initializer_called_ = num; \
  return result; \
}

class CoClassSuccessTester: public CoClassTesterBase,
        public InitializingCoClass<CoClassSuccessTester> {
 public:
  DECLARE_INIT_FUNCTION((), 0, S_OK)
  DECLARE_INIT_FUNCTION((int a1), 1, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2), 2, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3), 3, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4), 4, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5), 5, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6),
                        6, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7), 7, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7, int a8), 8, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7, int a8, int a9), 9, S_OK)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7, int a8, int a9, int a10), 10, S_OK)
};

class CoClassFailureTester: public CoClassTesterBase,
        public InitializingCoClass<CoClassFailureTester> {
 public:
  DECLARE_INIT_FUNCTION((), 0, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1), 1, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2), 2, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3), 3, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4), 4, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5), 5, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6),
                        6, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7), 7, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7, int a8), 8, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7, int a8, int a9), 9, E_FAIL)
  DECLARE_INIT_FUNCTION((int a1, int a2, int a3, int a4, int a5, int a6,
                        int a7, int a8, int a9, int a10), 10, E_FAIL)
};
}  // namespace

// Test for successful init
TEST(InitializingCoClassTest, InitSuccess) {
#define SUCCESS_TEST(num, args) \
  { \
    CComPtr<IDispatch> disp; \
    ASSERT_TRUE(SUCCEEDED(CoClassSuccessTester::CreateInitialized args)); \
    ASSERT_EQ(1, CoClassTesterBase::instances_); \
    ASSERT_EQ(num, CoClassTesterBase::last_initializer_called_); \
    disp.Release(); \
    ASSERT_EQ(0, CoClassTesterBase::instances_); \
  } \

  SUCCESS_TEST(0, (&disp))
  SUCCESS_TEST(1, (1, &disp))
  SUCCESS_TEST(2, (1, 2, &disp))
  SUCCESS_TEST(3, (1, 2, 3, &disp))
  SUCCESS_TEST(4, (1, 2, 3, 4, &disp))
  SUCCESS_TEST(5, (1, 2, 3, 4, 5, &disp))
  SUCCESS_TEST(6, (1, 2, 3, 4, 5, 6, &disp))
  SUCCESS_TEST(7, (1, 2, 3, 4, 5, 6, 7, &disp))
  SUCCESS_TEST(8, (1, 2, 3, 4, 5, 6, 7, 8, &disp))
  SUCCESS_TEST(9, (1, 2, 3, 4, 5, 6, 7, 8, 9, &disp))
  SUCCESS_TEST(10, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, &disp))
}

// Test for failure on initialization, proper cleanup
TEST(InitializingCoClassTest, InitFailure) {
#define FAILURE_TEST(num, args) \
  { \
    CComPtr<IDispatch> disp; \
    ASSERT_TRUE(FAILED(CoClassFailureTester::CreateInitialized args)); \
    ASSERT_EQ(0, CoClassTesterBase::instances_); \
    ASSERT_EQ(num, CoClassTesterBase::last_initializer_called_); \
    ASSERT_TRUE(NULL == disp.p); \
  } \

  FAILURE_TEST(0, (&disp))
  FAILURE_TEST(1, (1, &disp))
  FAILURE_TEST(2, (1, 2, &disp))
  FAILURE_TEST(3, (1, 2, 3, &disp))
  FAILURE_TEST(4, (1, 2, 3, 4, &disp))
  FAILURE_TEST(5, (1, 2, 3, 4, 5, &disp))
  FAILURE_TEST(6, (1, 2, 3, 4, 5, 6, &disp))
  FAILURE_TEST(7, (1, 2, 3, 4, 5, 6, 7, &disp))
  FAILURE_TEST(8, (1, 2, 3, 4, 5, 6, 7, 8, &disp))
  FAILURE_TEST(9, (1, 2, 3, 4, 5, 6, 7, 8, 9, &disp))
  FAILURE_TEST(10, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, &disp))
}

// Test for failure on QueryInterface, proper cleanup
TEST(InitializingCoClassTest, QueryInterfaceFailure) {
#define QI_FAILURE_TEST(num, args) \
  { \
    CComPtr<IStream> stream; \
    ASSERT_EQ(E_NOINTERFACE, CoClassSuccessTester::CreateInitialized args); \
    ASSERT_EQ(0, CoClassTesterBase::instances_); \
    ASSERT_EQ(num, CoClassTesterBase::last_initializer_called_); \
    ASSERT_TRUE(NULL == stream.p); \
  } \

  QI_FAILURE_TEST(0, (&stream))
  QI_FAILURE_TEST(1, (1, &stream))
  QI_FAILURE_TEST(2, (1, 2, &stream))
  QI_FAILURE_TEST(3, (1, 2, 3, &stream))
  QI_FAILURE_TEST(4, (1, 2, 3, 4, &stream))
  QI_FAILURE_TEST(5, (1, 2, 3, 4, 5, &stream))
  QI_FAILURE_TEST(6, (1, 2, 3, 4, 5, 6, &stream))
  QI_FAILURE_TEST(7, (1, 2, 3, 4, 5, 6, 7, &stream))
  QI_FAILURE_TEST(8, (1, 2, 3, 4, 5, 6, 7, 8, &stream))
  QI_FAILURE_TEST(9, (1, 2, 3, 4, 5, 6, 7, 8, 9, &stream))
  QI_FAILURE_TEST(10, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, &stream))
}


// Test for proper cleanup on Initialize failure for CreateInstance
TEST(InitializingCoClassTest, InitFailureOnCreateInstance) {
#define INIT_FAILURE_TEST(num, args) \
  { \
    CoClassSuccessTester* tester; \
    ASSERT_EQ(E_FAIL, CoClassFailureTester::CreateInstance args); \
    ASSERT_EQ(0, CoClassTesterBase::instances_); \
    ASSERT_EQ(num, CoClassTesterBase::last_initializer_called_); \
    ASSERT_TRUE(NULL == tester); \
  } \

  QI_FAILURE_TEST(0, (&stream))
  QI_FAILURE_TEST(1, (1, &stream))
  QI_FAILURE_TEST(2, (1, 2, &stream))
  QI_FAILURE_TEST(3, (1, 2, 3, &stream))
  QI_FAILURE_TEST(4, (1, 2, 3, 4, &stream))
  QI_FAILURE_TEST(5, (1, 2, 3, 4, 5, &stream))
  QI_FAILURE_TEST(6, (1, 2, 3, 4, 5, 6, &stream))
  QI_FAILURE_TEST(7, (1, 2, 3, 4, 5, 6, 7, &stream))
  QI_FAILURE_TEST(8, (1, 2, 3, 4, 5, 6, 7, 8, &stream))
  QI_FAILURE_TEST(9, (1, 2, 3, 4, 5, 6, 7, 8, 9, &stream))
  QI_FAILURE_TEST(10, (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, &stream))
}

namespace {

// Class that does not like to be copied.
class DoNotCopy {
 public:
  DoNotCopy() {
  }
  DoNotCopy(const DoNotCopy& copy) {
    EXPECT_TRUE(false);
  }
};

// Simple class we will use to test if reference parameters are being honoured
// or if in fact they are being copied somewhere inbetween CreateInstance() and
// Initialize().
class CoClassCopyTester
    : public CComObjectRootEx<CComSingleThreadModel>,
      public IDispatchImpl<IDispatch>,
      public InitializingCoClass<CoClassCopyTester> {
 public:
  BEGIN_COM_MAP(CoClassCopyTester)
    COM_INTERFACE_ENTRY(IDispatch)
  END_COM_MAP()

  HRESULT Initialize(const DoNotCopy& data) {
    // If we got this far it means we didn't run the copy constructor
    return S_OK;
  }
};
}  // namespace

// Test to make sure that passing a reference parameter doesn't trigger a copy
// on the argument.
TEST(InitializingCoClassTest, TestReferenceParams) {
  DoNotCopy data;
  CComPtr<IDispatch> tester;

  HRESULT hr = CoClassCopyTester::CreateInitialized(data, &tester);
  ASSERT_EQ(S_OK, hr);
}
