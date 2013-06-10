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

#include "syzygy/pe/test_dll.h"

#include <windows.h>  // NOLINT
#include <objbase.h>  // NOLINT
#include <winnt.h>  // NOLINT

#include <math.h>
#include <stdio.h>
#include <time.h>

#include <cstdlib>

#include "base/basictypes.h"

// Bring in a data import from export_dll.dll. This will cause a global data
// symbol to be emitted pointing to the import entry, but with the type we give
// here. If the type is bigger than the entire import table then the data
// symbol will be bigger than the block it resolves to. The data must be
// explicitly marked dllimport otherwise the linker will treat it as a code
// symbol and create a thunk for it.
__declspec(dllimport) extern int kExportedData[1024];

// A handful of TLS variables, to cause TLS fixups to appear.
__declspec(thread) int tls_int = 42;
__declspec(thread) int tls_array[64] = { 0 };
__declspec(thread) char tls_string_buffer[512] = { 0 };
__declspec(thread) double tls_double = 3.5;

// A dummy TLS Initialization callback handler.
VOID NTAPI MyTlsCallback(PVOID instance, DWORD reason, PVOID reserved) {
  ::time(NULL);
}

// Declare a TLS initializer callback to the linker.
#pragma section(".CRT$XLY",long,read)
extern "C" __declspec(allocate(".CRT$XLY"))
  PIMAGE_TLS_CALLBACK _xl_y1  = MyTlsCallback;

extern "C" __declspec(allocate(".CRT$XLY"))
  PIMAGE_TLS_CALLBACK _xl_y2  = MyTlsCallback;

// Use both mechanisms for importing functions (explicitly hinted with
// 'dllimport' and not) so that both code generation mechanisms are present
// in the final binary and subsequently tested by our decomposer.
__declspec(dllimport) extern int function1();
extern int function2();
extern int function3();

#pragma auto_inline(off)

DWORD WINAPI TestExport(size_t buf_len, char* buf) {
  static const char kTestString[] =
      "The quick brown fox jumped over the lazy dog";

  ::strncpy(buf, kTestString, buf_len);

  return 0;
}

DWORD WINAPI BringInOle32DelayLib() {
  // Reference this from Ole32 to pull in something.
  GUID guid = {};
  ::CoCreateGuid(&guid);

  return 0;
}

const char* BoolToString(bool value) {
  return value ? "true" : "false";
}

int FunctionWithInlineAssembly() {
  static int datum = 0;
  __asm {
    mov eax, [datum];
    add eax, 1;
    mov [datum], eax;
  }
  return datum;
}

#pragma auto_inline()

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  // The goal of the following weird code is to thwart any optimizations
  // that the compiler might try.

  // Put a series of calls in order. In general, expect they'll show up in
  // the same order when we search for references.
  function1();
  function1();
  function3();
  function2();
  function2();
  function3();
  function1();
  function1();

  int foo = FunctionWithInlineAssembly();
  foo += kExportedData[0];

  // We modify the exported data. If imports are improperly thunked this will
  // cause us to write junk all over any created thunks and should hopefully
  // cause the instrumented test_dll to explode.
  for (size_t i = 0; i < sizeof(kExportedData) / sizeof(kExportedData[0]); ++i)
    kExportedData[i] = i;

  // The following odd code and switch statement are to outsmart the
  // optimizer and coerce it to generate a case and jump table pair.
  // On decomposition, we expect to find and label the case and jump
  // tables individually.
  wchar_t c = rand() % static_cast<wchar_t>(-1);

  // We also need to coerce the optimizer into keeping around kExportedData and
  // FunctionWithInlineAssembly.
  c ^= static_cast<wchar_t>(foo);

  bool is_whitespace = false;
  bool is_qwerty = false;
  bool is_asdfgh = false;
  bool is_upper_case = false;
  bool is_other = false;

  // Switch over the UTF16 character space.
  switch (c) {
   case L'Q':
   case L'W':
   case L'E':
   case L'R':
   case L'T':
   case L'Y':
    is_qwerty = true;
    is_upper_case = true;
    break;

   case L'q':
   case L'w':
   case L'e':
   case L'r':
   case L't':
   case L'y':
    is_qwerty = true;
    is_upper_case = false;
    break;

   case L'A':
   case L'S':
   case L'D':
   case L'F':
   case L'G':
   case L'H':
    is_asdfgh = true;
    is_upper_case = true;
    break;

   case L'a':
   case L's':
   case L'd':
   case L'f':
   case L'g':
   case L'h':
    is_asdfgh = true;
    is_upper_case = false;
    break;

   case ' ':
   case '\t':
   case '\r':
   case '\n':
    is_whitespace = true;
    break;

   default:
    is_other = true;
    break;
  }

  char buffer[1024] = {'\0'};
  ::memset(buffer, 0, sizeof(buffer));
  ::_snprintf(buffer,
              sizeof(buffer) - 1,
              "is_qwerty=%s\nis_asdfgh=%s\nis_upper_case=%s\nis_whitespace=%s\n"
              "is_other=%s",
              BoolToString(is_qwerty),
              BoolToString(is_asdfgh),
              BoolToString(is_upper_case),
              BoolToString(is_whitespace),
              BoolToString(is_other));

  TestExport(sizeof(buffer), buffer);

  // This code generates a simple jump table with no case table following it.

  int n = rand();

  switch (n % 3) {
    case 0:
      n += function1();
      break;
    case 1:
      n += function2();
      break;
    case 2:
      n += function3();
      break;
    case 3:
      n -= function1();
      break;
    case 4:
      n -= function2();
      break;
    case 5:
      n -= function3();
      break;
  }

  // The following odd code and switch statement are to outsmart the
  // optimizer and coerce it to generate another case and jump table
  // pair. On decomposition, we expect to find and label the case
  // and jump tables individually.

  // Access the TLS data so that some TLS FIXUPs are produced.
  n += tls_int;
  n += tls_array[0];
  n += tls_string_buffer[0];
  n += static_cast<int>(tls_double);

  // The case table is a 20X expanded switch on n mod 7.
  switch (n % 140) {
    case 0:
    case 7:
    case 14:
    case 21:
    case 28:
    case 35:
    case 42:
    case 49:
    case 56:
    case 63:
    case 70:
    case 77:
    case 84:
    case 91:
    case 98:
    case 105:
    case 112:
    case 119:
    case 126:
    case 133:
      return reinterpret_cast<BOOL>(
          function1() + strstr("hello world", "hello"));

    case 1:
    case 8:
    case 15:
    case 22:
    case 29:
    case 36:
    case 43:
    case 50:
    case 57:
    case 64:
    case 71:
    case 78:
    case 85:
    case 92:
    case 99:
    case 106:
    case 113:
    case 120:
    case 127:
    case 134:
      return static_cast<BOOL>(function2() + strlen("foobar"));

    case 2:
    case 9:
    case 16:
    case 23:
    case 30:
    case 37:
    case 44:
    case 51:
    case 58:
    case 65:
    case 72:
    case 79:
    case 86:
    case 93:
    case 100:
    case 107:
    case 114:
    case 121:
    case 128:
    case 135:
      return static_cast<BOOL>(function3() + clock());

    case 3:
    case 10:
    case 17:
    case 24:
    case 31:
    case 38:
    case 45:
    case 52:
    case 59:
    case 66:
    case 73:
    case 80:
    case 87:
    case 94:
    case 101:
    case 108:
    case 115:
    case 122:
    case 129:
    case 136:
      return static_cast<BOOL>(function1() + function2() +
          reinterpret_cast<int>(memchr("hello", 'e', 5)));

    case 4:
    case 11:
    case 18:
    case 25:
    case 32:
    case 39:
    case 46:
    case 53:
    case 60:
    case 67:
    case 74:
    case 81:
    case 88:
    case 95:
    case 102:
    case 109:
    case 116:
    case 123:
    case 130:
    case 137:
      return static_cast<BOOL>(function1() + function3() + abs(-3));

    case 5:
    case 12:
    case 19:
    case 26:
    case 33:
    case 40:
    case 47:
    case 54:
    case 61:
    case 68:
    case 75:
    case 82:
    case 89:
    case 96:
    case 103:
    case 110:
    case 117:
    case 124:
    case 131:
    case 138:
      return static_cast<BOOL>(
          function2() + function3() + static_cast<int>(floor(1.3)));

    case 6:
    case 13:
    case 20:
    case 27:
    case 34:
    case 41:
    case 48:
    case 55:
    case 62:
    case 69:
    case 76:
    case 83:
    case 90:
    case 97:
    case 104:
    case 111:
    case 118:
    case 125:
    case 132:
    case 139:
      return static_cast<BOOL>(
          function1() + function2() + function3() + atoi("7"));
  }
}

void used_operation() {
  function1();
  function2();
  function3();
}

// This won't be called.
void unused_operation() {
  char dummy[512];
  TestExport(sizeof(dummy), dummy);
}

class Used {
 public:
  Used() {}
  virtual ~Used() {}
  virtual void M() {
    used_operation();
  }
};

// Unused::M() won't be called.
class Unused : public Used {
 public:
  virtual void M() {
    unused_operation();
  }
};

void CALLBACK TestUnusedFuncs(HWND unused_window,
                              HINSTANCE unused_instance,
                              LPSTR unused_cmd_line,
                              int unused_show) {
  bool call_it = time(NULL) > 10000;  // true unless you play with the clock.

  (call_it ? used_operation : unused_operation)();

  Used a;
  Unused b;
  (call_it ? &a : &b)->M();
}

DWORD FuncWithOffsetOutOfImage(int x, int y) {
  static const int kArray[4][256] = {};
  static const int kBigNum = 0xB0000000;
  return kArray[x][y + kBigNum];
}

static unsigned int ArrayComputation1() {
  // Dummy function to validate end to end instrumentation.
  const size_t kBufferLength = 1024;
  char A[kBufferLength];
  short B[kBufferLength];
  int C[kBufferLength];

  for (size_t i = 0; i < kBufferLength; ++i) {
    if (i == 0)
      A[i] = 0;
    else
      A[i] = 3*A[i-1] + 11;
  }

  for (size_t i = 0; i < kBufferLength; ++i) {
    B[i] = i;
    B[i] += A[i];
    B[i] = (B[i] << 1) ^ B[i];
  }

  for (size_t i = 0; i < kBufferLength; ++i) {
    C[i] = i;
    C[i] += A[i] + B[i];
    C[i] = ~C[i];
  }

  unsigned int sum = 0;
  for (int i = 0; i < kBufferLength; ++i) {
    sum += C[i] - (A[i] - B[i]);
  }

  return sum;
}

static unsigned int ArrayComputation2() {
  // Dummy function to validate end to end instrumentation.
  const size_t kBufferLength = 1024;
  int A[kBufferLength];

  for (size_t i = 0; i < kBufferLength; ++i) {
    A[i] = i;
  }

  int *ptr1 = &A[0];
  int *ptr2 = &A[kBufferLength-1];
  int result = 0;
  while (*ptr1 <= *ptr2) {
    ptr1++;
    ptr2--;
    result++;
  }

  return result;
}

// NOTE: This is used to fool compiler aliasing analysis. Do not make it static
//    nor const.
int kOffsetMinusOne = -1;
int kOffetZero = 0;
int kOffetOne = 1;

template<typename type>
static type AsanWriteBufferOverflow() {
  // Produce an ASAN error by writing one after the buffer.
  type* ptr = new type[1];
  ptr[kOffetZero] = static_cast<type>(1);
  ptr[kOffetOne] = static_cast<type>(2);
  type result = ptr[kOffetZero];
  delete ptr;
  return result;
}

template<typename type>
static type AsanWriteBufferUnderflow() {
  // Produce an ASAN error by writing one before the buffer.
  type* ptr = new type[1];
  ptr[kOffsetMinusOne] = static_cast<type>(1);
  ptr[kOffetZero] = static_cast<type>(2);
  type result = ptr[kOffetZero];
  delete ptr;
  return result;
}

template<typename type>
static type AsanReadBufferOverflow() {
  // Produce an ASAN error by reading one after the buffer.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = ptr[kOffetZero] + ptr[kOffetOne];
  delete ptr;
  return result;
}

template<typename type>
static type AsanReadBufferUnderflow() {
  // Produce an ASAN error by reading one before the buffer.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = ptr[kOffetZero] + ptr[kOffsetMinusOne];
  delete ptr;
  return result;
}

template<typename type>
static type AsanReadUseAfterFree() {
  // Produce an ASAN error by reading memory after deleting it.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  delete ptr;
  type result = ptr[kOffetZero];
  return result;
}

template<typename type>
static type AsanWriteUseAfterFree() {
  // Produce an ASAN error by writing memory after deleting it.
  type* ptr = new type[1];
  *ptr = static_cast<type>(42);
  type result = *ptr;
  delete ptr;
  ptr[kOffetZero] = static_cast<type>(12);
  return result;
}


// Functions below are used to test basic block counting in the end to end
// unittest. We assume the compiler won't simplify any calls.

// Avoiding global optimization.
#pragma optimize("g", off)

extern "C" unsigned int BBEntryCallOnce() {
  return 42;
}

extern "C" unsigned int BBEntryFunction1() {
  return 10;
}

extern "C" unsigned int BBEntryFunction2() {
  return BBEntryFunction1() + BBEntryFunction1();
}

extern "C" unsigned int BBEntryFunction3() {
  return BBEntryFunction2() + BBEntryFunction2();
}

extern "C" unsigned int BBEntryCallTree() {
  return BBEntryFunction3() + 2;
}

extern "C" unsigned int BBEntryFunctionRecursive(int n) {
  if (n == 1)
    return 1;
  return BBEntryFunctionRecursive(n - 1) + 1;
}

extern "C" unsigned int BBEntryCallRecursive() {
  return BBEntryFunctionRecursive(42);
}

unsigned int CALLBACK EndToEndTest(EndToEndTestId test) {
  // This function is used to dispatch test id to its corresponding function.
  switch (test) {
    // Behavior tests.
    case kArrayComputation1TestId:
      return ArrayComputation1();
    case kArrayComputation2TestId:
      return ArrayComputation2();

    // Asan Memory Error.
    case kAsanRead8BufferOverflowTestId:
      return AsanReadBufferOverflow<int8>();
    case kAsanRead16BufferOverflowTestId:
      return AsanReadBufferOverflow<int16>();
    case kAsanRead32BufferOverflowTestId:
      return AsanReadBufferOverflow<int32>();
    case kAsanRead64BufferOverflowTestId:
      return AsanReadBufferOverflow<double>();

    case kAsanRead8BufferUnderflowTestId:
      return AsanReadBufferUnderflow<int8>();
    case kAsanRead16BufferUnderflowTestId:
      return AsanReadBufferUnderflow<int16>();
    case kAsanRead32BufferUnderflowTestId:
      return AsanReadBufferUnderflow<int32>();
    case kAsanRead64BufferUnderflowTestId:
      return AsanReadBufferUnderflow<double>();

    case kAsanWrite8BufferOverflowTestId:
      return AsanWriteBufferOverflow<int8>();
    case kAsanWrite16BufferOverflowTestId:
      return AsanWriteBufferOverflow<int16>();
    case kAsanWrite32BufferOverflowTestId:
      return AsanWriteBufferOverflow<int32>();
    case kAsanWrite64BufferOverflowTestId:
      return AsanWriteBufferOverflow<double>();

    case kAsanWrite8BufferUnderflowTestId:
      return AsanWriteBufferUnderflow<int8>();
    case kAsanWrite16BufferUnderflowTestId:
      return AsanWriteBufferUnderflow<int16>();
    case kAsanWrite32BufferUnderflowTestId:
      return AsanWriteBufferUnderflow<int32>();
    case kAsanWrite64BufferUnderflowTestId:
      return AsanWriteBufferUnderflow<double>();

    case kAsanRead8UseAfterFreeTestId:
      return AsanReadUseAfterFree<int8>();
    case kAsanRead16UseAfterFreeTestId:
      return AsanReadUseAfterFree<int16>();
    case kAsanRead32UseAfterFreeTestId:
      return AsanReadUseAfterFree<int32>();
    case kAsanRead64UseAfterFreeTestId:
      return AsanReadUseAfterFree<double>();

    case kAsanWrite8UseAfterFreeTestId:
      return AsanWriteUseAfterFree<int8>();
    case kAsanWrite16UseAfterFreeTestId:
      return AsanWriteUseAfterFree<int16>();
    case kAsanWrite32UseAfterFreeTestId:
      return AsanWriteUseAfterFree<int32>();
    case kAsanWrite64UseAfterFreeTestId:
      return AsanWriteUseAfterFree<double>();

    case kBBEntryCallOnce:
      return BBEntryCallOnce();
    case kBBEntryCallTree:
      return BBEntryCallTree();
    case kBBEntryCallRecursive:
      return BBEntryCallRecursive();
  }
  return 0;
}
