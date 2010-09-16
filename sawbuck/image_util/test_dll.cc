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
#include <windows.h>
#include <cstdlib>
#include <time.h>
#include <math.h>

extern int function1();
extern int function2();
extern int function3();

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

  int n = rand();
  switch (n % 7) {
  case 0:
    return reinterpret_cast<BOOL>(
        function1() + strstr("hello world", "hello"));
    break;

  case 1:
    return static_cast<BOOL>(function2() + strlen("foobar"));
    break;

  case 2:
    return static_cast<BOOL>(function3() + clock());
    break;

  case 3:
    return static_cast<BOOL>(function1() + function2() +
        reinterpret_cast<int>(memchr("hello", 'e', 5)));
    break;

  case 4:
    return static_cast<BOOL>(function1() + function3() + abs(-3));
    break;

  case 5:
    return static_cast<BOOL>(
        function2() + function3() + static_cast<int>(floor(1.3)));
    break;

  case 6:
    return static_cast<BOOL>(
        function1() + function2() + function3() + atoi("7"));
  }
}
