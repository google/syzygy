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

#include <stdlib.h>

// This is a simple function that will contain a jump and case table. It has
// C linkage so that the name is not mangled for easy lookup in unittests.
extern "C" int TestFunctionWithNoPrivateSymbols() {
  int i = rand();
  switch (i % 140) {
    case 0:
    case 11:
    case 100:
    case 101:
    case 102: {
      i += 5;
      break;
    }

    case 1:
    case 7:
    case 80:
    case 87: {
      i -= 3;
      break;
    }

    case 2:
    case 6: {
      i += rand();
      break;
    }

    case 3:
    case 9: {
      i %= 8;
      break;
    }

    case 4:
    case 10: {
      i /= 2;
      break;
    }

    case 5:
    case 8:
    case 43:
    case 44: {
      i *= 17;
      break;
    }

    default: {
      i >>= 2;
      break;
    }
  }

  if (i % 2) {
    i *= 3;
  } else {
    --i;
  }

  return i;
}
