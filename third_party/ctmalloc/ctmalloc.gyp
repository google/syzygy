# Copyright 2014 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build configuration for ctmalloc. This is not a part of the original
# library.

{
  'targets': [
    {
      'target_name': 'ctmalloc_lib',
      'type': 'static_library',
      'sources': [
        'wtf/AsanHooks.cpp',
        'wtf/AsanHooks.h',
        'wtf/Assertions.h',
        'wtf/Atomics.h',
        'wtf/BitwiseOperations.h',
        'wtf/ByteSwap.h',
        'wtf/Compiler.h',
        'wtf/config.h',
        'wtf/CPU.h',
        'wtf/malloc.cpp',
        'wtf/PageAllocator.cpp',
        'wtf/PageAllocator.h',
        'wtf/PartitionAlloc.cpp',
        'wtf/PartitionAlloc.h',
        'wtf/ProcessID.h',
        'wtf/SpinLock.h',
        'wtf/WTFExport.h',
      ],
      'include_dirs': [
        '<(src)/third_party/ctmalloc',
      ],
      'all_dependent_settings': {
        'include_dirs': [
          '<(src)/third_party/ctmalloc',
        ],
      },
    },
  ],
}
