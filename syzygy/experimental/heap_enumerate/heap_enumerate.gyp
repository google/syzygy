# Copyright 2012 Google Inc. All Rights Reserved.
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

{
  'variables': {
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'heap_enumerate',
      'type': 'executable',
      'sources': [
        'heap_entry_walker.cc',
        'heap_entry_walker.h',
        'heap_enumerate.cc',
        'heap_enumerate.h',
        'heap_enumerate_app.cc',
        'heap_enumerate_app.h',
        'heap_enumerate_main.cc',
        'list_entry_enumerator.cc',
        'list_entry_enumerator.h',
      ],
      'working_directory': '$(OutDir)',
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/application/application.gyp:application_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/pe/pe.gyp:dia_sdk',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/refinery/testing/testing.gyp:refinery_testing_lib',
        '<(src)/syzygy/refinery/types/types.gyp:types_lib'
      ],
    },
  ]
}
