# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
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
      'target_name': 'validators_lib',
      'type': 'static_library',
      'dependencies': [
        '<(src)/syzygy/refinery/core/core.gyp:refinery_core_lib',
        '<(src)/syzygy/'
            'refinery/process_state/process_state.gyp:process_state_lib',
        '<(src)/syzygy/refinery/symbols/symbols.gyp:symbols_lib',
        '<(src)/syzygy/refinery/types/types.gyp:types_lib',
      ],
      'sources': [
        'validator.h',
        'exception_handler_validator.cc',
        'exception_handler_validator.h',
        'vftable_ptr_validator.cc',
        'vftable_ptr_validator.h',
      ],
    },
  ],
}
