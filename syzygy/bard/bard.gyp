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
      'target_name': 'bard_lib',
      'type': 'static_library',
      'sources': [
        'causal_link.cc',
        'causal_link.h',
        'event.h',
        'events/linked_event.cc',
        'events/linked_event.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
      ],
    },
    {
      'target_name': 'bard_unittests',
      'type': 'executable',
      'sources': [
        'causal_link_unittest.cc',
        'events/linked_event_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'bard_lib',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ]
}
