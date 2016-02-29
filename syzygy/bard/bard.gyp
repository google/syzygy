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
        'event.cc',
        'event.h',
        'raw_argument_converter.cc',
        'raw_argument_converter.h',
        'story.cc',
        'story.h',
        'trace_live_map.h',
        'trace_live_map_impl.h',
        'backdrops/heap_backdrop.cc',
        'backdrops/heap_backdrop.h',
        'events/heap_alloc_event.cc',
        'events/heap_alloc_event.h',
        'events/heap_create_event.cc',
        'events/heap_create_event.h',
        'events/heap_destroy_event.cc',
        'events/heap_destroy_event.h',
        'events/heap_free_event.cc',
        'events/heap_free_event.h',
        'events/heap_realloc_event.cc',
        'events/heap_realloc_event.h',
        'events/heap_set_information_event.cc',
        'events/heap_set_information_event.h',
        'events/heap_size_event.cc',
        'events/heap_size_event.h',
        'events/linked_event.cc',
        'events/linked_event.h',
        'events/play_util.cc',
        'events/play_util.h',
        'events/play_util_impl.h',
      ],
      'dependencies': [
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/agent/asan/asan.gyp:syzyasan_rtl',
        '<(src)/syzygy/core/core.gyp:core_lib',
      ],
    },
    {
      'target_name': 'bard_unittest_utils',
      'type': 'static_library',
      'sources': [
        'unittest_util.cc',
        'unittest_util.h',
      ],
      'dependencies': [
        'bard_lib',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'bard_unittests',
      'type': 'executable',
      'sources': [
        'event_unittest.cc',
        'raw_argument_converter_unittest.cc',
        'story_unittest.cc',
        'trace_live_map_unittest.cc',
        'backdrops/heap_backdrop_unittest.cc',
        'events/heap_alloc_event_unittest.cc',
        'events/heap_create_event_unittest.cc',
        'events/heap_destroy_event_unittest.cc',
        'events/heap_free_event_unittest.cc',
        'events/heap_realloc_event_unittest.cc',
        'events/heap_set_information_event_unittest.cc',
        'events/heap_size_event_unittest.cc',
        'events/linked_event_unittest.cc',
        'events/play_util_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'bard_lib',
        'bard_unittest_utils',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Disable support for large address spaces.
          'LargeAddressAware': 1,
        },
      },
    },
  ]
}
