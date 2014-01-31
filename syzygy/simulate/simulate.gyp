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
      'target_name': 'simulate_lib',
      'type': 'static_library',
      'sources': [
        'heat_map_simulation.cc',
        'heat_map_simulation.h',
        'page_fault_simulation.cc',
        'page_fault_simulation.h',
        'simulation_event_handler.h',
        'simulator.cc',
        'simulator.h',
      ],
      'dependencies': [
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pdb/pdb.gyp:pdb_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/playback/playback.gyp:playback_lib',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
      ],
    },
    {
      'target_name': 'simulate',
      'type': 'executable',
      'sources': [
        'simulate_main.cc',
      ],
      'dependencies': [
        'simulate_lib',
        '<(src)/base/base.gyp:base',
      ],
    },
    {
      'target_name': 'simulate_unittests',
      'type': 'executable',
      'sources': [
        'heat_map_simulation_unittest.cc',
        'page_fault_simulation_unittest.cc',
        'simulate_unittests_main.cc',
        'simulator_unittest.cc',
      ],
      'dependencies': [
        'simulate_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/syzygy/test_data/test_data.gyp:call_trace_traces',
        '<(src)/syzygy/test_data/test_data.gyp:copy_test_dll',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_unittest_utils',
        '<(src)/testing/gmock.gyp:gmock',
        '<(src)/testing/gtest.gyp:gtest',
      ],
    },
  ],
}
