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
      'target_name': 'analyzers_lib',
      'type': 'static_library',
      'dependencies': [
        '<(src)/syzygy/common/common.gyp:common_lib',
        '<(src)/syzygy/pe/pe.gyp:dia_sdk',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/refinery/core/core.gyp:refinery_core_lib',
        '<(src)/syzygy/'
            'refinery/process_state/process_state.gyp:process_state_lib',
        '<(src)/syzygy/refinery/symbols/symbols.gyp:symbols_lib',
      ],
      'sources': [
        'analysis_runner.cc',
        'analysis_runner.h',
        'analyzer.h',
        'analyzer_util.cc',
        'analyzer_util.h',
        'exception_analyzer.cc',
        'exception_analyzer.h',
        'memory_analyzer.cc',
        'memory_analyzer.h',
        'module_analyzer.cc',
        'module_analyzer.h',
        'stack_analyzer.cc',
        'stack_analyzer.h',
        'stack_analyzer_impl.cc',
        'stack_analyzer_impl.h',
        'thread_analyzer.cc',
        'thread_analyzer.h',
        'unloaded_module_analyzer.cc',
        'unloaded_module_analyzer.h',
      ],
    },
  ],
}
