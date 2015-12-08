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
      'target_name': 'types_lib',
      'type': 'static_library',
      'sources': [
        'dia_crawler.cc',
        'dia_crawler.h',
        'pdb_crawler.cc',
        'pdb_crawler.h',
        'type.cc',
        'type.h',
        'type_namer.cc',
        'type_namer.h',
        'type_repository.cc',
        'type_repository.h',
        'typed_data.cc',
        'typed_data.h',
      ],
      'dependencies': [
        'test_typenames',
        'test_types',
        '<(src)/syzygy/pe/pe.gyp:dia_sdk',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/refinery/core/core.gyp:refinery_core_lib',
      ],
    },
    {
      'target_name': 'test_typenames',
      'type': 'loadable_module',
      'sources': [
        'test_typenames.def',
        'test_typenames_main.cc',
        'test_typenames.cc',
        'test_typenames.h',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          'EntryPointSymbol': 'EntryPoint',
          # Turn down incremental linking for the test to avoid types
          # languishing from build to build.
          'LinkIncremental': '1',
        },
      },
    },
    {
      'target_name': 'test_types',
      'type': 'loadable_module',
      'sources': [
        'test_types.def',
        'test_types.h',
        'test_types_main.cc',
        'test_types_one.cc',
        'test_types_two.cc',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          'EntryPointSymbol': 'EntryPoint',
          # Turn down incremental linking for the test to avoid types
          # languishing from build to build.
          'LinkIncremental': '1',
        },
      },
    },
    {
      'target_name': 'test_vtables',
      'type': 'loadable_module',
      'sources': [
        'test_vtables.def',
        'test_vtables.cc',
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          # Turn down incremental linking for the test to avoid types
          # languishing from build to build.
          'LinkIncremental': '1',
        },
      },
    },
  ],
}
