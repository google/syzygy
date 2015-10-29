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

{
  'variables': {
    'chromium_code': 1,
  },
  'targets': [
    {
      'target_name': 'memprof',
      'type': 'loadable_module',
      'includes': ['../agent.gypi'],
      'sources': [
        'memprof.cc',
        'memprof.def',
        'memprof.h',
        'memprof.rc',
      ],
      'dependencies': [
        'memprof_lib',
        '<(src)/syzygy/common/common.gyp:common_lib',
      ],
    },
    {
      'target_name': 'memprof_lib',
      'type': 'static_library',
      'sources': [
        'asan_compatibility.cc',
        'crt_interceptors.cc',
        'heap_interceptors.cc',
        'function_call_logger.cc',
        'function_call_logger.h',
        'memory_interceptors.cc',
        'memory_profiler.cc',
        'memory_profiler.h',
        'parameters.cc',
        'parameters.h',
        'system_interceptors.cc',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/core/core.gyp:core_lib',
        '<(src)/syzygy/trace/client/client.gyp:rpc_client_lib',
        '<(src)/syzygy/trace/common/common.gyp:trace_common_lib',
        '<(src)/syzygy/trace/protocol/protocol.gyp:protocol_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:logger_rpc_lib',
        '<(src)/syzygy/trace/rpc/rpc.gyp:call_trace_rpc_lib',
        '<(src)/syzygy/version/version.gyp:syzygy_version',
      ],
    },
    {
      'target_name': 'memprof_harness',
      'type': 'executable',
      'sources': [
        'memprof_harness.cc',
      ],
      'dependencies': [
      ],
      'msvs_settings': {
        'VCLinkerTool': {
          'IgnoreDefaultLibraryNames': [
            # Disallow linking against the debug runtime, which Syzygy is
            # unable to instrument.
            'libcmtd.lib',
          ],
        },
      },
      # We more or less want this to always be a release-style executable
      # to facilitate instrumentation.
      # We have to do this per configuration, as base.gypi specifies
      # this per-config, which binds tighter than the defaults above.
      'configurations': {
        'Debug_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              # This corresponds to /INCREMENTAL:NO. With incremental linking
              # enabled, every function resolves to a location in a jump table
              # which jumps to the function proper. This gets in the way of
              # disassembly.
              'LinkIncremental': '1',
              # Ensure that the checksum present in the header of the binaries
              # is set.
              'SetChecksum': 'true',
            },
            'VCCLCompilerTool': {
              'BasicRuntimeChecks': '0',
              # Memprof needs the application to be linked with the release
              # static runtime library for full coverage.
              'RuntimeLibrary':  '0', # 0 = /MT (nondebug static)
            },
          },
        },
        'Common_Base': {
          'msvs_settings': {
            'VCLinkerTool': {
              # This corresponds to /PROFILE, which ensures that the
              # PDB file contains a FIXUP stream.
              # TODO(chrisha): Move this to base.gypi so everything links
              #     with this flag.
              'Profile': 'true',
            },
          },
        },
      },
    },
    {
      'target_name': 'memprof_unittests',
      'type': 'executable',
      'sources': [
        'function_call_logger_unittest.cc',
        'memprof_unittest.cc',
        'parameters_unittest.cc',
        '<(src)/syzygy/testing/run_all_unittests.cc',
      ],
      'dependencies': [
        'memprof',
        'memprof_lib',
        '<(src)/base/base.gyp:base',
        '<(src)/base/base.gyp:test_support_base',
        '<(src)/syzygy/core/core.gyp:core_unittest_utils',
        '<(src)/syzygy/agent/common/common.gyp:agent_common_lib',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_lib',
        '<(src)/syzygy/trace/parse/parse.gyp:parse_unittest_utils',
        '<(src)/syzygy/trace/common/common.gyp:trace_unittest_utils',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        '<(src)/syzygy/pe/pe.gyp:pe_lib',
        '<(src)/syzygy/pe/pe.gyp:pe_unittest_utils',
        '<(src)/testing/gtest.gyp:gtest',
        '<(src)/testing/gmock.gyp:gmock',
       ],
    },
  ],
}
