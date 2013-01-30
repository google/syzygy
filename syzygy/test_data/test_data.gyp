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
  'targets': [
    {
      'target_name': 'copy_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(src)/syzygy/pe/pe.gyp:test_dll',
      ],
      'copies': [
        {
          'destination': '<(PRODUCT_DIR)/test_data',
          'files': [
            '<(PRODUCT_DIR)/test_dll.dll',
            '<(PRODUCT_DIR)/test_dll.pdb',
          ],
        },
      ],
    },
    {
      'target_name': 'rpc_instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(src)/syzygy/instrument/instrument.gyp:instrument',
        'copy_test_dll',
      ],
      'actions': [
        {
          'action_name': 'rpc_instrument_test_data_test_dll',
          'inputs': [
            '<(PRODUCT_DIR)/instrument.exe',
            '<(PRODUCT_DIR)/test_data/test_dll.dll',
            '<(PRODUCT_DIR)/test_data/test_dll.pdb',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.pdb',
          ],
          'action': [
            '"<(PRODUCT_DIR)/instrument.exe"',
            '--mode=calltrace',
            '--input-image=<(PRODUCT_DIR)/test_data/test_dll.dll',
            '--input-pdb=<(PRODUCT_DIR)/test_data/test_dll.pdb',
            '--output-image='
                '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.dll',
            '--output-pdb='
                '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.pdb',
            '--overwrite',
          ],
        },
      ],
    },
    {
      'target_name': 'profile_instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(src)/syzygy/instrument/instrument.gyp:instrument',
        'copy_test_dll',
      ],
      'actions': [
        {
          'action_name': 'profile_instrument_test_data_test_dll',
          'inputs': [
            '<(PRODUCT_DIR)/instrument.exe',
            '<(PRODUCT_DIR)/test_data/test_dll.dll',
            '<(PRODUCT_DIR)/test_data/test_dll.pdb',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/profile_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/profile_instrumented_test_dll.pdb',
          ],
          'action': [
            '"<(PRODUCT_DIR)/instrument.exe"',
            '--mode=profile',
            '--input-image=<(PRODUCT_DIR)/test_data/test_dll.dll',
            '--input-pdb=<(PRODUCT_DIR)/test_data/test_dll.pdb',
            '--output-image=<(PRODUCT_DIR)/test_data/'
                'profile_instrumented_test_dll.dll',
            '--output-pdb=<(PRODUCT_DIR)/test_data/'
                'profile_instrumented_test_dll.pdb',
            '--overwrite',
          ],
        },
      ],
    },
    {
      'target_name': 'basic_block_entry_instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(src)/syzygy/instrument/instrument.gyp:instrument',
        'copy_test_dll',
      ],
      'actions': [
        {
          'action_name': 'basic_block_entry_instrument_test_data_test_dll',
          'inputs': [
            '<(PRODUCT_DIR)/instrument.exe',
            '<(PRODUCT_DIR)/test_data/test_dll.dll',
            '<(PRODUCT_DIR)/test_data/test_dll.pdb',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/'
                'basic_block_entry_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/'
                'basic_block_entry_instrumented_test_dll.pdb',
          ],
          'action': [
            '"<(PRODUCT_DIR)/instrument.exe"',
            '--mode=bbentry',
            '--input-image=<(PRODUCT_DIR)/test_data/test_dll.dll',
            '--input-pdb=<(PRODUCT_DIR)/test_data/test_dll.pdb',
            '--output-image=<(PRODUCT_DIR)/test_data/'
                'basic_block_entry_instrumented_test_dll.dll',
            '--output-pdb=<(PRODUCT_DIR)/test_data/'
                'basic_block_entry_instrumented_test_dll.pdb',
            '--overwrite',
          ],
        },
      ],
    },
    {
      'target_name': 'coverage_instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(src)/syzygy/instrument/instrument.gyp:instrument',
        'copy_test_dll',
      ],
      'actions': [
        {
          'action_name': 'coverage_instrument_test_data_test_dll',
          'inputs': [
            '<(PRODUCT_DIR)/instrument.exe',
            '<(PRODUCT_DIR)/test_data/test_dll.dll',
            '<(PRODUCT_DIR)/test_data/test_dll.pdb',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/coverage_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/coverage_instrumented_test_dll.pdb',
          ],
          'action': [
            '"<(PRODUCT_DIR)/instrument.exe"',
            '--mode=coverage',
            '--input-image=<(PRODUCT_DIR)/test_data/test_dll.dll',
            '--input-pdb=<(PRODUCT_DIR)/test_data/test_dll.pdb',
            '--output-image=<(PRODUCT_DIR)/test_data/'
                'coverage_instrumented_test_dll.dll',
            '--output-pdb=<(PRODUCT_DIR)/test_data/'
                'coverage_instrumented_test_dll.pdb',
            '--overwrite',
          ],
        },
      ],
    },
    {
      'target_name': 'asan_instrumented_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(src)/syzygy/instrument/instrument.gyp:instrument',
        'copy_test_dll',
      ],
      'actions': [
        {
          'action_name': 'asan_instrument_test_data_test_dll',
          'inputs': [
            '<(PRODUCT_DIR)/instrument.exe',
            '<(PRODUCT_DIR)/test_data/test_dll.dll',
            '<(PRODUCT_DIR)/test_data/test_dll.pdb',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/asan_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/asan_instrumented_test_dll.pdb',
          ],
          'action': [
            '"<(PRODUCT_DIR)/instrument.exe"',
            '--mode=asan',
            '--input-image=<(PRODUCT_DIR)/test_data/test_dll.dll',
            '--input-pdb=<(PRODUCT_DIR)/test_data/test_dll.pdb',
            '--output-image=<(PRODUCT_DIR)/test_data/'
                'asan_instrumented_test_dll.dll',
            '--output-pdb=<(PRODUCT_DIR)/test_data/'
                'asan_instrumented_test_dll.pdb',
            '--overwrite',
          ],
        },
      ],
    },
    {
      'target_name': 'randomized_test_dll',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        '<(src)/syzygy/relink/relink.gyp:relink',
        'copy_test_dll'
      ],
      'actions': [
        {
          'action_name': 'randomize_test_data_test_dll',
          'inputs': [
            '<(PRODUCT_DIR)/relink.exe',
            '<(PRODUCT_DIR)/test_data/test_dll.dll',
            '<(PRODUCT_DIR)/test_data/test_dll.pdb',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/randomized_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/randomized_test_dll.pdb',
          ],
          'action': [
            '"<(PRODUCT_DIR)/relink.exe"',
            '--seed=0',
            '--input-image=<(PRODUCT_DIR)/test_data/test_dll.dll',
            '--input-pdb=<(PRODUCT_DIR)/test_data/test_dll.pdb',
            '--output-image=<(PRODUCT_DIR)/test_data/randomized_test_dll.dll',
            '--output-pdb=<(PRODUCT_DIR)/test_data/randomized_test_dll.pdb',
            '--overwrite',
          ],
        },
      ],
    },
    # TODO(rogerm): The GYP snippets to generate the trace files are all
    #     pretty much identical to one other if parameterized by the mode,
    #     dll/pdb name, and output directory. Find a way to consolidate to
    #     a reusable rule or gypi.
    {
      'target_name': 'rpc_traces',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'generate_traces.py',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/call_trace/call_trace.gyp:call_trace_client',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        'rpc_instrumented_test_dll',
      ],
      'actions': [
        {
          'action_name': 'generate_rpc_traces',
          'inputs': [
            '<(PRODUCT_DIR)/call_trace_client.dll',
            '<(PRODUCT_DIR)/call_trace_service.exe',
            '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.pdb',
            '<(src)/syzygy/test_data/generate_traces.py',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-4.bin',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/test_data/generate_traces.py',
            '--output-dir=<(PRODUCT_DIR)/test_data/rpc_traces',
            '--instrumented-image='
                '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.dll',
            '--verbose',
            # The build-dir arg must be last to work around a bug in the
            # interaction between GYP and VS2010.
            # See: http://code.google.com/p/gyp/issues/detail?id=272
            '--build-dir=<(PRODUCT_DIR)',
          ],
        },
      ],
    },
    {
      'target_name': 'profile_traces',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'generate_traces.py',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/profiler/profiler.gyp:profile_client',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        'profile_instrumented_test_dll',
      ],
      'actions': [
        {
          'action_name': 'generate_profile_traces',
          'inputs': [
            '<(PRODUCT_DIR)/profile_client.dll',
            '<(PRODUCT_DIR)/call_trace_service.exe',
            '<(PRODUCT_DIR)/test_data/profile_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/profile_instrumented_test_dll.pdb',
            '<(src)/syzygy/test_data/generate_traces.py',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/profile_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/profile_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/profile_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/profile_traces/trace-4.bin',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/test_data/generate_traces.py',
            '--output-dir=<(PRODUCT_DIR)/test_data/profile_traces',
            '--instrumented-image='
                '<(PRODUCT_DIR)/test_data/profile_instrumented_test_dll.dll',
            '--verbose',
            # The build-dir arg must be last to work around a bug in the
            # interaction between GYP and VS2010.
            # See: http://code.google.com/p/gyp/issues/detail?id=272
            '--build-dir=<(PRODUCT_DIR)',
          ],
        },
      ],
    },
    {
      'target_name': 'test_dll_order_json',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'dependencies': [
        'rpc_traces',
        'rpc_instrumented_test_dll',
        '<(src)/syzygy/reorder/reorder.gyp:reorder',
      ],
      'actions': [
        {
          'action_name': 'generate_test_dll_order_file',
          'inputs': [
            '<(PRODUCT_DIR)/reorder.exe',
            '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.pdb',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-4.bin',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/test_dll_order.json',
          ],
          'action': [
            '<(PRODUCT_DIR)/reorder.exe',
            '--instrumented-image='
                '<(PRODUCT_DIR)/test_data/rpc_instrumented_test_dll.dll',
            '--output-file=<(PRODUCT_DIR)/test_data/test_dll_order.json',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/rpc_traces/trace-4.bin',
          ],
        }
      ],
    },
    {
      'target_name': 'coverage_traces',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'generate_traces.py',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/coverage/coverage.gyp:coverage_client',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        'coverage_instrumented_test_dll',
      ],
      'actions': [
        {
          'action_name': 'generate_coverage_traces',
          'inputs': [
            '<(PRODUCT_DIR)/coverage_client.dll',
            '<(PRODUCT_DIR)/call_trace_service.exe',
            '<(PRODUCT_DIR)/test_data/coverage_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/coverage_instrumented_test_dll.pdb',
            '<(src)/syzygy/test_data/generate_traces.py',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/coverage_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/coverage_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/coverage_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/coverage_traces/trace-4.bin',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/test_data/generate_traces.py',
            '--output-dir=<(PRODUCT_DIR)/test_data/coverage_traces',
            '--instrumented-image='
                '<(PRODUCT_DIR)/test_data/coverage_instrumented_test_dll.dll',
            '--verbose',
            # The build-dir arg must be last to work around a bug in the
            # interaction between GYP and VS2010.
            # See: http://code.google.com/p/gyp/issues/detail?id=272
            '--build-dir=<(PRODUCT_DIR)',
          ],
        },
      ],
    },
    {
      'target_name': 'basic_block_entry_traces',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
        'generate_traces.py',
      ],
      'dependencies': [
        '<(src)/syzygy/agent/basic_block_entry/basic_block_entry.gyp:'
            'basic_block_entry_client',
        '<(src)/syzygy/trace/service/service.gyp:call_trace_service_exe',
        'basic_block_entry_instrumented_test_dll',
      ],
      'actions': [
        {
          'action_name': 'generate_basic_block_entry_traces',
          'inputs': [
            '<(PRODUCT_DIR)/basic_block_entry_client.dll',
            '<(PRODUCT_DIR)/call_trace_service.exe',
            '<(PRODUCT_DIR)/test_data/'
                'basic_block_entry_instrumented_test_dll.dll',
            '<(PRODUCT_DIR)/test_data/'
                'basic_block_entry_instrumented_test_dll.pdb',
            '<(src)/syzygy/test_data/generate_traces.py',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-4.bin',
          ],
          'action': [
            '<(python_exe)',
            '<(src)/syzygy/test_data/generate_traces.py',
            '--output-dir=<(PRODUCT_DIR)/test_data/basic_block_entry_traces',
            '--instrumented-image=<(PRODUCT_DIR)/test_data/'
                'basic_block_entry_instrumented_test_dll.dll',
            '--verbose',
            # The build-dir arg must be last to work around a bug in the
            # interaction between GYP and VS2010.
            # See: http://code.google.com/p/gyp/issues/detail?id=272
            '--build-dir=<(PRODUCT_DIR)',
          ],
        },
      ],
    },
    {
      'target_name': 'basic_block_entry_counts',
      'type': 'none',
      'msvs_cygwin_shell': 0,
      'sources': [
      ],
      'dependencies': [
        'basic_block_entry_traces',
        '<(src)/syzygy/grinder/grinder.gyp:grinder',
      ],
      'actions': [
        {
          'action_name': 'generate_basic_block_entry_counts',
          'inputs': [
            '<(PRODUCT_DIR)/grinder.exe',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-4.bin',
          ],
          'outputs': [
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/'
                'entry_counts.json',
          ],
          'action': [
            '<(PRODUCT_DIR)/grinder.exe',
            '--mode=bbentry',
            '--output-file=<(PRODUCT_DIR)/test_data/basic_block_entry_traces/'
                'entry_counts.json',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-1.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-2.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-3.bin',
            '<(PRODUCT_DIR)/test_data/basic_block_entry_traces/trace-4.bin',
          ],
        },
      ],
    },
  ],
}
