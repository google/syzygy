#!python
# Copyright 2014 Google Inc. All Rights Reserved.
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
"""Unittests for the asan_system_interceptor_parser module."""

import asan_system_interceptor_parser as asan_parser
import logging
import optparse
import os
import re
import shutil
import tempfile
import unittest


class TestInterceptorParser(unittest.TestCase):
  """Unittests for asan_system_interceptor_parser."""


  def setUp(self):
    self.temp_dir = tempfile.mkdtemp()
    self.output_base = tempfile.NamedTemporaryFile(delete=False,
                                                   dir=self.temp_dir)
    self.def_file = tempfile.NamedTemporaryFile(delete=False, dir=self.temp_dir)
    self.output_base.close()
    self.def_file.close()
    self.generator = asan_parser.ASanSystemInterceptorGenerator(
        self.output_base.name, self.def_file.name)


  def tearDown(self):
    self.generator = None
    shutil.rmtree(self.temp_dir)


  def testFunctionMatchRegex(self):
    # Test against a regular function definition.
    valid_function1 =  \
        'MODULE: foo.dll\n'  \
        'VOID\n'  \
        'WINAPI\n'  \
        'function1('  \
        '    type1 param1,\n'  \
        '    type2 param2,\n'  \
        '    type3 param3\n'  \
        '    );\n'
    valid_function1_m = asan_parser._FUNCTION_MATCH_RE.search(valid_function1)
    self.assertTrue(valid_function1_m != None)
    self.assertEqual(valid_function1_m.group('ret'), 'VOID')
    self.assertEqual(valid_function1_m.group('name'), 'function1')

    # Test against a function definition including some complex annotations.
    valid_function2 =  \
        'MODULE: foo.dll\n'  \
        'BOOL\n'  \
        'WINAPI\n'  \
        'function2('  \
        '    _In_ type1 param1[],\n'  \
        '     _Out_writes_bytes_opt_(nNumberOfBytesToRead)\n'  \
        '         __out_data_source(FILE) LPVOID lpBuffer,\n'  \
        '    _Inout_opt_ type3 param3,\n'  \
        '    );\n'
    valid_function2_m = asan_parser._FUNCTION_MATCH_RE.search(valid_function2)
    self.assertTrue(valid_function2_m != None)
    self.assertEqual(valid_function2_m.group('ret'), 'BOOL')
    self.assertEqual(valid_function2_m.group('name'), 'function2')

    # Test against a simple function definition.
    valid_function3 =  \
        'MODULE: foo.dll\n'  \
        'int\n'  \
        'WINAPI\n'  \
        'function3(void foo);\n'
    valid_function3_m = asan_parser._FUNCTION_MATCH_RE.search(valid_function3)
    self.assertTrue(valid_function3_m != None)
    self.assertEqual(valid_function3_m.group('ret'), 'int')
    self.assertEqual(valid_function3_m.group('name'), 'function3')

    # Test against a function definition that doesn't contain the WINAPI
    # keyword.
    invalid_function1 =  \
        'BOOL\n'  \
        'function1('  \
        '    type1 param1,\n'  \
        '    type2 param2,\n'  \
        '    type3 param3\n'  \
        '    );\n'
    invalid_function1_m =  \
        asan_parser._FUNCTION_MATCH_RE.search(invalid_function1)
    self.assertTrue(invalid_function1_m == None)

    # Test against a function declaration containing an ifdef group.
    invalid_function2 =  \
        'BOOL\n'  \
        'WINAPI\n'  \
        '#ifdef FOO'  \
        'function2('  \
        'else'  \
        'function2('  \
        '#endif'  \
        '    type1 param1\n'  \
        '    );\n'
    invalid_function2_m =  \
        asan_parser._FUNCTION_MATCH_RE.search(invalid_function2)
    self.assertTrue(invalid_function2_m == None)

    # Test against an incomplete function definition.
    invalid_function3 =  \
        'BOOL\n'  \
        'function3('  \
        '    type1 param1,\n'
    invalid_function3_m =  \
        asan_parser._FUNCTION_MATCH_RE.search(invalid_function3)
    self.assertTrue(invalid_function3_m == None)

    # Test against a function with no return type specified.
    invalid_function4 =  \
        'WINAPI\n'  \
        'function4('  \
        '    type1 param1\n'  \
        '    );\n'
    invalid_function4_m =  \
        asan_parser._FUNCTION_MATCH_RE.search(invalid_function4)
    self.assertTrue(invalid_function4_m == None)

    # Test against an empty string.
    invalid_function5 = ''
    invalid_function5_m =  \
        asan_parser._FUNCTION_MATCH_RE.search(invalid_function5)
    self.assertTrue(invalid_function5_m == None)


  def testArgTokenizesRegex(self):
    # Test against some declarations encountered in fileapi.h

    valid_test_1 = '_In_ HANDLE hFile'
    valid_test_1_match = asan_parser._ARG_TOKENS_RE.search(valid_test_1)
    self.assertTrue(valid_test_1_match != None)
    self.assertEqual('_In_', valid_test_1_match.group('SAL_tag'))
    self.assertEqual(None, valid_test_1_match.group('SAL_tag_args'))
    self.assertEqual('HANDLE', valid_test_1_match.group('var_type'))
    self.assertEqual('hFile', valid_test_1_match.group('var_name'))

    valid_test_2 =  \
        '_In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer'
    valid_test_2_match = asan_parser._ARG_TOKENS_RE.search(valid_test_2)
    self.assertTrue(valid_test_2_match != None)
    self.assertEqual('_In_reads_bytes_opt_',  \
                     valid_test_2_match.group('SAL_tag'))
    self.assertEqual('nNumberOfBytesToWrite',  \
                    valid_test_2_match.group('SAL_tag_args'))
    self.assertEqual('LPCVOID', valid_test_2_match.group('var_type'))
    self.assertEqual('lpBuffer', valid_test_2_match.group('var_name'))

    valid_test_3 =  \
        '_Out_writes_to_opt_(nBufferLength, return + 1) LPWSTR lpBuffer'
    valid_test_3_match = asan_parser._ARG_TOKENS_RE.search(valid_test_3)
    self.assertTrue(valid_test_3_match != None)
    self.assertEqual('_Out_writes_to_opt_', valid_test_3_match.group('SAL_tag'))
    self.assertEqual('nBufferLength, return + 1',  \
                     valid_test_3_match.group('SAL_tag_args'))
    self.assertEqual('LPWSTR', valid_test_3_match.group('var_type'))
    self.assertEqual('lpBuffer', valid_test_3_match.group('var_name'))

    valid_test_2 =  \
        '_Out_writes_bytes_opt_(nNumber) __out_data_source(FILE) LPVOID lpBuf'
    valid_test_2_match = asan_parser._ARG_TOKENS_RE.search(valid_test_2)
    self.assertTrue(valid_test_2_match != None)
    self.assertEqual('_Out_writes_bytes_opt_',  \
                     valid_test_2_match.group('SAL_tag'))
    self.assertEqual('nNumber', valid_test_2_match.group('SAL_tag_args'))
    self.assertEqual('LPVOID', valid_test_2_match.group('var_type'))
    self.assertEqual('lpBuf', valid_test_2_match.group('var_name'))

    valid_test_5 = '_Out_writes_to_opt_(cchBufferLength, *lpcchReturnLength)'  \
        ' _Post_ _NullNull_terminated_ LPWCH lpszVolumePathNames'
    valid_test_5_match = asan_parser._ARG_TOKENS_RE.search(valid_test_5)
    self.assertTrue(valid_test_5_match != None)
    self.assertEqual('_Out_writes_to_opt_', valid_test_5_match.group('SAL_tag'))
    self.assertEqual('cchBufferLength, *lpcchReturnLength',  \
                     valid_test_5_match.group('SAL_tag_args'))
    self.assertEqual('LPWCH', valid_test_5_match.group('var_type'))
    self.assertEqual('lpszVolumePathNames',  \
                     valid_test_5_match.group('var_name'))

    valid_test_6 = '_In_ FILE_SEGMENT_ELEMENT aSegmentArray[]'
    valid_test_6_match = asan_parser._ARG_TOKENS_RE.search(valid_test_6)
    self.assertTrue(valid_test_6_match != None)
    self.assertEqual('_In_', valid_test_6_match.group('SAL_tag'))
    self.assertEqual(None, valid_test_6_match.group('SAL_tag_args'))
    self.assertEqual('FILE_SEGMENT_ELEMENT',  \
                     valid_test_6_match.group('var_type'))
    self.assertEqual('aSegmentArray', valid_test_6_match.group('var_name'))

    valid_test_7 = '_In_reads_bytes_opt_(PropertyBufferSize) CONST PBYTE '  \
                       'PropertyBuffer'
    valid_test_7_match = asan_parser._ARG_TOKENS_RE.search(valid_test_7)
    self.assertTrue(valid_test_7_match != None)
    self.assertEqual('_In_reads_bytes_opt_',  \
        valid_test_7_match.group('SAL_tag'))
    self.assertEqual('PropertyBufferSize',  \
        valid_test_7_match.group('SAL_tag_args'))
    self.assertEqual('CONST PBYTE',  \
                     valid_test_7_match.group('var_type'))
    self.assertEqual('PropertyBuffer', valid_test_7_match.group('var_name'))

    # Test against a non-annotated argument.
    invalid_test_1 = 'HANDLE hFile'
    invalid_test_1_match = asan_parser._ARG_TOKENS_RE.search(invalid_test_1)
    self.assertTrue(invalid_test_1_match == None)

    # Test against an argument where the variable type is missing.
    invalid_test_2 = '_Out_writes_to_opt_(cchBufferLength, '  \
        '*lpcchReturnLength) _Post_ _NullNull_terminated_ lpszVolumePathNames'
    invalid_test_2_match = asan_parser._ARG_TOKENS_RE.search(invalid_test_2)
    self.assertTrue(invalid_test_2_match == None)

    # Test against an empty string.
    invalid_test_3 = ''
    invalid_test_3_match = asan_parser._ARG_TOKENS_RE.search(invalid_test_3)
    self.assertTrue(invalid_test_3_match == None)


  def testParseFunctionsInFile(self):
    intercepted_functions = []

    def VisitorCallback(function_name, return_type, function_params,
          calling_convention, module_name):
      intercepted_functions.append(function_name)

    self.generator.VisitFunctionsInFiles(
        ['test_data\\interceptor_parser_test.h'], VisitorCallback)
    self.assertTrue('valid_function1' in intercepted_functions)
    self.assertTrue('valid_function2' in intercepted_functions)
    self.assertTrue('valid_function3' in intercepted_functions)
    self.assertFalse('invalid_function1' in intercepted_functions)
    self.assertFalse('invalid_function2' in intercepted_functions)
    self.assertFalse('invalid_function3' in intercepted_functions)
    self.assertFalse('invalid_function4' in intercepted_functions)
    self.assertEqual(3, len(intercepted_functions))


  class ScopedTempDir:
    """A scoped directory that gets automatically removed."""
    def __init__(self):
      self.path = tempfile.mkdtemp()


    def __enter__(self):
      return self


    def __exit__(self, type, value, traceback):
      shutil.rmtree(self.path)


  def testEndToEnd(self):
    with self.ScopedTempDir() as temp_dir:
      with tempfile.NamedTemporaryFile(dir=temp_dir.path) as output_base:
        args = ['--output-base', output_base.name,
                '--def-file', 'test_data\\interceptor_parser_test.def',
                'test_data\\interceptor_parser_test.h']
        asan_parser.main(args)


  def testGenerateFunctionInterceptor(self):
    self.generator._intercepted_functions.clear()
    self.generator.GenerateFunctionInterceptor('intercepted_function', 'void',
        '_In_reads_bytes_opt_(count) int foo', 'WINAPI', 'foo.dll')
    self.assertTrue(('intercepted_function',
                     '_In_reads_bytes_opt_(count) int foo')  \
        in self.generator._intercepted_functions)
    self.assertEqual(1, len(self.generator._intercepted_functions))

    self.generator.GenerateFunctionInterceptor('intercepted_function', 'void',
        '_In_reads_bytes_opt_(count) int foo', 'WINAPI', 'foo.dll')
    # Verify that we don't intercept several time a function with the same
    # signature.
    self.assertEqual(1, len(self.generator._intercepted_functions))

    self.generator.GenerateFunctionInterceptor('intercepted_function', 'void',
        '_In_reads_bytes_opt_(count) int foo, _In_ bar', 'WINAPI', 'foo.dll')
    self.assertTrue(('intercepted_function',
                     '_In_reads_bytes_opt_(count) int foo, _In_ bar') \
        in self.generator._intercepted_functions)
    self.assertEqual(2, len(self.generator._intercepted_functions))

    self.generator.GenerateFunctionInterceptor('non_intercepted_function',
        'void', '_In_ int foo', 'WINAPI', 'foo.dll')
    self.assertFalse('non_intercepted_function' in
        self.generator._intercepted_functions)
    self.assertEqual(2, len(self.generator._intercepted_functions))

  # TODO(sebmarchand): Add more tests.


if __name__ == '__main__':
  logging.basicConfig(level=logging.DEBUG)
  unittest.main()
