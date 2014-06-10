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
"""A utility script to automatically generate the SyzyASan interceptors for the
functions declared in a header file using SAL annotations.

Here's how this script should be used:
python asan_system_interceptor_parser.py input_header.h --output-file=$(OutName)
    --overwrite --def-file=$(DefFile)

3 files will be produced:
- $(OutName)_impl.h.gen : This will contain the implementation of the new
    interceptors.
- $(OutName)_instrumentation_filter.h.gen : This will contain a list of
   AsanInterceptor entries, e.g:
    { "foo", NULL, NULL, "foo.dll", true },
    { "bar", NULL, NULL, "bar.dll", true },
- $(OutName).def.gen : This will contain a copy of the input DEF file followed
    by the list of the new interceptors

As an example, for a definition like this:
MODULE: kernel32.dll
BOOL
WINAPI
WriteFile(
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    );

This will produce the following interceptor:
BOOL WINAPI asan_WriteFile(
    _In_ HANDLE hFile,
    _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer,
    _In_ DWORD nNumberOfBytesToWrite,
    _Out_opt_ LPDWORD lpNumberOfBytesWritten,
    _Inout_opt_ LPOVERLAPPED lpOverlapped
    ) {
  if (lpBuffer != NULL) {
    TestMemoryRange(reinterpret_cast<const uint8*>(lpBuffer),
                    nNumberOfBytesToWrite,
                    HeapProxy::ASAN_READ_ACCESS);
  }

  if (lpNumberOfBytesWritten != NULL) {
    TestMemoryRange(reinterpret_cast<const uint8*>(lpNumberOfBytesWritten),
                    sizeof(*lpNumberOfBytesWritten),
                    HeapProxy::ASAN_WRITE_ACCESS);
  }

  if (lpOverlapped != NULL) {
    TestMemoryRange(reinterpret_cast<const uint8*>(lpOverlapped),
                    sizeof(*lpOverlapped),
                    HeapProxy::ASAN_READ_ACCESS);
  }


  BOOL ret = ::WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
                         lpNumberOfBytesWritten, lpOverlapped);

  if (interceptor_tail_callback != NULL)
    (*interceptor_tail_callback)();


  if (lpNumberOfBytesWritten != NULL) {
    TestMemoryRange(reinterpret_cast<const uint8*>(lpNumberOfBytesWritten),
                    sizeof(*lpNumberOfBytesWritten),
                    HeapProxy::ASAN_WRITE_ACCESS);
  }

  if (lpBuffer != NULL) {
    TestMemoryRange(reinterpret_cast<const uint8*>(lpBuffer),
                    nNumberOfBytesToWrite,
                    HeapProxy::ASAN_READ_ACCESS);
  }

  return ret;
}
"""

import logging
import optparse
import os
import re
import sys
from string import Template

# Matches a function declaration of this type:
# MODULE: MODULE_NAME
# RETURN_TYPE
# WINAPI
# FUNCTION_NAME(
#     ...
#     );
_FUNCTION_MATCH_RE = re.compile(r"""
    MODULE\:\s*(?P<module_name>(\w+\.\w+))\s+
                                # Match the name of the module implementing the
                                # function.
    (?P<ret>\w+)\s+             # Match the return type of the function.
    (?P<conv>WINAPI|__cdecl)\s+ # Match the calling convention keyword.
    (?P<name>\w+)\s*\(          # Match the function name.
      (?P<params>[^;]+)\)\s*;   # Match the functions parameters, terminated by
                                # ');'. This field can contain embedded
                                # parenthesis.
    """, re.VERBOSE | re.IGNORECASE | re.MULTILINE)


# Match and tokenize an argument in a function declaration using SAL
# annotations. Here are some examples of strings that we need to be able to
# match:
#     - _In_ HANDLE hFile
#     - _In_reads_bytes_opt_(nNumberOfBytesToWrite) LPCVOID lpBuffer
#     - _Out_writes_to_opt_(nBufferLength, return + 1) LPWSTR lpBuffer
#     - _Out_writes_bytes_opt_(nNumber) __out_data_source(FILE) LPVOID lpBuffer
#     - _Out_writes_to_opt_(cchBufferLength, *lpcchReturnLength) _Post_
#           _NullNull_terminated_ LPWCH lpszVolumePathNames
#     - _In_ FILE_SEGMENT_ELEMENT aSegmentArray[]
#     - _In_reads_bytes_opt_(PropertyBufferSize) CONST PBYTE PropertyBuffer
#     - _Inout_ _Interlocked_operand_ LONG volatile *Addend
#
# Here's a description of the different groups in this regex:
#     - SAL_tag corresponds to the SAL tag of the argument.
#     - SAL_tag_args (optional) corresponds to the arguments accompanying the
#       tag.
#     - var_type corresponds to the type of the argument.
#     - var_name corresponds to the name of the argument.
#
# For an argument like:
#     _Out_writes_to_opt_(nBufferLength, return + 1) LPWSTR lpBuffer
# we'll get the following values:
#     - SAL_tag: _Out_writes_to_opt_
#     - SAL_tag_args: nBufferLength, return + 1
#     - var_type: LPWSTR
#     - var_name: lpBuffer
#     - var_keyword corresponds to the potential keyword qualifier accompanying
#       the variable type (e.g. 'volatile')
#
# See http://msdn.microsoft.com/en-us/library/hh916382.aspx for a complete list
# of the possible annotations.
_ARG_TOKENS_RE = re.compile(r"""
    (?P<SAL_tag>(\_\w+\_))            # Match the SAL annotation, it starts and
                                      # ends with an underscore and usually
                                      # contains one or several words separated
                                      # by an underscore.
    (\((?P<SAL_tag_args>[^\)]*)\))?   # Match the optional arguments
                                      # accompanying a tag.
    \s+((\_[^ ]+\s+)*)?               # The annotation is sometimes followed by
                                      # one or several other tags, all starting
                                      # with at least one underscore, like:
                                      #     - _Post_ _NullNull_terminated_
                                      #     - __out_data_source(FILE)
    (?P<var_type>(((CONST|FAR)\s*)?[a-zA-Z][a-zA-Z_0-9]+)
                                      # Match the type of the argument.
    (\s+(?P<var_keyword>volatile|const))?(\*)?(\s+\*)?)
                                      # Match the optional keyword of the
                                      # argument.
    (\*)?\s+(\*\s*)?(?P<var_name>\w+)(\[\])?
                                      # Match the name of the argument.
    """, re.VERBOSE | re.IGNORECASE | re.MULTILINE)


# Non-exhaustive dictionary of the annotations that we're interested in. All of
# these usually refer to a buffer that we should check. The key of the entry
# is the SAL tag and the value of this key corresponds to the access mode for
# this tag.
_TAGS_TO_INTERCEPT = {
    '_In_reads_bytes_opt_' : 'READ',
    '_Out_writes_to_opt_' : 'WRITE',
    '_Out_writes_bytes_opt_' : 'WRITE',
    '_Out_writes_bytes_to_opt_' : 'WRITE',
}


# List of the SAL tags meaning that an argument should be checked once the call
# to the intercepted function has returned.
_TAGS_TO_CHECK_POSTCALL = frozenset(['_Out_', '_Out_opt_'])


# List of the SAL tags meaning that an argument should be checked the call to
# the intercepted function. This includes the tag of some parameters that might
# become invalid once the call to the original function has returned (i.e. if
# the parameter is invalidated by the asynchronous callback made by the system
# call).
_TAGS_TO_CHECK_PRECALL = frozenset(list(_TAGS_TO_CHECK_POSTCALL) +
    ['_Inout_', '_Inout_opt_'])


_LOGGER = logging.getLogger(__name__)


# String template for an entry in an ASan instrumentation filter array.
#
# Here's the description of the different identifiers in this template:
#     - function_name: Name of the function.
#     - module_name: Name of the module containing this function.
instrumentation_filter_entry_template = Template("""
{ "${function_name}", NULL, "${module_name}", NULL, true },
""")


# String template for an ASan interceptor implementation.
#
# Here's the description of the different identifiers in this template:
#     - ret_type: Return type of the function.
#     - calling_convention: The calling convention of the function.
#     - function_name: Name of the function.
#     - function_arguments: Function's arguments, with their types.
#     - buffer_check: Optional check on the buffer passed to the function.
#     - function_param_names: String containing the name of the arguments to
#         pass to the intercepted function.
#     - param_checks_precall: Optional parameter check done before the call to
#         the intercepted function.
#     - param_checks_postcall: Optional parameter check done after the call to
#         the intercepted function.
interceptor_template = Template("""
${ret_type} ${calling_convention} \
asan_${function_name}(${function_arguments}) {
  ${buffer_check}
  ${param_checks_precall}

  ${ret_type} ret = ::${function_name}(${function_param_names});

  if (interceptor_tail_callback != NULL)
    (*interceptor_tail_callback)();

  ${param_checks_postcall}
  ${buffer_check}

  return ret;
}
""")


# String template for an ASan check on a parameter.
#
# Here's the description of the different identifiers in this template:
#     - param_to_check: The parameter to check.
#     - param_size: Size of the variable that should be checked.
#     - access_type: The access type to the parameter.
#     - param_keyword: The optional keyword qualifier accompanying the variable
#       type (e.g. 'volatile').
#
# We need to do a double cast on the parameter to check to convert it to the
# expected type (via a reinterpret_cast) and to lose the optional keyword
# qualifier (via a const_cast).
param_checks_template = Template("""
  if (${param_to_check} != NULL) {
    TestMemoryRange(
        const_cast<const uint8*>(
            reinterpret_cast<const uint8 ${param_keyword}*>(${param_to_check})),
        ${param_size},
        HeapProxy::ASAN_${access_type}_ACCESS);
  }
""")


class ASanSystemInterceptorGenerator(object):
  """Implement the ASan system interceptor generator class.

  The instances of this class should be created with a 'with' statement to
  ensure that the output files get correctly closed.
  """

  def __init__(self, output_base, def_file, overwrite=False):
    # Creates the output files:
    #     - output_base + '_impl.gen' : This file will contain the
    #           implementation of the interceptors.
    #     - output_base + '_instrumentation_filter.gen : This file will
    #           contain a list of AsanIntercept entries.
    #     - output_base + 'def.gen' : This file will contain a copy of the input
    #           DEF file followed by the list of the new interceptors.
    output_impl_filename = output_base + '_impl.gen'
    output_instrumentation_filter_filename = output_base +  \
        '_instrumentation_filter.gen'
    output_def_filename = output_base + '.def.gen'

    if (os.path.isfile(output_impl_filename) or  \
        os.path.isfile(output_instrumentation_filter_filename) or  \
        os.path.isfile(output_def_filename)) and  \
        not overwrite:
      _LOGGER.error('Output files already exist, use the --overwrite flag to '
                    'overwrite it.')
      return

    self._output_impl_file = open(output_impl_filename, 'w')
    self._output_instrumentation_filter_file =  \
        open(output_instrumentation_filter_filename, 'w')
    self._def_file = open(output_def_filename, 'w')

    # Copy the input DEF file.
    with open(def_file, 'r') as f:
      self._def_file.write(f.read())

    # List of the intercepted functions.
    self._intercepted_functions = set()

  def __enter__(self):
    """This generator should be instantiated via a 'with' statement to ensure
    that it resources are correctly closed.
    """
    return self

  def __exit__(self, type, value, traceback):
    """Close the handle to the allocated files. This is executed when the
    instance of this generator are created with a 'with' statement.
    """
    self._output_impl_file.close()
    self._output_instrumentation_filter_file.close()
    self._def_file.close()

  def GenerateFunctionInterceptor(self, function_name, return_type,
                                  function_arguments, calling_convention,
                                  module_name):
    """Generate the interceptor for a given function if necessary.

    Args:
      function_name: The name of the function for which an interceptor should be
          generated.
      return_type: The return type of the function.
      function_arguments: A string representing the functions arguments
          (e.g. 'int foo, bool bar'). It can contain newline characters.
    """

    # Prevent repeatedly intercepting the same function.
    if (function_name, function_arguments) in self._intercepted_functions:
      _LOGGER.error('Trying to intercept the same function twice !')
      return

    # Check if the function should be intercepted. If at least one of its
    # parameters is annotated with one of the tags we're interested in then it
    # should be intercepted.
    m_buffer_size_arg = None
    for m_iter in _ARG_TOKENS_RE.finditer(function_arguments):
      if m_iter.group('SAL_tag') in _TAGS_TO_INTERCEPT:
        # Keep a reference to the argument of interest.
        m_buffer_size_arg = m_iter
        break

    # TODO(sebmarchand): Only check the argument type (instead of the raw
    #     string).
    self._intercepted_functions.add((function_name, function_arguments))

    _LOGGER.debug('Function to intercept:')
    _LOGGER.debug('  Function calling convention : %s' % calling_convention)
    _LOGGER.debug('  Function name : %s' % function_name)
    _LOGGER.debug('  Function type : %s' % return_type)
    _LOGGER.debug('  Function module : %s' % module_name)
    _LOGGER.debug('  Function args : ')

    param_checks_precall = ''
    param_checks_postcall = ''

    # Form a string containing the name of the arguments separated by a comma
    # and fill the precall and postcall parameter check strings.
    function_param_names = ''
    for m_iter in _ARG_TOKENS_RE.finditer(function_arguments):
      # Concatenate the argument names.
      if function_param_names:
        function_param_names = function_param_names + ', '
      function_param_names = function_param_names + m_iter.group('var_name')
      # Check if this argument should be checked prior to a call to the
      # intercepted function.
      if m_iter.group('SAL_tag') in _TAGS_TO_CHECK_PRECALL:
        param_keyword = ''
        if m_iter.group('var_keyword'):
          param_keyword = m_iter.group('var_keyword')
        param_check_str = param_checks_template.substitute(
            param_to_check=m_iter.group('var_name'),
            param_size='sizeof(*%s)' % m_iter.group('var_name'),
            access_type='READ' if 'In' in m_iter.group('SAL_tag') else 'WRITE',
            param_keyword=param_keyword)
        param_checks_precall += param_check_str
        # Check if it should also be checked once the function returns.
        if m_iter.group('SAL_tag') in _TAGS_TO_CHECK_POSTCALL:
          param_checks_postcall += param_check_str

      _LOGGER.debug('    %s' %  \
          ''.join(m_iter.group().replace('\n', ' ').split()))
      _LOGGER.debug('      SAL tag: %s' % m_iter.group('SAL_tag'))
      _LOGGER.debug('      SAL tag arguments: %s' %  \
          m_iter.group('SAL_tag_args'))
      _LOGGER.debug('      variable type: %s' % m_iter.group('var_type'))
      _LOGGER.debug('      variable name: %s' % m_iter.group('var_name'))
      _LOGGER.debug('      variable keyword: %s' % m_iter.group('var_keyword'))
    _LOGGER.debug('\n')

    buffer_check = ''
    if m_buffer_size_arg:
      param_keyword = ''
      if m_buffer_size_arg.group('var_keyword'):
        param_keyword = m_buffer_size_arg.group('var_keyword')
      buffer_check = param_checks_template.substitute(
          param_to_check=m_buffer_size_arg.group('var_name'),
          param_size=m_buffer_size_arg.group('SAL_tag_args').split(',')[0],
          access_type=_TAGS_TO_INTERCEPT[m_buffer_size_arg.group('SAL_tag')],
          param_keyword=param_keyword)

    # Write the function's implementation in the appropriate file.
    self._output_impl_file.write(interceptor_template.substitute(
        ret_type=return_type,
        calling_convention=calling_convention,
        function_name=function_name,
        function_arguments=function_arguments,
        function_param_names=function_param_names,
        param_checks_precall=param_checks_precall,
        param_checks_postcall=param_checks_postcall,
        buffer_check=buffer_check))

    # Write the entry into the instrumentation filter file.
    self._output_instrumentation_filter_file.write(
        instrumentation_filter_entry_template.substitute(
            function_name=function_name,
            module_name=module_name))

    # Add the new interceptor to the DEF file.
    self._def_file.write('asan_' + function_name + '\n')

  def VisitFunctionsInFiles(self, files, callback):
    """Parse the functions declared in a given list of files and invokes the
    callback per encountered function.

    Args:
      files: The files to parse.
      callback: The callback to invoke per encountered function.
      output_base: A handle to the output file that will receive the function
          definitions.
    """
    for filename in files:
      with open(filename, 'r') as f:
        f_content = f.read()

      for m_iter in _FUNCTION_MATCH_RE.finditer(f_content):
        callback(m_iter.group('name'), m_iter.group('ret'),
                 m_iter.group('params'), m_iter.group('conv'),
                 m_iter.group('module_name'))


_USAGE = """\
%prog [options] [files to process]

Parse a list of files to find the SAL annotated functions.
"""


def ParseOptions(args, parser):
  parser.add_option('--verbose',
                    dest='log_level',
                    default=logging.INFO,
                    action='store_const',
                    const=logging.DEBUG,
                    help='Enable verbose logging.')
  parser.add_option('--def-file', help='The def file that should be '
                    'augmented. This file won\'t be modified, instead a new '
                    'one will be created and will be filled with the content '
                    'of this one followed by the new interceptors.')
  parser.add_option('--output-base', help='Base name of the output files to '
                    'produce (without the extensions).')
  parser.add_option('--overwrite', default=False, action='store_true',
                    help='Overwrite the output files if they already exist.')
  return parser.parse_args(args)


def main(args):
  parser = optparse.OptionParser(usage=_USAGE)
  (opts, input_files) = ParseOptions(args, parser)

  logging.basicConfig(level=opts.log_level)

  if not opts.output_base:
    parser.error('You must specify an output base filename.')

  if not opts.def_file:
    parser.error('You must specify a DEF file to update.')

  # The first argument might be the current script name, remove it and make sure
  # that there's at least one input file.
  if __file__ in input_files:
    input_files.remove(__file__)
  if not len(input_files):
    parser.error('You must specify at least one input file.')

  with ASanSystemInterceptorGenerator(opts.output_base,
                                      opts.def_file,
                                      opts.overwrite) as generator:
    generator.VisitFunctionsInFiles(input_files,
                                    generator.GenerateFunctionInterceptor)


if __name__ == '__main__':
  sys.exit(main(sys.argv))
