#!python
# Copyright 2013 Google Inc. All Rights Reserved.
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
"""A utility script to automate the process of symbolizing a SyzyASan
minidump.
"""

from collections import namedtuple
import optparse
import os
import re
import subprocess
import sys


# The sentinel value that we use at the end of the command executed in the
# debugger.
_SENTINEL = 'ENDENDEND'


# The default values for the path to cdb.exe.
_DEFAULT_CDB_PATHS = [
    r'c:\Program Files (x86)\Debugging Tools for Windows (x86)\cdb.exe',
    r'c:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86\cdb.exe',
  ]


# The frame containing the error info structure.
_BAD_ACCESS_INFO_FRAME = 'asan_rtl!agent::asan::AsanRuntime::OnError'


# Various command that'll be run in the debugger.
_GET_BAD_ACCESS_INFO_COMMAND = 'dt -o error_info'
_GET_ALLOC_STACK_COMMAND = 'dps @@(&error_info->alloc_stack) ' \
                           'l@@(error_info->alloc_stack_size);'
_GET_FREE_STACK_COMMAND = 'dps @@(&error_info->free_stack) ' \
                          'l@@(error_info->free_stack_size);'


# The helper string that will be included at the beginning of the printed crash
# reports.
_ERROR_HELP_URL = 'You can go to \
https://code.google.com/p/syzygy/wiki/SyzyASanBug to get more information \
about how to treat this bug.'


# A named tuple that will contain an ASan crash report.
ASanReport = namedtuple('ASanReport',
                        'bad_access_info '
                        'crash_stack '
                        'crash_stack_hash '
                        'alloc_stack '
                        'alloc_stack_hash '
                        'free_stack '
                        'free_stack_hash '
                        'corrupt_heap_info')


# Match a stack frame as printed by cdb.exe (or windbg.exe).
#
# Here's some examples of stack frames that this regex will match:
#   - 003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 foo!bar+0x18
#   - 003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 0xcafebabe
#
# Here's a description of the different groups in this regex:
#     - args: The arguments in front of the module name.
#     - module: The module's name.
#     - location: The location in the module.
#     - address: If the module name is not available then we'll get its address.
_STACK_FRAME_RE = re.compile("""
    ^
    (?P<args>([0-9A-F]+\ +)+)
    (?:
      (?P<module>[^ ]+)(!(?P<location>.*))? |
      (?P<address>0x[0-9a-f]+)
    )
    $
    """, re.VERBOSE | re.IGNORECASE)


# Match a list of modules as printed by cdb.exe when running the 'lm n' command.
#
# Here's a description of the different groups in this regex:
#     - start: Module's start address.
#     - end: Module's end address.
#     - module_name: Module's name.
#     - image_name: Image's name.
_MODULE_MATCH_RE = re.compile("""
    (?P<start>\w+)\s+
    (?P<end>\w+)\s+
    (?P<module_name>\w+)\s+
    (?P<image_name>.*)
    """, re.VERBOSE | re.IGNORECASE)


# Match a Chrome frame in a stack trace.
_CHROME_RE = re.compile('(chrome[_0-9A-F]+)', re.VERBOSE | re.IGNORECASE)


# Match a frame pointer in a stack frame as it is printed by a debugger.
_FRAME_POINTER_RE = re.compile(
    '\s*[a-z0-9]+\s+(?P<address>[a-z0-9]+)\s+.*', re.VERBOSE | re.IGNORECASE)


# Match an enum value as it is printed by a debugger. They're usually
# represented as 'NUMERIC_VALUE ( LITERAL_VALUE )'.
_ENUM_VAL_RE = re.compile(
    '\s*(?P<num_value>\d+)\s*\(\s*(?P<literal_value>[a-zA-Z0-9_]+)\s*\)',
    re.VERBOSE | re.IGNORECASE)


def _Command(debugger, command):
  """Execute a command in a debugger instance.

  Args:
    debugger: A handle to a cdb debugging session.
    command: The command to execute.

  Returns:
    The output of the debugger after running this command.
  """
  debugger.stdin.write(command + '; .echo %s\n' % _SENTINEL)
  lines = []
  while True:
    line = debugger.stdout.readline().rstrip()
    # Sometimes the sentinel value is preceded by something like '0:000> '.
    if line.endswith(_SENTINEL):
      break
    lines.append(line)
  return lines


def NormalizeChromeSymbol(symbol):
  """Normalize a Chrome symbol."""
  return _CHROME_RE.sub('chrome_dll', symbol)


def NormalizeStackTrace(stack_trace):
  """Normalize a given stack trace.

  Args:
    stack_trace: The stack trace to normalize.

  Returns:
    The normalized stack trace and its hash.
  """
  trace_hash = 0
  output_trace = []
  for line in stack_trace:
    m = _STACK_FRAME_RE.match(line)
    if not m:
      continue
    if m.group('args'):
      # Extract the frame pointer from the 'args' group.
      m_frame = _FRAME_POINTER_RE.match(m.group('args'))
      if m_frame and m_frame.group('address'):
        trace_hash ^= int(m_frame.group('address'), 16)
    address = m.group('address')
    module = m.group('module')
    location = m.group('location')
    if address:
      output_trace.append(address)
    else:
      module = NormalizeChromeSymbol(module)
      if location:
        location = NormalizeChromeSymbol(location)
      else:
        location = 'unknown'
      frame = '%s!%s' % (module, location)
      output_trace.append(frame)

  return (output_trace, trace_hash)


def LoadSymbols(debugger, pdb_path):
  """Loads the pdbs for the loaded modules if they are present in |pdb_path|

  Args:
    debugger: A handle to a cdb debugging session.
    command: The path containing the pdbs.
  """
  pdbs = [f for f in os.listdir(pdb_path) if f.endswith('.pdb')]
  # The path needs to be quoted to avoid including the sentinel value in cdb's
  # symbol search path.
  _Command(debugger, '.sympath \"%s\"' % pdb_path)
  for line in _Command(debugger, 'lm n'):
    m = _MODULE_MATCH_RE.match(line)
    if m is None:
      continue
    image_name =  m.group('image_name')
    if image_name is None:
      continue
    pdb_name = image_name + '.pdb'
    if pdb_name in pdbs:
      _Command(debugger, '.reload /fi %s' % image_name)

  _Command(debugger, '.symfix')


def DebugStructToDict(structure):
  """Converts a structure as printed by the debugger into a dictionary. The
  structure should have the following format:
      field1 : value1
      field2 : value2
      ...

  Args:
    structure: The structure to convert.

  Returns:
    A dict containing the values stored in the structure.
  """
  ret = dict()
  for entry in structure:
    if not entry.find(':'):
      continue
    key = entry[:entry.find(':')]
    value = entry[entry.find(':') + 1:]
    ret[key.rstrip().lstrip()] = value.rstrip().lstrip()
  return ret


def GetCorruptHeapInfo(debugger, bad_access_info_vals, bad_access_info_frame):
  """Extract the information stored in the minidump about the heap corruption.

  Args:
    debugger: A handle to a cdb debugging session.
    bad_access_info_vals: A dictionary containing the information about the
        invalid access.
    bad_access_info_frame: The number of the frame containing the error_info
        structure.

  Returns:
    A list of corrupt ranges, each of them containing the information about the
    corrupt blocks in it.
  """
  # Reset the debugger context and jump to the frame containing the information.
  corrupt_range_count = int(bad_access_info_vals['corrupt_range_count'])
  _Command(debugger, '.cxr; .frame %X' % bad_access_info_frame)

  corrupt_ranges = []

  # Iterates over the corrupt ranges.
  for corrupt_range_idx in range(0, corrupt_range_count):
    corrupt_range_info = []

    # When using the '??' operator in a debugging session to evaluate a
    # structure the offsets gets printed, this regex allows their removal.
    struct_field_re = re.compile('\s+\+0x[0-9a-f]+\s*(.*)')

    # Get the information about this corrupt range.
    for line in _Command(debugger,
        '?? ((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
        '(error_info->corrupt_ranges))[%x]' % corrupt_range_idx):
      m = struct_field_re.match(line)
      if m:
        corrupt_range_info.append(m.group(1))
    corrupt_range_info_vals = DebugStructToDict(corrupt_range_info)
    block_info_count = int(corrupt_range_info_vals['block_info_count'])
    corrupt_range_info_vals['block_info'] = []

    # Iterates over the block info structure available for this range.
    for block_info_idx in range(0, block_info_count):
      # Retrieves the information about the current block info structure.
      block_info = []
      for line in _Command(debugger,
          '?? ((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
          '(error_info->corrupt_ranges))[%d].block_info[%d]' % (
              corrupt_range_idx, block_info_idx)):
        m = struct_field_re.match(line)
        if m:
          block_info.append(m.group(1))
      block_info_vals = DebugStructToDict(block_info)
      # Get the allocation stack trace for this block info structure.
      block_info_vals['alloc_stack'], _ = NormalizeStackTrace(_Command(debugger,
          'dps @@(((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
          '(error_info->corrupt_ranges))[%d].block_info[%d].alloc_stack) '
          'L@@(((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
          '(error_info->corrupt_ranges))[%d].block_info[%d].alloc_stack_size)' %
          (corrupt_range_idx, block_info_idx, corrupt_range_idx,
          block_info_idx)))
      # Get the free stack trace for this block info structure.
      block_info_vals['free_stack'], _ = NormalizeStackTrace(_Command(debugger,
          'dps @@(((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
          '(error_info->corrupt_ranges))[%d].block_info[%d].free_stack) '
          'L@@(((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
          '(error_info->corrupt_ranges))[%d].block_info[%d].free_stack_size)' %
          (corrupt_range_idx, block_info_idx, corrupt_range_idx,
          block_info_idx)))
      corrupt_range_info_vals['block_info'].append(block_info_vals)

    # Append the information about the current range to the list of corrupt
    # ranges.
    corrupt_ranges.append(corrupt_range_info_vals)

  return corrupt_ranges


def ProcessMinidump(minidump_filename, cdb_path, pdb_path):
  """Process a minidump.

  This analyzes the error contained in the minidump and returns the crash report
  for it.

  Args:
    minidump_filename: The minidump filename.
    cdb_path: The path to cdb.exe.
    pdb_path: (Optional) The path to the pdbs for the loaded modules.

  Returns:
    The crash report to be printed.
  """
  debugger = subprocess.Popen([cdb_path,
                               '-z', minidump_filename],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
  if pdb_path is not None:
    LoadSymbols(debugger, pdb_path)

  # Enable the line number informations.
  _Command(debugger, '.lines')

  # Get the SyzyASan crash stack and try to find the frame containing the
  # bad access info structure.

  asan_crash_stack = _Command(debugger, 'kv')

  bad_access_info_frame = 0;
  crash_lines, _ = NormalizeStackTrace(asan_crash_stack)
  for line in crash_lines:
    if line.find(_BAD_ACCESS_INFO_FRAME) == -1:
      bad_access_info_frame += 1
    else:
      break

  if bad_access_info_frame == -1:
    # End the debugging session.
    debugger.stdin.write('q\n')
    debugger.wait()
    print 'Unable to find the %s frame for %d.' % (_BAD_ACCESS_INFO_FRAME,
                                                   minidump_filename)
    return

  # Get the information about this bad access.
  _Command(debugger, '.frame %X' % bad_access_info_frame)
  bad_access_info = _Command(debugger, _GET_BAD_ACCESS_INFO_COMMAND)
  # The first two lines contain no useful information, remove them.
  bad_access_info.pop(0)
  bad_access_info.pop(0)
  bad_access_info_vals = DebugStructToDict(bad_access_info)

  # Checks if the heap is corrupt.
  heap_is_corrupt = bad_access_info_vals['heap_is_corrupt'] == '1'

  # Cleans the enum value stored in the dictionary.
  for key in bad_access_info_vals:
    m = _ENUM_VAL_RE.match(bad_access_info_vals[key])
    if m:
      bad_access_info_vals[key] = m.group('literal_value')

  # If the heap is not corrupt and the error type indicates an invalid or wild
  # address then there's no useful information that we can report.
  if not heap_is_corrupt and (
      bad_access_info_vals['error_type'] == 'INVALID_ADDRESS' or
      bad_access_info_vals['error_type'] == 'WILD_ACCESS'):
    # End the debugging session.
    debugger.stdin.write('q\n')
    debugger.wait()
    return

  alloc_stack, alloc_stack_hash = \
      NormalizeStackTrace(_Command(debugger, _GET_ALLOC_STACK_COMMAND))
  free_stack, free_stack_hash = \
      NormalizeStackTrace(_Command(debugger, _GET_FREE_STACK_COMMAND))
  _Command(debugger, '.ecxr')
  crash_stack, crash_stack_hash = NormalizeStackTrace(_Command(debugger, 'kv'))

  corrupt_heap_info = None
  if heap_is_corrupt:
    corrupt_heap_info = GetCorruptHeapInfo(debugger,
                                           bad_access_info_vals,
                                           bad_access_info_frame)

  # End the debugging session.
  debugger.stdin.write('q\n')
  debugger.wait()

  report = ASanReport(bad_access_info = bad_access_info_vals,
                      crash_stack = crash_stack,
                      crash_stack_hash = crash_stack_hash,
                      alloc_stack = alloc_stack,
                      alloc_stack_hash = alloc_stack_hash,
                      free_stack = free_stack,
                      free_stack_hash = free_stack_hash,
                      corrupt_heap_info = corrupt_heap_info)

  return report


def PrintASanReport(report, file_handle = sys.stdout):
  """Print a crash report.

  Args:
    report: The report to print.
    file_handle: A handle to the out stream, by default we print the report to
        stdout.
  """
  file_handle.write('Bad access information:\n')
  for key in report.bad_access_info:
    file_handle.write('  %s: %s\n' % (key, report.bad_access_info[key]))
  file_handle.write('\nCrash stack:\n')
  for line in report.crash_stack: file_handle.write('%s\n' % line)
  if len(report.alloc_stack) != 0:
    file_handle.write('\nAllocation stack:\n')
    for line in report.alloc_stack: file_handle.write('%s\n' % line)
  if len(report.free_stack) != 0:
    file_handle.write('\nFree stack:\n')
    for line in report.free_stack: file_handle.write('%s\n' % line)

  if report.corrupt_heap_info:
    file_handle.write('\n\nHeap is corrupt, here\'s some information about the '
        'corrupt ranges.\n\n')
    corrupt_range_idx = 0
    for corrupt_heap_range in report.corrupt_heap_info:
      file_handle.write('Corrupt range #%d\n' % corrupt_range_idx)
      corrupt_range_idx += 1
      file_handle.write('  Address : %s\n' % corrupt_heap_range['address'])
      file_handle.write('  Length : %s\n' % corrupt_heap_range['length'])
      file_handle.write('  Block count : %s\n' %
          corrupt_heap_range['block_count'])
      file_handle.write('  Block info count : %s\n' %
          corrupt_heap_range['block_info_count'])
      file_handle.write('  Block infos:\n')
      block_info_idx = 0
      for block_info in corrupt_heap_range['block_info']:
        file_handle.write('    Block info #%d\n' % block_info_idx)
        file_handle.write('      Header : %s\n' % block_info['header'])
        file_handle.write('      User size : %s\n' % block_info['user_size'])
        file_handle.write('      State : %s\n' % block_info['state'])
        file_handle.write('      Alloc TID : %s\n' % block_info['alloc_tid'])
        file_handle.write('      Free TID : %s\n' % block_info['free_tid'])
        file_handle.write('      Is corrupt : %s\n' % block_info['corrupt'])
        file_handle.write('      Alloc stack size : %s\n' %
            block_info['alloc_stack_size'])
        file_handle.write('      Free stack size : %s\n' %
            block_info['free_stack_size'])
        file_handle.write('      Alloc stack:\n')
        for frame in block_info['alloc_stack']:
          file_handle.write('        %s\n' % frame)
        if block_info['free_stack']:
          file_handle.write('      Free stack:\n')
          for frame in block_info['free_stack']:
            file_handle.write('        %s\n' % frame)

  file_handle.write('\n\n%s\n' % _ERROR_HELP_URL)


_USAGE = """\
%prog [options]

Symbolizes a minidump that has been generated by SyzyASan. This prints the
crash, alloc and free stack traces and gives more information about the crash.
"""


def _ParseArguments():
  """Parse the command line arguments.

  Returns:
    The options on the command line.
  """
  parser = optparse.OptionParser(usage=_USAGE)
  # TODO(sebmarchand): Move this to an argument instead of a switch?
  parser.add_option('--minidump',
                    help='The input minidump.')
  parser.add_option('--cdb-path', help='(Optional) The path to cdb.exe.')
  parser.add_option('--pdb-path',
                    help='(Optional) The path to the folder containing the'
                         ' PDBs.')
  (opts, args) = parser.parse_args()

  if len(args):
    parser.error('Unexpected argument(s).')

  if not opts.cdb_path:
    for path in _DEFAULT_CDB_PATHS:
      if os.path.isfile(path):
        opts.cdb_path = path
        break
    if not opts.cdb_path:
      parser.error('Unable to find cdb.exe.')

  if not opts.minidump:
    parser.error('You must provide a minidump.')

  opts.minidump = os.path.abspath(opts.minidump)

  return opts


def main():
  """Parse arguments and do the symbolization."""
  opts = _ParseArguments()

  report = ProcessMinidump(opts.minidump, opts.cdb_path, opts.pdb_path)
  if report:
    PrintASanReport(report)

  return 0


if __name__ == '__main__':
  sys.exit(main())
