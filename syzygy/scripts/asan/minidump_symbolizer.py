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
_BAD_ACCESS_INFO_FRAMES = [
    'asan_rtl!agent::asan::AsanRuntime::OnError',
    'syzyasan_rtl!agent::asan::AsanRuntime::ExceptionFilterImpl',
]


# The helper string that will be included at the beginning of the printed crash
# reports.
_ERROR_HELP_URL = 'You can go to \
https://code.google.com/p/syzygy/wiki/SyzyASanBug to get more information \
about how to treat this bug.'


# Command to print the error info structure.
_GET_BAD_ACCESS_INFO_COMMAND = 'dt -o error_info'


# Command to print the block info structure nested into the error info one.
_GET_BLOCK_INFO_COMMAND = 'dt agent::asan::AsanBlockInfo poi(error_info) -o'


# Template command to print a stack trace from an error info structure.
#
# Here's the description of the keyword to use in this template:
#     - operand: The operator to use to access the structure ('.' or '->').
#     - type: The stack trace type ('alloc' or 'free')
_GET_STACK_COMMAND_TEMPLATE = (
    'dps @@(&error_info{operand}block_info.{type}_stack) '
    'l@@(error_info{operand}block_info.{type}_stack_size);'
  )


# Template command to print the stack trace of a corrupt block from an error
# info structure.
#
# Here's the description of the keyword to use in this template:
#     - operand: The operator to use to access the structure ('.' or '->').
#     - range_idx: The corrupt range index.
#     - block_idx: The block index in its range.
#     - type: The stack trace type ('alloc' or 'free')
_GET_CORRUPT_BLOCK_STACK_TRACE_TEMPLATE = (
  'dps @@(((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
  '(error_info{operand}corrupt_ranges))[{range_idx}].block_info[{block_idx}].'
  '{type}_stack) '
  'L@@(((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
  '(error_info{operand}corrupt_ranges))[{range_idx}].block_info[{block_idx}].'
  '{type}_stack_size)'
)


# A named tuple that will contain an ASan crash report.
ASanReport = namedtuple('ASanReport',
                        'bad_access_info '
                        'crash_stack '
                        'crash_stack_hash '
                        'alloc_stack '
                        'alloc_stack_hash '
                        'free_stack '
                        'free_stack_hash '
                        'corrupt_heap_info '
                        'from_uef')


# Match a stack frame as printed by cdb.exe (or windbg.exe).
#
# Here's some examples of stack frames that this regex will match:
#   - 003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 foo!bar+0x18
#   - 003cd6b8 0ff3a36b 007bff00 00004e84 003cd760 0xcafebabe
#   - (Inline) -------- -------- -------- -------- foo!bar+0x42
#
# Here's a description of the different groups in this regex:
#     - args: The arguments in front of the module name.
#     - module: The module's name.
#     - location: The location in the module.
#     - address: If the module name is not available then we'll get its address.
_STACK_FRAME_RE = re.compile("""
    ^
    (\(Inline\)\s)?
    (?P<args>([0-9A-F\-]+\ +)+)
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
_CHROME_RE = re.compile('^(chrome[_0-9A-F]+)$', re.VERBOSE | re.IGNORECASE)


# Match a frame pointer in a stack frame as it is printed by a debugger.
_FRAME_POINTER_RE = re.compile(
    '\s*[a-z0-9]+\s+(?P<address>[a-z0-9]+)\s+.*', re.VERBOSE | re.IGNORECASE)


# Match an enum value as it is printed by a debugger. They're usually
# represented as 'NUMERIC_VALUE ( LITERAL_VALUE )'.
_ENUM_VAL_RE = re.compile(
    '\s*(?P<num_value>\d+)\s*\(\s*(?P<literal_value>[a-zA-Z0-9_]+)\s*\)',
    re.VERBOSE | re.IGNORECASE)


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


def GetCorruptHeapInfo(debugger, bad_access_info_vals, bad_access_info_frame,
                       from_uef):
  """Extract the information stored in the minidump about the heap corruption.

  Args:
    debugger: A handle to a cdb debugging session.
    bad_access_info_vals: A dictionary containing the information about the
        invalid access.
    bad_access_info_frame: The number of the frame containing the error_info
        structure.
    from_uef: Indicates if the error has been caught by the unhandled exception
        filter.

  Returns:
    A list of corrupt ranges, each of them containing the information about the
    corrupt blocks in it.
  """
  # Reset the debugger context and jump to the frame containing the information.
  corrupt_range_count = int(bad_access_info_vals['corrupt_range_count'], 16)
  debugger.Command('.cxr; .frame %X' % bad_access_info_frame)

  corrupt_ranges = []

  # Iterates over the corrupt ranges.
  for corrupt_range_idx in range(0, corrupt_range_count):
    corrupt_range_info = []

    # When using the '??' operator in a debugging session to evaluate a
    # structure the offsets gets printed, this regex allows their removal.
    struct_field_re = re.compile('\s+\+0x[0-9a-f]+\s*(.*)')
    operand = '.' if from_uef else '->'

    # Get the information about this corrupt range.
    for line in debugger.Command(
        '?? ((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
        '(error_info%scorrupt_ranges))[0x%x]' % (operand, corrupt_range_idx)):
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
      for line in debugger.Command(
          '?? ((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
          '(error_info%scorrupt_ranges))[%d].block_info[%d]' % (
              operand, corrupt_range_idx, block_info_idx)):
        m = struct_field_re.match(line)
        if m:
          block_info.append(m.group(1))
      block_info_corruption_state = []
      for line in debugger.Command(
          '?? ((syzyasan_rtl!agent::asan::AsanCorruptBlockRange*)'
          '(error_info%scorrupt_ranges))[%d].block_info[%d].analysis' % (
              operand, corrupt_range_idx, block_info_idx)):
        m = struct_field_re.match(line)
        if m:
          block_info_corruption_state.append(m.group(1))
      block_info_vals = DebugStructToDict(block_info)
      block_info_corruption_state_vals = DebugStructToDict(
          block_info_corruption_state)
      block_info_vals.pop('analysis', None)
      for e in block_info_corruption_state_vals:
        block_info_vals['analysis.%s' % e] = block_info_corruption_state_vals[e]
      # Get the allocation stack trace for this block info structure.
      block_info_vals['alloc_stack'], _ = NormalizeStackTrace(debugger.Command(
          _GET_CORRUPT_BLOCK_STACK_TRACE_TEMPLATE.format(type='alloc',
              operand=operand, range_idx=corrupt_range_idx,
              block_idx=block_info_idx)))
      # Get the free stack trace for this block info structure.
      block_info_vals['free_stack'], _ = NormalizeStackTrace(debugger.Command(
          _GET_CORRUPT_BLOCK_STACK_TRACE_TEMPLATE.format(type='free',
              operand=operand, range_idx=corrupt_range_idx,
              block_idx=block_info_idx)))

      # Get the block content.
      block_address = block_info_vals['header'].split(' ')[0]
      block_info_vals['block_content'] = []
      block_content = debugger.Command('db %s+0x10 L0x80' % block_address)

      # Match a block data line as printed by Windbg. This helps to get rid of
      # the extra characters that we sometime see at the beginning of the
      # lines ('0:000>').
      line_cleanup_re = re.compile('^\d\:\d+>\s*(.*)')
      for line in block_content:
        m = line_cleanup_re.match(line)
        if m:
          line = m.group(1)
        block_info_vals['block_content'].append(line)

      corrupt_range_info_vals['block_info'].append(block_info_vals)

    # Append the information about the current range to the list of corrupt
    # ranges.
    corrupt_ranges.append(corrupt_range_info_vals)

  return corrupt_ranges


class ScopedDebugger(subprocess.Popen):
  """A scoped debugger instance.
  """
  def __init__(self, debugger_path, minidump_filename):
    """Initialize the debugger instance.

    Args:
      debugger_path: The debugger's patth.
      minidump_filename: The minidump filename.
    """
    super(ScopedDebugger, self).__init__([debugger_path,
                                          '-z', minidump_filename],
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)

  def __enter__(self):
    """This debugger should be instantiated via a 'with' statement to ensure
    that its resources are correctly closed.
    """
    return self

  def __exit__(self, e_type, value, traceback):
    """Terminate the debugger process. This is executed when the instance of
    this debugger is created with a 'with' statement.
    """
    self.StopDebugger()

  def StopDebugger(self):
    """Terminate the debugger process. We could send the terminate command ('q')
    to the debugger directly but at this point the debugger might be stuck
    because of a previous command and it's just faster to kill the process
    anyway.
    """
    self.terminate()

  def Command(self, command):
    """Execute a command in the debugger instance.

    Args:
      command: The command to execute.

    Returns:
      The output of the debugger after running this command.
    """
    self.stdin.write(command + '; .echo %s\n' % _SENTINEL)
    lines = []
    while True:
      line = self.stdout.readline().rstrip()
      # Sometimes the sentinel value is preceded by something like '0:000> '.
      if line.endswith(_SENTINEL):
        break
      lines.append(line)
    return lines

  def LoadSymbols(self, pdb_path):
    """Loads the pdbs for the loaded modules if they are present in |pdb_path|

    Args:
      pdb_path: The path containing the pdbs.
    """
    pdbs = [f for f in os.listdir(pdb_path) if f.endswith('.pdb')]
    # The path needs to be quoted to avoid including the sentinel value in cdb's
    # symbol search path.
    self.Command('.sympath \"%s\"' % pdb_path)
    for line in self.Command('lm n'):
      m = _MODULE_MATCH_RE.match(line)
      if m is None:
        continue
      image_name =  m.group('image_name')
      if image_name is None:
        continue
      pdb_name = image_name + '.pdb'
      if pdb_name in pdbs:
        self.Command('.reload /fi %s' % image_name)

    self.Command('.symfix')


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
  if not os.path.exists(minidump_filename):
    return

  with ScopedDebugger(cdb_path, minidump_filename) as debugger:
    if pdb_path is not None:
      debugger.LoadSymbols(debugger, pdb_path)

    # Enable the line number information.
    debugger.Command('.lines')

    # Get the SyzyASan crash stack and try to find the frame containing the
    # bad access info structure.

    asan_crash_stack = debugger.Command('kv')

    bad_access_info_frame = 0;
    crash_lines, _ = NormalizeStackTrace(asan_crash_stack)

    # Indicates if this bug has been caught by the unhandled exception filter.
    from_uef = False

    for line in crash_lines:
      if not any(line.find(b) != -1 for b in _BAD_ACCESS_INFO_FRAMES):
        bad_access_info_frame += 1
      else:
        if line.find('ExceptionFilter') != -1:
          from_uef = True
        break

    if bad_access_info_frame == -1:
      print ('Unable to find the frame containing the invalid access'
             'informations for %d.' % minidump_filename)
      return

    # Get the information about this bad access.
    debugger.Command('.frame %X' % bad_access_info_frame)
    debugger.Command('kv')
    bad_access_info = debugger.Command(_GET_BAD_ACCESS_INFO_COMMAND)
    bad_access_block_info = debugger.Command(_GET_BLOCK_INFO_COMMAND)
    # The first two lines contain no useful information, remove them.
    bad_access_info.pop(0)
    bad_access_info.pop(0)
    bad_access_block_info.pop(0)
    bad_access_block_info.pop(0)
    bad_access_info_vals = DebugStructToDict(bad_access_info)
    bad_access_info_vals.update(DebugStructToDict(bad_access_block_info))

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

      report = ASanReport(bad_access_info=bad_access_info_vals,
                          crash_stack=None,
                          crash_stack_hash=None,
                          alloc_stack=None,
                          alloc_stack_hash=None,
                          free_stack=None,
                          free_stack_hash=None,
                          corrupt_heap_info=None,
                          from_uef=None)
      return report

    alloc_stack = None
    alloc_stack_hash = None
    free_stack = None
    free_stack_hash = None

    def GetStackAndStackHashFromErrorInfoStruct(debugger, stack_type, is_ptr):
      assert stack_type in ['alloc', 'free']
      command = _GET_STACK_COMMAND_TEMPLATE.format(type=stack_type,
          operand='->' if is_ptr else '.')
      return NormalizeStackTrace(debugger.Command(command))

    alloc_stack, alloc_stack_hash = GetStackAndStackHashFromErrorInfoStruct(
        debugger, 'alloc', is_ptr=not from_uef)
    free_stack, free_stack_hash = GetStackAndStackHashFromErrorInfoStruct(
        debugger, 'free', is_ptr=not from_uef)

    debugger.Command('.ecxr')
    crash_stack, crash_stack_hash = NormalizeStackTrace(
        debugger.Command('kv'))

    corrupt_heap_info = None

    if heap_is_corrupt:
      corrupt_heap_info = GetCorruptHeapInfo(debugger,
                                             bad_access_info_vals,
                                             bad_access_info_frame, from_uef)

    report = ASanReport(bad_access_info=bad_access_info_vals,
                        crash_stack=crash_stack,
                        crash_stack_hash=crash_stack_hash,
                        alloc_stack=alloc_stack,
                        alloc_stack_hash=alloc_stack_hash,
                        free_stack=free_stack,
                        free_stack_hash=free_stack_hash,
                        corrupt_heap_info=corrupt_heap_info,
                        from_uef=from_uef)
  return report


def PrintASanReport(report, file_handle=sys.stdout):
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
  if report.crash_stack and len(report.crash_stack) != 0:
    for line in report.crash_stack:
      file_handle.write('%s\n' % line)
  if report.alloc_stack and len(report.alloc_stack) != 0:
    file_handle.write('\nAllocation stack:\n')
    for line in report.alloc_stack:
      file_handle.write('%s\n' % line)
  if report.free_stack and len(report.free_stack) != 0:
    file_handle.write('\nFree stack:\n')
    for line in report.free_stack:
      file_handle.write('%s\n' % line)

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
        for field in sorted(block_info):
          if not field.endswith('stack') and field != ('block_content'):
            file_handle.write('      %s : %s\n' % (field, block_info[field]))
        file_handle.write('      Alloc stack:\n')
        for frame in block_info['alloc_stack']:
          file_handle.write('        %s\n' % frame)
        if block_info['free_stack']:
          file_handle.write('      Free stack:\n')
          for frame in block_info['free_stack']:
            file_handle.write('        %s\n' % frame)
        file_handle.write('      Block content:\n')
        for line in block_info['block_content']:
          file_handle.write('        %s\n' % line)

  file_handle.write('\n\n%s\n' % _ERROR_HELP_URL)


_USAGE = """\
%prog [options] <minidumps>

Symbolizes a list of minidumps that has been generated by SyzyASan. For each of
them this prints the crash, alloc and free stack traces and gives more
information about the crash.
"""


def _ParseArguments():
  """Parse the command line arguments.

  Returns:
    The options on the command line and the list of minidumps to process.
  """
  parser = optparse.OptionParser(usage=_USAGE)
  parser.add_option('--cdb-path', help='(Optional) The path to cdb.exe.')
  parser.add_option('--pdb-path',
                    help='(Optional) The path to the folder containing the'
                         ' PDBs.')
  (opts, args) = parser.parse_args()

  if not opts.cdb_path:
    for path in _DEFAULT_CDB_PATHS:
      if os.path.isfile(path):
        opts.cdb_path = path
        break
    if not opts.cdb_path:
      parser.error('Unable to find cdb.exe.')

  return opts, args


def main():
  """Parse arguments and do the symbolization."""
  opts, minidumps = _ParseArguments()

  for minidump in minidumps:
    report = ProcessMinidump(minidump, opts.cdb_path, opts.pdb_path)
    if report:
      print 'Report for %s' % minidump
      PrintASanReport(report)
      print '\n'
    else:
      print 'Error while processing %s' % minidump

  return 0


if __name__ == '__main__':
  sys.exit(main())
