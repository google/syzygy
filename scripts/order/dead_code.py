#!/usr/bin/python2.6
# Copyright 2011 Google Inc.
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

"""A script to list dynamically dead code."""

import call_trace
import ctypes
import comtypes.client
import etw
import etw_db
import json
import logging
import optparse
import os.path
import sys


_LOGGER = logging.getLogger('dead_code_finder')


_DEFAULT_DIA_DLL = os.path.abspath(os.path.join(
    r'C:\Program Files (x86)\Microsoft Visual Studio 9.0',
    r'DIA SDK\bin\msdia90.dll'))


FUNCTION_TAGS = (
    5,  # Function
    27,  # Thunk
    )


class SymbolTableEntry(object):
  """Denotes a code symbol and whether or not it was reached in a trace.

  Attributes:
    symbol: A DiaSymbol object.
    visited: Whether or not the symbol was dynamically visited.
  """

  def __init__(self, symbol, visited=False):
    """Initializes a symbol table entry.

    Args:
      symbol: The DiaSymbol for this entry.
      visited: Whether or not the symbol was dynamically visited.
    """
    self.symbol = symbol
    self.visited = visited

  def __repr__(self):
    """Represents this symbol as a string."""
    return '%s<rva=0x%08X, tag=%s, kind=%s, name=%r, undecorated=%r>' % (
        self.__class__.__name__,
        self.symbol.relativeVirtualAddress,
        self.symbol.symTag,
        self.symbol.dataKind,
        self.symbol.name,
        self.symbol.undecoratedName)

  __str__ = __repr__


class DeadCodeFinder(etw.EventConsumer):
  """Handles call trace events and produces a list of unvisited symbols."""

  def __init__(self, input_file, trace_files, dia_dll=None):
    """Initializes a CallTraceHandler.

    Args:
      input_file: The EXE or DLL file being traced.
      trace_files: A list of .ETL file paths.
      dia_dll: If not None, use the DIA SDK DLL at the given path instead
          of the default DIA SDK DLL.
    """
    super(DeadCodeFinder, self).__init__()
    self._process_database = etw_db.ProcessThreadDatabase()
    self._module_database = etw_db.ModuleDatabase()
    self._dia_dll = dia_dll or _DEFAULT_DIA_DLL
    self._input_file = input_file
    self._dia_session = self._GetDiaSession(self._dia_dll, self._input_file)
    self._symbol_table = self._ExtractSymbols(
        self._dia_session, filter_func = lambda x: x.symTag in FUNCTION_TAGS)
    self._visited_addresses = None
    self._ConsumeTraceFiles(trace_files)

  def GetUnvisitedSymbols(self):
    """Gets the list of RVA, Symbol pairs not visited in the trace."""
    return [x for x in self._symbol_table.itervalues() if not x.visited]

  @staticmethod
  def _GetDiaSession(dia_dll, input_file):
    """Returns a DiaSession object.

    Args:
      dia_dll: The path to the DIA dll to load.
      input_file: The path to the EXE or DLL under test.
    """
    dia_api = comtypes.client.GetModule(dia_dll)
    dia_source = comtypes.client.CreateObject(dia_api.DiaSource)
    extension = os.path.splitext(input_file)[1].lower()
    if extension == '.pdb':
      dia_source.loadDataFromPdb(input_file)
    else:
      dia_source.loadDataForExe(input_file, None, None)
    dia_session = dia_source.openSession()
    dia_session.loadAddress = 0x20000000  # Arbitrary address.
    return dia_session

  @staticmethod
  def _ExtractSymbols(dia_session, filter_func=None):
    """Returns an RVA to SymbolTableEntry mapping.

    Args:
      dia_session: The DIA session with all the symbols
      filter_func: A function (symbol->bool) used to decide if
          each symbol should be included in the returned map.
    """
    enumerator = dia_session.getSymbolsByAddr()
    root_rva = enumerator.symbolByAddr(1, 0).relativeVirtualAddress
    symbol = enumerator.symbolByRVA(root_rva)
    symbol_table = {}
    count = 1
    while count == 1:
      if filter_func is None or filter_func(symbol):
        symbol_table[symbol.relativeVirtualAddress] = SymbolTableEntry(symbol)
      symbol, count = enumerator.Next(1)
    return symbol_table

  @etw.EventHandler(call_trace.Event.TraceBatchEnter)
  def OnTraceBatchEnter(self, event):
    """Handler invoked when tracing into a call site.

    Args:
      event: The trace event.
    """
    process = self._process_database.GetThreadProcess(event.ThreadId)
    if process:
      for call in event.Calls:
        address = call.address
        if address in self._visited_addresses:
          continue
        module = self._module_database.GetProcessModuleAt(
            process.process_id, address)
        if module:
          self._visited_addresses.add(address)
          rva = address - module.module_base
          try:
            self._symbol_table[rva].visited = True
          except KeyError:
            symbol = self._dia_session.getSymbolsByAddr().symbolByRVA(rva)
            entry = SymbolTableEntry(symbol, True)
            self._symbol_table[rva] = entry
            _LOGGER.warning('Unexpected reference to symbol: %r\n' % entry)

  def _ConsumeTraceFiles(self, trace_files):
    """Ingests the given list of .ETL files, updating the symbol table."""
    self._visited_addresses = set()
    source = etw.TraceEventSource()
    source.AddHandler(self._process_database)
    source.AddHandler(self._module_database)
    source.AddHandler(self)
    for trace_file in trace_files:
      source.OpenFileSession(trace_file)
    source.Consume()
    self._visited_addresses = None


class SymbolEntryJsonEncoder(json.JSONEncoder):
  """A JSONEncoder extended to handle SymbolTableEntry objects."""
  def default(self, obj):
    """Called when no other object constructor is found."""
    if isinstance(obj, SymbolTableEntry):
      return dict(
          name=obj.symbol.name, rva=obj.symbol.relativeVirtualAddress,
          tag=obj.symbol.symTag, undecorated=obj.symbol.undecoratedName)
    return json.JSONEncoder.default(self, obj)


def ParseCommandLine():
  """Retrieves the command line options and trace file list."""
  option_parser = optparse.OptionParser(
      usage='usage: %prog [options] log_file1.etl ...')
  option_parser.add_option(
      '-i', '--input_file', metavar='PE_PATH',
      help='The path to the EXE, DLL or PDB file to be analyzed.')
  option_parser.add_option(
      '-o', '--output-file', metavar='PATH',
      help='The name of a file to write the output to (default: stdout)')
  option_parser.add_option(
      '-f', '--format', choices=('json', 'report'), default='json',
      help='The output format: json (default) or report')
  option_parser.add_option(
      '-d', '--dia-dll', metavar='DLL_PATH', default=_DEFAULT_DIA_DLL,
      help='The Debug Interface Access SDK DLL path (default: %default)')
  options, trace_files = option_parser.parse_args()
  if not options.input_file:
    option_parser.error('No input file specified.')
  if not trace_files:
    option_parser.error('No trace files specified.')
  trace_files = [os.path.abspath(f) for f in trace_files]
  for trace_file in trace_files:
    if not os.path.isfile(trace_file):
      option_parser.error('%s does not exist' % trace_file)
  return options, trace_files


def PrintReport(unvisited_symbol_entries, stream):
  """Outputs a pretty formatted textual report of the unused symbols.

  Args:
    unvisited_symbol_entries: The list of unvisoted symbol table entries.
    stream: The output stream to which to write the report.
  """
  format_string = '%10s %3s %4s %-60s\n'
  stream.write(format_string % ('RVA', 'Tag', 'Kind', 'Name'))
  stream.write(format_string % (10 * '-', 3 * '-', 4 * '-', 60 * '-'))
  for entry in unvisited_symbol_entries:
    stream.write(format_string % (
        '0x%08x' % entry.symbol.relativeVirtualAddress,
        entry.symbol.symTag,
        entry.symbol.dataKind,
        entry.symbol.name))


def main():
  """Runs this module as a script."""
  options, trace_files = ParseCommandLine()

  dead_code_finder = DeadCodeFinder(
      options.input_file, trace_files, options.dia_dll)

  stream = options.output_file and open(options.output_file, 'w') or sys.stdout
  try:
    unvisited = dead_code_finder.GetUnvisitedSymbols()
    if options.format == 'json':
      json.dump(unvisited, stream, cls=SymbolEntryJsonEncoder, indent=2)
    elif options.format == 'report':
      PrintReport(unvisited, stream)
  finally:
    if options.output_file:
      stream.close()


if __name__ == '__main__':
  main()
