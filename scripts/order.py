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
"""A script to generate a call order used to reorder a binary."""
from etw import EventConsumer, EventHandler, TraceEventSource
from etw_db import ModuleDatabase, ProcessThreadDatabase
import call_trace
import json
import optparse


class CallTraceHandler(EventConsumer):
  """Handles call trace events and produces a call order."""
  def __init__(self, process_database, module_database):
    super(CallTraceHandler, self).__init__()
    self._process_database = process_database
    self._module_database = module_database
    # Set of addresses used to avoid duplicates.
    self._address_set = set()
    # List of RVAs that represent the call order.
    self.rva_order = []

  @EventHandler(call_trace.Event.TraceBatchEnter)
  def OnTraceBatchEnter(self, event):
    # We process the calls in order, and append unique RVAs to the list which
    # will give us a simple linear ordering.
    # TODO(ericdingle): We shouldn't ignore the case where the process
    # doesn't exist in the process database.
    process = self._process_database.GetThreadProcess(event.ThreadId)
    if process:
      for call in event.Calls:
        address = call.address
        if address in self._address_set:
          continue
        module = self._module_database.GetProcessModuleAt(
            process.process_id, address)
        if module:
          self._address_set.add(address)
          self.rva_order.append(address - module.module_base)


def GetOptionParser():
  usage = "usage: %prog [options] log_file.etl"
  parser = optparse.OptionParser(usage=usage)
  parser.add_option('-o', '--output-file', dest='output_file',
                    help='The JSON output file.')
  return parser


def main():
  parser = GetOptionParser()
  options, args = parser.parse_args()

  if not options.output_file:
    parser.error('No output file specified.')
  if not args:
    parser.error('No trace files specified.')

  # Set up the event source and handlers.
  source = TraceEventSource()
  process_database = ProcessThreadDatabase()
  module_database = ModuleDatabase()
  ct_handler = CallTraceHandler(process_database, module_database)
  source.AddHandler(process_database);
  source.AddHandler(module_database);
  source.AddHandler(ct_handler);

  # Open the trace files and consume them.
  for trace_file in args:
    source.OpenFileSession(trace_file)
  source.Consume()

  # Write to the output file in JSON format.
  f = open(options.output_file, 'w')
  f.write(json.dumps(ct_handler.rva_order))
  f.close()


if __name__ == '__main__':
  main()
