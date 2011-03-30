#!python
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
"""A script to create plots for page fault traffic per module."""
from etw import EventConsumer, EventHandler, TraceEventSource
from etw_db import FileNameDatabase, ModuleDatabase, ProcessThreadDatabase
import etw.descriptors.pagefault as pagefault
import matplotlib.patches as patches
import matplotlib.ticker as ticker
import matplotlib.pyplot as pyplot
import optparse
import os.path
import re


_PAGE_SIZE = 4096


class _ModuleFaults(object):
  """Implementation class that stores faults per module."""
  def __init__(self, module):
    self.file_name = os.path.basename(module.file_name)
    self.module_base = module.file_name
    self.page_faults = []

  def AddFault(self, time, type, address, size):
    self.page_faults.append((time, type, address, size))


class _ProcessFaults(object):
  """Implementation class that stores faults per process."""
  def __init__(self, process):
    self.cmd_line = process.cmd_line
    self.start_time = process.start_time
    self.process_id = process.process_id
    self.modules = {}

  def AddFault(self, module, time, type, address, size):
    # Adjust the time to process-relative.
    assert(time >= self.start_time)
    time = time - self.start_time
    mod = self.modules.get(module.file_name)
    if not mod:
      mod = _ModuleFaults(module)
      self.modules[module.file_name] = mod

    # Adjust the address to module-relative.
    assert(address >= module.module_base or
           address < module.module_base + module.module_size)
    address = address - module.module_base

    mod.AddFault(time, type, address, size)


class _PageFaultHandler(EventConsumer):
  """An implementation class to collect information about page faults."""
  def __init__(self, process_database, file_database, module_database):
    self._process_database = process_database
    self._file_database = file_database
    self._module_database = module_database
    self._module_filter = re.compile('.*')
    self._process_filter = re.compile('.*')
    self._processes = {}

  def SetModuleFilter(self, module_pattern):
    self._module_filter = re.compile(module_pattern)

  def SetProcessFilter(self, process_pattern):
    self._process_filter = re.compile(process_pattern)

  def _ShouldRecord(self, process, module):
    if not process or not module:
      return False

    return (self._process_filter.search(process.cmd_line) and
            self._module_filter.search(module.file_name))

  def _RecordFault(self, process, module, time, type, address, size):
    proc = self._processes.get(process.process_id)
    if not proc:
      proc = _ProcessFaults(process)
      self._processes[process.process_id] = proc

    proc.AddFault(module, time, type, address, size)

  @EventHandler(pagefault.Event.HardFault)
  def _OnHardFault(self, event):
    assert(type(event) == pagefault.PageFault_V2.PageFault_HardFault)

    process = self._process_database.GetThreadProcess(event.TThreadId)
    module = self._module_database.GetProcessModuleAt(
        process and process.process_id, event.VirtualAddress)

    if self._ShouldRecord(process, module):
      self._RecordFault(process,
                        module,
                        event.time_stamp,
                        "Hard",
                        event.VirtualAddress & ~0xFFF,
                        event.ByteCount)

  @EventHandler(pagefault.Event.TransitionFault)
  def _OnTransitionFault(self, event):
    self.OnSoftFault('Transition', event)

  @EventHandler(pagefault.Event.DemandZeroFault)
  def _OnDemandZeroFault(self, event):
    self.OnSoftFault('DemandZeroFault', event)

  @EventHandler(pagefault.Event.CopyOnWrite)
  def _OnCopyOnWrite(self, event):
    self.OnSoftFault('CopyOnWrite', event)

  @EventHandler(pagefault.Event.GuardPageFault)
  def _OnGuardPageFault(self, event):
    self.OnSoftFault('GuardPageFault', event)

  @EventHandler(pagefault.Event.HardPageFault)
  def _OnHardPageFault(self, event):
    pass
    # self.OnSoftFault('HardPageFault', event)

  @EventHandler(pagefault.Event.AccessViolation)
  def _OnAccessViolation(self, event):
    self.OnSoftFault('AccessViolation', event)

  def OnSoftFault(self, type, event):
    process_id = event.process_id
    process = self._process_database.GetProcess(process_id)
    module = self._module_database.GetProcessModuleAt(
        process and process.process_id, event.VirtualAddress)
    if self._ShouldRecord(process, module):
      self._RecordFault(process,
                        module,
                        event.time_stamp,
                        type,
                        event.VirtualAddress & ~0xFFF,
                        _PAGE_SIZE)


def GetOptionParser():
  parser = optparse.OptionParser()
  parser.add_option('-p', '--processes', dest='processes',
                    help='A regular expression that matches the command lines '
                         'of the processes to collect information about.',
                    default='.*')
  parser.add_option('-m', '--modules', dest='modules',
                    help='A regular expression that matches the modules '
                         'to collect information about.',
                    default='.*')
  parser.add_option('-o', '--output', dest='output',
                    help='The file where the graph is written, if not '
                         'supplied the graph will be displayed interactively.',
                    default=None)
  parser.add_option('--width', dest='width', type='int',
                    help='Width of the generated graph.',
                    default=16)
  parser.add_option('--height', dest='height', type='int',
                    help='Height of the generated graph.',
                    default=9)
  return parser


def ConsumeLogs(files, process_filter, module_filter):
  """Consumes a set of kernel logs and collect page fault information.

  Args:
      files: a list of paths to kernel trace logs (.etl files) to consume.
      process_filter: a regular expression that matches the processes of
          interest. Example: "chrome.exe|regsvr32.exe".
      module_filter: a regular expression that matches the modules of interest.
          Example: "chrome.dll".
  """
  source = TraceEventSource(raw_time=True)
  process_database = ProcessThreadDatabase()
  file_database = FileNameDatabase()
  module_database = ModuleDatabase()
  pf_handler = _PageFaultHandler(process_database,
                                 file_database,
                                 module_database)
  pf_handler.SetModuleFilter(module_filter)
  pf_handler.SetProcessFilter(process_filter)
  source.AddHandler(process_database)
  source.AddHandler(file_database)
  source.AddHandler(module_database)
  source.AddHandler(pf_handler)

  # Open the trace files.
  for trace_file in files:
    source.OpenFileSession(trace_file)

  # And consume them.
  source.Consume()

  return pf_handler._processes


def GenerateGraph(info, file_name, width, height):
  """Generates a graph from collected information.

  Args:
    info: a dictionary of pid->_ProcessFault instances.
    file_name: output file name, or None to show the graph interactively.
    width: the width (in inches) of the generated graph.
    height: the height (in inches) of the generated graph.
  """
  fig = pyplot.figure(figsize=(width, height), dpi=80)
  ax = fig.add_axes([0.1, 0.2, 0.8, 0.7])
  hist = fig.add_axes([0.1, 0.1, 0.8, 0.1])

  # Start by figuring out the x and y ranges for the graphs by running
  # through and recording the max time and address encountered.
  max_time = 0
  max_addr = 0
  start_time = None
  for process_faults in info.itervalues():
    if not start_time or process_faults.start_time < start_time:
      start_time = process_faults.start_time

  # Add rectangles for every fault, red for hard faults, green for soft.
  # Keep a tally of the number of faults per 0.2 second bucket in our
  # range for the volume plot.
  faults = {}
  for process_faults in info.itervalues():
    for module_faults in process_faults.modules.itervalues():
      for (time, kind, address, size) in module_faults.page_faults:
        time = time + start_time - process_faults.start_time
        if not (address & 0xFFF) == 0:
          print hex(address)
        max_addr = max(max_addr, address + size)
        max_time = max(max_time, time)

        pages = (size + _PAGE_SIZE - 1) / _PAGE_SIZE
        rounded_time = int(time * 5) / 5.0
        pages += faults.get(rounded_time, 0)
        faults[rounded_time] = pages

        color = "#00ff00"
        if kind in ["HardFault", "Hard"]:
          color = "#ff0000"

        box = patches.Rectangle((time, address), 0, size, color=color, lw=2)
        ax.add_patch(box)

  # Set the two graphs to the same X-axis range.
  ax.set_xlim(0, max_time)
  hist.set_xlim(0, max_time)

  # Create the paging volume graph.
  hist.bar(faults.keys(), faults.values(), width=0.2, color="r")
  hist.set_ylabel("Faulting pages")
  hist.set_xlabel('Time (s)')
  ax.set_ylabel('Address')

  formatter = ticker.FormatStrFormatter('0x%08X')
  ax.yaxis.set_major_formatter(formatter)
  for label in ax.yaxis.get_ticklabels():
    label.set_rotation(45)

  ax.set_ylim(0, max_addr)
  ax.set_ylabel('Address')

  # Display the process start times as a yellow marker line.
  for process_faults in info.itervalues():
    ax.axvline(x=(process_faults.start_time - start_time),
               color="y",
               label="PID: %d" % process_faults.process_id)

  if file_name:
    pyplot.savefig(file_name)
  else:
    pyplot.show()


def Main():
  parser = GetOptionParser()
  options, args = parser.parse_args()

  if not args:
    parser.error('You must provide one or more trace files to parse.')

  info = ConsumeLogs(args, options.processes, options.modules)
  GenerateGraph(info, options.output, options.width, options.height)


if __name__ == '__main__':
  Main()
