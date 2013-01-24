#!python
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
"""A script to create plots for page fault traffic per module."""

import optparse
import os.path
import random
import re

# TODO(siggi): Figure out why Tk is broken in Chrome's python26 interpreter
#     and fix it, then revisit this code.
# pylint: disable=F0401
from etw import EventConsumer, EventHandler, TraceEventSource
from etw_db import FileNameDatabase, ModuleDatabase, ProcessThreadDatabase
import etw.descriptors.pagefault as pagefault
import matplotlib

# This is ugly, but the back-end has to be selected before importing any
# submodules.
matplotlib.use('PDF')

import matplotlib.ticker as ticker
import matplotlib.pyplot as pyplot
import matplotlib.colors as colors
# pylint: enable=F0401


_PAGE_SIZE = 4096


class _ModuleFaults(object):
  """Implementation class that stores faults per module."""
  def __init__(self, module):
    self.file_name = os.path.basename(module.file_name)
    self.module_base = module.file_name
    self.page_faults = []

  def AddFault(self, thread_id, time, fault_type, address, size):
    self.page_faults.append((thread_id, time, fault_type, address, size))


class _ProcessFaults(object):
  """Implementation class that stores faults per process."""
  def __init__(self, process):
    self.cmd_line = process.cmd_line
    self.start_time = process.start_time
    self.process_id = process.process_id
    self.modules = {}

  def AddFault(self, module, thread_id, time, fault_type, address, size):
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

    mod.AddFault(thread_id, time, fault_type, address, size)


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

  def _RecordFault(self, process, module, thread_id, time, fault_type,
                   address, size):
    proc = self._processes.get(process.process_id)
    if not proc:
      proc = _ProcessFaults(process)
      self._processes[process.process_id] = proc

    proc.AddFault(module, thread_id, time, fault_type, address, size)

  @EventHandler(pagefault.Event.HardFault)
  def _OnHardFault(self, event):
    process = self._process_database.GetThreadProcess(event.TThreadId)
    module = self._module_database.GetProcessModuleAt(
        process and process.process_id, event.VirtualAddress)

    if self._ShouldRecord(process, module):
      self._RecordFault(process,
                        module,
                        event.thread_id,
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

  def OnSoftFault(self, fault_type, event):
    process_id = event.process_id
    process = self._process_database.GetProcess(process_id)
    module = self._module_database.GetProcessModuleAt(
        process and process.process_id, event.VirtualAddress)
    if self._ShouldRecord(process, module):
      self._RecordFault(process,
                        module,
                        event.thread_id,
                        event.time_stamp,
                        fault_type,
                        event.VirtualAddress & ~0xFFF,
                        _PAGE_SIZE)


def DataStartOptionCallback(dummy_option, dummy_opt, value, parser):
  try:
    # Split the parameter into 'module_name,rva_address'.
    match = re.match('^([^,]+),([^,]+)$', value)
    if match == None:
      raise
    module = match.groups()[0]
    address = int(match.groups()[1], 0)  # Auto-detect base 8/10/16.
  except:
    raise optparse.OptionValueError(
        'Invalid data_start option: \'%s\'.' % value)
  if parser.values.data_start == None:
    parser.values.data_start = {}
  parser.values.data_start[module] = address


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
  parser.add_option('-d', '--data_start', dest='data_start',
                    help='A comma separated "module,rva_start" pair '
                         'which specifies where non-text data starts. '
                         'To be called once per module.',
                    action='callback', type='string',
                    callback=DataStartOptionCallback)
  parser.add_option('-c', '--categorize', dest='categorize',
                    help='A category indicated how to group fault events. '
                         'One of {process, module, thread} (default: process).',
                    default='process')
  parser.add_option('-o', '--output', dest='output',
                    help='The file where the graph is written, if not '
                         'supplied the graph will be displayed interactively.',
                    default=None)
  parser.add_option('--width', dest='width', type='int',
                    help='Width of the generated graph (inches, default: 16).',
                    default=16)
  parser.add_option('--height', dest='height', type='int',
                    help='Height of the generated graph (inches, default: 9).',
                    default=9)
  parser.add_option('--dpi', dest='dpi', type='int',
                    help='DPI of the generated graph (default: 80).',
                    default=80)
  return parser


def ConsumeLogs(files, process_filter, module_filter):
  """Consumes a set of kernel logs and collects page fault information.

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

  return pf_handler._processes  # pylint: disable=W0212


def WhitenColor(color, factor):
  """Makes a color whiter.

  Args:
    color: the color to whiten, in any of the formats supported
        by matplotlib.colors.
    factor: the amount by which to whiten the color.
        (0=do not change the color, 1=make it completely white)
  """
  assert(factor >= 0 and factor <= 1)
  if isinstance(color, (int, long, float)):
    color = str(color)
  color = colors.colorConverter.to_rgb(color)
  color = map(lambda x: 1 - ((1 - x) * (1 - factor)), color)
  color = colors.rgb2hex(color)
  return color


def PlotStackedBar(ax, x, heights, scale=100.0, width=0.6, color=0.5,
                   labels=None, annotate=None):
  """Adds a stacked bar chart to a graph.

  Args:
    ax: axes object.
    x: horizontal placement of the center of the bar.
    heights: tuple/list of bar heights.
    scale: used to scale the heights (default: 100).
    width: width of bar chart (default: 0.6).
    color: tuple/list of colors.  If a single color is specified,
        will decrease saturation for each successive bar (default: 0.5).
    labels: tuple/list of labels that will be applied to the bars
        (default: None).
    annotate: format specifier used to annotate bar labels with values
        values from 'heights' (default: None).
  """
  real = (int, long, float)
  assert(isinstance(x, real))
  assert(isinstance(heights, (list, tuple)))

  assert(isinstance(scale, real) and scale > 0)
  assert(isinstance(width, real) and width > 0)

  n = len(heights)

  # Get partial sums.
  heights_partialsum_0 = [0] * n  # [0, h[0], h[0] + h[1], ...]
  heights_partialsum_1 = [heights[0]] * n  # [h[0], h[0] + h[1], ...]
  for i in range(1, n):
    heights_partialsum_0[i] = heights_partialsum_0[i - 1] + heights[i - 1]
    heights_partialsum_1[i] = heights_partialsum_1[i - 1] + heights[i]

  # Scale the partial sums so they sum to 'scale'.
  scale_factor = heights_partialsum_1[n - 1] / scale
  for i in range(0, n):
    heights_partialsum_0[i] /= scale_factor
    heights_partialsum_1[i] /= scale_factor

  # Set up colors for each bar.
  if isinstance(color, (list, tuple)):
    assert(len(color) == n)
  else:
    color = [color] * n
    for i in range(0, n):
      color[i] = WhitenColor(color[0], i * 1.0 / n)

  # Plot the actual bar.
  ax.bar([x] * n, heights_partialsum_1,
         bottom=heights_partialsum_0,
         color=color, width=width, align='center')

  if labels != None:
    assert(len(labels) == n)
    for i in range(0, n):
      y = (heights_partialsum_0[i] + heights_partialsum_1[i]) / 2
      label = labels[i]
      if annotate != None:
        label = label + (annotate % heights[i])
      ax.annotate(label, (x, y), horizontalalignment='center',
                  verticalalignment='center', rotation='vertical')


def GenerateGraph(info, file_name, width, height, dpi, data_start=None,
                  categorize=None):
  """Generates a graph from collected information.

  Args:
    info: a dictionary of pid->_ProcessFault instances.
    file_name: output file name, or None to show the graph interactively.
    width: the width (in inches) of the generated graph.
    height: the height (in inches) of the generated graph.
    dpi: the DPI of the generated graph.
    data_start: dict of of rva_start addresses keyed by module name
        (default: {}).
    categorize: function that receives (process_id, module_id, thread_id)
        and returns a key used to group faults (default: None).
  """
  fig = pyplot.figure(figsize=(width, height), dpi=dpi)
  ax = fig.add_axes([0.1, 0.2, 0.75, 0.7])
  ax_cpf = fig.add_axes([0.1, 0.1, 0.75, 0.1])
  ax_bar = fig.add_axes([0.85, 0.1, 0.05, 0.8])

  if categorize == None:
    categorize = lambda p, m, t: 0

  if data_start == None:
    data_start = {}

  # Get the earliest start time across all processes.
  start_time = None
  for process_faults in info.itervalues():
    if not start_time or process_faults.start_time < start_time:
      start_time = process_faults.start_time

  max_addr = 0
  max_time = 0
  fault_times = {}
  start_times = {}
  faults = {}
  for fault_type in ['hard_code', 'hard_data', 'soft_code', 'soft_data']:
    faults[fault_type] = {}

  # Categorize the faults and calculate summary information.
  for process_faults in info.itervalues():
    process_id = process_faults.process_id
    for module_faults in process_faults.modules.itervalues():
      module_id = module_faults.file_name
      for (thread_id, time, kind, address, size) in module_faults.page_faults:
        time = time + process_faults.start_time - start_time
        max_addr = max(max_addr, address + size)
        max_time = max(max_time, time)

        # Categorize the fault event.
        category = categorize(process_id, module_id, thread_id)

        # Classify the fault type.
        hard = kind in ['HardFault', 'Hard']
        code = True
        if data_start.has_key(module_id):
          code = address < data_start[module_id]
        fault_type = ('hard_' if hard else 'soft_')
        fault_type += ('code' if code else 'data')

        if not faults[fault_type].has_key(category):
          faults[fault_type][category] = []
        faults[fault_type][category].append((time, address))

        # Keep track of earliest start time per category.
        if not start_times.has_key(category):
          start_times[category] = time
        start_times[category] = min(time, start_times[category])

        # We are only interested in hard code faults for the cumulative
        # display. So keep track of the set of unique times across all
        # categories for this fault type.
        if hard and code:
          fault_times[time] = True

  # A small set of preferred colors that we use for consistent coloring. When
  # this is exhausted we start generating random colors.
  pref_colors = ['red', 'blue', 'green', 'orange', 'magenta', 'brown']

  # Get the categories as a list, sorted by start time.
  categories = map(lambda x: x[0],
                   sorted(start_times.items(), lambda x, y: cmp(x[1], y[1])))

  # Assign category colors.
  category_colors = {}
  pref_color_index = 0
  for category in categories:
    if pref_color_index < len(pref_colors):
      category_colors[category] = pref_colors[pref_color_index]
    else:
      category_colors[category] = (random.random(), random.random(),
                                   random.random())
    pref_color_index += 1

  # Display data_start lines as horizontal pale yellow marker lines.
  for module_id, rva in data_start.items():
    if rva < max_addr:
      ax.axhline(y=(rva), color=WhitenColor('y', 0.8), zorder=0)

  # Plot the fault events.
  size_data = 3
  size_code = 5
  marker_soft = 'o'
  marker_hard = 's'
  data_whiten = 0.5
  soft_whiten = 0.7
  for category in categories:
    color = WhitenColor(category_colors[category],
                        1 - data_whiten * soft_whiten)
    for (time, address) in faults['soft_data'].get(category, []):
      ax.plot(time, address, markeredgecolor=color, markeredgewidth=0.5,
              marker=marker_soft, markersize=size_data, markerfacecolor='None',
              zorder=1)

    color = WhitenColor(category_colors[category], 1 - data_whiten)
    for (time, address) in faults['hard_data'].get(category, []):
      ax.plot(time, address, markeredgecolor=color, markeredgewidth=0.5,
              marker=marker_hard, markersize=size_data, markerfacecolor='None',
              zorder=2)

    color = WhitenColor(category_colors[category], 1 - soft_whiten)
    for (time, address) in faults['soft_code'].get(category, []):
      ax.plot(time, address, markeredgecolor=color, markeredgewidth=0.5,
              marker=marker_soft, markersize=size_code, markerfacecolor='None',
              zorder=3)

    color = category_colors[category]
    for (time, address) in faults['hard_code'].get(category, []):
      ax.plot(time, address, markeredgecolor=color, markeredgewidth=0.5,
              marker=marker_hard, markersize=size_code, markerfacecolor='None',
              zorder=4)

  # Build and plot the cumulative hard_code plots.
  fault_times = sorted(fault_times.keys())
  fault_counts = [0] * len(fault_times)
  zorder = 0
  for category in categories:
    fault_sum = 0
    fault_dict = {}
    for (time, address) in faults['hard_code'].get(category, []):
      fault_dict[time] = fault_dict.get(time, 0) + 1

    fault_sum = 0
    for time_index in range(len(fault_counts)):
      time = fault_times[time_index]
      delta = fault_dict.get(time, 0)
      fault_sum += delta
      fault_counts[time_index] += fault_sum

    ax_cpf.fill_between(fault_times, fault_counts,
                        color=category_colors[category], zorder=zorder)
    zorder -= 1

  # Display the process start times as vertical yellow marker lines.
  for process_faults in info.itervalues():
    time = process_faults.start_time - start_time
    if time > 0:
      ax.axvline(x=(process_faults.start_time - start_time),
                 color="y",
                 label="PID: %d" % process_faults.process_id, zorder=5)
      ax_cpf.axvline(x=(process_faults.start_time - start_time), color="y",
                     zorder=5)

  # Do the bar plots of total faults.
  hard = 0
  soft = 0
  hard_code = 0
  hard_data = 0
  for category in categories:
    hc = len(faults['hard_code'].get(category, []))
    hd = len(faults['hard_data'].get(category, []))
    soft += len(faults['soft_code'].get(category, [])) + \
            len(faults['soft_data'].get(category, []))
    hard += hc + hd
    hard_code += hc
    hard_data += hd
  PlotStackedBar(ax_bar, 0.5, (hard_code, hard_data),
                 labels=('hard code', 'hard data'), annotate=' (%d)')
  PlotStackedBar(ax_bar, 1.5, (hard, soft),
                 labels=('hard', 'soft'), annotate=' (%d)')

  ax_cpf.set_xlim(0, max_time)
  ax_cpf.set_xlabel('Time (s)')
  ax_cpf.set_ylabel('Hard code faults')

  ax.set_xlim(0, max_time)
  ax.xaxis.set_major_formatter(ticker.NullFormatter())
  ax.set_ylabel('Address')
  ax.set_ylim(0, max_addr)
  ax.yaxis.tick_left()
  formatter = ticker.FormatStrFormatter('0x%08X')
  ax.yaxis.set_major_formatter(formatter)
  for label in ax.yaxis.get_ticklabels():
    label.set_rotation(-45)
    label.set_verticalalignment('bottom')

  ax_bar.set_ylim(0, 100.0)
  ax_bar.yaxis.tick_right()
  ax_bar.yaxis.set_major_formatter(ticker.FormatStrFormatter('%d%%'))
  ax_bar.set_xlim(0, 2)
  ax_bar.xaxis.set_major_locator(ticker.NullLocator())
  ax_bar.xaxis.set_major_formatter(ticker.NullFormatter())

  if file_name:
    pyplot.savefig(file_name)
  else:
    pyplot.show()


def main():
  """Script's main function."""
  parser = GetOptionParser()
  options, args = parser.parse_args()

  if not args:
    parser.error('You must provide one or more trace files to parse.')

  categorize = {'process': lambda p, m, t: p,
                'module': lambda p, m, t: m,
                'thread': lambda p, m, t: t}
  categorize = categorize.get(options.categorize, None)

  info = ConsumeLogs(args, options.processes, options.modules)
  GenerateGraph(info, options.output, options.width, options.height,
                options.dpi, categorize=categorize,
                data_start=options.data_start)


if __name__ == '__main__':
  main()
