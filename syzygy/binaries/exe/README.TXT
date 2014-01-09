Syzygy Post-Link Transformation Toolchain
=========================================

Date:     2014/01/09
Version:  0.7.7.1 (1984)

The Syzygy project consists of a suite of tools for the instrumentation of
PE binaries. The various instrumentation modes allow for computing code
coverage results, profiling source code, applying profile-guided basic block
optimizations as well as block (function) level profile-guided reordering.


CONTENTS
========

Executables
-----------

agent_logger.exe
  A RPC logging service. For use with ASAN instrumented binaries, accepting
  error logs across process boundaries. Works for sandboxed processes, like
  Chrome.

call_trace_control.exe
  Controls ETW kernel logging services. This tool is primarily intended for
  use with the Chrome benchmarking and profiling scripts, packaged elsewhere.

call_trace_service.exe
  Controls the data collection backend used by the various instrumentation
  agents. This must be running while executing an instrumented binary,
  otherwise no data will be collected.

decompose.exe
  Utility for decomposing PE files (.exe and .dll) to the intermediate
  representation format used by the Syzygy toolchain.

decompose_image_to_text.exe
  Utility that decomposes a PE file to a textual representation.

dump_trace.exe
  Explores trace files produced by call_trace_service by dumping them to a
  textual format.

genfilter.exe
  Used to produce filters that can in turn be fed to the instrumenter. This
  allows for partial instrumentation of a binary. See FILTER-FORMAT.TXT for
  details.

grinder.exe
  Processes trace files and produces some summary output. The output of this
  tool is typically used as input to other tools for visualizing profile data
  or performing optimizations.

instrument.exe
  Instruments a PE file with a given agent.

pdbfind.exe
  A utility for locating the PDB file that is matched to a given PE file.

pehacker.exe
  A utility for applying various transforms to a PE file via a text
  configuration file.

relink.exe
  Relinks a PE file after applying specified transformations. Combined with
  output from grinder and reorder this is used to apply optimizations to a
  binary.

reorder.exe
  Uses aggregated profile data from grinder to produce an order file
  describing an optimized binary layout. The output is intended to be used
  with relink to actually apply the optimization.

run_in_snapshot.exe:
run_in_snapshot_x64.exe:
run_in_snapshot_xp.exe:
  Simulate cold-start performance by running the provided executable on a
  cold virtual volume.

sampler.exe:
  A sampling profiler. This monitors running processes and attaches a
  sampling profiler to modules of interest, dumping output to trace files.

simulate.exe
  Simulates OS page faults by playing back a call_trace_client data file.

swapimport.exe
  Makes a named import library the first one in the import directory by
  swapping it if necessary. This operates on a raw PE file, with no need for
  symbols.

wsdump.exe
  Dumps the working set associated with a running process. The output is in
  JSON format.

zap_timestamp.exe
  A utility for normalizing a PE/PDB file pair after a build. Used as a post-
  build step this should allow for production of identical binary outputs
  given identical inputs. Typical outputs vary in the timestamp, and various
  unique IDs and checksums.

Instrumentation Agents
----------------------

The release package includes the following instrumentation agent libraries,
and their debugging symbols (PDB files).

basic_block_entry_client.dll
  The agent associated with the basic-block entry instrumentation mode. This
  collects frequency of execution counts for each basic block in a binary.
  Intended for use with grinder/reorder/relink for applying basic block
  optimizations (hot cold separation and basic-block reordering).

call_trace_client.dll
  The agent associated with the call-trace instrumentation mode. This
  collections function entry events. Intended for use with
  grinder/reorder/relink for applying block (function) level reordering.

coverage_client.dll
  The agent associated with the code coverage instrumentation mode. This
  collects basic block visited information. Intended for use with grinder
  to produce LCOV coverage reports. These can then be used with a variety
  of code coverage tools.

profile_client.dll
  The agent associated with the hierarchichal profiler. Collects function entry
  and exit events per thread. Intended for use with grinder to produce
  cachegrind files. These can then be used with a KCacheGrind or QCacheGrind
  for visualization.

syzyasan_rtl.dll
  The runtime library associated with the address-sanitizer instrumentation
  mode. Useful for finding heap use errors (use after free, double free, etc).

Experimental Executables
------------------------

code_tally.exe
  Processes a PDB file and produces a cachegrind file documenting bytes of
  code/occurrence code per line of source file, as well as code volume per
  compiland. These can be visualized with KCacheGrind or QCacheGrind.

compare.exe
  Reconciles two different but related binaries (two versions of the same
  program, for example), mapping unchanged blocks and then attempting to
  determine which blocks in one binary are related/have evolved from which
  blocks in the other binary.

pdb_dumper.exe
  Dumps a textual representation of the contents of a PDB file.

timed_decomposer.exe
  Repeatedly runs decomposition and reports timing information.

Experimental Python Scripts
---------------------------

convert_code_tally.py
  Convert a JSON file generated by code_tally.exe into a format that can be
  uploaded to the Chromium size viewer app engine instance.

Include files
-------------

nested_heap.h
  Header file for the SyzyASAN nested heap API.

Lib files
---------

syzyasan_rtl.lib
  Library file for importing the SyzyASAN runtime.

USAGE
-----

Invoke the individual tools with a '--help' argument for further details.

In general the toolchain is applied in the following manner:

  (1) instrument a binary with instrument.exe
  (2) start call_trace_service.exe
  (3) run the instrumented binary through a suite of tests
  (4) stop call_trace_service.exe
  (5) aggregate the call-trace data with grinder.exe

If you are collecting code coverage or profile info the output of grinder.exe
is ready for visualization. If you are optimizing a binary the workflow is
a little different:

  (1) - (4) as above
  (5) analyze the trace files and produce an order file with reorder.exe
  (6) apply the calculated optimization using relink.exe


REDISTRIBUTION
--------------

Any of the binaries included in this distribution may be freely redistributed
as long as LICENSE.TXT is included in the distribution.


LICENSING
---------

The Syzygy project is licensed under the Apache Software license. You should
have received a copy of this in LICENSE.TXT.
