Welcome to SyzyProf!

To use SyzyProf you need to follow these steps:
1. Instrument the executables to profile.
2. Launch the call trace service to capture profiling data.
3. Exercise your profiled executable.
4. Convert (grind) the captured binary logs to KCacheGrind files.
5. View the KCacheGrind files.

A typical session to profile Chrome might look like this.
> InstrumentChrome.bat <chrome directory>
> mkdir traces
> start call_trace_service.exe start --verbose --trace-dir=traces
> <chrome directory>\chrome.exe
    ... time passes ...
> call_trace_service.exe stop
> grinder.exe --output-file=chrome.callgrind traces\*.bin
> kcachegrind.exe chrome.callgrind

Note that for these instructions to work, the <chrome directory> must contain
a flat Chrome directory, such as is to be found in the Chrome continuous
builder chrome-win32.zip archives. The directory must also contain symbols for
the binaries, and the binaries must be linked with the /PROFILE flag.

Note that KCacheGrind is not distributed as part of SyzyProf, but you
can download pre-built Windows binaries from
http://sourceforge.net/projects/precompiledbin/files/kcachegrind.zip/download.

If you work at Google, you can download a slightly more recent version
of QCacheGrind from http://goto.google.com/qcachegrind-win.
