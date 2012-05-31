Welcome to SyzyProf!

To use SyzyProf you need to follow these steps:
1. Instrument the executables to profile.
2. Launch the call trace service to capture profiling data.
3. Exercise your profiled executable.
4. Convert (grind) the captured binary logs to KCacheGrind files.
5. View the KCacheGrind files.

A typical session might look like this:
> mkdir instrumented
> instrument.exe --verbose --call-trace-client=PROFILER^
    --input-dll=original\chrome.dll^
    --output-dll=instrumented\chrome.dll
> start call_trace_service.exe start --verbose --enable-exits --trace-dir=traces
> instrumented\chrome.exe
    ... time passes ...
> call_trace_service.exe stop
> grinder.exe --output-file=chrome.callgrind traces\*.bin
> kcachegrind.exe chrome.callgrind

Note that KCacheGrind is not distributed as part of SyzyProf, but you
can download pre-built Windows binaries from
http://sourceforge.net/projects/precompiledbin/files/kcachegrind.zip/download.

If you work at Google, you can download a slightly more recent version
of QCacheGrind from http://goto.google.com/qcachegrind-win.
