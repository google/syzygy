The test data is laid out in the following manner:

zap_timestamps/test_data/[Configuration]/copy[i]/test_dll.[dll|pdb]

Items in copy0 are made from a clean build.
Items in copy1 are built by deleting the final output and relinking.
Items in copy2 are made from a rebuild all.

zap_timestamps/test_data/test_dll_no_pdb.dll

Is a release build of a PDB with no matching symbol file. The image doesn't
even contain a CodeView debug directory entry.