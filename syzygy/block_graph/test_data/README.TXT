Files with a ".bg" extension are serialized block-graphs. In fact, they are
filtered subsets of a block-graph. To preserve the nature and layout of
references two additional blocks have been added, named "CodeMaster" and
"DataMaster".

Any references to data blocks have been remapped to point to the
beginning of "DataMaster" (likewise for code references and "CodeMaster").

Any references from a data block to a block that has been kept have been
transferred to originate from "DataMaster" (likewise for references from code
blocks and "CodeMaster").

has_inline_assembly.bg:
  This consists of all blocks from Chrome 28.0.1486.0 that have the
  HAS_INLINE_ASSEMBLY attribute, with all other blocks having been removed.
  References have been preserved using the mechanism discussed above.
