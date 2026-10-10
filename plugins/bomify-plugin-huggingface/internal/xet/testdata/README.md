These files come from the Xet protocol's reference files,
https://huggingface.co/datasets/xet-team/xet-spec-reference-files
(Apache-2.0), for Electric_Vehicle_Population_Data_20250917.csv:

- `reference.chunks`: its `.csv.chunks`, each chunk's hash and length.
- `reference.shard`: its `.csv.shard.verification-no-footer`, the shard
  that registers it.
- `099cb228….chunk`: one of its chunks, named by its hash.

Two more are too big to keep here. To run the tests that use them,
download them and point these at them:

- `XET_REFERENCE_CSV`: `Electric_Vehicle_Population_Data_20250917.csv`
  (63 MB), which `TestChunkerReference` chunks.
- `XET_REFERENCE_XORB`: `eea25d6e….xorb` (14 MB), which xet-core wrote
  and `TestReferenceXorb` decompresses.
