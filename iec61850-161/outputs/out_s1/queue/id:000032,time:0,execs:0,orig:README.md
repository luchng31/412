# libiec61850 1.6.1 MMS/TCP harness corpus

This package targets the `MMSF` stateful testcase format used by your harness:

- magic: `MMSF` + 1-byte version
- actions:
  - `0x01`: connect
  - `0x02`: send
  - `0x03`: wait
  - `0x04`: shutdown
  - `0x05`: close
  - `0x06`: pulse
  - `0x07`: drain

Contents:
- seeds/: 128 testcase files
- mmsf_libiec61850_161.dict: 217 dictionary entries

Seed mix:
- raw_fallback: 10
- discovery_read: 27
- segmented: 30
- write_dataset: 24
- file_service: 10
- log_operator_misc: 6
- multi_connection: 3
- truncated_halfclose: 5
- service_drift: 13

Recommended use:
- Primary queue: all seeds
- Fast smoke subset:
  - 010_mmsf_handshake_only.bin
  - 011_mmsf_identify.bin
  - 012_mmsf_vmd_discovery.bin
  - 017_mmsf_ld0_status_reads.bin
  - 053_mmsf_write_multi_cfg.bin
  - 058_mmsf_filedir_root.bin
  - 066_mmsf_report_journal_status.bin
  - 071_mmsf_multiconn_discovery.bin
  - 074_mmsf_pipeline_discovery.bin
  - 077_mmsf_service_drift_write_from_read.bin

Suggested AFL++ invocation:
`afl-fuzz -i seeds -o out -x mmsf_libiec61850_161.dict -- ./target 15102`

Notes:
- Some seeds are fully valid discovery/read/file templates.
- Some seeds are intentionally near-valid and use service-tag drift, truncation, half-close, send-length mismatch, and odd segmentation to reach parser/service-edge code.
- Several requests intentionally use model/object names from the custom harness model (`LD0`, `LD1`, `LLN0`, `LPHD1`, `GGIO1`, `MMXU1`, `CSWI1`, datasets, log, files).

