# Recalculated fresh results

The offline public checker authenticates all 52 records and computes these results without expected headline-total assertions.

| Metric | Before repair | After repair |
| --- | ---: | ---: |
| Destination effects | 15 | 14 |
| Signed native approval/denial decisions | 25 | 25 |
| Permitted signed first consumptions after grant expiry | 1 | 0 |
| Effects linked to those expired consumptions | 1 | 0 |
| Explicitly unqualified legacy effects | 1 | 1 |

Case 15 is the observed expiry race: the baseline signs an allowed decision with a durable first-consumption timestamp after the signed grant expiry and delivers one effect. The repaired implementation signs a denial and produces no effect.

All 16 portable tamper controls reject their edits, including approval-expiry edits, consumption-time edits, altered native decision/operation/grant binding, approval or permit removal, journal truncation, role/batch/case substitution, relabeling a timing violation as an evidence gap, whole-case omission with a repinned outer manifest, and optimized Python execution.

These counts are experimental evidence. The one deliberately unsafe legacy effect per batch is not counted as qualified authority success. Within-window approval is not a claim about all possible revocation, physical-commit, external-delivery or host-compromise properties. Production and model-training qualification remain unchanged.
