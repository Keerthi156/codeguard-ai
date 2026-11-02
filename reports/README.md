# Reports

These files are committed measurements. A `.json` file with the same name as a `.md` file is that run's machine-readable copy, and the commit and date below are the header fields in the file. Nothing here is a claim about code outside these runs.

## Cited by the README

- `latest.html` is the one-page scan report. `report` writes it from the newest row in the local database.
- `benchmark_after_dependency_fix.md`: commit `b7744ab1115061137525061404c4d94b385d5517`, date 2026-10-30, model `meta-models/muse-spark-open-1026`. This is the benchmark before the destructive-state reset.
- `benchmark_comparison_after_reset.md`: commit `97e81aed1f7dea4299461f5d994ea3ac4902fa20`. The after-reset comparison.
- `benchmark_meta_after_reset.md` and `benchmark_baseten_after_reset.md`: same commit, date 2026-11-01. The Baseten file records `Errors: 1`.
- `benchmark_no_model_after_reset.md`: same commit and date. Required tests only, no model.
- `reliability_meta.md` and `reliability_baseten.md`: commit `65b73161fedead5411dd27874bdb59733a4f3775`, date 2026-10-30. Both say `AUTO-APPROVED (measurement mode, temporary copies only)` and `Measured on the benchmark fixtures only; not a claim of real-world reliability.`
- `reliability_meta_after_guard.md` and `reliability_baseten_after_guard.md`: commit `56b40c45a5793e463dcb2d964310dc47c6ff61d1`, date 2026-10-30. Same measurement note. Both say `patches with at least one style flag: 0 of 20`.
- `ai_written_apps_run3.md`: commit `5ff4ec4d6db1cf200920dd13f06dbfc5089ac349`, date 2026-11-02. The latest experiment report. It says `Small sample of 10 apps from one model and one prompt; not a claim about AI-written code in general.`
- `ai_written_apps_run1.md` and `ai_written_apps.md`: both headers cite commit `fbf687991ecf6456b626e3a039a33deaebd16492`, date 2026-11-02.
- `ai_written_apps_run2.md`: commit `f44d3dc68e556a583a35cb4441f0047800dcc3b0`, date 2026-11-02.

## Superseded

The README does not use these for its headline counts.

- `benchmark.md` and `benchmark.json`: commit `a4df4722010e029bb50d87a17b10294b1b6594df`, date 2026-10-30. The first baseline. The markdown file's recall line is `Recall: 0.57`, and its definitions include a `not discovered` bucket.
- `benchmark_meta.md`, `benchmark_baseten.md`, and `benchmark_no_model.md`, with their `.json` copies: commit `6e6b15f39daca97d53dd1d3c3e76e38146fabc95`, date 2026-10-30. These are the runs from before the destructive-state reset.
- `benchmark_comparison.md` is the default `--out` of `benchmark-compare`, so a later run overwrites it. The copy in this commit has commit `97e81aed1f7dea4299461f5d994ea3ac4902fa20` and `Working tree: clean`.

## Dirty-tree warning

These headers say the working tree was dirty when the run was recorded. Do not treat them as a clean-tree measurement.

- `benchmark_comparison_before_reset_dirty_tree.md` begins with `WARNING: THE WORKING TREE IS DIRTY` and says `Working tree: dirty`.
- `benchmark_baseten.md` and `benchmark_baseten.json` say the working tree was dirty.
- `benchmark_no_model.md` and `benchmark_no_model.json` say the working tree was dirty.
