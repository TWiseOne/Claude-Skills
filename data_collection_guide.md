# Splunk security map: structure and data collection

## Scope and structure

Your structure is suitable. Keep `inputs/es/` and `inputs/adhoc/`; replace all `inputs/raw/` references in the earlier skill with `inputs/`. Raw exports are immutable. Empty directories are fine; do not create zero-byte CSVs or Python modules as placeholders. Claude should generate outputs and choose its implementation.

Recommended additions:
- `docs/data_collection_guide.md` and `docs/claude_code_prompts.md` (these two documents).
- `inputs/collection_manifest.csv` to record provenance and observation windows.
- `output/content.csv` for one record per saved search, including searches with no resolved sourcetype.
- `output/search_types.csv`, `output/search_type_sankey.csv`, and `visualisations/search_types.html` for the separate access-method diagram.
- `output/additional_splunk_data_needed.md` for precise unresolved evidence requests.
- A small `tests/` directory for meaningful parser/aggregation fixtures once code exists.

Keep the four `src/` filenames as suggestions, not a required architecture. No database, server, scheduler or MITRE integration is needed. `05_es_detections.spl` can derive a convenience subset of saved searches; a separate ES inventory is not required if the main export includes the correlation-search flag.

## Corrections to the earlier specification

1. This is configuration-backed reference coverage. Enabled/scheduled configuration does not prove successful execution or that a search matches events. Observed means present in the chosen window and accessible indexes, not proof of every ingest source.
2. With CIM resolution explicitly out of scope, data-model-only detections remain unresolved to sourcetypes. Say **no identified usage**, not **unused data**. Index-only searches must not automatically cover every sourcetype in that index.
3. Scheduling is a proxy for continuing use, not proof that every non-ES scheduled search is security content. Retain this assumption prominently and use explicit exclusions for housekeeping searches.
4. Preserve the original saved-search title as identity; a detection label is display metadata. Use `(search_head, app, owner, content_name)` and REST id where available. Keep ES/ADHOC identities separate, even if names coincide. Deduplicate copies of the same source object, never just by title.
5. Classify `search_type` after macro expansion. Store `uses_macro` separately: a macro is an indirection mechanism, not a peer of event search/tstats/datamodel. Use event_search, tstats_index, tstats_datamodel, datamodel, mixed, other, unresolved.
6. Parse data-source predicates, not arbitrary text matches. Negations, comments, strings, `eval sourcetype=...`, output lookups and synthetic data do not establish positive source usage. Preserve Boolean context and subsearch provenance. Separate branches must not be combined into invented index/sourcetype pairs.
7. Macro resolution requires arguments, arity, app/owner/sharing scope, cycles and depth limits. Ambiguous macro visibility must remain unresolved. Do not pick a similarly named macro from another app or search head without evidence.
8. Keep source-resolution provenance separate from domain/app presentation mappings. A manual domain label must not turn a discovered sourcetype relationship into `manual_mapping`.
9. Sankey flow counts must be consistent. Form distinct included `(content_id, sourcetype, effective_domain, effective_app)` tuples. Count these on BOTH stages. Thus domain→app counts sourcetype-content relationships, not unique detections alone. A detection using three sourcetypes contributes three units on that stage. Report distinct content totals separately. This conserves domain flow and avoids mixing two measures.
10. Coverage states: covered; disabled_only (otherwise eligible but disabled); excluded_only (unscheduled/excluded references); no_identified_usage. Keep estate-level unresolved counts separate unless evidence associates a particular sourcetype. Unknown enabled/scheduled state never counts as enabled.

## Collection procedure

Run collectors manually on one representative ES search-head member and one representative ADHOC member, with an account permitted to see the intended knowledge objects and indexes. All-user/all-app namespace queries still respect account permissions. Record permission limitations, search-head identities, versions, result counts, warnings and any truncation. Do not collect every SHC member and treat copies as new content.

Export the complete results as UTF-8 CSV, with headers, preserving quoted multiline SPL. Use Splunk's CSV export rather than copying visible rows. Header-only CSV is legitimate only when the search completed with zero rows; missing, failed and empty exports are different states. Store each collector below in its corresponding `spl/` file. The ES and ADHOC queries differ only where explicitly stated.

### 01_saved_searches.spl — required, both search heads

Export all saved searches so disabled/unscheduled records remain available for diagnostics. Claude filters eligibility locally.

```spl
| rest splunk_server=local count=0 /servicesNS/-/-/saved/searches
| rename title AS content_name search AS spl eai:acl.app AS app eai:acl.owner AS owner eai:acl.sharing AS sharing action.correlationsearch.enabled AS correlation_enabled action.correlationsearch.label AS detection_label action.notable.param.security_domain AS security_domain
| eval search_head="ES"
| table search_head id app owner sharing content_name detection_label description disabled is_scheduled cron_schedule correlation_enabled security_domain spl
```

Change `search_head="ES"` to `"ADHOC"` for ADHOC. Save:
- `inputs/es/saved_searches.csv`
- `inputs/adhoc/saved_searches.csv`

`disabled=0` means enabled; `correlation_enabled=1` identifies traditional correlation content independently of the disabled flag. Normalize true/false variants locally. Blank flags mean unknown, not false. If your ES version uses a different detection framework, verify this inventory against ES Content Management. A discrepancy requires a version-specific export; this flag must not be claimed to identify every detection framework universally.

### 02_sourcetypes.spl — required, both search heads

Use the SAME explicit observation window on both. Example: last 30 days. Change it deliberately if low-frequency sources require a longer period.

```spl
| tstats count AS event_count min(_time) AS first_seen max(_time) AS last_seen WHERE index=* earliest=-30d@d latest=now BY index sourcetype
| eval search_head="ES"
| table search_head index sourcetype event_count first_seen last_seen
```

Change the head label for ADHOC. Save `inputs/es/sourcetypes.csv` and `inputs/adhoc/sourcetypes.csv`. Times remain epoch values to avoid timezone ambiguity. Event counts are collection diagnostics only; do not use them for graph widths. `index=*` covers searchable non-internal indexes; document this scope and role restrictions. Add explicitly approved internal indexes only if they belong to the assessment.

Union sourcetypes across the two inventories; retain per-head/index provenance. Shared indexer visibility can produce duplicate inventory rows and must not double the sourcetype denominator. Since this is sourcetype-level coverage, one reference may mark the combined sourcetype covered without proving coverage in every index/environment.

### 03_macros.spl — required where macros are used, both search heads

```spl
| rest splunk_server=local count=0 /servicesNS/-/-/admin/macros
| rename title AS macro eai:acl.app AS app eai:acl.owner AS owner eai:acl.sharing AS sharing
| eval search_head="ES"
| table search_head id app owner sharing macro definition args iseval validation errormsg
```

Change the head label for ADHOC. Save `inputs/es/macros.csv` and `inputs/adhoc/macros.csv`. Preserve parameterized names such as `example(2)` and the `args` field. If this endpoint fails or returns incomplete scope, capture the error and have your Splunk administrator validate the supported endpoint/permissions; do not substitute guessed definitions.

### 04_datamodel_references.spl — optional parser cross-check, both heads

Raw saved-search SPL is authoritative. This lightweight regex identifies only a subset of explicit tstats-style references; it is not a complete SPL parser and does not pair repeated model/dataset captures reliably.

```spl
| rest splunk_server=local count=0 /servicesNS/-/-/saved/searches
| rename title AS content_name search AS spl eai:acl.app AS app eai:acl.owner AS owner
| rex field=spl max_match=0 "(?i)\\bdatamodel\\s*=\\s*[\"']?(?<datamodel_reference>[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)?)"
| mvexpand datamodel_reference
| where isnotnull(datamodel_reference)
| eval search_head="ES"
| table search_head id app owner content_name datamodel_reference spl
```

Change the head label for ADHOC. Save each head's `datamodel_references.csv`. Treat differences as review items, not automatically as parser failures: macro-hidden references and `| datamodel ...` need local parsing. Do not collect CIM/eventtype/tag definitions for model-to-sourcetype resolution in this scope.

### 05_es_detections.spl — optional ES convenience export

Use collector 01 on ES, insert this immediately before its final `table`:

```spl
| where in(lower(tostring(correlation_enabled)),"1","true")
```

Save `inputs/es/es_detections.csv` if used. Merge by source object identity; do not count it as additional content. Enabled and disabled detections remain included. Reconcile metadata conflicts explicitly.

## Local configuration files

These are curated locally, not exported from Splunk. Start with header-only CSVs; add only mappings you actually authorize. No inferred title classification.

`config/domain_mappings.csv`:
```csv
search_head,app,owner,content_name,security_domain,reason
```
Exact-match content keys only. Populate missing domains; reject overrides of explicit ES metadata. Store discovered and effective domains separately. No matching row means `unmapped` when no authoritative domain exists.

`config/app_mappings.csv`:
```csv
search_head,app,display_app,reason
```
Optional display grouping only. Preserve the owning app and provenance. A mapping never changes content identity or eligibility.

`config/exclusions.yaml`:
```yaml
excluded_content: []
```
Each optional item uses exact `search_head`, `app`, `owner`, `content_name` and a `reason`. Excluded records remain in diagnostic outputs but contribute no current coverage or Sankey units.

Manual sourcetype assertions need a SEPARATE optional `config/source_mappings.csv`:
```csv
search_head,app,owner,content_name,sourcetype,evidence,reason
```
Do not populate this merely to compensate for unresolved data models. Accept only explicit, documented human assertions and label their resolution as manual; report the count separately.

`inputs/collection_manifest.csv`:
```csv
search_head,file,collected_at_utc,earliest_utc,latest_utc,splunk_version,es_version,collector_account,scope_notes,result_count,collection_status
```
One row per export. Use ISO UTC timestamps and exact resolved observation bounds for sourcetype inventory; leave inventory time fields blank for configuration exports. Record completed/failed/not_collected distinctly. Account names are provenance and must not appear as Sankey nodes.

## Before giving Claude the dataset

Confirm headers, row counts, full multiline SPL, raw titles, both head labels, disabled/scheduled flags and macro scope fields. Verify detection totals against the ES UI and investigate any missing metadata. Ensure no synthetic/example data has entered production inputs. Do not prepopulate generated outputs.

## Documentation sources

Queries are proposed collectors and require validation in your environment; they were not executed against your Splunk deployment.
- REST search endpoints: https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions
- REST command all-namespace scheduled-search example: https://help.splunk.com/ja-jp/splunk-cloud-platform/search/search-reference/10.6/search-commands/rest
- Dashboard Studio native Sankey and source/target/value example: https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/9.4/visualizations/sankey-diagrams

Record your installed Splunk/ES versions. Dashboard JSON must target those versions and be labelled untested until you validate it in Splunk.
