# Claude Code prompts for the Splunk security map

Place `data_collection_guide.md` and this document in `docs/` in your project. Save the previously provided custom skill as `.claude/skills/splunk-security-map/SKILL.md`. The prompts below explicitly update its earlier assumptions. Run Claude from the `splunk-security-map/` root. It works only within this directory, with no Splunk/network access.

## Prompt 1 — prepare the project and inspect collected data

Run after collection (or run early to prepare documentation, accepting that inspection will report missing inputs).

```text
Use the project-local splunk-security-map skill. Read docs/data_collection_guide.md as the current agreed contract and this prompt as explicit amendments to the earlier skill. Inspect actual files before assuming schemas. Work only inside this project directory and offline. Do not connect to Splunk, fetch dependencies or modify inputs/.

Create a concise CLAUDE.md with project-wide evidence rules, input immutability, scope, source identities, enabled/scheduled eligibility, no CIM-to-sourcetype inference, and canonical outputs. Create README.md explaining collection, local setup, the eventual build command, outputs and limitations. Reconcile SKILL.md with the contract: inputs/es and inputs/adhoc paths; search_type after macro expansion plus separate uses_macro; conservative SPL parsing; scoped parameterized macros; separate source/domain/app provenance; consistent Sankey tuple weighting; configuration-backed coverage language. Keep the skill focused and link detailed contracts rather than duplicating them.

Inspect every supplied input's schema, row count, head label, collection window, Boolean states, identity fields, SPL preservation and macro scope. Reconcile any es_detections convenience export with saved_searches without double counting. Compare ES inventory with any supplied UI count; do not assume correlation_enabled covers every ES detection framework. Report missing/ambiguous metadata and unknown eligibility, preserving unresolved objects.

Initialize absent config files with the headers/empty YAML from the guide, but preserve existing files. Keep mapping and exclusion defaults empty. Add a suitable .gitignore for virtual environments, Python caches and local temporary files; do not hide canonical outputs or raw inputs by default.

Write output/input_audit.md with blockers, limitations and accepted assumptions. Do not generate fabricated relationship rows. Continue with independent setup work if data is incomplete. Ask only about genuinely unresolved decisions that prevent safe analysis; otherwise record the issue and continue.
```

## Prompt 2 — implement and build both diagrams

```text
Use the splunk-security-map skill, CLAUDE.md, docs/data_collection_guide.md and output/input_audit.md. Implement and execute the current-state analysis against all supplied data. Choose a simple local Python implementation; use installed dependencies or the standard library and document any missing dependencies without fetching them. Provide one documented build command. Do not edit raw inputs.

Include enabled ES detections and enabled scheduled ADHOC searches in current coverage; keep disabled/unscheduled/excluded content in diagnostics. Treat ADHOC scheduling as a continuing-use proxy, not verified security relevance or execution. Missing or contradictory eligibility flags do not imply enabled. Preserve the raw saved-search title, owner, owning app, REST identity and head, with a deterministic content_id. Do not deduplicate different source objects by label or across heads.

Parse positive source predicates with SPL context. Support quoted sourcetypes, IN lists, supported wildcards and scoped macro expansion with arguments, depth 10 and cycle/ambiguity handling. Never turn comments, literals, eval assignments, NOT filters or synthetic output into usage. Preserve Boolean/subsearch context; do not cross-join unrelated index and sourcetype references. Mark unsupported constructs unresolved instead of inventing edges. A partial resolution may retain valid edges while also retaining unresolved dependencies.

No CIM/datamodel/eventtype/tag-to-sourcetype inference. No index-only expansion to all inventory sourcetypes. An explicit sourcetype in a data-model branch must be shown to constrain the actual contributing data before being accepted. Record model references for the separate access-method analysis. Classify expanded access methods as event_search, tstats_index, tstats_datamodel, datamodel, mixed, other or unresolved; track uses_macro separately.

Apply exact-match domain and app mappings according to the guide. Preserve source resolution provenance independently of presentation mappings. Use unmapped where an authoritative domain is absent. Do not classify search titles semantically; report candidate naming patterns only. Explicit exclusions affect eligibility and retain their reasons.

Produce output/content.csv with one row per content object; output/relationships.csv with resolved sourcetype edges and traceable evidence; output/unresolved.csv with all unresolved dependencies; output/coverage.csv against the union of observed inventory; output/nodes.csv and edges.csv; output/sankey.csv with exactly source,target,value; output/search_types.csv and search_type_sankey.csv; output/report.md and additional_splunk_data_needed.md.

Use distinct eligible (content_id, sourcetype, effective_domain, effective_app) tuples for BOTH primary Sankey stages. Each sourcetype-content tuple contributes one unit on both stages, so domain flow is conserved. Do not label domain→app values unique detections; report unique content counts separately. Prefix ST:, DOMAIN:, APP:. For the second diagram count each included content once using its single search_type, including content whose sourcetype is unresolved. Keep both measures separate.

Generate self-contained local visualisations/sankey.html and search_types.html with readable labels and hover provenance/count definitions, no external CDN, no drill-downs and no owners/usernames as nodes. Never silently drop nodes. Include a coverage summary/list for observed sourcetypes with no identified usage; do not invent domain edges for those sources. Escape input strings safely in HTML.

Generate visualisations/splunk_dashboard.json for the recorded version where feasible, plus output/splunk_sankey.spl using an inputlookup source,target,value dataset and brief import/setup instructions. Label the dashboard untested in Splunk. If version information is missing, document the target assumption instead of claiming compatibility. Do not deploy anything.

Write meaningful fixtures for source predicate versus literal/negation, IN lists, scoped/argument/nested/cyclic/unknown macros, wildcard provenance, disabled/unscheduled eligibility, duplicate export identities, partial resolution and multi-sourcetype flow conservation. Keep fixtures outside raw inputs. Run the build and relevant tests. Validate evidence completeness, distinct-content accounting, eligible filters, deterministic sorting, malformed/null identities and conservation per domain.

The report must distinguish observed-window coverage, no identified usage, disabled_only, excluded_only, mapped-but-not-observed sourcetypes and estate-level unresolved content. A graph is not proof that every ingest source is used, that all scheduled content is security relevant, or that configured searches ran successfully. Never assign an unresolved sourcetype status without evidence tying it to that dependency.

Finish with the documented command, actual counts, validation results and exact remaining evidence gaps. Do not stop simply because files exist. Where data is insufficient, give precise additional exports needed, but respect the decision to leave CIM resolution out of scope. Do not request generic CIM collection merely to make the diagram look complete.
```

## Prompt 3 — final audit and presentation fixes

```text
Audit the implemented Splunk security map against CLAUDE.md, the custom skill and docs/data_collection_guide.md. Trace a small varied sample of actual edges back to source SPL and macro chains. Check unresolved-only content survives in content.csv and the access-method diagram. Verify enabled/scheduled/exclusion filtering, no model/index inference, source identity deduplication, mapping provenance and per-domain Sankey flow conservation.

Inspect local HTML readability and self-contained operation using tools already available. Check source labels are escaped and no owner identities become visual nodes. Validate JSON syntax and the documented Splunk version target; do not claim a live Splunk test. Fix evidence-backed defects, rerun the necessary checks and update the report. Preserve raw inputs and user-authored mappings.

Report observed unique sourcetypes; those with identified eligible references; those without; disabled/excluded-only counts; eligible content with unresolved source dependencies; unmapped-domain content; and data-model access counts. Explain limits precisely. Provide the generated file locations and any concrete user validation still needed.
```

## Optional prompt — after manual domain review

```text
I have updated config/domain_mappings.csv and/or app_mappings.csv. Rebuild using the existing documented command. Validate exact-match keys and mapping conflicts; preserve original domains/apps and sourcetype-resolution evidence. Do not infer new source mappings. Regenerate affected diagrams/report and summarize the changes in effective grouping.
```

No further context questions are necessary to start. During collection, record your Splunk/ES versions, inventory window and visibility scope in the manifest; these resolve the remaining compatibility and observation assumptions.
