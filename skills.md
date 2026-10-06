---
name: splunk-security-map
description: Analyse exported Splunk configuration and inventory data to determine which ingested sourcetypes are used by enabled ES detections and scheduled searches, map sourcetypes to security domains and apps, identify unused or unresolved data sources, and build Sankey visualisations and Splunk Dashboard Studio outputs.
---

# Splunk Security Data Coverage Map

## Purpose

Use this skill to build a current-state, evidence-backed map showing how ingested Splunk data is used by security detections and scheduled searches.

The primary question is:

> Are we making use of all the data we ingest into Splunk for detections and continuing security use cases?

The primary unit of data is the Splunk `sourcetype`.

The principal visual relationship is:

    sourcetype -> security_domain -> app

The detailed underlying relationship is:

    sourcetype -> detection/search -> security_domain -> app

The repository contains exports from two types of Splunk Search Head:

- Enterprise Security (ES)
- Ad-hoc / non-ES

Combine both environments into a single canonical relationship dataset and ultimately a single primary Sankey diagram.

Claude Code has NO direct access to Splunk.

Do not attempt to connect to Splunk APIs, REST endpoints, search heads, MCP servers, or external services.

Work exclusively with files available inside the current project directory.

---

# Core analytical objective

Determine, for every observed sourcetype:

1. Is it currently ingested?
2. Is it referenced by an enabled ES detection?
3. Is it referenced by an enabled scheduled search on the ad-hoc Search Head?
4. Which security domain does that use represent?
5. Which Splunk app owns the detection/search?
6. Which detection/search establishes the relationship?
7. How is the data accessed by that search?
8. Can the relationship be demonstrated from available evidence?

The output must make it easy to identify:

- sourcetypes with detection/search coverage;
- sourcetypes with no identified security usage;
- sourcetypes used by multiple security domains;
- sourcetypes used by multiple apps;
- security domains dependent upon particular sourcetypes;
- apps dependent upon particular sourcetypes;
- searches whose data dependencies cannot be resolved;
- detections using direct event searches versus `tstats` or data models.

---

# Definition of coverage

A sourcetype is considered `covered` only when an evidence-backed relationship exists between that sourcetype and at least one:

- enabled ES detection; or
- enabled scheduled non-ES saved search.

Do NOT count the following as coverage by themselves:

- existence of the sourcetype;
- event volume;
- presence in an index;
- an unscheduled ad-hoc saved search;
- a dashboard that does not represent an included scheduled search;
- generic knowledge that a sourcetype normally supports a particular CIM data model;
- an inferred relationship without evidence from supplied files.

Disabled searches/detections may be analysed and retained in the canonical dataset, but they MUST NOT count as current coverage.

---

# Search Head scope

There are two sources of Splunk configuration data.

## ES Search Head

Analyse ES detections/correlation searches.

Include both enabled and disabled detections in the canonical dataset.

For current-state visualisations and coverage calculations:

    enabled only

Where available, use Splunk ES detection metadata for the security domain.

An explicit ES security-domain property is authoritative.

Do not replace an explicit ES security domain based on detection name or Claude's interpretation.

## Ad-hoc Search Head

The relevant content is:

    enabled scheduled saved searches

Unscheduled searches are not considered evidence of continued operational use for this exercise.

Retain them only if useful for diagnostics, but exclude them from coverage and primary visualisations.

Ad-hoc saved searches may not contain an authoritative security domain.

Do NOT automatically invent one.

Initially use:

    security_domain = unmapped

Potential future classification may use:

- search title;
- app;
- search description;
- naming conventions;
- manual mappings.

However, automatic semantic classification of an ad-hoc search title into a security domain is NOT part of the initial build.

Report useful recurring patterns in titles/apps that could support later classification.

---

# Raw inputs

Treat all files under the input/raw directory as immutable source evidence.

NEVER modify raw input files.

Expected logical inputs include:

    inputs/
      raw/
        es/
        adhoc/

Input files may include:

- saved searches;
- ES detections;
- sourcetype inventory;
- macros;
- data-model references;
- other Splunk configuration exports supplied by the user.

Do not fail simply because an optional input is absent.

Instead:

1. report the missing input;
2. explain which analysis is affected;
3. continue with analyses that remain possible.

---

# Preserve source environment

Every discovered relationship must preserve its origin.

Use a field such as:

    search_head

with values such as:

    ES
    ADHOC

Do not create separate final graphs for ES and ad-hoc unless useful for diagnostics.

The principal result combines both.

---

# Canonical relationship model

The canonical analytical product is:

    output/relationships.csv

The Sankey is derived from this dataset.

Do NOT treat the Sankey CSV as the canonical source.

Where available, `relationships.csv` should contain:

    search_head
    sourcetype
    index
    security_domain
    app
    content_name
    content_type
    enabled
    scheduled
    search_type
    dependency_type
    dependency
    resolution_method
    confidence
    evidence
    original_spl

Definitions:

## content_name

Name of the detection or saved search.

## content_type

Prefer controlled values:

    es_detection
    scheduled_search
    saved_search

## search_type

Classify how the search accesses data.

Prefer controlled values:

    event_search
    tstats_index
    tstats_datamodel
    datamodel
    macro
    mixed
    other
    unresolved

The classification must be based on SPL evidence.

### event_search

A conventional search directly querying events/indexes/sourcetypes without a principal `tstats` or data-model search.

### tstats_index

Uses `tstats` against indexes/indexed fields without relying on a data model.

### tstats_datamodel

Uses constructs such as:

    | tstats ... FROM datamodel=...

### datamodel

Uses a Splunk data model by a mechanism other than the above `tstats` classification.

### macro

The meaningful data access is hidden behind one or more macros and can only be understood by resolving them.

### mixed

The search materially combines more than one access method.

### unresolved

There is insufficient evidence to classify it.

Do not force ambiguous searches into a category.

---

# Dependency types

Prefer controlled values such as:

    direct_sourcetype
    macro
    index
    datamodel
    eventtype
    tag
    lookup
    unresolved

Multiple dependency records may exist for a single detection/search.

---

# Sourcetype extraction

Inspect the complete SPL for explicit sourcetype references.

Support common constructs including:

    sourcetype=foo

    sourcetype="foo"

    sourcetype='foo'

    sourcetype IN (foo, bar)

    sourcetype IN ("foo", "bar")

Handle reasonable whitespace and case variation.

Do not assume these examples are exhaustive.

Preserve wildcard sourcetypes rather than silently expanding them.

For example:

    sourcetype=aws:*

is evidence for:

    aws:*

It is NOT automatically evidence for every observed sourcetype beginning with `aws:`.

Wildcard expansion may be performed as a separate derived operation against the supplied observed-sourcetype inventory, but:

- record that expansion explicitly;
- retain the original wildcard expression as evidence;
- do not hide the fact that wildcard matching was used.

---

# Macro resolution

Resolve Splunk macros when macro definitions have been supplied.

Macro resolution MUST:

1. support nested macros;
2. recurse through nested definitions;
3. detect cycles;
4. stop at a maximum depth of 10;
5. preserve the resolution chain;
6. report unresolved macros.

Example:

    Detection
      -> `endpoint_base`
      -> `windows_base`
      -> sourcetype=XmlWinEventLog:Security

This creates an evidence-backed relationship to:

    XmlWinEventLog:Security

with:

    dependency_type = macro
    resolution_method = macro_expansion

Evidence should preserve a readable chain.

For example:

    detection -> endpoint_base -> windows_base -> XmlWinEventLog:Security

Never silently ignore a macro that cannot be resolved.

Write unresolved macro dependencies to:

    output/unresolved.csv

---

# Data models and CIM

DO NOT attempt to infer sourcetypes from CIM data models.

For example:

    FROM datamodel=Endpoint.Processes

does NOT provide sufficient evidence to assign:

    XmlWinEventLog:Security

or:

    Sysmon

or any other sourcetype.

Do not use generic Splunk/CIM knowledge to manufacture this relationship.

Instead preserve:

    dependency_type = datamodel

and the data-model/dataset name, such as:

    Endpoint.Processes

A detection using only a data model may therefore have no resolved sourcetype.

That is a valid analytical result.

It should appear in unresolved/dependency reporting rather than being guessed.

---

# Detection/search access-method analysis

Produce a separate analysis describing how included security content accesses data.

At minimum calculate counts and lists for:

    event_search
    tstats_index
    tstats_datamodel
    datamodel
    macro
    mixed
    unresolved

Where possible break this down by:

    search_head
    security_domain
    app

This is intended to support a separate visualisation showing the types of searches used across the detection estate.

Suggested conceptual diagram:

    search_type -> security_domain -> app

or:

    security_domain -> search_type -> app

Do not mix this second diagram's meaning into the primary sourcetype coverage Sankey.

---

# Security domains

For ES detections:

Use the explicit Splunk ES security-domain metadata where present.

For ad-hoc scheduled searches:

Default to:

    unmapped

unless an explicit supplied mapping exists.

Do not semantically classify titles without being asked.

However, analyse unmapped content names for obvious recurring patterns and report candidate groupings in the human-readable report.

Example:

If many unmapped searches contain consistent naming terms such as:

    Firewall
    Authentication
    Endpoint
    Proxy

report that observation.

Do not automatically turn those observations into mappings.

---

# Manual mappings

Manual mappings are permitted.

Look for configuration such as:

    config/manual_mappings.csv

Manual mappings must be clearly distinguished from discovered mappings.

Use:

    resolution_method = manual_mapping

Never overwrite or disguise the original discovered state.

Where possible preserve both:

    discovered_security_domain
    effective_security_domain

so that:

    discovered_security_domain = unmapped
    effective_security_domain = network

can be traced to a manual decision.

Manual mappings take precedence for presentation only when explicitly configured.

---

# Confidence and evidence

Every relationship must be explainable.

Prefer explicit resolution methods such as:

    direct_spl
    macro_expansion
    wildcard_match
    manual_mapping
    unresolved

Suggested confidence values:

    direct_spl       1.00
    macro_expansion  0.95
    wildcard_match   0.90
    manual_mapping   1.00

Do not assign high confidence merely because a relationship seems plausible.

Confidence describes confidence in the provenance/resolution, not the quality of the detection.

If a relationship cannot be supported:

    resolution_method = unresolved

Do not guess.

---

# Observed sourcetype inventory

Use supplied sourcetype inventory exports to determine which sourcetypes are currently observed.

The purpose is coverage, NOT volume analysis.

Event counts may exist in source data but must not drive the principal visualisation.

Classify observed sourcetypes into useful states such as:

    covered
    uncovered
    unresolved
    disabled_only

Suggested meanings:

## covered

At least one enabled included detection/search resolves to the sourcetype.

## uncovered

The sourcetype is observed but no included detection/search resolves to it.

## unresolved

Potential relevant searches exist but their dependency cannot currently be resolved to a sourcetype.

Do not claim that a specific sourcetype is unresolved unless evidence actually connects it to the unresolved dependency.

## disabled_only

The sourcetype is referenced by detections/searches, but only disabled or otherwise excluded content references it.

---

# Primary Sankey

Generate:

    output/sankey.csv

with exactly:

    source,target,value

The principal visual relationship is:

    sourcetype -> security_domain -> app

Prefix node names to avoid collisions:

    ST: <sourcetype>
    DOMAIN: <security_domain>
    APP: <app>

Example:

    ST: pan:traffic,DOMAIN: network,1
    DOMAIN: network,APP: SplunkEnterpriseSecuritySuite,1

The visualisation MUST use current enabled content only.

For ad-hoc Search Head content it MUST additionally be scheduled.

Disabled detections/searches must not contribute to the primary Sankey.

---

# Sankey weighting

The Sankey is about mappings, not event volume.

Do NOT use:

- event count;
- bytes;
- ingestion volume;
- EPS;
- licence consumption.

Use the number of distinct included detections/searches establishing each relationship.

For example:

If `pan:traffic` supports 12 enabled network detections:

    ST: pan:traffic -> DOMAIN: network

may have:

    value = 12

Ensure aggregation does not accidentally double-count a detection because it contains the same sourcetype multiple times or resolves through multiple equivalent dependency paths.

Deduplicate at an appropriate relationship/content level before aggregation.

---

# Important Sankey consistency rule

The Sankey should remain semantically interpretable.

Do not combine unrelated measures between stages.

For example, never create:

    2 billion events
        ->
    network
        ->
    30 detections

using the same flow.

The primary Sankey uses detection/search relationship counts throughout.

---

# Unmapped security domain

Ad-hoc searches with no assigned security domain may initially appear as:

    DOMAIN: unmapped

This is intentional.

Do not hide unmapped content merely to make the diagram cleaner.

It represents work required to improve classification.

---

# Coverage output

Generate:

    output/coverage.csv

Suggested fields:

    sourcetype
    coverage_status
    enabled_content_count
    disabled_content_count
    security_domains
    apps
    search_heads

This output should make the primary business question easy to answer:

> Which ingested sourcetypes have no identified ongoing security detection/search usage?

Produce a prominent list of uncovered sourcetypes.

Do not rank them by event volume unless explicitly requested.

---

# Unresolved output

Generate:

    output/unresolved.csv

Include unresolved items such as:

- unknown macros;
- data-model-only searches with no sourcetype evidence;
- ambiguous SPL constructs;
- parsing failures;
- unknown dependency mechanisms.

Suggested fields:

    search_head
    app
    content_name
    security_domain
    dependency_type
    dependency
    reason
    original_spl

Unresolved dependencies are a first-class analytical output.

Do not treat them as processing errors to hide.

---

# Nodes and edges

Where useful generate:

    output/nodes.csv
    output/edges.csv

These should support alternative graphing tools without requiring the entire analysis to be repeated.

Nodes may include:

    sourcetype
    detection
    security_domain
    app
    datamodel
    macro

Edges should preserve relationship type and provenance.

---

# Standalone visualisation

Generate a standalone interactive HTML Sankey when practical.

Suggested location:

    visualisations/sankey.html

The HTML should be self-contained where practical so it can be opened locally.

Primary hierarchy:

    sourcetype -> security_domain -> app

The purpose is current-state exploration and presentation.

Do not implement elaborate drill-down behaviour in the initial version.

Prioritise:

- readability;
- clear labels;
- useful hover information;
- sensible sizing;
- ability to identify uncovered areas from supporting outputs.

If the number of sourcetypes makes one diagram unreadable, do not silently discard nodes.

Instead consider:

- generating an all-data version;
- generating additional filtered views;
- documenting visualisation limitations.

---

# Splunk Dashboard Studio output

Generate supporting material for recreating the Sankey in Splunk Dashboard Studio.

Where practical produce:

    visualisations/splunk_dashboard.json

and/or:

    output/splunk_sankey.spl

The Splunk-native dataset required by the Sankey should ultimately contain:

    source
    target
    value

Prefer generating the relationship dataset in a way that can later be imported into Splunk as:

- a lookup;
- a KV-backed dataset if subsequently chosen;
- or regenerated using SPL.

The initial project is offline, so do not assume Claude can install or test the dashboard against Splunk.

Clearly identify any portions that require user validation in Splunk.

---

# Validation

Every build must validate the result before reporting completion.

At minimum report:

## Input statistics

- observed sourcetypes;
- ES detections;
- enabled ES detections;
- disabled ES detections;
- ad-hoc saved searches;
- enabled scheduled ad-hoc searches;
- macros available.

## Resolution statistics

- searches with direct sourcetype references;
- searches resolved through macros;
- searches using wildcard sourcetypes;
- searches using indexes only;
- searches using `tstats`;
- searches using data models;
- searches with unresolved dependencies.

## Coverage statistics

- observed sourcetypes covered;
- observed sourcetypes uncovered;
- sourcetypes referenced only by disabled content;
- mapped sourcetypes not present in observed inventory.

## Domain statistics

- mapped ES security domains;
- content with `security_domain=unmapped`;
- apps represented;
- candidate recurring title patterns among unmapped searches.

Write the human-readable result to:

    output/report.md

---

# Quality checks

Check for:

- duplicate relationships;
- empty sourcetypes;
- empty application names;
- contradictory enabled states;
- duplicate content caused by exports;
- macro recursion;
- malformed SPL;
- suspicious parser results;
- wildcard expansions;
- unresolved dependencies;
- content accidentally included despite being unscheduled;
- disabled content accidentally contributing to current-state coverage;
- the same detection being counted multiple times on one Sankey edge.

Do not claim success merely because output files exist.

---

# Evidence preservation

For every important derived relationship, preserve enough evidence to answer:

> Why does the analysis say this sourcetype supports this security domain/app?

The answer should ultimately be traceable to something such as:

    Detection X
      -> contains sourcetype=pan:traffic
      -> security_domain=network
      -> app=SplunkEnterpriseSecuritySuite

or:

    Detection Y
      -> calls `windows_security`
      -> macro expands to sourcetype=XmlWinEventLog:Security
      -> security_domain=endpoint
      -> app=CustomSecurity

This traceability is more important than maximising the number of resolved relationships.

---

# Do not infer from generic knowledge

Never create relationships because they are conventionally true in Splunk.

For example, do NOT reason:

    Endpoint.Processes usually contains Sysmon
    therefore
    Endpoint.Processes -> Sysmon sourcetype

Only use evidence supplied from this Splunk environment.

Likewise, do not assume:

- vendor sourcetypes;
- CIM mappings;
- app ownership;
- security domain;
- index membership.

Use source evidence or leave the relationship unresolved.

---

# Implementation

Claude may choose an appropriate implementation.

Python is preferred for parsing, normalisation, validation and graph generation unless another local approach has a clear advantage.

Do not over-engineer the solution.

This is initially a one-shot current-state assessment, not a production service.

Prioritise:

1. correctness;
2. provenance;
3. understandable code;
4. reproducible output;
5. useful reporting;
6. visual quality.

Avoid building unnecessary:

- databases;
- APIs;
- web services;
- schedulers;
- deployment systems.

CSV/JSON plus local Python processing is sufficient unless the available data demonstrates otherwise.

---

# Working approach

When starting the task:

1. Inspect the files actually available.
2. Report which expected inputs are present.
3. Inspect their schemas.
4. Do not assume column names before inspecting them.
5. Reconcile actual exports with the logical model in this skill.
6. Build the parser and normalisation process.
7. Run it against the complete supplied dataset.
8. Inspect unresolved results.
9. Improve resolution where evidence permits.
10. Build canonical relationships.
11. Validate coverage.
12. Generate Sankey data.
13. Generate the standalone visualisation.
14. Generate Splunk Dashboard Studio supporting output.
15. Produce the final report.

If additional Splunk information would materially improve resolution, do NOT invent it.

Instead write a precise request into:

    output/additional_splunk_data_needed.md

For every request specify:

- what information is missing;
- why it is needed;
- which unresolved relationships it affects;
- the SPL the user should run, if known;
- expected output columns;
- suggested output filename.

This allows the user to return to Splunk, run the search manually, and provide the resulting file.

---

# Interaction with the user

When source data is insufficient, be specific.

Prefer:

    "17 enabled detections use data models but contain no explicit
    sourcetype and cannot currently be mapped to sourcetypes."

over:

    "More data may be needed."

When requesting another export, provide runnable SPL wherever possible.

Do not ask the user to manually inspect individual searches if the same information can reasonably be obtained with one Splunk export.

---

# Success criteria

The task is successful when the project can provide an evidence-backed answer to:

> Of the sourcetypes currently ingested, which are being used by ongoing
> security detections/searches, in which security domains, and by which
> Splunk applications?

and produces at least:

    output/relationships.csv
    output/coverage.csv
    output/sankey.csv
    output/unresolved.csv
    output/report.md
    visualisations/sankey.html

plus Splunk Dashboard Studio supporting material where feasible.

The analysis must explicitly expose uncertainty and unresolved relationships.

A visually complete Sankey built using guessed relationships is considered a failure.

An incomplete Sankey accompanied by an accurate unresolved analysis is considered a valid intermediate result.
