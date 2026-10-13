# Detection module: Splunk SPL

Static analysis of a Splunk SPL detection into the detection profile
defined in "Detection profile contract" (`../method.md`). The
analysis is performed on the rule TEXT alone -- no Splunk instance is
required. The profile carries only NATIVE event paths; every
Splunk-layer name (CIM, datamodel, TA-extracted) must be mapped before
it lands in the profile.

## 1. Recognizing SPL

Treat the rule as SPL when it shows any of:

- a leading bare-term search fragment with `index=`, `sourcetype=`,
  `source=`, or `EventCode=` style key=value filters;
- a pipeline of `|`-separated commands (`stats`, `eval`, `where`,
  `rename`, `table`, `bin`, `dedup`, ...);
- `| tstats ... from datamodel=<Model>.<Object>` or
  `| datamodel <Model> <Object> search`;
- backtick macro invocations (`` `some_macro` ``,
  `` `rule_name_filter` ``);
- Splunk time modifiers (`earliest=`, `latest=`, `span=`).

Result: `siem: splunk` in the profile. The inferred SIEM is always
user-confirmed -- the method's Profile step owns that confirmation; do
not skip it.

## 2. Filters -> load_bearing_fields

Read, in order: the base search terms (everything before the first
`|`), every `| search` and `| where` clause, and any `| eval` whose
result gates a later filter. Each field compared against a concrete
value or pattern is load-bearing; record the field and the matched
value(s).

Skip as NOT load-bearing:

- `index=`, `sourcetype=`, `source=` -- routing/ingest plumbing, not
  event content. They still inform surface identification (e.g.
  `XmlWinEventLog` points at `windows.wineventlog@v1`).
- time modifiers (`earliest=`, `latest=`) -- they feed `time_window`
  (section 3), not `load_bearing_fields`.
- trailing `` `<rule_name>_filter` `` macros -- conventionally empty
  per-site tuning hooks. Note their presence and move on.
- any other macro whose body the rule text does not show: do NOT guess
  what it filters. Record it in the profile as an unresolved input and
  tell the user (section 5).

Value patterns map to profile values directly: an exact comparison
becomes one `path`/`value` entry; `IN(...)`, `OR` lists, and wildcard
matches become the value set or glob the categorization step matches
against (and the glob tokens the fidelity check consumes).

### Naming layers

SPL field names come from one of three layers; all three must be
mapped to native paths before entering the profile:

1. **Add-on-extracted names** -- for `XmlWinEventLog`, Splunk extracts
   each `EventData` `Data[@Name]` pair under its XML name
   (`TargetUserName`, `IpAddress`); classic text WinEventLog uses
   underscored variants (`Logon_Type`). For CloudTrail JSON, extracted
   names largely equal the native JSON paths (`eventName`,
   `errorCode`, `requestParameters.keyId`).
2. **CIM names** -- normalized aliases (`user`, `src`, `dest`,
   `signature_id`) layered on top by the Splunk add-on.
3. **Datamodel names** -- `Model.field` forms in tstats rules
   (`Processes.process_name`, `Authentication.user`); after a
   prefix-stripping rename (e.g. a `drop_dm_object_name`-style macro)
   they appear bare.

Native-path notation: CloudTrail uses JSON dot-paths (`eventName`,
`userIdentity.arn`); WinEventLog/Sysmon XML uses the master dot-path
form where the `EventData` name/value list flattens to
`EventData.<Name>` and the envelope is `System.<Field>` -- the same
notation the fidelity comparison's load-bearing tokens use
(`../method.md`, Fidelity step).

### Mapping table: AWS CloudTrail (`aws.cloudtrail@v1`)

| Rule-layer name (CIM / add-on / datamodel) | Native CloudTrail path |
|---|---|
| `eventName`, `signature` | `eventName` |
| `eventSource` | `eventSource` |
| `errorCode`, `error_code` | `errorCode` |
| `src`, `src_ip`, `sourceIPAddress` | `sourceIPAddress` |
| `user`, `user_name` | `userIdentity.userName` (IAM user; for assumed roles the name rides in `userIdentity.arn`) |
| `user_arn` | `userIdentity.arn` |
| `user_type` | `userIdentity.type` |
| `aws_account_id`, `vendor_account` | `recipientAccountId` (actor side: `userIdentity.accountId`) |
| `region`, `vendor_region` | `awsRegion` |
| `user_agent`, `userAgent`, `http_user_agent` | `userAgent` |
| `requestParameters.<p>` / `responseElements.<p>` | same path, natively nested |

### Mapping table: Windows WinEventLog / Sysmon (`windows.wineventlog@v1`)

| Rule-layer name (CIM / add-on / datamodel) | Native path |
|---|---|
| `EventCode`, `signature_id` | `System.EventID` |
| `Computer`, `ComputerName`, `dest` | `System.Computer` |
| `user`, `Authentication.user`, `TargetUserName` | `EventData.TargetUserName` |
| `src`, `src_nt_host` (logon events, e.g. 4625) | `EventData.WorkstationName` (the Splunk add-on aliases `src` from `WorkstationName`) |
| `src_ip`, `IpAddress` | `EventData.IpAddress` |
| `Status` / `SubStatus` (logon failure codes) | `EventData.Status` / `EventData.SubStatus` |
| `Logon_Type`, `LogonType` | `EventData.LogonType` |
| `Processes.process`, `CommandLine` (Sysmon EID 1) | `EventData.CommandLine` |
| `Processes.process_name`, `Image` (Sysmon EID 1) | `EventData.Image` (`process_name` is the basename of `Image`) |
| `Processes.parent_process_name`, `ParentImage` | `EventData.ParentImage` |
| `SourceImage` / `TargetImage` / `GrantedAccess` / `CallTrace` (Sysmon EID 10) | `EventData.<same name>` |

### Mapping table: Microsoft Entra ID / Azure AD Monitor (`azure.monitor.aad@v1`)

The Splunk Add-on for Microsoft Cloud Services extracts the nested
camelCase `properties.*` fields (raw rules often `rename properties.* as *`
first, so `properties.status.errorCode` reads as `status.errorCode`) and
applies the CIM Authentication aliases below. Map each rule-layer name to
its native camelCase path under `properties` (or the diagnostic envelope).

| Rule-layer name (CIM / add-on / native) | Native Azure Monitor path |
|---|---|
| `category` | `category` (envelope; e.g. `SignInLogs`) |
| `src`, `src_ip` | `properties.ipAddress` (envelope copy: `callerIpAddress`) |
| `user`, `Authentication.user` | `properties.userPrincipalName` |
| `user_id` | `properties.userId` |
| `app`, `dest` | `properties.appDisplayName` |
| `signature`, `signature_id`, `resultType` | `properties.resultType` (also `properties.status.errorCode`; `0` = success, e.g. `50126` = invalid credentials) |
| `status.errorCode` (post `rename properties.* as *`) | `properties.status.errorCode` |
| `authenticationDetails{}.succeeded` | `properties.authenticationDetails[].succeeded` (`{}` is Splunk array notation; `false` on a failed step) |
| `action` | derived: `success` when `properties.resultType` == `0`, else `failure` |
| `user_agent` | `properties.userAgent` (when present) |
| `vendor_account` | `tenantId` (the add-on aliases the tenant) |
| `vendor_product` | constant `Azure AD` (add-on eval; not an event field) |

### Mapping table: Amazon Security Lake CloudTrail (`aws.asl@v1`)

Amazon Security Lake normalizes CloudTrail management events to OCSF
API Activity (class_uid 6003); Splunk extracts the dotted OCSF paths
via default JSON key-value extraction, with no TA add-on CIM layer
sitting between the native event and the rule. The stock ASL
detection's own `stats ... BY` clause renames the native paths it
groups on to CIM-style short names inline.

| Rule-layer name (CIM / add-on / native) | Native ASL (OCSF) path |
|---|---|
| `user` | `actor.user.uid` |
| `action` | `api.operation` |
| `src` | `src_endpoint.ip` |
| `dest` | `api.service.name` |
| `vendor_account` | `actor.user.account.uid` |
| `vendor_product` | `cloud.provider` |
| `vendor_region` | `cloud.region` |
| `user_agent` | `http_request.user_agent` |

For a field outside these tables, derive the native path from the
master sample (the extracted per-group sample shows the real shape)
and the add-on's extraction rule above; if the mapping is still ambiguous,
ask the user rather than guessing.

## 3. Aggregation -> group_by / threshold / time_window

**group_by.** The by-clause of the FINAL aggregating command
(`stats`, `tstats`, `chart`, `timechart`; `transaction` fields count
too) is the group-by tuple. Project each field through any later
`rename` (`A AS B` reverses to A), strip datamodel prefixes
introduced by tstats once a prefix-strip rename runs, then map to
native paths. `_time` in a by-clause is time bucketing, not a group
member -- it pairs with `bin`/`span=` and feeds `time_window`.

**threshold.** A post-aggregation `| where` on an aggregate value is
the volumetric predicate: `where count > 9`, `where count >= 10`,
`where dc(user) > 30`. Preserve the operator exactly -- `> 9` and
`>= 10` admit different minimum volumes, and the method's Job step
sizes the job `loop:` from this predicate. Resolve aliases back to
their definition (`as unique_accounts` -> the `dc(...)` it names) and map
the inner field to its native path.

**time_window.** In priority order: an explicit `span=` on
`bin`/`timechart`; `earliest=`/`latest=` bounds in the base search or
tstats `where` clause (window = latest - earliest); otherwise omit
and note that the window is the savedsearch's dispatch window, which
the rule text does not show.

**Eval-synthesized group keys.** For
`| eval key=user.":".src | stats count by key`, the synthesized key
is not a native field; the group-by tuple is the constituent fields
(`user`, `src` -> their native paths). Record the constituents in
`group_by` and note the synthesis in the profile so job bindings pin
each constituent.

## 4. Optional group-by cross-check (parser reduction)

When the group-by tuple is hard to read statically -- long rename
chains, macro-heavy pipelines -- and a Splunk instance is reachable,
cross-check your reading with the group-by reduction. Your surface
layer names the concrete tool; this section defines the operation.

Input: the JSON Splunk returns for the SPL from its
`/services/search/parser` REST endpoint (submit the SPL as the `q`
parameter of a POST; current Splunk versions reject GET there).
Fetching it needs an authenticated management-port connection, but
no indexed data.

Reduction (walks the parsed commands in order):

- Each aggregating command (`stats`, `chart`, `timechart`, `tstats`)
  replaces the tuple with its by-clause; `transaction` replaces it
  with its field arguments (options such as `maxspan=` or
  `keepevicted` are not fields).
- A later `rename A AS B` projects the tuple forward: the output
  carries the post-rename name `B` (reverse it per section 3 before
  mapping to a native path).
- A post-aggregation `lookup` adds a warning: the tuple usually
  survives into result rows, but verify.
- A post-aggregation `fields - <f>` that removes a tuple member adds a
  warning naming the dropped field(s): they will not appear in result
  rows.
- `_time` is reported if it is in the by-clause; it is still time
  bucketing, not a group member (section 3).

Output: the group-by field names plus the warnings. Typed refusals:

- **count-only** -- an aggregation with no by-clause (`stats count`);
  there is no group-by tuple to record.
- **no aggregation** -- no aggregating command at all; the rule is
  per-event, so the profile has no `group_by`.
- **malformed parser JSON** -- the input is not a parser response
  (often an auth or HTTP error body); fix the fetch, not the rule.

Field names come back in the RULE's naming layer -- map them to native
paths (section 2) before they enter the profile. With no Splunk
access, static reading per sections 2-3 is the only path, which is
fine.

Disagreement between your reading and the reduction is a
stop-and-ask: present both tuples to the user.

## 5. Non-goals

Explicitly out of scope for this module:

- **Correlation-mode classification** -- how any platform validates or
  correlates fired alerts back to delivered events is platform
  plumbing, not rule analysis; no such classification is produced.
- **Datamodel acceleration requirements** -- whether a tstats rule
  needs an accelerated datamodel is a deployment concern; the profile
  records only the fields and semantics.
- **Macro expansion beyond the rule text** -- if a macro body is not
  visible in the supplied text, record the macro name in the profile
  as an unresolved input and tell the user; never invent its
  contents.
- **Savedsearch installation** or any other SIEM configuration
  (the method's "Scope and inputs" applies).

## 6. Worked example

SPL (generic failed-logon spray over WinEventLog 4625):

```text
sourcetype=XmlWinEventLog source="XmlWinEventLog:Security" EventCode=4625 LogonType=3
| bin _time span=10m
| stats dc(TargetUserName) as unique_accounts, count by IpAddress, _time
| where unique_accounts > 30
```

Reading: `sourcetype`/`source` are routing (surface =
`windows.wineventlog@v1`, Security channel). `EventCode=4625` and
`LogonType=3` are filters -> load-bearing with values. The stats
by-clause is `IpAddress, _time`; `_time` is the `span=10m` bucket ->
`time_window`, leaving `IpAddress` as the group key. The threshold
alias `unique_accounts` resolves to `dc(TargetUserName)`; operator `>`
preserved. `TargetUserName` carries no fixed value -- it lives in the
threshold predicate (and must VARY across the burst), not in
`load_bearing_fields`.

Resulting profile:

```yaml
siem: splunk                  # user-confirmed (method Profile step)
load_bearing_fields:
  - path: System.EventID
    value: "4625"
  - path: EventData.LogonType
    value: "3"
group_by: [EventData.IpAddress]
threshold: "dc(EventData.TargetUserName) > 30"
time_window: 10m
```

Downstream (per the method's Author scenarios and Job steps): the
scenario hardcodes the two load-bearing values and models ONE 4625; the job loops it with
margin above 30 distinct `EventData.TargetUserName` values while
binding `EventData.IpAddress`'s backing state through job state so
the burst collapses into one group.
