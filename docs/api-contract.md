# Microsegmentation API v1

This is the current 0.10 source API contract. Dated release records and illustrated PDFs describe their own snapshots; older release evidence does not validate changed code.

## GUI-first setup and endpoint kits

- Super Admin GET `/api/v1/platform/setup` returns installed capability, manager
  revision/configuration digest, public provider/runtime values and the current
  private-owner review summary. It never returns a client secret. A joined
  profile/provider mismatch disables this editor before mutation.
- POST `/api/v1/platform/setup/preview` accepts `expected_revision`,
  `expected_config_digest`, a fixed `environment` string mapping (the four
  `SEG_ENTRA_*`/bootstrap identity public fields and HTTP/pool and separate control/discovery listener values), plus
  a separate initial `client_secret`. Arbitrary environment variables are rejected.
  Initial Entra setup uses verified candidate login. Provider/secret changes use the supervised same-Super-Admin transition, current provider epoch, all-node readiness and retained rollback context; they do not silently swap a running tenant.
- POST `/api/v1/platform/setup/login` with `{preview_id}` requires the current
  setup Super Admin. It returns `{location}` and a Secure/HttpOnly OIDC state
  cookie. The existing `/api/v1/auth/callback` verifies purpose-scoped state,
  PKCE, signature, tenant/nonce and the exact initial Super Admin Object ID.
  Candidate verification creates no users or application sessions and preserves
  the running provider. It returns to `/settings?setup=verified` without credentials.
- POST `/api/v1/platform/setup/apply` accepts the exact review ID, digest, nonce
  and typed phrase. Initial Entra activation requires verified candidate login;
  runtime-only changes do not. It queues a fixed local manager action. Success
  and verified rollback require matching binding receipts; stale/replayed payloads
  do not change the deployment. All setup mutations require installed HTTPS.
- Admin/Super Admin POST `/api/v1/agent-installation/kit` accepts Linux `family`
  (`rhel`/`ubuntu`), `architecture` (`amd64`/`arm64`), optional exact hostname,
  HTTPS controller origin, polling intervals and optional public HTTPS CA PEM.
  CA/path/SAN validation completes before minting one 15-minute single-use token.
  The no-store JSON attachment contains only schema version/timestamps, expected
  hostname, canonical monitor-only config, public CA PEM and enrollment token.
  No endpoint private key, controller signing key or executable code is included.
- Admin/Super Admin GET `/api/v1/agent-installation/fleet-profiles` lists public
  profile IDs, names, creators, expiry/status and enrollment counts, using
  `limit` (1–200, default 50) and `offset`. No shared secret is returned.
- POST the same route accepts common kit fields plus `name` and integer
  `validity_hours` (1–720, default 24), without a hostname. It returns
  `{profile,kit}` with no-store handling. The schema-2 kit adds
  `enrollment_profile_id`, uses a 64-character URL-safe shared credential and
  contains canonical monitor-only configuration/public trust. Reuse this exact
  kit across hosts; each host creates its own CSR/key/certificate automatically.
  Public trust must cover its selected lifetime. No fixed host-count limit applies.
- POST `/api/v1/agent-installation/fleet-profiles/{id}/revoke` with `{}` disables
  future enrollment and bootstrap replay. Existing enrolled mTLS identities
  remain separate and active. Individual certificate revocation is a different
  operation. Profile creation/revocation require current Admin authority and
  existing same-origin/CSRF checks, with safe audit metadata.

Fleet bootstrap uses the existing Discovery-channel `POST /api/v1/agent/enroll`
wire shape `{token,hostname,csr}`. The current profile is checked before any
new enrollment or retry. Separate durable canonical-public-key receipts bind
profile, hostname, server identity and issued certificate; changing CSR bytes
cannot mint another identity from the same key. Expiry, profile revocation,
retirement and certificate-registry revocation are rechecked. The shared secret
is stored hashed only, with no shared endpoint private key. Recovery discards
fleet bootstrap authority while retaining consumed key receipts.

The helper consumes the kit through the signed family installer's `--setup-file`
option. Tags/DC remain controller-managed. Central polling can override kit
intervals. See [the pilot workflow](pilot-gui-installation.md).

All timestamps RFC3339 UTC. IDs strings. Browser APIs use JSON and `/api/v1`, except the SAML form-POST callback and XML metadata download. Local `--demo` mode has explicit synthetic data and no authentication; production mode requires TLS and authenticated application access. Local and SSO role authority is application-owned: `read_only`, `admin`, `super_admin`. No automatic UFW changes.

## Authentication and application-user authority

- GET `/api/v1/auth/config` is public. Current installed modes are `local` and `hybrid`; explicit legacy integrations may retain `entra`/`tokens`, and the synthetic preview uses `demo`. Status includes `local_enabled`, configured `providers`, nested `entra`/`saml`, password length bounds, the same three roles and session duration, without credentials or raw IdP metadata.
- POST `/api/v1/auth/local` `{username,password}` requires HTTPS and same-origin handling. Fresh empty installations seed `admin`/`admin` once as Super Admin. The returned cookie and auth summary have `password_change_required:true`; only auth status, own password change and logout are admitted until replacement. Existing account databases never receive a new default password on upgrade/restart.
- POST `/api/v1/auth/password` `{current_password,new_password,confirm_password}` is available to every local role, including change-only and Read Only sessions. It requires CSRF, rotates the cookie, revokes old sessions and returns the new auth summary. SSO passwords remain IdP-managed.
- GET `/api/v1/auth/login` begins HTTPS-only Entra authorization code + PKCE sign-in. GET `/api/v1/auth/callback` validates one-use state/browser binding/nonce and verified tenant identity, then issues a Secure HttpOnly SameSite=Lax session cookie. Only preprovisioned enabled `tid:oid` records may enter, except the explicitly configured initial Super Admin while no Entra access records exist; local/SAML users do not block that reviewed bootstrap.
- GET `/api/v1/auth` returns `{role,demo,user,auth_type,auth_provider,csrf_token,password_change_required}`. Session mutations require `X-CSRF-Token` and valid same-origin handling. POST `/api/v1/auth/logout` `{}` revokes the application session; it does not sign out globally at the IdP.
- GET/POST `/api/v1/access/users` and PATCH `/api/v1/access/users/{URL-encoded-id}` are **super_admin only**. Creation selects `provider:local|entra|saml` with `username,password`, `object_id`, or exact SAML `subject` respectively, plus role and optional display_name/email/enabled. Updates accept only role/enabled/display_name/email. Local users start with mandatory password replacement. POST `.../{id}/reset-password` `{password,confirm_password}` resets another local account, revokes sessions and requires replacement. POST `.../{id}/revoke-sessions` `{}` revokes sessions for any provider. Neither operation creates or changes a directory account.
- GET `/api/v1/auth/providers` is Super Admin-only and includes the SAML revision. PUT `/api/v1/auth/providers/saml` `{expected_revision,enabled,sp_entity_id,origin,idp_metadata_xml,display_name}` validates uploaded public metadata and publishes shared database configuration. A blank metadata field retains existing metadata. Missing/noninteger revision is 400; stale revision is 409. Saving retires SAML sessions/states and advances the authority epoch; Local/Entra sessions remain independent. A SAML caller receives `signed_out:true` after its own provider change.
- GET `/api/v1/auth/saml/login` starts SP-initiated sign-in; GET `/api/v1/auth/saml/metadata` serves public XML. POST `/api/v1/auth/saml/callback` accepts only bounded form-urlencoded `SAMLResponse` and `RelayState`. Signed response **and** assertion, exact issuer/audience/destination/recipient/request, bounded validity, browser binding, current epoch and replay checks precede session creation. Its browser state cookie alone uses SameSite=None; application sessions remain SameSite=Lax. Roles come only from the exact provisioned persistent NameID, with no email/group/JIT grants.
- Admin and Read Only cannot create any user, assign any role or promote themselves. Read Only cannot mutate infrastructure. Admin and Super Admin may manage infrastructure. Self role/disable changes by a Super Admin and loss of the last enabled Super Admin are rejected. Role/enablement changes revoke affected local sessions immediately.
- Configured SSO disables legacy bearer compatibility, including when the SAML provider is temporarily unavailable. Full sessions last at most eight hours; change-only local sessions last ten minutes and SAML sessions additionally honor IdP expiry. Entra-side status/Conditional Access changes apply at the next sign-in (no CAE). See [configuration and boundaries](authentication.md).

## Direct Admin authority and endpoint configuration

Normal policy POST/PUT and authorized server/group/tag changes publish affected exact intent directly for ordinary per-port hosts. On an existing whole-server default-deny host, a changed deny-bearing bundle remains pending until its dedicated exact review and manual downtime acknowledgement. Read Only cannot mutate; Admin manages business metadata and policies; Super Admin additionally manages users and privileged platform settings. There is no selectable approval mode or different-person requirement. Deny/restrictive imported changes, restrictive learned changes/removal and destructive recovery retain their same-actor explicit confirmations.

Admin POST `/agent-installation/configuration/preview` freezes the selected endpoint, exact current configuration digest, URLs, management sources/SSH ports, explicit security opt-ins and optional public HTTPS CA. The opt-ins are `enforce`, `allow_firewall_changes`, `learning_auto_allow`, `unexpected_port_monitor_enabled` and the optional `allow_host_default_deny`. The last flag defaults to false when omitted; true requires a compatible endpoint and managed enforcement, with automatic learned access disabled. It returns an Admin-authorized signed-kit review without a submit/checker cycle. POST `.../{id}/kit` downloads the private no-store signed configuration kit; local root must apply it with the verified family installer. This does not silently enable any endpoint opt-in. Existing identity/issuer/signing trust, endpoint binding, health witness, rollback and result checks remain mandatory. `/platform/approval-settings` compatibility reads do not represent a configurable product mode; current GUI has no approval-mode tab.

## Whole-server inbound default deny

This optional feature starts disabled. Ordinary policy saves cannot enable it, and the generic rollout API cannot substitute for its downtime acknowledgement. Read Only may inspect its status/reviews and use the read-query POST; preview and confirm require a current authorized Admin or Super Admin. Browser POSTs retain CSRF and same-origin checks.

- GET `/api/v1/host-default-deny?limit=50&offset=0&server_id=optional&search=optional` returns `{items,total,limit,offset,has_more}`. POST `/api/v1/host-default-deny/query` accepts `{limit,offset,server_ids,search}` for a complete selected endpoint scope. Limits are 1..500, scope at most 20,000 IDs and search at most 200 characters. Omit `server_ids` for all hosts; `[]` explicitly selects none. Status uses scalar SQL projections rather than decoding fleet source matrices.
- Each status item includes `{server_id,hostname,desired_enabled,active,removal_pending,revision,rollout_id,status,desired_version,applied_version,allowed_service_count,protected_ssh_ports,capable,local_optin,blockers,last_good_version,active_verified,last_outcome}`. States include `not_enabled`, `review_required`, `pending`, `enforced`, `removal_pending`, `disabled`, `rolled_back` and `error`. `not_enabled` makes no verified-removal claim. `active` and `active_verified` describe the last authenticated known state, not a live kernel probe. `last_outcome` includes `{status,rollout_id,version,updated_at,error,rollback_reason,last_good_version,last_good_digest,is_current}`; a prior receipt is not the outcome of a newly queued push.
- POST `/api/v1/host-default-deny/preview` takes `{action:"enable"|"disable",server_ids:[],group_ids:[]}`. At least one explicit server or saved group must resolve to existing endpoints. It returns `{id,revision,digest,plan_digest,confirmation_nonce,action,server_ids,group_ids,preview:{targets:[]},can_apply,blockers,status,created_at,expires_at,approval}`. GET `/api/v1/host-default-deny/{id}` retrieves that exact review. Selection freezes current membership; future group members are not enabled automatically. Reviews expire after ten minutes and are bounded to 8 MiB; an oversized scope must be split, never truncated.
- Each review target contains `{server_id,hostname,revision,base_version,version,digest,ips,services,protection,configuration_digest,blockers}`. `services` contains the exact effective **enforce** grants; monitor rows do not authorize access. `base_version` is the currently compiled version and `version` the proposed version. Protection includes the reported `host_default_deny_context_digest` and `host_default_deny_control_profile`. Recently received authenticated snapshots are not live probes; the endpoint rechecks the native context before mutation.
- POST `/api/v1/host-default-deny/{id}/confirm` takes exactly `{digest,expected_revision:review.revision,confirmation_nonce,acknowledge_downtime:true}`. The GUI checkbox begins unchecked and must be manually ticked for this push. Omitted, false or string values cannot acknowledge downtime. The same current Admin confirms; no second person or extra typed phrase is required. Revision, full frozen membership, policy matrix, protected context and configuration are rechecked atomically. An identical retry of an already queued request may return `duplicate:true` without publishing a second push; it cannot authorize changed intent.

Enable requires `host_default_deny_v1`, `signed_assignments_v1`, an authenticated configuration receipt with local `allow_host_default_deny:true`, ready protected management paths and a supported network context. Active automatic learning or remaining learning-owned grants block enable. Observational learning may continue. Imported-rule and learned-access mutations are held while the fallback or its removal remains active.

The candidate is host INPUT enforcement for **new inbound connections**, with an owned final IPv4/IPv6 **REJECT**, not DROP. Approved enforce grants and `host-inbound-control-v1` exceptions remain ahead of it: source-restricted actual SSH ports, ICMP/ICMPv6 and DHCP-client UDP 68/546; base loopback and established/related handling is preserved. Existing sessions are not flushed. Egress, container/forwarding traffic and unsupported NAT/routing/foreign-rule/zone contexts are outside this feature or block admission.

Disable uses the same exact review and manual acknowledgement. It removes only the owned global fallback and retains the last authenticated applied ordinary grant matrix; pending edits are not applied as part of removal. This path remains available after the local opt-in is turned off. Normal compilation resumes only after a matching successful removal receipt. Remaining owned ordinary controls may require the separate explicit cleanup workflow.

Agent assignments bind `host_default_deny:true` into the effective policy digest and carry enforcement intent `enforce_host_default_deny` or `remove_host_default_deny`, `host_default_deny_ack:true`, `host_default_deny_revision` and `host_default_deny_configuration_digest`. The signed Admin proof identifies `kind:"host_default_deny"` and exact `action`. The fresh nonce-bound health witness repeats the host acknowledgement/configuration binding. A queued review, compiled version or cached status alone cannot establish kernel application. See [the operator workflow](whole-server-default-deny.md).

## Dashboard APIs
- GET `/api/v1/firewall` returns `{servers:[{server_id,hostname,snapshot}],common_rules:[],changes:[]}`; optional endpoint scope is supported. Rules have exact fingerprints/logical keys, zone, kind, value, action/risk, runtime/permanent host counts, editability/reason and observed service-port definitions.
- POST `/api/v1/firewall/changes` (admin/super_admin) `{name,server_ids,rule_key,operation:"replace"|"remove",new_value?,scopes:["runtime","permanent"]}` creates an immutable draft with before/after preview, target/snapshot digests, confirmation nonce and challenge. No endpoint work is delivered yet.
- POST `/api/v1/firewall/changes/{id}/confirm` `{confirmation_nonce,challenge?}` queues a normal supported change with one authorized Admin action. Deny/restrictive changes require two explicit confirmations by the same current actor; the final step uses its rotated nonce and exact typed challenge. Consumed nonces cannot advance twice. Snapshot/target drift, expiry or revoked authority invalidates review. History and POST `.../{id}/cancel` remain available.
- GET `/api/v1/overview`: `{servers:[], policies:[], learning_policies:[], service_groups:[], learning_sessions:[], learning_session_pagination:{total,active_total,limit,offset,has_more}, alerts:[], flows:[], stats:{}, meta:{demo:bool,version:"0.9.0",traffic_retention_hours:24}}`. The version identifies the installed release and can advance in a patch. `policies` contains normal managed intent; `learning_policies` contains separate exact additive allowances and pending cleanup. `flows` default last 1h, bounded 500 aggregate rows; collection windows shown. Learning sessions are the first six compact navigation records, not canonical authority/discovery documents; `stats.active_learning` counts all active sessions, not just that page.
- GET `/api/v1/servers` -> `{items:[]}`; GET `/api/v1/servers/{id}` -> server detail plus bounded compiled **intent** (not an agent assignment or live authorization), and the first six server-scoped learning summaries with `learning_session_pagination`. Internal signed agent assignments retain their separate endpoint-authenticated contract.
- PATCH `/api/v1/servers/{id}` supports centrally managed metadata and `expected_services:[{port:80,protocol:"tcp"}]` (admin/super_admin). See classification APIs below.
- GET `/api/v1/policies?limit=20&offset=0&mode=optional&search=optional` and `/api/v1/learning-policies?limit=20&offset=0&server_id=optional&session_id=optional&status=optional&search=optional` return bounded navigation `{items,total,limit,offset,next_offset,has_more,summary_only:true,scope_digest,filters,byte_limited}`. Limits are 1..100. Overview supplies the same first-page summaries plus `policy_pagination` and `learning_policy_pagination`; `stats.policy_count` is the full managed-policy count. Services expose exact port identity, frozen service-group ports, selectors/groups and literal `source_count`, with `sources_omitted:true`; CIDR arrays never appear in catalogue summaries. Counts refer to literal entries, not unique clients or resolved selector membership. A cumulative 8 MiB summary budget may shorten a page: follow `next_offset` (actual rows returned), never infer the next offset from requested `limit`.
- POST `/api/v1/policies/query` and `/api/v1/learning-policies/query` accept `{server_ids:null|[endpointIDs],search_server_ids:[endpointIDs],ports:["8443/tcp"],search:"billing",limit:20,offset:0}` plus the catalogue-specific scalar filters above. These are Read Only-accessible read queries, with existing session CSRF and same-origin checks retained. The dashboard derives complete endpoint scope IDs using its existing application/DC/location/group/custom-tag/health filters, ignoring ports until the policy service check; `null` means no metadata scope, while `[]` means no matching endpoints. Source search for learned policies is performed in the database. Ordinary policy search matches the name or matching target metadata. Fixed port predicates and compact target headers apply these combinations **before pagination**, with exact filtered totals; source matrices are not loaded to filter the list. At most 20,000 IDs in each scope, 100 port selections, 256 search characters; unsupported keys/catalogue filters are rejected.
- GET `/api/v1/policies/{id}` and `/api/v1/learning-policies/{id}` return the complete exact selected canonical policy after an 8 MiB stored-byte check, under one read snapshot. Editors/removal reviews must fetch this detail first; summary-only/omitted-source bodies are rejected, never interpreted as empty sources. POST `/policies` creates canonical intent; ordinary PUT/DELETE `/policies/{id}` accept optional `expected_revision` (DELETE body contains only this field), checked atomically before mutation. A changed revision returns 409. New managed and learned policy writes are fenced by their normalized storage bytes, including group snapshot expansion, so valid accepted writes remain retrievable by exact detail. Group expansion failures roll back the whole group/policy/history transaction.
- Policy input: `{name,selector:{application:"billing"},group_ids:[],mode:"monitor"|"enforce",services:[{service_group_id:"saved-service-guid",sources:["10.0.0.0/24"],source_selector:{role:"load-balancer",environment:"prod"},source_group_ids:["saved-server-group-id"]},{port:5432,protocol:"tcp",sources:["10.8.0.0/24"]}]}`. Each of 1–100 rows chooses **either** `service_group_id` **or** a single `port`/`protocol`; combining them is invalid. A policy targets either `group_ids` or a tag selector; nonempty groups require an empty selector. Multiple target groups union their members. With no groups, an empty target selector explicitly targets all endpoints. Within each row, CIDRs, matches of the source selector (AND across tags) and members of every `source_group_ids` server group form a union, applied to every port in that row. Sources from unrelated rows do not mix. At most 100 source group IDs and 1,000 source CIDRs per row; references must exist. Exact ports are integers 1..65535, protocol tcp/udp. Empty resolved sources allow nobody. Source groups/selectors resolve current enrolled IPs; observed traffic never authorizes a source. Overlapping enforce rows union enforcing sources only; monitor rows never widen them. Ordinary per-port enforcement manages listed ports and preserves unrelated defaults. Optional whole-server default deny has its separate review contract above; runtime conflicts refuse apply in either mode.
- DELETE `/api/v1/policies/{id}` returns **200** `{deleted:true,deployment:summary|null}`. The current authenticated Admin supplies fresh exact ordinary cleanup authority, including when the former author is disabled. The deployment reference opens progress through the same dashboard publication path as Save. Intent deletion is not an agent cleanup receipt. Existing whole-server default-deny guards remain in effect. Automatically merged bundles revalidate every contributing current intent/author/provider on polling and management-health admission.
- Saved service-group rows add server-resolved `service_group_snapshot:{id,revision,name,ports}`; client snapshots are ignored. Historical policy revisions retain that snapshot. Compiler bundle history adds `service_group_snapshots` with the exact catalogue ports/revisions used. Changes to a service group update active referring policies atomically; source-group membership or reported address changes recompile current intent. Only changed effective access advances host versions. Missing service/source-group references abort compilation and preserve previous bundles; they never become a valid empty or unrestricted scope.
- Public service-group listing/detail counts references with SQL scalar projections rather than decoding all canonical policy source matrices. It reports exact `policy_count`, at most 100 navigation `policy_ids`, `policy_ids_limit:100`, and `policy_ids_has_more`; those reference hints are not target or grant authority. Authorized impact/compile workflows retain their exact internal reference semantics.
- GET `/api/v1/groups` -> `{items:[{id,name,type:"dynamic"|"static",selector:{},server_ids:[],member_count,member_ids:[],created_at,updated_at}]}`. POST creates, PUT `/groups/{id}` edits, DELETE `/groups/{id}` removes a group only when no policy references it as a target or `source_group_ids` source. Dynamic groups require a nonempty arbitrary tag selector and no explicit server IDs; static groups accept known server IDs and no selector. Dynamic membership updates automatically on enrollment/tag changes. Overview includes `groups` as well.
- POST `/api/v1/learning` `{server_ids:[explicit IDs],selection_mode:"discovered",duration_seconds:3600}` creates an automatic session. The dashboard defaults to this mode; `selection_mode` omitted in legacy API requests remains `manual`, with required `ports:[{port:80,protocol:"tcp"}]`. Duration is 60..604800 seconds; manual mode takes 1–100 ports and discovered mode rejects supplied ports. GET `/learning` lists sessions; POST `/learning/{id}/stop` stops one. See automatic learning below.
- GET `/api/v1/learning?limit=6&offset=0&server_id=optional` -> `{items,total,active_total,limit,offset,has_more,server_id,summary_only:true}`. Limits are 1..20. Every summary preserves the exact complete `server_ids` membership (maximum 20,000) and reports scalar status/times/action plus discovery counts. It excludes frozen listener/process snapshots, per-host matrices, approval scope/proof and confirmation credentials. Discovered sessions expose exact per-host ports through the host page below; their summary does not represent a union of all hosts' ports. Loaded-page filter matches are not a claim about unrequested history.
- GET `/api/v1/learning/{id}/hosts?limit=50&offset=0` -> `{session_id,items:[{server_id,ports,status,error,discovered_at,pending}],total,limit,offset,has_more}`. Limits are 1..100. Ports are the exact frozen per-host scope; no listener/process snapshots or authorization proof is included. These public navigation records can never grant access.
- GET `/api/v1/learning-policies/approvals?limit=200&offset=0&session_id=optional` -> a compact SQL-paged navigation queue, with `summary_only:true`, totals and no canonical target/source matrices or confirmation nonce. Limits are 1..500. GET `/api/v1/learning-policies/approvals/{id}` returns the exact selected immutable review for exact same-Admin application or destructive confirmation. Stored bytes are checked before canonical decoding; reviews (including an initial review's enclosing session) larger than 8 MiB are rejected with an instruction to create a smaller frozen review. Scope is never silently truncated. GET details do not themselves authorize an operation.
- GET `/api/v1/flows?window=3600&server_id=...` -> `{items:[]}` aggregate `{server_id,source_ip,port,protocol,verdict:"observed"|"allowed"|"denied",count,first_seen,last_seen,session_id}`. Count means observed events, not successful connections. GET `/api/v1/alerts`, GET `/api/v1/audit` -> `{items:[]}`. POST `/api/v1/alerts/{id}/ack`.
- POST `/api/v1/enrollment-tokens` `{name,server_id?}` -> `{token,expires_at}` single-use identity-only token (admin/super_admin); optional `server_id` binds a current planned reservation and exact hostname. Nonempty `tags` or `location_id` are rejected; legacy token defaults are ignored. Classify endpoints centrally after enrollment or through saved IP/subnet mappings.
- GET `/healthz` public `{status:"ok"}`; GET `/api/v1/auth` authenticated `{role,demo}`.
- GET `/readyz` public `{status:"ready"|"not_ready",checks:{metadata:bool,traffic:bool},ha,controller_id,site}`. Returns 503 if either shared dependency is unavailable. Liveness remains separate. No database URLs or connection errors are exposed.
- GET `/api/v1/cluster` authenticated `{ha,mode:"active-active"|"standalone",controller_id,site,nodes:[{id,site,last_seen,status:"healthy"|"offline"|"unavailable",role,ready}],storage:{metadata,traffic}}`. HA nodes report every 10 seconds; a node becomes stale after 30 seconds. Standalone mode reports only its real local node.

Server shape: `{id,hostname,ips:[],os,os_version,agent_version,capabilities:[],firewalld_version,firewall_backend,firewalld_state,ufw_active,listeners:[{port,protocol,address,process}],tags:{},expected_services:[],last_seen,status:"healthy"|"warning"|"offline",desired_version,applied_version,apply_status:"synced"|"pending"|"error"|"preview",apply_error,collector_status:"off"|"learning",last_learning_at}`.

Listener metadata additionally includes `{service,application,systemd_unit,pid,first_seen,last_seen,is_new}` where known. Identity comes from the actual owning process/unit, including SSH on 2022; unknown owners remain unknown. Server discovery fields include `{discovery_interval_seconds,last_discovery_at,last_discovery_attempt_at,next_discovery_at,discovery_status:"current"|"stale"|"error"|"unknown",discovery_error,discovery_changes:[{kind,port,protocol,service,...}],service_health_status}`. New/changed listener highlights persist until their discovery alert is acknowledged or 24 hours elapse.

Reports include `control_interval_seconds` (integer 5–3600, default 60). The controller derives `heartbeat_timeout_seconds = max(180, 3 × control_interval_seconds)` for server, collector and service freshness. Client-supplied timeout values are ignored. The dashboard uses the same derived timeout. This permits a longer configured control interval without false offline alerts; legacy agents retain the 180-second threshold.

## Reusable service/port catalogue

Read APIs are available to all authenticated roles. Catalogue mutations and preview POST require Admin or Super Admin; Read Only cannot save changes. The dashboard catalogue is `/services`.

- GET `/api/v1/service-groups` -> `{items:[group]}`; GET `/service-groups/{id}` -> one group. Shape: `{id,name,description,ports:[{port,protocol}],revision,created_at,updated_at,policy_ids:[],policy_count}`. UUID identity is assigned at creation and immutable. Name is required (max 120 characters), description max 2,000; ports are flat exact TCP/UDP pairs, normalized/deduplicated to 1–100 distinct entries. Nested groups and port ranges are unsupported.
- POST `/api/v1/service-groups` `{name,description?,ports}` -> 201 group. PUT `/service-groups/{id}` takes the same fields plus required integer `expected_revision`. Omission is invalid; a stale revision returns 409. Exact no-op edits preserve the revision. A rename/description edit advances catalogue and referring-policy revisions while leaving unchanged access versions alone.
- POST `/api/v1/service-groups/preview` `{id?,name,description?,ports,expected_revision?}` -> `{before,after,changed,ports_changed,affected_policy_ids,affected_policies,target_server_ids,target_server_count,affected_server_ids,affected_servers,effective_change_count,requires_managed_review}`. `expected_revision` is required for an existing ID. `affected_server_ids` contains only hosts with changed effective rules; target IDs show the full referring scope. Preview writes no catalogue, policy, bundle or audit state and does not authorize subsequent firewall writes.
- Saving records immutable catalogue history, revises all active referring policy snapshots and compiles once in one metadata transaction. GET `/service-groups/{id}/revisions` -> `{items:[]}`; GET `.../revisions/{revision}` -> one immutable definition with actor/reason. Only changed effective bundles advance host versions and invalidate old exact-bundle authorization. Saving never creates a managed approval.
- DELETE `/api/v1/service-groups/{id}` -> 204 only after all active policy references are removed. Historical revisions remain readable. Restoring an old policy resolves the current saved service group and current source memberships; an absent referenced catalogue entry rejects restore.

## Automatic learning discovery

- POST `/api/v1/learning/preview` `{server_ids:[explicit IDs]}` -> `{selection_mode:"discovered",server_ids,servers:[{server_id,hostname,ports,last_discovery_at,freshness:"cached_preview",discovery_pending:true,supported,offline,synthetic}],freshness:"cached_preview",message}`. This reads cached inventory only and starts no scan or collection.
- An automatic create requires every selected endpoint to advertise `learning_discovery_v1` (agent 0.3.0 or later). Older/missing capabilities reject the request with an upgrade/manual-mode message. Explicit server IDs freeze the selected host set. Another active session on any selected host rejects creation.
- Automatic sessions persist `{id,server_ids,selection_mode:"discovered",ports:[],server_ports:{host:[]},discovery_pending_server_ids:[],discovery_results:{host:{status,ports,error?,attempted_at?,discovered_at?}},starts_at,expires_at,status,created_by}`. Initially every selected host is pending; `server_ports` freezes each host's first valid fresh snapshot. The session-level `ports` becomes a display union; it never authorizes that union on every host. Endpoint assignments contain only that endpoint's `ports` and `discovery_pending`, with other hosts' maps/results removed.
- Pending assignments trigger a fresh endpoint scan. Acknowledgement must name the session, endpoint and `discovery_performed:true` snapshot with a successful `discovered_at` at/after session start. Wildcard or known non-loopback TCP/UDP binds qualify; unknown/missing binds and loopback-only binds do not. A scan with no eligible listeners records `no_listeners`; more than 100 ports or scan failure records `error` and remains pending for retry. No ready ports means no learning instrumentation. Offline/pending/error/no-listener status is visible; a failed scan cannot use stale cached listeners as its new scope. Later listener changes do not expand frozen ports.
- `starts_at`/`expires_at` measure duration from creation, including discovery and outage time. No full-duration coverage is promised. Stop/expiry removes owned instrumentation locally; retained tombstones allow bounded final draining and explicit cleanup acknowledgement. Discovery requests and learning delivery change ETag only, never the access-policy version. Manual mode remains available with an explicit common port list.

## Planned servers and reviewed retirement

- POST `/api/v1/servers` (admin/super_admin) `{hostname,ips?:[]}` creates a planned reservation with `waiting_enrollment`, no last-seen/listeners and `planned_unverified` addresses. Hostname is exact; IPs are optional numeric addresses, not CIDRs. GET `/api/v1/server-reservations` lists pending registrations. Planned addresses are excluded from policy-source resolution.
- Issue a token with the reserved `server_id`; the agent hostname must match. The first bound certificate enrollment creates the authenticated identity and consumes the reservation; discovered addresses are established by actual inventory reports. Unbound tokens still support automatic onboarding with no manual record.
- POST `/api/v1/servers/{id}/delete-preview` `{}` returns the before state, blockers, impact, expiry and confirmation nonce. POST `.../{id}/delete-confirm` `{plan_id,confirmation_nonce}` retires only that reviewed state. Active/uncertain managed enforcement, missing verified owned-rule cleanup, active/pending learning or monitoring, and unresolved imported-rule operations block retirement.
- Retirement archives inventory/history, revokes related bootstrap tokens, tombstones the identity and rejects later agent requests. It removes static membership and recalculates source/target intent; ordinary eligible intent publishes directly, while changed whole-server default-deny bundles require their dedicated acknowledgement. It does not uninstall the local agent or modify firewall rules. Saved CSV IP profiles remain until separately reviewed removal. Historical audit remains available.

## Endpoint APIs (mTLS identity; only demo mode accepts X-Agent-ID)
- Reports can include `firewall_snapshot`, pending `firewall_change_results`, `security_monitor` coverage and at most 100 `security_events`. Successful responses contain `ack_firewall_change_ids` and `ack_security_event_ids`; agents retain pending outcomes/observations until an explicit durable receipt. Replayed security IDs do not increment counts again.
- Policy assignments can include `firewall_changes` with plan ID/digest, expected snapshot digest, exact typed operations, expiry and completed confirmation count. These assignments change the delivery ETag but not the compiled access-policy version. Only a locally opted-in agent may execute the supported imported-rule subset. Per-host outcomes distinguish preview/applied/conflict/failed.
- POST `/api/v1/agent/enroll` `{token,hostname,csr}` -> `{server_id,certificate,ca_certificate,policy_signing_trust}`. CSR PEM. Cert CN=server UUID. One-time token hashed in DB; short expiry. The same token/CSR/hostname can retry within that expiry and receives the identical identity/certificate; a changed request cannot reuse the token. The agent persists its pending key/CSR before requesting enrollment. Agent verifies controller HTTPS with CA configured at bootstrap. Enrollment creates identity only; endpoint-supplied tags/DC and legacy token metadata cannot assign business classification.
- POST `/api/v1/agent/report` `{hostname,ips,os,os_version,firewalld_version,firewall_backend,firewalld_state,ufw_active,listeners:[],applied_version,apply_status,apply_error,collector_status,learning_coverage:{session_id,started_at,ended_at,dropped_events}}` -> `{server_id,desired_version}`. Identity from client cert, not body. Demo header X-Agent-ID may identify seeded or new demo agents.
- Reports also carry explicit `discovery_performed`, `discovered_at` (last successful scan), `discovery_interval_seconds` (default 900), and `discovery_error`. A new scan attempt, including failure, stays `discovery_performed:true` until the controller acknowledges it; HTTP retries reuse its inventory/timestamp without rescanning. After acknowledgement, cached heartbeats send false. Only successful scan data can replace listeners or generate discovery events. Omitted flags are treated as fresh scans for older-agent compatibility. Failed discovery preserves previous listeners and produces an unknown health result rather than a false outage. Agent 0.3.0 reports `agent_version:"0.3.0"`, `capabilities:["learning_discovery_v1"]`, and `learning_discovery_session_ids:[session IDs]` on snapshots requested by automatic learning. Session acknowledgements are endpoint-bound, idempotent and accepted only within the active session; cached or pre-session scans cannot freeze its ports.
- GET `/api/v1/agent/policy`: If-None-Match delivery ETag -> HTTP304 only when compiled policy, learning, approval/imported operations, polling intent and signature freshness are unchanged. `{server_id,version,digest,mode:"monitor"|"enforce",services:[{port,protocol,mode,sources:[CIDR]}],learning_sessions:[session],learning_tombstones:[session],generated_at}`. Each service has its own mode; the top-level mode is enforce if any service enforces. For a port matched by enforcing policies, union only sources from enforcing policies. Monitor sources must never widen an enforced allowlist. ETag includes learning assignment changes and tombstones; digest/version for access policy only. Tombstones retain stopped/expired session metadata for five minutes, including `stopped_at` (effective cutoff is the earlier of stopped_at and expires_at), so the agent can drain its final journal records.
- POST `/api/v1/agent/flows` `{batch_id,session_id,events:[event]}` -> 202 `{accepted:count,duplicate?,duplicate_events?}` only after durable enqueue. Batch IDs are idempotent. Max2000 events; selected session ports/kinds and the actual session window/upload grace are checked. Identity comes from mTLS, never body `server_id`. Typed events additionally have stable event-ID deduplication across batches, with changed payload conflicts refused. See the typed contract below.

### Typed capture evidence (0.9)

New learning requests and monitor previews accept `observation_kinds:["accepted_connection","denied_packet"]`, a nonempty subset defaulting to both. New scopes require endpoint `traffic_capture_v1`; the exact list is stored and signed with the endpoint scope/automatic authority. Metadata-free records cannot substitute for a selected typed kind. Historical stored scopes with this field omitted retain their journal-only contract and canonical retry bytes; their records are labelled `legacy_log`/`journal`/`log_records`, including historical `allowed` or `denied` strings.

Typed `event` is `{event_id,source_ip,port,protocol,verdict,count:1,first_seen,last_seen,capture_kind,capture_backend,count_unit,address_family}`. `event_id` is 64 lowercase hexadecimal characters; `first_seen==last_seen`. Only `accepted_connection/conntrack/connections/allowed` and `denied_packet/nflog/packets/denied` combinations are admitted. `address_family` is `ipv4` or `ipv6` and must match the native source address; scoped and IPv4-mapped IPv6 are refused. A conntrack NEW record alone is not accepted-connection evidence. NFLOG requires a verified supported terminal deny path, not generic logging or a claim to cover every host deny.

Flows, evidence, hit queries and CSV keep these count units separate. CSV appends `count_unit,capture_kind,capture_backend,address_family`. Overview `stats.capture_counts:{connections,packets,log_records}` describes its bounded last-hour relationships; compatibility `observed_events` counts legacy logs only, with `observed_events_unit:"legacy_log_records"`. Raw retention never turns a stable typed replay into another evidence count; nonpublishing redacted ID/digest tombstones persist until the session upload deadline.

`learning_coverage` and each `hit_monitoring` receipt may carry `capture_backends:[{backend,status:"active"|"off"|"unsupported"|"error",ipv4:bool,ipv6:bool,lost_events:int|null,error}]` and bounded `capture_gaps:[reason]`. Null/missing loss is unknown, not zero. Missing/unsupported/stale coverage and an empty last-hour result never prove no hits. Typed backends do not silently fall back to journal capture. Demo coverage is explicitly synthetic/unsupported; historical seeded rows are not relabelled. See [traffic capture, priorities and limits](traffic-capture.md).

Controller health job independent of requests, runs every30s. Heartbeat older than the derived timeout (180 seconds by default) -> offline; expected listener absent -> service_down; initial/new listener -> service_discovered (initial info, later warning); changed application on an existing listener -> service_changed; recovered events. Cached reports never create discovery events; PID-only restarts do not mean a new service. Agent outage suppresses per-service false alarms. Learning expiry independent of API. Flow retention24h default; preserve session metadata and audit. Durable flow queue separate from inventory DB, worker deduplicates. Collector reported state is retained until an endpoint acknowledgement: `collector_desired_status` is the requested state, `learning_stop_pending` means a stop is awaiting acknowledgement, `collector_state` becomes `unknown` if the last heartbeat is stale, and `collector_status_stale` marks this distinction.

Agent default is preview. Managed writes require explicit local enforce=true, complete protection and an exact authorized enforcement descriptor; cleanup of previously managed rules also requires an explicit review. Fleet control sync defaults to 30 seconds and discovery to 900 seconds, independently of temporary learning. Ordinary per-port enforcement preserves established sessions and unrelated configuration. Whole-server default deny separately adds a reviewed host INPUT fallback as described above. No shell interpolation or automatic UFW migration is permitted. Simulated/demo mode never invokes firewall tools.

## Managed policy history, review and health

- GET `/api/v1/policies/{id}/revisions` returns `{items:[immutable configuration revisions]}`; GET `.../revisions/{revision}` fetches one. GET `/policies/{id}/diff?from=1&to=2` returns before/after and field changes.
- POST `/api/v1/policies/{id}/rollback` (admin/super_admin) `{revision,reason}` restores configuration as a new revision and higher effective versions where rules change. Service-group IDs resolve the current catalogue, while source selectors and source server groups resolve current inventory. Historical saved port/revision snapshots remain immutable. Any changed effective bundle needs fresh authorization.
- GET `/api/v1/servers/{id}/policy-history` returns `{items:[immutable bundles plus separate outcomes]}`; GET `.../policy-history/{version}` returns one bundle.
- POST `/api/v1/policy-rollouts` (admin/super_admin) `{name,server_ids}` publishes selected current exact ordinary bundles when current protections permit, returning queued status with single-Admin authority. Ordinary policy POST/PUT and authorized group/tag changes publish affected per-port intent directly without a separate rollout request. Whole-server default-deny hosts require the dedicated review/acknowledgement; generic rollouts cannot authorize their changed fallback bundles. GET collection/detail preserves change and endpoint outcome history. Retained risky cleanup confirmation routes use current nonce/digest and the same actor when two explicit steps are required. Cancellation revokes future delivery without undoing committed rules. Local endpoint opt-ins and actual read-back still determine application.
- Policy assignments add `enforcement:{authorized,approval_id,approved_version,approved_digest,protection_digest,binding_digest,confirmation_count,expires_at,intent}`. Ordinary intent is `enforce` or explicitly reviewed `remove_managed_rules` for previously managed endpoints; the whole-server intents and acknowledgement fields are described above. Changed policy/protection/IPs, expired or cancelled authority revokes admission. Authorizing a replacement deactivates the endpoint's older delivery approvals. ETags include authorization changes.
- Reports add `protection:{digest,ready,management_sources,ssh_ports,controller_url,management_probe_url,zone,blockers}` and `managed_enforcement:{status,version,digest,approval_id,rollback_reason,error,last_good_version,last_good_digest,updated_at}`. Detailed states are preview, pending_approval, staging, runtime_healthchecking, committing, enforced, rolled_back or error. Legacy `apply_status` maps to preview, pending, applying, synced, rolled_back or error. A bare version is insufficient to establish successful enforcement. Rollback must explicitly name a valid historical last-good bundle or the genuinely initial unmanaged version 0.
- POST `/api/v1/agent/enforcement/check` requires enrolled mTLS and `{approval_id,version,digest,protection_digest,binding_digest,nonce,ssh_ports}`. It returns `{server_id,version,digest,protection_digest,binding_digest,nonce,checked_at,controller_ok:true,status:"healthy",ssh_checks:[{target_ip,port,source_ip,ssh_banner_verified:true}]}` only after current authorization and fresh source-bound SSH probes pass. Missing vantage configuration or failed probes returns 503; unauthorized bindings return 403. Demo refuses this proof. See [management vantage configuration](managed-enforcement.md).

## Manual DC/location catalogue

- GET `/api/v1/locations` returns `{items:[{id,key,name,location,type,provider,region,server_count,...}]}`. POST creates and PUT `/locations/{id}` edits a record (admin/super_admin). `name` and geographic `location` are required; type is `datacenter` or `cloud`. UUID identity and canonical key are immutable; names and geography are editable. DELETE refuses assigned or referenced locations.
- PATCH `/api/v1/servers/{id}` may set one `location_id` (or null to explicitly pin unassigned) separately from multiple custom tags. A location must exist first. Tags/location changes require admin, and expected-service declarations also require admin/super_admin.
- New policies/groups use a stable `location_id` selector alongside custom tags. Recognized legacy DC-name selectors resolve to that identity and keep membership after rename. Arbitrary reserved DC/location tag keys cannot be used to create extra assignments. Unknown existing tags remain unassigned migration notes and never auto-create catalogue records. Server views include resolved `location`, `location_id` and legacy migration candidates; overview includes the catalogue.

## Dashboard-owned classification, CSV and subnet mapping

Agents report inventory only. Effective metadata resolves per field as manual override > CSV exact-IP profile > subnet DC rule > unassigned. Subnets supply DC only; business tags come from manual editing or CSV. Manual removal of a tag persists as a tombstone until reset. Existing saved tags/DC migrate to manual overrides. Multiple tags and at most one DC are supported. Conflicting CSV values, shared endpoint IPs or different winning subnet DCs across a multi-IP server produce visible conflict information instead of an arbitrary choice. Longest prefix wins for each IP (/24 over /16 over /8); exact canonical CIDRs are unique. One IP cannot classify endpoints into different DCs. A later conflicting report is accepted as inventory while classification conflicts are surfaced. Manual overrides resolve eligible fields, while conflicting ownership still requires operator resolution.

- PATCH `/api/v1/servers/{id}` (admin/super_admin metadata) accepts `tag_updates:{application:"billing",owner:null}` to merge/add or explicitly remove keys; `reset_tag_keys:["application"]` returns individual keys to CSV defaults. `tags:{...}` remains a full effective-map editor and only pins changed values. `location_id` pins one saved DC or null; `location_mode:"automatic"` removes the manual DC override. `location_mode:"manual"` with an ID pins it. Agent reports never replace these values. Public server fields include `tag_sources`, `location_source`, `metadata_conflicts`, `metadata_manual_tag_keys`, `metadata_removed_tag_keys` and `metadata_manual_location`.
- POST `/api/v1/metadata/bulk/preview` (admin/super_admin) takes `{server_ids:[explicit IDs],tag_updates?,reset_tag_keys?,location_id?,location_mode?}` and returns a durable reviewed plan with `id`, `items` (before/after/provenance), `summary`, `confirmation_nonce` and ten-minute expiry. POST `/metadata/bulk/{plan_id}/apply` with `{confirmation_nonce}` atomically applies exactly those targets. A changed filter cannot widen a reviewed target list.
- GET `/api/v1/metadata/subnets` returns `{items:[{id,name,cidr,location_id,location,matched_servers,...}]}` to authenticated roles. POST `/metadata/subnets/preview` (admin/super_admin) takes `{id?,name?,cidr,location_id}` for a new/edit rule; POST `/metadata/subnets/{rule_id}/delete-preview` takes `{}`. Both return a before/after plan; POST `/metadata/subnets/{plan_id}/apply` with `{confirmation_nonce}` commits it. CIDRs are canonicalized; duplicate CIDRs and `/0` are rejected. The saved DC must exist first. Current and future matching inventory receive eligible assignments without endpoint configuration.
- POST `/api/v1/metadata/imports/preview` (admin/super_admin) accepts `{csv:"ip,application,dc,zone,criticality,tag.cost_center\\n..."}`. Maximum 1 MiB/10,000 rows; numeric IPv4/IPv6 only, one unique IP per row. `dc` resolves a saved location ID/name; unknown DCs are row errors. Header aliases support IP Address/Application Name/DC Name. `tag.<key>` supplies custom tags; reserved DC keys are rejected. Blank cells preserve existing profile values. A row must supply at least one nonblank tag/DC. Hostname is informational and never overwrites discovered inventory. Preview returns `rows`, `summary`, `errors`, `status`, `id`, expiry and a nonce for valid plans. It distinguishes current/future IPs, manual fields retained and effective before/after changes. Invalid imports apply nothing.
- POST `/api/v1/metadata/imports/{plan_id}/apply` (admin/super_admin) with `{confirmation_nonce}` atomically stores reviewed exact-IP defaults and reconciles current inventory. Future endpoints pick up profiles on their first matching inventory report. GET `/metadata/imports/profiles?limit=100&offset=0` (admin/super_admin) returns `{items,total,limit,offset}` with profile tags/DC and current/future/conflict bindings. POST `/metadata/imports/profiles/{URL-encoded-IP}/delete-preview` with `{}` reviews removal; use the same imports apply endpoint to remove it. Manual overrides survive; eligible fields fall back to remaining profiles, subnet or unassigned. Location deletion is blocked while an assignment, subnet or CSV profile references it.

All preview types are stored in the shared inventory database for HA. Apply verifies expiry, an unused nonce and the reviewed metadata/IP snapshot; stale or replayed plans return 409. Ordinary heartbeats do not invalidate review. Metadata changes reconcile membership and compile intended policy once per transaction; authorized saves publish changed exact intent while local endpoint opt-ins and current protection checks remain mandatory. No traffic learning is converted into a business tag or allowlist automatically.

## Exact-port learning, recommendations and additive auto allowances

Create a fresh-discovery session with optional exact `port_filter`; omission means all eligible discovered listeners. A present filter must contain 1–100 exact TCP/UDP pairs. For a host listening on 22, 80 and 443, this request freezes observation only on TCP443; the initiating Admin action authorizes this scope and fresh discovery freezes it before automatic entries:

```json
{"server_ids":["node-a"],"selection_mode":"discovered","port_filter":[{"port":443,"protocol":"tcp"}],"policy_action":"auto_allow","auto_allow_confirmed":true,"duration_seconds":3600}
```

`policy_action` defaults to `observe`; new scopes additionally require `traffic_capture_v1` and accept the selected observation kinds described above. `auto_allow` requires literal explicit consent, fresh-discovery mode and `learning_auto_allow_v1`. Both kinds default selected, so verified denied first-hits can become exact source allowances; there is no additional approver or per-hit consent. Operators may select only accepted-connection evidence instead. The filter is intersected after each endpoint's fresh scan and applied to cached preview. Empty matching scope never falls back to other ports. Agent inventory remains complete. Auto mode requires both local `enforce` and `learning_auto_allow`, protected management configuration, fresh health evidence and the initiating Admin session authority. Fresh discovery must finish before eligible per-host ports can authorize additions; consent never bypasses local protections.

- GET `/learning/{session}/recommendations?limit=200&offset=0`: paginated durable exact evidence, `evidence_revision`, `total_rows`, `has_more`, coverage and generated policies. Each row includes stable `id`, `server_id`, hostname, source IP and host CIDR, port/protocol, service/process, count, verdicts, first/last observation, eligibility and exclusion reason. Max page size 2000.
- GET `/learning/{session}/export.csv`: authenticated UTF8-BOM CSV attachment containing all retained pairs, independent of the traffic chart's 500-row cap. Formula-leading textual cells are escaped. Durable evidence survives raw traffic pruning.
- POST `/learning/{session}/recommendations/preview`: `{row_ids,server_ids:[]|group_ids:[],name,expected_evidence_revision}`. Admin/Super Admin only. Returns `id,digest,plan_digest,expires_at,services,target_server_ids,targets,warnings,approval,confirmation_count,confirmation_nonce,confirmation_phrase`. Source sets remain bound to their exact TCP/UDP port; applying a row to additional selected servers is explicitly shown. Group members are frozen. Warnings block apply.
- POST `/learning/{session}/recommendations/apply`: `{preview_id,digest,confirmation_nonce,confirm:true}` applies the exact fresh suggestion with one current authorized Admin action and returns `pending_approval:false` plus policy intents. Evidence, membership, protection or current identity/role/session changes invalidate the review. A saved intent or queued update is not an applied endpoint result.
- GET `/learning-policies` and GET `/learning-policies/{id}` expose generated/reviewed policy revision, exact services, target, origin, automatic update state and endpoint result/error. Pending cleanup remains visible.
- POST `/learning-policies/{id}/change-preview`: `{expected_revision,services?,name?,remove?:bool}` freezes an exact edit/removal. POST `.../change-confirm` uses `{preview_id,digest,confirmation_nonce,confirm:true,challenge?}`. Safe additions complete with one Admin action; restrictive edits/removal require two explicit confirmations by that same actor, with a rotated nonce and final exact typed challenge. The first restrictive response has `pending_approval:true`; completed changes return `pending_approval:false` and current `policy`. Direct production PATCH/DELETE cannot bypass exact review. Edits suppress removed tuples; removal remains pending until actual endpoint cleanup. Sources stay unicast /32 or /128.
- GET `/learning-policies/approvals?limit=200&offset=0` returns paginated current reviews, including `kind:initial_learning` and `kind:policy_change`; recommendations also exposes session `pending_approvals`.
- `/learning/{session}/approval-preview` and `/approval-confirm` are retained compatibility routes for initial-authority records. The current GUI has no separate initial approval workflow: the initiating Admin auto-allow session action authorizes its selected scope, and successful fresh per-host discovery freezes eligible ports before automatic additions. `initial_approval_state` remains explicit. Legacy history does not substitute for current role, scope, protection or endpoint checks.

Agent policy assignments carry independent `learning_allow` generations, exact services/provenance authorities, target/protection/binding digests, expiry and authorization. They do not grant normal `enforcement` approval. Reports use `learning_allow_outcome` with generation, digest, binding digest, status (`applied|preview|blocked|rolled_back|error`), error, and last applied generation/digest. Generation-zero sentinel assignments have no outcome. POST `/agent/learning-allow/check` is mTLS-only and checks the exact current learning authority before and after fresh SSH probes; it uses a separate context from managed-rollout approval. Demo mode supplies no real health proof.

Automatic additions require active endpoint-specific learning authority, exact locally observed ingress tuples and frozen selected ports. Stop/expiry halts new automatic grants; committed allowances persist. A mutating rollback/error holds that session's endpoint authority until explicit review. Protected SSH/local controller ingress, invalid sources, unknown firewall context and capability-dependent capacity can block application. Legacy learning admits 64 tuples; 0.6 `learning_ipsets_v1` admits 10,000 exact source/port tuples across 64 services in separate prepared banks. Read Only may inspect/export; mutation routes require Admin or Super Admin and session CSRF. This accept-only overlay does not narrow existing broad firewall openings or change zone defaults.


## Independent signed assignment and endpoint certificate lifecycle

The agent validates the complete typed Ed25519 envelope against separately pinned public deployment/key trust before caching or mutation. Changed, expired or foreign authority is rejected; signature freshness affects the delivery ETag, not the access version. First authenticated enrollment may pin initial trust only when none exists. Existing trust is never silently replaced. `GET /platform/policy-signing-trust` returns public `{deployment_id,keys}` only. Online and optional exact offline-artifact providers are separate from TLS/issuing CA keys; see [signing operations](policy-signing.md).

`ca_cert` pins web HTTPS. Optional `endpoint_ca_cert` independently pins a different public endpoint issuer; empty falls back to `ca_cert`. Stock `--ca-file` installs web trust only. Renewal/recovery validates locally pinned issuers and never accepts replacement roots from response material.

- POST `/agent/certificates/renew` is mTLS-only and accepts bounded CSR material. It binds the enrolled identity/current fingerprint, issues a 90-day leaf in the renewal window and tracks the retiring credential overlap. Registry revocation is checked on every request, including an already established TLS connection.
- GET `/platform/endpoint-certificates` returns public expiry/fingerprint/registry status. Super Admin POST `/platform/endpoint-certificates/revoke-preview` `{server_id}`, then `/revoke-apply` `{preview_id,digest,confirmation_nonce,confirmation_phrase}` revokes exact reviewed identities.
- Super Admin POST `/platform/endpoint-certificates/recovery-token` `{server_id}` returns a 15-minute one-time credential, displayed once. HTTPS POST `/agent/certificates/recover` accepts `{token,csr}` with a fresh key, derives identity from the token and preserves the enrolled UUID. It is not an implicit revocation of an older certificate.
- GET `/platform/internal-certificates` exposes current internal-leaf expiry/renewal/runtime receipts. Super Admin `/suspend-preview` `{node_id,expected_revision}` then typed `/suspend-apply` suspends admission/sync/renewal/routing. This is not complete revocation of copied database credentials or internal CA material.

## Platform operations

Authenticated roles can read `/platform/status`, `/platform/appliance`, `/platform/backup-schedule`, `/platform/agent-settings`, public certificate-status and public signing-trust routes. They contain redacted state, never raw private keys/DSNs. Other privileged backup, notification and recovery metadata plus all platform mutations require Super Admin. Entra cookie mutations require CSRF. A returned job is queued work, not a verified operation.

- GET/POST `/platform/backup-schedule` reads/saves `{expected_revision,enabled,frequency,time,timezone,weekday,interval_hours,retention_count}`; default timezone Asia/Kolkata, weekdays Monday 0–Sunday 6, intervals 1–168 h, retention 1–365 successful scheduled archives. Next/last/success/error are explicit. Pruned archives remain historical records.
- GET/POST `/platform/backups`, GET `/{id}/inspect`, GET `/{id}/download`, POST `/{id}/restore-validation` create/inspect/download/structurally validate local database archives. Structural validation does not replace a live DB. Archives exclude PKI/Vault/active profile/environment; local bytes are not silently downloadable from another controller.
- POST `/platform/demo/preview` then typed `/platform/demo/clear` binds exact proven synthetic counts/dependencies, nonce/fingerprint/expiry and automatic verified pre-clear backup. Retained policy names/reasons remain public in the review. Mixed/manual/real records stay protected; successful cleanup disables reseeding.
- POST `/platform/appliance/config` saves an expected revision, name/site/IP/origin, optional shared/replication passwords, routing and approved watchdog settings. Blank secrets preserve existing values. Saved settings do not imply shared DB activation. Join preview uses `{peer_url,cluster_password}` but sends no password before the exact peer TLS trust review. Join/service/storage apply uses the returned exact typed review and durable job. Only fixed owned services/validated paths are accepted; demo blocks live operations.
- POST `/platform/certificates/preview` accepts PEM/key with optional `key_password`, PKCS#12/password or self-signed hostname/SAN mode. Typed `/apply` queues actual served-pair/readiness/restart verification with old-pair rollback. Managed corporate imports require a complete verifiable chain. Generation/import is distinct from active TLS.

### Reviewed local application port

Super Admin GET `/platform/application-port` returns `{revision,mode,current_port,desired_port,applied_port,bind_address,current_url,new_url,controller_origin,origin_mode,can_apply,blockers,last_job,allowed_range}`. Mode is `standalone` or `appliance_public`, origin mode is `preserve`, and allowed range is 1–65535. Missing supervisor/listener context is reported as blocked rather than inventing an active port.

POST `/platform/application-port/preview` `{expected_revision,port}` returns the frozen current/new ports and addresses, bind address, digest, expected revision, nonce, exact phrase, expiry, plain dependency list and blockers. Demo can review but has `can_apply:false`. POST `/apply` requires `{preview_id,digest,expected_revision,confirmation_nonce,confirmation_phrase,acknowledge_dependencies:true}` and returns a durable `operation:"application-port"` job. Actual bind permission/collision is checked before the old listener is stopped. A port change grants no new process privileges.

Only exact `status:"applied",phase:"active",result:{applied_port,new_url,verified:true}` establishes the verified target. Verified compensation is `status:"rolled_back",phase:"previous_port_restored",result:{applied_port:old,current_url,verified:true}`. Failure to verify compensation stays blocked/failed; queueing, a closed connection or a desired value is not an applied listener. Preserve the proposed address before Apply and inspect durable status after reconnecting.

This changes only the current node’s listener/publisher. The configured application/SSO origin is preserved; external LB targets, direct agents/peer URLs, Entra callback/origin settings, DNS and firewall rules are not automatically reconfigured. A direct new URL may allow authenticated reads while sign-in or mutations still require the original configured origin to be routable. Local TCP/TLS/database readiness is not external-route or Microsoft sign-in acceptance.

### Central endpoint cadence

GET `/platform/agent-settings` returns revisioned defaults/rules plus per-host desired/observed/support state. POST the same route with `{expected_revision,defaults,rules}` saves; POST `/preview` exposes exact changed hosts without saving. Bounds are control 5–3600s and discovery 60–86400s. Rules use name/enabled/priority plus explicit server IDs, saved groups or AND selector; each interval resolves independently by higher priority, server, group, tag specificity and stable rule ID. Agent capability is `agent_polling_config_v1`. The Go runtime updates protected timing fields safely and persists the last valid remote assignment through outage. Same global version with a changed per-host digest after membership/tag changes is valid. A syntactically valid future receipt remains observed `ahead_of_controller`, not current, and never rejects the heartbeat/inventory.

### Reviewed external notifications

GET `/platform/notifications`, POST `/preview` `{expected_revision,enabled,channels}`, POST `/apply` exact typed review and GET `/deliveries?limit&offset` manage a default-disabled encrypted configuration/outbox. Channels are Slack, HTTPS webhook or TLS/STARTTLS email, with severity/event filters, exact recipients/resolved addresses, optional private-network approval and webhook receiver-idempotency guarantee. Empty secrets preserve saved private values; public responses expose only masked configuration/flags. DNS changes require re-review.

POST `/platform/notifications/channels/{id}/test` `{expected_revision,confirm:true,request_id}` creates one stable explicit test. POST `/platform/notifications/deliveries/{id}/retry` `{expected_revision,expected_attempts,confirm_possible_duplicate:true}` explicitly accepts duplicate risk. Automatic temporary retries are bounded; unknown Slack/SMTP acknowledgement is held. Provider acknowledgement is not inbox delivery. Per-occurrence event IDs hash stable alert ID, created time, kind and occurrence identity; `event.alert_id` retains the original ID. Recovery filters are informational and opt-in through severity/type selection. Demo sends are blocked.

### Super Admin supervised recovery: two explicit confirmations

GET `/platform/recovery` returns durable `active`, current `pending_reviews` and supervisor requirement. POST `/preview` `{backup_id,reason}` freezes the verified local archive/backend/version, active identity/epoch/membership, current PKI/Vault safety context and exact digest/nonce/phrase. A live enabled Entra **Super Admin** completes both explicit confirmation steps; no different reviewer or approval mode is required. Token/demo authority cannot authorize production recovery.

POST `/platform/recovery/confirm` `{preview_id,digest,confirmation_nonce,challenge?}` first records an explicit confirmation and returns `{pending_approval:true,preview}`; the same current Super Admin supplies the rotated nonce and exact typed challenge and receives `{pending_approval:false,preview,job}`. A different active recovery cannot be overwritten. All writers are drained/fenced; public HTTPS/API/readiness may be held/503 while private candidate readiness is checked. The private nonce cannot bypass business APIs. Transient fixed-helper failures retry the same immutable phase with durable 5–60s backoff; safety-binding mismatches remain blocked. Original DB/protected copies remain preserved. Completion requires verified durable results, a fresh Entra sign-in and fresh policy authority. Missing current trust/safety ledger blocks online recovery; older PG archives without canonical hashes are structural-only. This is not archive-only offline DR.

### Optional continuous port hit monitoring

This capture is **disabled by default** and separate from finite learning sessions,
recommendations, and firewall access policy. Read Only may inspect/export; Admin or
Super Admin may submit a typed review to start/stop. Browser mutations retain the
normal session, CSRF, and origin checks. Demo apply is refused.

- `GET /api/v1/hit-monitors?limit=20&offset=0`: bounded configuration page with
  exact `total`, `has_more`, desired `enabled`, per-target reported
  `status_counts`, `storage_budget`, and `pending_batches`.
- `POST /api/v1/hit-monitors/preview`: `{name,selection:{server_ids,group_ids,selector},ports:[{port,protocol}],retention_hours,observation_kinds?}`.
  Select 1–64 exact TCP/UDP port pairs and 1–24 hours retention. Selection resolves
  to a frozen enrolled endpoint set; changed membership/configuration invalidates
  the review. Return includes `id`, `digest`, `confirmation_nonce`,
  `confirmation_phrase`, `expires_at`, `target_count`, and the exact port pairs.
- `POST /api/v1/hit-monitors/{id}/stop-preview`: `{expected_revision}` returns the
  same immutable typed-review contract.
- `POST /api/v1/hit-monitors/apply`:
  `{preview_id,digest,confirmation_nonce,confirmation_phrase}`. Same authenticated
  review actor and current provider epoch are required. The desired duration is
  **until stopped**; enable never creates a policy or learned recommendation.
- `GET /api/v1/hit-monitors/{id}/hits?window_hours=1&limit=100&offset=0&server_id=...`:
  exact grouped source/endpoint/port/protocol observations, `count`, first/last
  time, and service/process labels frozen from inventory at enable. Limit ≤200.
- `GET /api/v1/hit-monitors/{id}/targets?limit=50&offset=0`: paged target identity
  and actual endpoint cleanup/observation receipts. Central desired off alone is
  **not** evidence that endpoint instrumentation has already stopped.
- `GET /api/v1/hit-monitors/{id}/export.csv?window_hours=1&server_id=...`: individual
  logged records from one database snapshot, formula-safe UTF-8 CSV. The private
  export spool is capped at 64 MiB; an oversized request fails before success
  headers, requiring a narrower scope/window.

New monitor reviews additionally require `traffic_capture_v1`. Only `port_hit_monitor_v1` + `signed_assignments_v1` endpoints receive the signed
`hit_monitors` assignment array. Each lease contains
`{id,server_id,starts_at,expires_at,ports,observation_kinds}` for new typed scopes; historical scopes omit the final field. Starts are minute-bucketed and expiry
is 120 seconds later. New leases require an accepted fresh full signed response;
cached assignments and 304 responses cannot renew capture. Endpoint monotonic
elapsed deadlines and temporary native observation rules/subscriptions bound a controller outage.
A stop can retain observations from an already-issued lease for at most 120
seconds. At most 8 monitor records / 64 total port scopes per endpoint are allowed.

`POST /api/v1/agent/hits` is a **Discovery-channel, mTLS-only** route. Body:
`{batch_id,monitor_id,lease_starts_at,lease_expires_at,events:[event]}` with the typed event contract above. Historical journal-only scopes retain their observed-log contract.
Stable event IDs bind the monitor and native lifecycle/packet identity (historically the journal cursor); deduplication includes the
certificate-bound endpoint identity and survives batch retries/renewals. Event
scope must match the frozen monitor; uploads expire five minutes after the lease.
`202` acknowledges durable queue admission, not complete traffic coverage. The
worker processes this queue separately from learning/evidence/policy creation.

Capture records are bounded evidence, not a complete flow/packet ledger or proof
of application success. NFLOG sidecars limit records to 200/second per rule, port
and family; omitted records leave unknown total loss. Conntrack uses bounded
queues and a non-evicting identity ledger, not a 20-events/second limiter.
Backend gaps, netlink/journal loss, local spool limits, backpressure, or storage budgets
can produce gaps. Retention is a maximum age, not a completeness guarantee.
The shared traffic store caps retained hit records at 2,000,000, batch receipts
at 1,000,000, and pending batches at 10,000. Service labels are inventory-at-enable
context; observed source IP is the kernel-visible address, including NAT effects.
Recovery retains current monitor identities but disables capture, removes pending
reviews, and requires a fresh enable review. Retirement requires actual cleanup
acknowledgement. Full-fleet capture throughput and native distro behavior remain
separate acceptance work.

### Scoped pilot discovery timing preset

Super Admin may `POST /api/v1/platform/agent-settings/pilot-preview` with
`{expected_revision,server_ids:[...]}` for 1–20 explicit capable endpoints. The
response contains normal polling impact review plus `configuration` (the exact
existing save payload) and `pilot:{server_ids,removed_server_ids,control_interval_seconds:30,discovery_interval_seconds:60,global_defaults_unchanged:true}`.
After impact review, save `configuration` through the existing
`POST /api/v1/platform/agent-settings`. Other rules/defaults are preserved;
removed previous preset members and precedence conflicts are explicit.
The normal fleet discovery default remains 900 seconds unless the operator
changes it. This preset neither enables monitoring nor changes access policy.


## Endpoint diagnostics and alert navigation (0.11)

Authenticated inventory reports can include `fast_discovery` and
`preparation_status`. These are bounded observations, not policy authority.
The controller rejects invalid fields/types/timestamps before storing a report.
A diagnostic-only cached report cannot replace or freshen listener inventory.
Public server detail/inventory preserves validated receipts. UFW raw rule
contents are never part of this contract; only the fixed private endpoint
export reference is accepted. Unknown service activity is omitted, not false.
See [receipt semantics](endpoint-discovery-and-preparation.md).

`GET /api/v1/alerts` supports `limit` (default 50, maximum 100), `offset` and
`include_resolved=true|false` (default false). `POST /api/v1/alerts/query` is
read-only navigation with the same pagination plus `server_ids`,
`listener_server_ids`, `search_server_ids`, `ports` and literal `search`.
Read Only may query; normal session CSRF/origin requirements still apply.
Acknowledgement remains an Admin mutation. The selected endpoint scopes are
filters, never authorization grants.

A page returns `items`, `total`, `all_count`, `unresolved_count`, `critical_count`,
`unacknowledged_count`, `open_count`, `limit`, `offset`, `has_more` and
`include_resolved`. Counts cover the complete matching scope independently of
page size. Rows use stable created-time/ID ordering. The ordinary overview
includes 50 unresolved summaries and `alert_pagination` with exact aggregate
counts; newer resolved history cannot conceal an older open outage. Large
navigation details are explicitly marked omitted rather than loaded without a
bound. Lateral-movement events retain target-endpoint scope matching.


## Complete Traffic and Audit navigation (0.12)

`POST /api/v1/flows/query` applies endpoint/tag/group/location scope, ports and
literal search before aggregation and pagination. Its bounded page includes
exact relationship/endpoint totals, separate counts by observation unit and a
stable full-dimension ordering. The request accepts `window_seconds`,
`server_ids`, `search_server_ids`, `ports`, `search`, optional `as_of`, `limit`
(default 50, maximum 100) and `offset`. `as_of` fixes the query window, not an
immutable cross-request database snapshot; late processing and retention remain
explicit. The overview/topology flow list remains a labelled bounded preview.

`GET /api/v1/audit` and `POST /api/v1/audit/query` accept bounded pagination,
`search` (action/actor/event ID), exact `action`/`actor` and inclusive
`from_at`/`to_at`. Detail values are excluded from search and are defensively
redacted in output. Large navigation details are explicitly omitted.

`POST /api/v1/flows/export.csv` and `POST /api/v1/audit/export.csv` use the same
applied filters without `limit`/`offset`. They return complete scoped CSV within
explicit export bounds, or fail before headers. They never silently export
only a loaded page. Private anonymous spools, bounded concurrency and CSV
formula protection apply. Read Only can query/export; session CSRF/origin
checks remain mandatory. No mutation or lookalike path inherits that exception.

## GUI source-bank maintenance (0.12)

`POST /api/v1/source-banks/query` returns bounded public job/receipt summaries.
Read Only may inspect; Admin mutations are distinct. `POST /source-banks/assess`
and `/source-banks/preview` accept `server_ids`/`group_ids`, freezing 1–100 current
endpoints. Assessment creates a signed read-only agent job. Preview requires
fresh successful receipts and returns exact targets, baseline/protection
digests, assessed times, blockers, a review digest/nonce, expiry and challenge.

`POST /source-banks/{review_id}/confirm` requires exactly `digest`,
`confirmation_nonce`, `confirmation_phrase: "PREPARE SOURCE BANKS"` and literal
`acknowledge_downtime: true` from the same current Admin. It creates per-endpoint
`prepare_activate` assignments with independent exact Admin proofs. Pending is
never returned as kernel-applied.

Signed policy auxiliary `source_bank_preparation` contains `id`, `operation`,
`plan_digest`, `baseline_digest`, `protection_digest`, `expires_at` and activation
`approval_proof`. Agent capability is `source_bank_preparation_v1`.
Authenticated report field of the same name carries the bounded schema-1
status, bindings, counts and blockers. Activation receipts must match the exact
reviewed binding; late progress or contradictory terminal replays cannot revive
an operation. The control listener alone admits
`POST /api/v1/agent/source-banks/check`; fresh nonce/SSH/controller checks and
current authority are revalidated before/after probing. Admission is durably
recorded before endpoint writes. Unresolved admitted operations cannot be
erased by expiry/reassessment or bypassed by endpoint retirement. Recovery
invalidates pending jobs and reviews. [GUI sequence and safety](source-bank-preparation.md).

## Policy deployment readback and passive witnesses (0.13)

Policy saves return an additional public `deployment` summary without adding
that operational field to persisted policy intent. Explicit managed/default-deny
pushes also return a tracker. Authorized tag/group/service-group/address
resolution creates automatic tracking for changed existing enforced contexts.
The policy form and allowed-source/port schema remain OS-neutral.

Read Only can use `GET /api/v1/policy-deployments?limit=10&offset=0`,
`GET /policy-deployments/{id}`, `GET /policy-deployments/{id}/targets?limit=50&offset=0`
and `GET /policy-deployments/{id}/targets/{server_id}`. Counts cover complete
frozen scopes; source matrices are not duplicated into notification summaries.
Current Admins may `POST /policy-deployments/{id}/targets/{server_id}/recheck`
with exactly `{}` to start a new passive window against unchanged, currently
authorized bindings. It grants no access or policy authority.

Capability `policy_verification_v1` receives optional signed policy auxiliary
`policy_verification`: schema 1, observation `id`, bulk-run `deployment_id`,
`server_id`, `version`, `digest`, `approval_id`, `protection_digest`,
`target_ips_digest`, up to 64 exact `ports`, `starts_at`, `expires_at` and
`window_seconds` (default 600). The bulk-run ID is separate from the signing
controller's deployment identity. Ordinary policy digest/signature and local
firewall prerequisites remain independently checked.

The authenticated report echoes these bindings and adds monotonic `sequence`,
`state`, `applied_generation`, `armed_at`, nullable true `committed_at`,
`checked_at`, optional bounded `error`, and per-port independent `allow`/`deny`
cases. Verified cases carry one complete native witness: event/source/destination,
port/protocol/family, typed capture kind/backend/unit, expected decision,
observation/receive times and capture epoch. Allowed witnesses require a kernel
connection birth after arming. Denied witnesses require the fresh generation-
and observation-bound NFLOG prefix. Generic historical flows cannot qualify.

Managed enforcement reports preserve generation and true commit time, optional
boolean `already_present`, and paired `verification_id` /
`verification_readback_at` from the actual fresh pre-arm readback. Fractional
boundaries are preserved. Later normal readback timestamps may advance without
replacing that observation's immutable anchor. Lost initial reports do not
require invented timestamps or a new commit.

Positive evidence requires exact current authority, addresses, protection,
generation and fresh accepted readback; every applicable case on every port
must be covered. Replay, cross-port/source/generation evidence and old
connections fail admission. Conservative invalidation cannot upgrade history
and remains bounded even after upload grace, so an old restart receipt does
not block a healthy heartbeat. Recovery makes retained observations historical.
Historical witnesses remain inspectable and are not displayed as a current
green pass. See [workflow and limitations](policy-rollout-verification.md).
