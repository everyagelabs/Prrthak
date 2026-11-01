#!/usr/bin/env python3
"""Build the standalone illustrated HTML and reviewed ReportLab PDF.

Run --html-only while screenshots are being collected. Before the first PDF
creation in a Codex artifact task, run the PDF skill's operation marker once.
This script never starts a controller, contacts Entra, or changes a firewall.
"""
from __future__ import annotations
import argparse, base64, html, json, math, os, re, shutil
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / 'docs/guide'
OUTPUT = ROOT / 'output/pdf'
TITLE = 'Prṛthak deployment & onboarding guide'
STAMP = '31 October 2026'
RELEASE = '0.6.0'
# Root supplies combined release totals after the final acceptance rerun.
VALIDATION_EVIDENCE = 'Recorded controller and integration runs pass with PostgreSQL fixtures. Dashboard and Go regular/race/vet pass.'
OVERLAY_LIVE_VALIDATION = 'Retained Ubuntu 24.04.4 ARM64/systemd/firewalld 2.1.1 evidence includes real 443 collection, full mTLS/HTTP/SSH wire and independent agent rollback. Ubuntu 26.04/firewalld 2.3.1 source-set transactions passed in disposable containers with test health/timer callbacks. Native RHEL 8/9, target-host Ubuntu/systemd, DB fencing and WAN acceptance remain gates.'
# Capture these actual product screens after the new UI is ready, then supply
# their metadata under the matching keys in docs/guide/screenshots.json. They
# are deliberately not synthetic images or fabricated screenshot placeholders.
EXPECTED_SCREENSHOTS = {
 'service-groups': {'path':'docs/guide/images/service-groups.png', 'title':'Reusable service/port groups', 'provenance':'Actual local application capture; synthetic demonstration data.'},
 'auto-learning': {'path':'docs/guide/images/auto-learning.png', 'title':'Automatic per-endpoint learning discovery', 'provenance':'Actual local application capture; synthetic demonstration data.'},
 'learning-actions': {'path':'docs/guide/images/learning-actions.png', 'title':'Exact-port learning filter and cached preview', 'provenance':'Actual isolated 0.4 QA UI; synthetic endpoints; cached preview is limited to 443/tcp.'},
 'learning-auto-consent': {'path':'docs/guide/images/learning-auto-consent.png', 'title':'Explicit automatic allowance choice and consent', 'provenance':'Actual isolated 0.4 QA form; staged automatic allowance choice and consent, separate from the filter frame.'},
 'learning-evidence': {'path':'docs/guide/images/learning-evidence.png', 'title':'Durable observed source and exact-service evidence', 'provenance':'Actual isolated 0.4 QA evidence table; synthetic Nginx 443/tcp observations, not real traffic.'},
 'learned-policies': {'path':'docs/guide/images/learned-policies.png', 'title':'Separate learned allow policies and endpoint application status', 'provenance':'Actual isolated 0.4 QA; generated/reviewed synthetic intent is blocked because no real endpoint firewall is connected.'},
 'learning-review': {'path':'docs/guide/images/learning-review.png', 'title':'Exact two-server allowance review', 'provenance':'Actual isolated 0.4 QA; freezes two current Billing QA members and 10.50.10.21/32 to 443/tcp only. Desired intent, not real firewall application.'},
}
RED = '#d71920'; INK = '#152235'; MUTED = '#586779'; LINE = '#dde3e9'; PALE = '#fff0f0'
FONT_DIR = Path(os.environ.get('PRTHAK_GUIDE_FONT_DIR','/Users/pratik/.cache/codex-runtimes/codex-primary-runtime/dependencies/native/libreoffice-headless/libreoffice/LibreOfficeDev.app/Contents/Resources/fonts/truetype'))

# Declarative content is shared by HTML and PDF. Figures are original vectors;
# screenshots must come from the actual running application, with provenance.
def p(text): return {'type':'p', 'text':text}
def h(text): return {'type':'h', 'text':text}
def note(text, label='Operational boundary'): return {'type':'note','label':label,'text':text}
def bullets(*items): return {'type':'bullets','items':items}
def steps(*items): return {'type':'steps','items':items}
def table(headers, rows, widths=None): return {'type':'table','headers':headers,'rows':rows,'widths':widths}
def code(text): return {'type':'code','text':text}
def diagram(kind, caption, height=115): return {'type':'diagram','kind':kind,'caption':caption,'height':height}
def shot(key, caption, height=170): return {'type':'shot','key':key,'caption':caption,'height':height}
def shots(items, height=170): return {'type':'shots','items':[shot(k,c,height) for k,c in items]}

PAGES = [
 {'title':'Prerequisites first', 'subtitle':'Prepare the platform, access and recovery path before installing anything.', 'elements':[
  diagram('readiness','Readiness sequence: complete foundations and identity before enrolling preview-only endpoints.',96),
  table(['Prepare','Required before deployment'],[
   ['Controller platform','Same reviewed Git release and local installer on every Linux/systemd host. Root-owned Python 3.9+, Docker Engine and Compose v2 are host prerequisites; containers supply controller/DB runtimes. Use private basic.env.'],
   ['Endpoint platform','RHEL or Ubuntu, matching Linux amd64/arm64 binary, root installation, genuine systemd, ss (iproute/iproute2), firewalld and journal access. Fresh automatic discovery requires agent 0.3.0+ with learning_discovery_v1. Auto-allow needs agent 0.4.0+ with learning_auto_allow_v1. Go 1.23+ builds the binary.'],
   ['DNS and TLS','One stable application hostname. Server certificate SAN includes it; browsers, agents and LB readiness probes trust its chain. Every controller trusts the same endpoint issuing CA.'],
   ['Identity and secrets','Single-tenant Entra Web registration, tenant/client IDs, private client-secret file, existing initial Super Admin Object ID and approved organization MFA/Conditional Access.'],
   ['Network and recovery','Routes and scoped firewall permissions in the next page; actual SSH ports and approved bastion CIDRs; local console/recovery access; backup owner and a disposable enforcement lab.'],
   ['Central metadata','Saved DC/cloud catalogue and agreed application/tag names. Optional reviewed exact-IP CSV profiles or subnet location mappings may be prepared before agents.'],
  ],[108,403]),
  note('This is a development/lab release. Actual Ubuntu 24.04 systemd and Ubuntu 26.04/firewalld 2.3.1 container checks passed within their stated limits. Native RHEL 8/9, target-host fencing/WAN and live Entra acceptance remain. The 20-server pilot has not started.','Release status'),
  p('<b>Illustration key.</b> Product captures in this guide are actual local application screens with explicitly synthetic records. Native diagrams explain the design. Neither represents a connected organizational tenant or production deployment.'),
 ]},
 {'title':'Open only the documented paths', 'subtitle':'Destination ports are shown below. Stateful return traffic is required.', 'elements':[
  diagram('network','Control traffic and application traffic follow separate paths. The agent exposes no listening control port.',122),
  table(['Source','Destination','Protocol / port','Required when'],[
   ['Browser','Stable app/LB','HTTPS / TCP 443','Dashboard and Entra callback'],
   ['Endpoint agent','Stable app/LB','HTTPS + mTLS / TCP 443','Enrollment, report, policy, events'],
   ['Load balancer','Controller backends','TLS passthrough / TCP 8787','HA data path; HTTPS readiness probes'],
   ['Controller','PostgreSQL writer(s)','PostgreSQL TLS / TCP 5432','HA; metadata and traffic DBs'],
   ['Controller','login.microsoftonline.com','HTTPS / TCP 443','Entra discovery, token exchange, JWKS'],
   ['Browser','Approved Microsoft sign-in/MFA','HTTPS / TCP 443','Live sign-in; use approved endpoint allowlist'],
   ['Controller approved source','Endpoint management IP','TCP / actual SSH port(s), e.g. 22 or 2022','Managed-enforcement health proof'],
   ['Hosts using name resolution','Existing DNS resolvers','UDP/TCP 53','If DNS is used by the deployment'],
   ['Hosts using time sync','Existing approved NTP','UDP 123','If NTP is the chosen clock service'],
   ['Workload clients','Workload servers','Actual application ports, e.g. TCP 80/8443','Direct workload traffic; approved policy'],
  ],[91,133,128,159]),
  note('SSH health verifies actual listeners from a pinned source; it does not log in or install software. Enrollment uses trusted HTTPS + single-use token before certificate issuance; later agent APIs require mTLS. Browsers/callbacks need no agent certificate. Do not require client certificates globally at the LB.','TLS bootstrap and SSH direction'),
  p('<b>App URL:</b> <code>https://prthak.example.internal</code> (replace DNS). Public <code>:443</code> forwards controller TLS <code>:8787</code>. Direct standalone access may use <code>https://host:8787</code> consistently in DNS/TLS, agent and Entra settings. Loopback synthetic demo: <code>http://127.0.0.1:8787</code>.'),
 ]},
 {'title':'Install the same appliance at each site', 'subtitle':'One reviewed Git release and installer at Noida 81, Pune, AWS and every later management host.', 'elements':[
  diagram('controller','One application origin serves dashboard, enrollment and endpoint mTLS. Site routing is an infrastructure decision.',105),
  code('cp .env.example basic.env\nchmod 600 basic.env\n# Edit DATA_ROOT, NODE_ID, SITE and this host’s NODE_IP.\nsudo scripts/install-controller.sh --env-file basic.env'),
  steps(
   '<b>Prepare the host.</b> Use genuine Linux/systemd, a root-owned Python 3.9+ interpreter, Docker Engine/Compose v2, durable disk and scoped private routes. Supply required image access. The installer does not disable a host firewall or open ports.',
   '<b>Set unique local identity.</b> <code>basic.env</code> is a protected local copy of <code>.env.example</code>, parsed as data. Check auto-detected NODE_IP for peer reachability. Choose one private persistent DATA_ROOT; no unsafe symlinks/ancestors.',
   '<b>Open trusted HTTPS.</b> Initial origin is normally <code>https://NODE_IP:8787</code>. The installer prints the initial Super Admin token’s <b>file path</b>, never its value. Review the CA/fingerprint and keep the token private.',
   '<b>Create or join in Settings.</b> First host sets the shared cluster password. Another empty host uses an existing node IP and that password, with exact certificate review before transmission. Three eligible independent-site registrations become voters; later hosts are management-only.'),
  table(['Private item','Purpose'],[
   ['DATA_ROOT/config/controller','TLS/enrollment identity, protected launch settings and controller state.'],
   ['DATA_ROOT/controller + database + etcd','Private persistent application/database/consensus state and journals.'],
   ['/etc/prthak/data-root','Atomic boot pointer; a live move uses reviewed stopped-storage migration.'],
  ],[185,326]),
  note('Native required watchdog approval gates every database voter. More management controllers are allowed; they do not add database votes. Legacy external/SSH templates are advanced appendix material in docs/ha.md.','Setup boundary'),
 ]},
 {'title':'Connect Microsoft Entra ID', 'subtitle':'Entra authenticates the person; the Prṛthak database grants the role.', 'elements':[
  diagram('auth','Code + PKCE S256, single-use state/nonce and browser binding protect sign-in. The secret stays on the server.',158),
  shot('signin','Actual application sign-in UI staged in QA; no Microsoft request or real MFA was performed.',250),
  steps(
   '<b>Register single-tenant Web.</b> Entra admin center → App registrations → New registration. Choose this organization only. Set the exact <b>Web</b> callback shown below.',
   '<b>Protect credentials.</b> Copy tenant ID and application/client ID. Create a client secret under Certificates & secrets; install its value in a service-readable 0600 file. Do not use SPA/implicit grant or Graph directory writes.',
   '<b>Apply organization controls.</b> Configure enterprise-app assignment and MFA/Conditional Access. Group/app-role/email claims do not grant a Prṛthak role.',
   '<b>Bootstrap once.</b> Set an existing tenant user Object ID only with an empty app-user table. Sign in, remove bootstrap on every node, restart, then add a second approved Super Admin.'),
  code('SEG_ENTRA_TENANT_ID=REPLACE_TENANT_UUID\nSEG_ENTRA_CLIENT_ID=REPLACE_APPLICATION_CLIENT_UUID\nSEG_ENTRA_REDIRECT_URI=https://prthak.example.internal/api/v1/auth/callback\nSEG_ENTRA_CLIENT_SECRET_FILE=/etc/prthak/secrets/entra-client-secret\nSEG_BOOTSTRAP_SUPER_ADMIN_OID=REPLACE_EXISTING_USER_OBJECT_UUID'),
  p('<b>Session:</b> signature/issuer/audience/tenant/time-validated identity; hashed eight-hour local session, Secure/HttpOnly/Lax cookies and CSRF protection. Entra mode ignores legacy bearer tokens.'),
  note('Live tenant/MFA acceptance remains: test real redirect, DNS/TLS, egress, denied identities and both HA backends. Sign out is local only. Entra-side disablement/policy changes apply at next sign-in (no CAE).','Live configuration remains'),
 ]},
 {'title':'Grant access with exactly three roles', 'subtitle':'Only Super Admin can create or manage any application user.', 'elements':[
  table(['Capability','Read Only\nread_only','Admin\nadmin','Super Admin\nsuper_admin'],[
   ['View servers, services, locations, policies, traffic, alerts, activity','Yes','Yes','Yes'],
   ['Create/update/retire servers; tags, locations and groups','No','Yes','Yes'],
   ['Manage service groups, policies, learning, enrollment and reviewed firewall operations','No','Yes','Yes'],
   ['Create any user, including a Read Only user; assign any role','No','No','Yes'],
   ['Change roles, disable/reactivate users, revoke sessions','No','No','Yes'],
   ['Promote themselves or bypass the role checks','No','No','No'],
  ],[253,86,78,94]),
  shots([('access','Actual Users & access screen, using three fictional role examples.'),('grant','Actual grant form populated with a fictional existing identity; not submitted.')],160),
  steps(
   'Sign in as Super Admin and open <b>Users & access</b> (<code>/access</code>). Choose <b>Add Entra user</b>; enter the existing tenant user <b>Object ID</b>, optional display/email labels, and one role.',
   'Create the application access record, then have that user sign in with Microsoft. Unprovisioned or disabled users are denied. This creates access in Prṛthak, not an Entra directory account; there is no general JIT provisioning.',
   'Use the same page to change a role, disable/reactivate an account or revoke sessions. Local role/enablement changes revoke sessions immediately across controllers. Entra claims never override the stored role.'),
  note('Admin and Read Only cannot create any user or manage user access. The API enforces these boundaries independently of hidden/disabled UI controls. A Super Admin cannot change their own role or disable themselves; the last enabled Super Admin is protected.','Authority guardrails'),
 ]},
 {'title':'Install the endpoint agent', 'subtitle':'Install locally or with your approved software-distribution system. The agent calls out.', 'elements':[
  diagram('files','The stock installer preserves enrolled identity on reinstall and validates bootstrap files before starting systemd.',108),
  steps(
   '<b>Verify the matching package.</b> Obtain Linux amd64/arm64 0.6 material. Verify the Ed25519 archive signature with independently trusted release public keys before extraction; checksums alone are insufficient. Locally unsigned packages are labelled lab-only.',
   '<b>Prepare agent.json.</b> Start from <code>agent/config.example.json</code>. Set <code>controller_url</code> to the stable HTTPS origin and keep canonical file paths. Leave <code>enforce:false</code>, <code>learning_auto_allow:false</code> and <code>allow_firewall_changes:false</code> for initial onboarding.',
   '<b>Issue a 15-minute single-use token</b> as Admin/Super Admin immediately before installation. Save it in a root-owned mode-0600 file. Transfer only the public controller CA to the endpoint; the issuing private key stays on the controller.'),
  code('sudo install -d -m 0700 /etc/seg-agent\nsudo install -o root -g root -m 0600 ./endpoint.token \\\n  /etc/seg-agent/enrollment-token\nsudo ./scripts/install-agent.sh --ca-file ./controller-ca.pem \\\n  --token-file /etc/seg-agent/enrollment-token \\\n  ./agent/bin/seg-agent-linux-amd64 ./agent.json\nsudo journalctl -u seg-agent -f'),
  table(['Installed path','Purpose'],[
   ['/usr/local/bin/seg-agent','Compiled endpoint binary; product retains seg-agent path for upgrades'],
   ['/etc/seg-agent/config.json','Private agent configuration; prior file saved on explicit replacement'],
   ['/etc/seg-agent/controller-ca.crt','Public TLS trust anchor'],
   ['/etc/seg-agent/enrollment-token; bootstrap.env','Private bootstrap credentials/environment'],
   ['/var/lib/seg-agent/agent.crt; agent.key','90-day mTLS identity; authenticated renewal and tracked overlap'],
   ['/var/lib/seg-agent/','Private cache, registration state, durable queues and rollback journals'],
   ['/etc/systemd/system/seg-agent.service','Enabled systemd service; root/local firewall and journal access'],
  ],[238,273]),
  p('<b>Defaults:</b> control/heartbeat <code>60s</code>, fresh service discovery <code>900s</code>, request timeout <code>15s</code>, at most <code>500</code> spool batches. Change configuration, run <code>seg-agent --config /etc/seg-agent/config.json --check-config</code>, then restart the service. A different existing config requires <code>--replace-config</code>; staging supports <code>--no-start</code>. The installer neither enables firewalld nor disables UFW.'),
 ]},
 {'title':'Onboard automatically or reserve first', 'subtitle':'A successful authenticated report creates inventory; a planning record is not a live server.', 'elements':[
  diagram('enrollment','Choose automatic enrollment or an exact-hostname reservation. Both finish with authenticated inventory.',92),
  shots([('servers','Actual inventory screen, with synthetic hosts and services.'),('addserver','Actual Add server form staged with example hostname/IPs; not submitted.')],165),
  table(['Automatic onboarding','Manual planned registration'],[
   ['1. Open Install agent and generate an unbound single-use enrollment token.\n2. Install the matching binary/config/trusted CA/token locally.\n3. The agent creates a key/CSR, enrolls and immediately reports real inventory.\n4. The server appears automatically; no precreated record is required.', '1. Servers → Add server: enter exact hostname and optional planned numeric IPs.\n2. The pending row is Waiting for agent; planned IPs are unverified and excluded from source-policy membership.\n3. Generate the token bound to that reservation. Install it only on that hostname.\n4. Matching mTLS enrollment consumes the reservation; discovery establishes live inventory.'],
  ],[255,256]),
  h('Verify the first report'),
  p('Check hostname/IPs, OS/architecture, firewalld/UFW state, actual listeners and process/unit identity. SSH on 2022 is identified from sshd rather than guessed from the port. Confirm <b>Preview</b>, recent heartbeat and discovery timestamp. Heartbeats reuse inventory; a new scan runs every 15 minutes. Failed scans preserve last-known listeners with incomplete/error status.'),
  note('Use the reviewed server-retirement workflow only after owned-rule cleanup, learning/monitor cleanup acknowledgement and resolution of pending firewall operations. Retirement archives inventory/rejects the old identity and recalculates membership; it does not uninstall the service or modify endpoint rules. CSV IP profiles remain until separately removed.','Retirement is separate from uninstall'),
 ]},
 {'title':'Assign locations, tags and groups centrally', 'subtitle':'Agent discovery supplies technical inventory. Administrators supply business classification.', 'elements':[
  shots([('csv','Actual staged CSV review, showing synthetic current/future IP profiles.'),('subnet','Actual staged subnet review, showing synthetic eligible assignments.')],120),
  diagram('metadata','Per-field assignment precedence. Subnet mappings supply location only; absent tags remain absent.',76),
  steps(
   '<b>Create Locations first.</b> Add each DC/cloud name and geography. A server has one saved location and multiple custom tags. Renaming a location preserves its immutable ID and group/policy references.',
   '<b>Choose an assignment method.</b> One server: settings. Multiple servers: select explicit IDs → Assign tags & location → preview → apply. Merge changes only supplied keys. Manual tag removal and explicit Unassigned remain pinned until returned to automatic.',
   '<b>Prepare current/future IPs.</b> Servers → Import CSV. Validate all rows, inspect effective before/after changes and apply separately. Blank cells preserve profile values; unknown DCs/ambiguous addresses are errors. Manage imported IP profiles reviews removals separately.',
   '<b>Map subnets.</b> Locations → Subnet location mappings → choose CIDR and existing saved location → preview → apply. Longest prefix wins per address; contradictory DC matches across a server remain a visible conflict.'),
  code('ip,application,dc,network_zone,criticality,tag.owner\n10.241.1.21,billing,Noida 81,production,high,finance'),
  p('<b>Groups:</b> save an arbitrary tag scope as a dynamic group (future matching servers join automatically) or choose explicit members for a static group. Example: <code>application=billing</code> targets the Billing application across DCs. Filters use OR within one category and AND across categories. A policy can target saved groups or a tag selector.'),
  note('Review central assignments because they can change source/target membership and intended bundles. Metadata apply never authorizes firewall writes. An approved source group resolves reported endpoint IPs, which are not cryptographically authenticated packet identity.','Membership and enforcement are distinct'),
 ]},
 {'title':'Align each policy row with its sources', 'subtitle':'The selected server is the destination. Each row defines its own ports and source union.', 'elements':[
  shot('policies','Actual 0.6 synthetic Payments Web rows: 80/443 with source-tag selectors. Intended access is not proof of enforcement.',164),
  steps(
   '<b>Choose targets and ports.</b> Policies → Create policy: select saved target server group(s) or an AND tag selector. Each service row chooses one exact TCP/UDP port or one saved service group. Review target hosts; an explicitly empty target selector covers the fleet.',
   '<b>Attach sources to that row.</b> CIDRs, matches of a source tag selector (all its tags) and members of multiple existing source server groups form one union for every port in the row. A separate row keeps another port aligned with different sources. Empty resolved sources allow nobody.',
   '<b>Review current membership.</b> Dynamic source groups follow effective central tags/location; static groups use their selected enrolled members. Membership/IP changes recompile intended access. Overlapping enforce rows union enforcing sources only; monitor rows never widen them. Only effective access changes advance host versions.'),
  diagram('service_sources','Source unions stay inside their own row; a database row does not inherit Web clients.',115),
  note('Normal policy/catalogue edits change intended configuration; changed compiled bundles need a new managed rollout review. Automatic learning uses separate exact-source authority after independent initial review; it does not approve this compiled bundle.','Normal policy review'),
  p('<b>Other pages:</b> Overview combines scoped health/topology; Alerts supports acknowledgement and recovery; Activity shows individually attributed Entra actions; Firewall imports exact runtime/permanent rules and common patterns. Supported imported-rule edits require separate endpoint opt-in, immutable preview and confirmations. Unsupported entries remain view-only.'),
 ]},
 {'title':'Enforce a normal managed bundle', 'subtitle':'Start with a disposable supported host, protected management routes and a recovery console.', 'elements':[
  diagram('enforcement','Managed state sequence. Fresh health proof gates runtime staging, permanent commit and final success.',110),
  steps(
   '<b>Prepare local protection.</b> Pin restricted <code>management_sources</code>; never use /0. Discover actual SSH ports, resolve UFW/conflicting zones/rules, confirm firewalld/systemd readiness, and retain <code>enforce:false</code> until the reviewed lab activation.',
   '<b>Configure every controller vantage.</b> Set a local <code>SEG_MANAGEMENT_PROBE_SOURCE_IP</code> inside approved management CIDRs and scoped <code>SEG_MANAGEMENT_PROBE_TARGET_CIDRS</code>. Route from that source to every actual SSH port on the approved endpoint address.',
   '<b>Review desired enforced policy.</b> In Policies → Managed rollouts, freeze explicit server IDs, target addresses, services, source lists, version/digest and protected configuration. The preview creator submits first. A different enabled Entra Admin/Super Admin opens the same pending review and types its exact phrase using the fresh nonce.',
   '<b>Enable local enforcement and verify outcome.</b> The agent admits only that authorized binding, checks a fresh controller mTLS connection and SSH banners, journals writes and arms independent systemd rollback. Inspect actual applied outcome and runtime/permanent read-back; independently test new allowed and denied connections.'),
  shot('rollouts','Actual 0.6 cancelled lab review, 0/2 confirmations and no endpoint result. No production approval is represented.',145),
  note('The small adapter admits 64 rich rules; capable 0.6 agents use bounded prepared source banks for larger bundles. Missing banks or unsupported contexts block before mutation. Normal independent rollback deadline is 120 seconds. Failed approvals stay held across restarts. Risky production changes require a requester and a different live, enabled same-tenant Entra Admin/Super Admin. Shared-token/demo lab confirmations are explicitly lab-only; two clicks do not establish two people.','Enforcement limits'),
  p('<b>Rollback/removal:</b> restoring an older policy creates a new revision/version and requires fresh approval. Removing the final enforcing policy needs an explicit <b>Remove Prṛthak-managed rules</b> rollout. Disabling the local switch alone leaves committed restrictions installed. Existing established sessions retain kernel state; egress, forwarding and containers are outside this adapter.'),
 ]},
 {'title':'Operate HA, health and recovery', 'subtitle':'Application active-active needs one authoritative writer per database and redundant ingress.', 'elements':[
  diagram('ha','HA controllers share metadata, traffic, user/session state and endpoint trust. Site placement alone does not provide database DR.',148),
  table(['Check / operation','Expected behavior'],[
   ['/healthz','Process liveness; can be 200 while a database is unavailable.'],
   ['/readyz','Dependency readiness; 503 removes a node from LB rotation when required shared storage is unavailable.'],
   ['/api/v1/cluster','Authenticated node/site/storage status. Shared node heartbeat is 10s; stale after 30s.'],
   ['Controller loss','Another ready node serves the same endpoint identity, inventory, policy and browser session. No SQLite fallback.'],
   ['Endpoint/controller outage','Committed rules persist. In-progress failed health rolls back. Failed approvals remain held; no outage-triggered allow-all.'],
   ['Storage and locks','Use both shared writer endpoints and session-preserving PostgreSQL connections. Transaction/statement pooling is unsuitable for leadership session locks.'],
  ],[145,366]),
  bullets(
   '<b>Drills.</b> Test stable-URL enrollment, existing mTLS policy delivery and Entra callback/session use on each node. Stop one controller and verify readiness removal, continued service and unchanged identity.',
   'Test metadata and traffic database outages separately; prove readiness failure with no alternate local writer. Coordinate database promotion with fencing so two sites never accept independent writes.',
   'Back up metadata/traffic, PKI, auth configuration and release/schema coherently. Protect backups and rehearse restore, policy/history continuity, agent reconnect and measured RPO/RTO.',
   'Verify real management routes, console recovery, timer rollback and reload/reboot/failure behavior on selected OS/SELinux/polkit combinations.'),
  note('Settings workflows follow. Private three-node wiring passed; native watchdog/site-failure acceptance and redundant external LB/DNS remain required.','Recovery boundary'),
 ]},
 {'title':'Validate, record evidence, then pilot', 'subtitle':'Implemented behavior, limited lab evidence and production readiness are different claims.', 'elements':[
  diagram('evidence','Evidence ladder: implemented code → isolated validation → live tenant/platform acceptance → approved pilot → measured fleet rollout.',80),
  table(['Capability','Evidence now','Still required'],[
   ['Application / three-role access',VALIDATION_EVIDENCE,'Real tenant, MFA/Conditional Access, proxy, identity lifecycle and HA login acceptance.'],
   ['Linux discovery/enrollment','Ubuntu 24.04 and RHEL UBI 9.8 ARM64 socket/mTLS smoke passed.','Selected OS/CPU matrix; full RHEL systemd/SELinux/polkit testing.'],
   ['Linux firewall paths','Ubuntu 24.04.4 ARM64/systemd/firewalld 2.1.1: normal policies and 0.4 overlays, exact 443 scope, SSH 2022, independent SIGKILL rollback, stop persistence, deletion; full controller/agent wire passed.','RHEL VM (UBI lacked firewalld); IPv6/reload/reboot/failure matrix; real bastion path.'],
   ['HA application','Shared PG, actual HTTPS recovery, three-node PG/etcd leaf/restore helpers and coordinated rotation passed separate private fixtures.','Native watchdog reset, promotion/fencing, real site partitions, redundant ingress and recovery objectives.'],
   ['5,000-server target','5,000 synthetic records; direct DB compiler/approval/poll benchmarks.','Real agents, WAN/TLS, enrollment bursts, sustained flows, soak and incident/query load.'],
  ],[107,202,202]),
  h('Acceptance checklist'),
  bullets(
   '<b>Platform/network:</b> approved runtimes, selected OS matrix, stable DNS/TLS, port directions, actual SSH ports, management vantage and recovery console verified.',
   '<b>Identity:</b> live Entra sign-in/MFA; all three roles; no Admin/Read Only user creation; unprovisioned/disabled denial; local role/disable/session revocation and expiry; bootstrap removed.',
   '<b>Onboarding:</b> automatic and reserved-host installation; one identity after restart; fresh listener/process discovery; central CSV/subnet/manual precedence and conflicts checked.',
   '<b>Access:</b> row-local sources; per-host fresh/filtered learning; normal rollout confirmations and separate learned-overlay guards/status; allowed/denied tests, read-back, rollback and cleanup.',
   '<b>Operations:</b> node/DB loss, backup restore, retention/volume and capacity measured. Record release, configs, test results, owners and approval before the 20-server pilot.'),
  note('Production work also includes managed certificate renewal/revocation, signed release distribution/bundle authority, independent approval/tag-scoped permissions where required, external alert delivery and trustworthy long-term evidence. Dashboard alerts exist; Slack/email/webhook dispatch is not implemented.','Known limits'),
  p('<b>References:</b> README; docs/authentication.md, security.md, ha.md, api-contract.md, managed-enforcement.md, linux-validation.md and scale-validation.md; agent/config.example.json; scripts/install-agent.sh. External Entra references and original screen captures are included in the companion HTML. Date: '+STAMP+'.'),
 ]},
]

# Expand dense operations topics into separate readable pages. All essential
# instructions are prose/tables; a screenshot is never the only instruction.
original = PAGES
entra = original[3]
auth_figure = entra['elements'][0]
entra['elements'] = [entra['elements'][1], entra['elements'][2], entra['elements'][3], entra['elements'][5]]
auth_page = {'title':'Understand the two identity paths','subtitle':'Human Entra sessions and endpoint mTLS are separate credentials with separate lifecycles.','elements':[
 diagram('auth','The controller exchanges the code, validates the ID token, then checks enabled application access.',235),
 p('<b>Browser:</b> authorization code + PKCE S256, one-use state/nonce and browser binding. The controller verifies RS256/JWKS signature, issuer, audience, configured tenant and time. The client secret stays on the server.'),
 table(['Human access','Endpoint control access'],[
  ['Identity: Entra tenant ID + user Object ID (tid:oid).','Identity: enrolled client certificate CN assigned to server UUID.'],
  ['Authority: enabled application-user record and exactly one DB role. Email, groups and role claims grant no authority.','Enrollment: 15-minute single-use token + locally generated key/CSR. A matching retry recovers the same identity.'],
  ['Fixed 8-hour local session; hashed at rest. Secure, HttpOnly, SameSite=Lax cookie and CSRF-protected mutation.','Client-auth certificate: 90 days. Agent always verifies HTTPS server trust; no insecure skip-verify option.'],
  ['Role/disable/session revocation applies immediately across HA nodes. Sign out ends only the local session.','Agent identity does not log into Entra. Enrollment transfers no business tags/location or firewall permission.'],
 ],[255,256]),
 note('Entra-side account/policy changes apply on the next sign-in; existing local sessions have no CAE/token-refresh integration. Endpoints support authenticated renewal before expiry, tracked overlap and explicit revocation/recovery. Internal-node renewal and suspension are separate. Entra-side changes still lack CAE; live tenant acceptance and complete compromised-CA recovery remain required.','Lifecycle limits'),
 p('<b>No LDAP bind:</b> this integration does not use LDAP TCP 389 or LDAPS TCP 636. Controller-to-Microsoft HTTPS and browser-to-approved Microsoft sign-in/MFA HTTPS are the identity network paths.')
]}
agent = original[5]
agent_files = {'title':'Know the installed files and intervals','subtitle':'Keep the canonical paths and private state so reinstall preserves the enrolled identity.','elements':[
 agent['elements'][0],agent['elements'][3],agent['elements'][4],
 code('{\n  "controller_url": "https://prthak.example.internal",\n  "interval_seconds": 60,\n  "discovery_interval_seconds": 900,\n  "request_timeout_seconds": 15,\n  "enforce": false,\n  "learning_auto_allow": false,\n  "allow_firewall_changes": false\n}'),
 note('The excerpt omits other supported options; start from agent/config.example.json. Keep management_sources scoped before enforcement. Certificate/private-key files stay on the endpoint; never copy one enrolled identity across hosts.','Configuration example')
]}
agent['elements']=[shot('install','Actual local installation-instructions dialog. Complete commands and paths are written below.',260),agent['elements'][1],agent['elements'][2],note('The installer enables/restarts systemd after validation and reports ready or automatic retry status. A changed existing config requires --replace-config. Reinstallation keeps matching certificate/key identity. UFW is detected, not disabled.','Installation behavior')]
meta = original[7]
meta_steps=meta['elements'][2]['items']
csv_page = {'title':'Review CSV and subnet assignments','subtitle':'Preview and apply are separate operations. Validate effective before/after values before applying.','elements':[
 steps(meta_steps[2],meta_steps[3]),
 code('ip,application,dc,network_zone,criticality,tag.owner\n10.241.1.21,billing,Noida 81,production,high,finance'),
 shot('csv','Actual synthetic CSV review: current/future profiles and preserved manual overrides.',185),
 shot('subnet','Actual synthetic subnet review: exact mapping and before/after effects.',168),
 p('<b>Guardrails:</b> invalid imports apply nothing. Relevant intervening state changes, expired reviews or replayed nonces reject apply. Removing an imported profile also requires a reviewed plan; manual values survive and automatic fields recalculate. Reports never supply business classification.')
]}
meta['elements']=[shot('locations','Actual synthetic location catalogue. Saved IDs survive renaming; every host has at most one location.',260),meta['elements'][1],steps(*meta_steps[:2]),meta['elements'][4],meta['elements'][5]]
service_groups_page = {'title':'Reuse service/port groups','subtitle':'Save shared ports once; preserve the sources attached to each policy row.','elements':[
 shot('service-groups','Actual Services catalogue with synthetic reusable port definitions and policy references.',205),
 steps(
  '<b>Create the definition.</b> Admin or Super Admin → Service groups (<code>/services</code>) → create a named flat set. Example: <b>Web</b> = <code>80/tcp</code> + <code>443/tcp</code>. Use 1-100 distinct exact TCP/UDP pairs; ranges and nested groups are unsupported. Read Only can inspect saved definitions.',
  '<b>Use the group in a policy row.</b> Select the saved service-group ID, then attach approved CIDRs, one AND source-tag/location selector and/or multiple existing source server groups. Every port in that row receives that union. Another port with different clients belongs in another row.',
  '<b>Review a global edit.</b> Preview referring policies, all their targets and hosts whose effective rules change. Save with the loaded <code>expected_revision</code>; a stale revision is rejected. One transaction records catalogue history, revises policy snapshots and compiles once. Renames do not advance unchanged host access versions.'),
 table(['Policy row','Ports','Sources for that row'],[
  ['Web group','TCP 80 + 443','Approved CIDR + Frontends + Load balancers'],
  ['Database port','TCP 5432','Database clients only'],
 ],[110,118,283]),
 note('Used service groups and server groups referenced by a policy cannot be deleted until references are removed. History keeps actual port/revision snapshots. Restoring an old policy resolves the current catalogue and current source membership; missing references are rejected. Effective changes need new managed review.','Stable identities and history'),
]}
automatic_learning_page = {'title':'Discover each endpoint before learning','subtitle':'Automatic mode requests a fresh scan and freezes a separate port set for every selected host.','elements':[
 shot('auto-learning','Actual automatic-learning dialog using selected synthetic endpoints and a cached preview.',205),
 steps(
  '<b>Upgrade and select.</b> Use agent <b>0.3.0+</b> reporting <code>learning_discovery_v1</code>. Select explicit servers → Start learning. Automatic discovery is the default; manual ports remain available to older agents.',
  '<b>Start a bounded window.</b> Choose 60 seconds to seven days. Preview is cached; start requests fresh scans. Each host freezes its own first valid TCP/UDP snapshot. Other hosts’ ports and later listeners never expand it.',
  '<b>Inspect status and coverage.</b> Only wildcard or known non-loopback TCP/UDP binds qualify. Unknown/loopback-only binds are excluded. Pending/offline/error, over-100-port and no-listener results add no instrumentation for that host. Discovery errors retry while time remains; a later listener needs a new window.'),
 note('Expiry includes discovery/retry/outage time; one hour requested does not guarantee one hour observed. Observe-only mode writes log rules and changes no access. Auto-allow is a separate opt-in described next; exact allowances require consent and independent initial review.','Collection time and behavior'),
 shot('traffic','Actual Traffic view: historical synthetic events, collection windows and incomplete coverage.',116),
 p('Stop/local expiry removes owned rules; inspect cleanup acknowledgement and Traffic coverage/loss. Retention defaults to 24 hours; each query is bounded to 500 aggregate rows.'),
]}
learning_actions_page = {'title':'Choose learning behavior and exact ports','subtitle':'Discover scope first, then choose observation with review or explicitly authorized automatic allowances.','elements':[
 shots([('learning-actions','Focused QA port filter: 443/tcp only in the cached preview.'),('learning-auto-consent','Separate focused QA frame: staged auto-allow choice and explicit consent.')],190),
 table(['Choice','Access behavior'],[
  ['Observe and recommend','Collect evidence only. Review selected source/service pairs and targets before applying learned allowances.'],
  ['Auto-allow observed sources','After explicit consent, fresh scope and independent initial approval, eligible sources may add exact allowances during the active window.'],
 ],[143,368]),
 steps(
  '<b>Select endpoints and services.</b> In Start learning, choose explicit server IDs and automatic service discovery. To learn only <code>443/tcp</code>, enable <b>Limit learning to selected ports</b> and enter that pair. A host running 22, 80 and 443 still learns only its matching 443 listener.',
  '<b>Keep the filter exact.</b> A fresh per-host scan is intersected with <code>port_filter</code>; other listeners stay visible in inventory. Copying a service group takes its current port snapshot. Later catalogue/listener changes do not expand this window.',
  '<b>Choose Policy behavior.</b> Observe and recommend remains available. Auto-allow requires discovered mode, the capability, explicit unwanted-client consent and independent approval of the fresh frozen scope. Use the current 0.6 signed-assignment agent.'),
 note('Counts and verdicts describe sampled inbound observations, including unwanted or denied attempts; they do not prove successful connections or trusted dependencies. Consent alone grants no authority. Independent approval binds the exact scope; neither approval nor an observed hit proves a client is safe.','Meaning of the consent'),
]}
learning_overlay_page = {'title':'Enable the separate learned overlay','subtitle':'Learning-owned rules add exact accepts. They do not install rejects or change default zones.','elements':[
 diagram('learning_overlay','Observation-derived exact host tuples enter a separate learning-owned overlay; agent verification confirms application.',104),
 steps(
  '<b>Prepare the endpoint.</b> Upgrade to agent 0.4.0 with <code>learning_auto_allow_v1</code>. Set both local switches below, pin management sources, and verify actual SSH/controller protection and the controller health vantage.',
  '<b>Approve the frozen window.</b> Start discovered auto-allow with explicit consent. After every host finishes fresh discovery, the requester submits the initial authority and a different Entra administrator approves its exact hosts, ports and protection binding. Before approval, no automatic access authority exists.',
  '<b>Check the agent result.</b> The agent requires fresh SSH/controller health, journals mutations, arms independent rollback and reads back owned rules. Pending/generated intent is not applied access.'),
 code('"enforce": true,\n"learning_auto_allow": true'),
 table(['Guard','Result'],[
  ['Exact source and service','IPv4 /32 or IPv6 /128 host sources only, bound to one exact protocol/port. Invalid/non-unicast sources are excluded.'],
  ['Protected management','SSH and local controller API ingress are excluded from learned opening. Use the ordinary protected policy workflow for SSH.'],
  ['Capacity and ownership','Legacy agents admit 64 tuples. Capable 0.6 agents admit 10,000 exact source/port tuples across 64 services using separate prepared banks. Only learning-owned accepts change.'],
  ['Active authority','New automatic grants require an active window. A later reviewed recommendation has separate explicit authority.'],
 ],[143,368]),
 note(OVERLAY_LIVE_VALIDATION,'Validation boundary'),
]}
learned_policy_page = {'title':'Operate learned allow policies','subtitle':'Policies shows learned allowances separately, including actual application state reported by the endpoint.','elements':[
 shot('learned-policies','Focused actual QA auto-generated card. Synthetic learned policies are blocked: no real endpoint firewall is connected.',205),
 table(['Status','Operational meaning'],[
  ['Generated / Pending agent','Queued intent; no matching endpoint verification yet.'],
  ['Applied - agent verified','The endpoint verified the matching learned revision/generation after checks and read-back.'],
  ['Preview / Blocked / Failed','Application is unverified. Inspect the reported opt-in, protection, capacity, health or failure reason.'],
  ['Rolled back','The attempt was restored; its proposed allowances are not installed.'],
  ['Removal pending / blocked','Cleanup awaits verified endpoint success and remains visible.'],
 ],[151,360]),
 steps(
  '<b>After stop or expiry:</b> collection and new automatic grants end. Committed allowances persist until a reviewed change/removal is verified.',
  '<b>Edit sources:</b> preview the exact revision and sources, submit, then obtain a different Entra approver. An applied reviewed edit stops automatic additions and suppresses removed pairs for that session/host.',
  '<b>Remove:</b> submit the exact cleanup review and obtain independent approval. Wait for endpoint verification; resolve blocked removal before retiring the host.'),
 note('These are additive accepts. They do not establish default-deny, close other ports, add rejects, alter default zones or prove end-to-end reachability. Existing broad firewall allows may still permit other clients.','Access scope'),
]}
learning_review_page = {'title':'Review observed access and export evidence','subtitle':'Keep the exact source-to-service relationship while choosing where to apply it.','elements':[
 shots([('learning-evidence','Focused QA evidence: two synthetic source IPs to Nginx 443/tcp, with counts 3 and 1.'),('learning-review','Separate focused review: one source /32 to 443/tcp on two selected synthetic targets.')],190),
 steps(
  '<b>Open Review observed access</b> on a learning session. Inspect source IP, observed server, exact TCP/UDP port, discovered service/process, counts, verdicts, first/last times and coverage. Unknown identity stays unknown.',
  '<b>Select observations and targets.</b> Page through the evidence, select exact pairs, then choose explicit servers or saved server groups. Preview freezes current group membership as explicit target IDs; future members do not inherit this review.',
  '<b>Preview selected access.</b> Resolve protected-service/capacity/agent blockers and inspect the exact source/service matrix of every target. Evidence, membership or protected target-state changes invalidate the review. The requester submits; a different Entra administrator approves the same binding with its typed phrase. Then inspect Learned allow policies for actual agent outcomes.',
  '<b>Export all observed pairs - CSV.</b> The session export includes all retained pairs beyond the 500-row traffic display bound. Durable evidence survives raw traffic retention pruning; the export is not limited to the displayed page or selected rows.'),
 note('Review/apply creates separate learned allow policies, not the normal compiled managed bundle. Endpoint local opt-in, health, protection, exact-source capacity and rollback checks still apply. An observation or saved review alone is not proof of firewall application.','Reviewed application'),
]}

# Keep the final evidence page readable. References and originals are in HTML.
original[11]['elements'][0]=diagram('evidence','Implemented, isolated tests, live acceptance and fleet rollout are distinct evidence levels.',57)
original[11]['elements']=[e for e in original[11]['elements'] if not (e['type']=='p' and '<b>References:</b>' in e['text'])]
PAGES=original[:4]+[auth_page]+original[4:6]+[agent_files]+original[6:8]+[csv_page,service_groups_page]+original[8:9]+[automatic_learning_page,learning_actions_page,learning_overlay_page,learned_policy_page,learning_review_page]+original[9:]
# Preserve the 21 onboarding/learning topics; replace legacy default setup
# pages with focused appliance operator workflows. Historical external templates live
# only in the advanced runbook appendix, never as the default installation.
PAGES += [
 {'title':'Back up data and review demo cleanup', 'subtitle':'Super Admin operations. Database archives are only one part of full recovery.', 'elements':[
  shot('platform-backups','Actual local demo: a database archive was created and verified; no real endpoint changed.',55),
  shot('platform-demo-review','Actual staged review: edited/legacy policy records are retained, confirmation blank; no deletion.',120),
  steps(
   '<b>Create → inspect → download.</b> Settings → Backups. Inspect members, schema metadata and hashes; download to protected recovery storage. SQLite uses online snapshots; PostgreSQL uses real custom dumps with application writer locks.',
   '<b>Validate structure.</b> The GUI checks archive/component hashes, SQLite integrity/schema or PostgreSQL catalogue. It does not replace a running database. An actual isolated offline dump/restore drill passed separately.',
   '<b>Review demo removal.</b> Inspect proven eligible synthetic counts/dependencies and type the exact phrase. A verified automatic pre-clear backup must succeed before mutation. Mixed real-data dependencies block unsafe deletion.'),
  table(['Recovery item','Treatment'],[
   ['Database archive','Sensitive accounts, identities, audit, policy and traffic; private 0600 bytes. Copies remain local to their executing controller.'],
   ['Separate protected recovery','PKI/issuing keys, Vault, vault.key, active profile, environment and Entra secrets are excluded. Preserve separately.'],
   ['Demo cleanup','Only proven fixtures. Real/manual/shared records, edited/legacy policies without seed proof, accounts and audit survive. Successful removal disables reseeding.'],
  ],[145,366]),
  note('Restore requires fenced writers and compatible metadata/traffic recovery points plus matching protected trust/state. Never expose an independent restored writer alongside the authoritative deployment.','Recovery boundary'),
 ]},
 {'title':'Schedule verified database backups', 'subtitle':'Durable schedules execute in the background; a saved schedule is not a successful backup.', 'elements':[
  shot('platform05-schedule','Actual 0.5 scheduling controls on local staged/demo data. No production backup schedule is implied.',195),
  steps(
   '<b>Choose a schedule.</b> Settings → Backups: daily or weekly local wall-clock time, or a 1-168 hour interval. Use an IANA timezone; default <code>Asia/Kolkata</code>. Weekly weekday is Monday 0 through Sunday 6.',
   '<b>Review next/last results.</b> Enable and save the current revision. Inspect next run, last run, last success and error. Restart retains intent; a missed slot is caught up once, without replaying every missed backup.',
   '<b>Choose retention deliberately.</b> Retain 1-365 successful scheduled archives. Deletion occurs only after a verified successful scheduled replacement. Manual and pre-cleanup backups are preserved.',
   '<b>Protect off-node recovery.</b> Shared PostgreSQL elects one due-slot worker across controllers. The archive bytes remain on that executing node; arrange protected replication or an explicitly shared archive directory.'),
  note('No local/manual/scheduled overlap is assumed successful. Failed jobs remain visible. Archive structure checks do not prove an end-to-end recovery; rehearse an offline restore and measure recovery time.','Operational checks'),
 ]},
 {'title':'Create or join the controller cluster', 'subtitle':'Shared password plus verified peer identity; an IP address alone grants no authority.', 'elements':[
  shot('platform05-appliance','Actual 0.5 local Controller cluster setup. Demo/manager-unavailable states remain explicit; no real cluster was installed from this screen.',180),
  steps(
   '<b>First host.</b> Sign in as Super Admin, set the cluster name, site, reachable node IP and intended origin. Set the shared cluster password; initial replication password is 32-128 printable ASCII characters.',
   '<b>Another host.</b> Install the same release using its own basic.env. Join from an empty controller using a reachable existing controller IP/HTTPS URL and the shared password.',
   '<b>Review before transmission.</b> Inspect the peer certificate, independently compare its fingerprint, and type the exact TRUST … AND JOIN phrase. Until approval only the public certificate is fetched; no password is sent.',
   '<b>Wait for actual readiness.</b> Private replies are sealed to the persistent node RSA key. Three distinct-site voters must be present and native fencing approved before database activation. A staged/accepted command is not healthy shared storage.'),
  note('Local populated inventory/policy/learning/traffic cannot be merged into another cluster. Same-key retries preserve membership and issued certificate. Replacing a registered IP/site/key requires review. New enrollment waits during an active replication-password rotation.','Membership guards'),
 ]},
 {'title':'Place voters and route clients by site', 'subtitle':'Three database copies; additional management controllers have no three-node limit.', 'elements':[
  diagram('site-routing','Illustrative Noida 81/Pune/AWS placement and external routing. These labels do not claim a deployed customer network.',172),
  table(['Role','Data and authority'],[
   ['Three independent-site voters','Each runs PostgreSQL 16/Patroni and etcd. One primary writes; strict synchronous replication requires an eligible standby. This is not the historical two-DB-plus-witness layout.'],
   ['Additional management controllers','Serve the same shared inventory, policies, accounts and traffic state. They do not add etcd votes or separate writable databases.'],
   ['Site-local preferred pool','Noida 81 clients prefer Noida; Pune clients prefer Pune; AWS clients prefer AWS. Configure reachable trusted fallback controllers and test real continuity.'],
   ['External routing','The appliance supplies a local router. Redundant site LBs, DNS/global routing, WAN paths and cloud infrastructure remain operator responsibilities.'],
  ],[150,361]),
  note('Loss of every eligible synchronous standby can stop writes. etcd majority alone does not prove a healthy writer or native fencing. A cloud host without suitable native watchdog support is not an accepted database voter.','Availability tradeoff'),
  p('<b>Trust:</b> database/etcd/Patroni use a dedicated internal CA; endpoint enrollment trust cannot authorize those services. A stable HTTPS origin and shared endpoint trust let agents reconnect without a new identity. Use verified /readyz routing probes; /healthz is process liveness only.'),
  p('<b>Private peer paths:</b> controller backend HTTPS 8786, PostgreSQL TLS 5432, etcd 2379/2380 and Patroni mTLS 8008. Restrict each path to its participants; backend 8786 is not public ingress.'),
 ]},
 {'title':'Control services and move stopped storage', 'subtitle':'Review exact owned actions; retain the old source until the new boot pointer is verified.', 'elements':[
  shot('platform05-storage','Actual 0.5 storage path review. Demo action is disabled; no filesystem move was performed.',90),
  shot('platform05-services','Actual 0.5 Services empty state: no installed manager reports health, and no operation was requested.',90),
  steps(
   '<b>Services.</b> Select controller, database, etcd, router or all owned services. Review start/stop/restart, then type the exact confirmation. The restricted local root manager rechecks dependencies/quorum; no arbitrary command is accepted.',
   '<b>Storage review.</b> Validate a dedicated mounted target beneath /var/lib, /mnt, /srv or /data. Review the actual source/target/revision, blockers and typed phrase; a path string alone proves no mount durability.',
   '<b>Stopped migration.</b> Owned writers stop. Foreign bindings, unsafe symlinks/tablespaces and unsafe watchdog state block copying. Contents, modes and ownership are checked and fsynced before the boot pointer changes atomically.',
   '<b>Verify and recover.</b> The original directory remains. Pre-commit failures retain the old pointer; post-commit failures retain the verified new pointer for controlled recovery. Inspect actual health before admitting the node.'),
  note('No running PGDATA copy is performed. DATA_ROOT covers controller/Vault, database, etcd, configuration, journals and backups; Docker engine/image/log cache and OS journals remain outside it. Moving a voter still needs a maintenance and console-recovery plan.','Persistence boundary'),
 ]},
 {'title':'Review TLS and replication credentials', 'subtitle':'Private previews and staged operations keep desired state distinct from verified application.', 'elements':[
  shot('platform05-certificates','Actual 0.5 certificate controls; no private key/password is shown and no certificate was applied from this capture.',180),
  steps(
   '<b>Choose certificate material.</b> Import matching PEM/key or PKCS#12 with its private password, or generate hostname/SAN material. Corporate identities need the complete public issuer/root chain, supplied or completed from known trust. Review validity, fingerprint, usage and matching key.',
   '<b>Confirm exact trust.</b> Generation retains the existing local issuing trust when available. A literal new self-signed server identity requires explicit trust-change acknowledgement. This does not silently rotate endpoint enrollment CA authority.',
   '<b>Apply and verify.</b> The runtime stages private files, restarts, checks readiness and retains the old pair for rollback. Verify the intended hostname through the actual router; a leaf-pinned local probe alone can miss a corporate-chain failure.'),
  h('Live replication-password changes'),
  p('An active edit stages all three voters without reload → changes the SQL role only on the observed primary → reloads all three → authenticates a genuinely new replication connection from every voter → finalizes all. Progress and errors remain visible until exact final acknowledgements. After durable role-change intent, recovery proceeds forward; it never blindly restores the old credential.'),
  note('Private keys, PKCS#12 passwords and raw replication passwords are excluded from public status/audit. Shared rotation metadata carries recipient-sealed envelopes; each controller refreshes its private material after completion.','Secret handling'),
 ]},
 {'title':'Manage polling and reported addresses', 'subtitle':'Control cadence centrally; address reporting does not create a NAT or routing service.', 'elements':[
  shot('platform05-polling-impact','Actual unsaved Billing 30s/300s override: 3 of 14 synthetic endpoints affected. Saved defaults remain 60s/900s; no apply.',185),
  table(['Setting','Bounds and default'],[
   ['Control / heartbeat interval','5-3,600 seconds; default 60 seconds.'],
   ['Discovery interval','60-86,400 seconds; default 900 seconds. Heartbeats reuse the last real scan.'],
   ['Override targets','Explicit enrolled servers, saved groups or AND tag/location selectors. Each interval resolves independently.'],
   ['Precedence','Higher priority, then explicit server, group, more-specific tags and stable rule ID. Supported agents report version/digest and current/pending/error status.'],
  ],[150,361]),
  steps(
   '<b>Preview scope and save.</b> Review affected hosts and changed intervals. Offline/unsupported agents stay visible; a controller save is not an endpoint acknowledgement.',
   '<b>Keep security local.</b> Polling intent cannot change enforcement, management protection, trust or credential paths. Use the supported agent release and inspect its observed status.',
   '<b>Read addresses correctly.</b> Inventory IPs come only from authenticated agent payloads; control-path NAT never replaces them. Reservations keep an empty live-IP list and planned/unverified addresses until a real agent report. Traffic source_ip is the kernel-observed source at the destination.'),
  note('Application-path NAT can hide the original client; recovering it needs separate mappings/logs. No NAT translation or IP-ownership proof is supplied. Source groups use reported addresses; shared NAT may collapse several clients into one source.','Address-ownership limit'),
 ]},
 {'title':'Record the recovery and release boundary', 'subtitle':'Actual wiring evidence supports a pilot decision; it does not replace native failure acceptance.', 'elements':[
  table(['Evidence','What it proves / does not prove'],[
   ['Actual shared PostgreSQL','Identity/epoch guards, fixed-table migration, durable queues, shared coordination, real archive restore and coordinator barriers. Separate CLI/Gunicorn HTTPS SQLite recovery drains/restarts a real child.'],
   ['Private three-node cluster','Real etcd mTLS, PostgreSQL 16/Patroni primary + two copies, SCRAM application writes, synchronous replication and read-only replicas.'],
   ['Replication credential operation','Full shared-PG coordinator on the actual three-node cluster: READY/epoch guards, SQL mutation once, mTLS reloads, new auth-all and finalized private materials. Separate concurrency/retry tests also pass.'],
   ['Native infrastructure still pending','Required watchdog reset, promotion/fencing under host/site partition, production WAN/ingress behavior and measured RPO/RTO. Test fixture watchdog was explicitly off.'],
   ['Platform and fleet still pending','Native RHEL 8/9 and target Ubuntu/systemd matrix, live Entra/MFA, 20-host pilot and real endpoint/WAN/soak acceptance.'],
  ],[150,361]),
  p('<b>Combined release checks:</b> '+VALIDATION_EVIDENCE),
  steps(
   '<b>Preserve coherent recovery.</b> Keep protected database copies plus PKI, Vault/key, active profile, environment and Entra material. Record release/schema, target identities, archive owners and recovery objectives.',
   '<b>Rehearse with fenced writers.</b> Restore compatible metadata/traffic, recover trust/identity, test enrollment and existing-policy continuity, then admit one authoritative deployment through routing.',
   '<b>Approve the pilot.</b> Record the selected native platform/failure results, workload tests, management/console paths, monitoring owners and explicit release approval. Expand only after measured pilot evidence.'),
  note('Signing, certificate lifecycle, reviewed notifications and supervised recovery are implemented and exercised in isolated fixtures. Actual provider destinations, live Entra, native DB watchdog reset, physical WAN partitions, site failover and real fleet/pilot acceptance remain external gates.','Remaining scope'),
 ]},
]
# 0.6 operations: explicit individual authority and actual runtime evidence.
def guide_page(title):
 page=next(page for page in PAGES if page['title']==title)
 for item in page['elements']:
  if item['type'] in ('steps','bullets'):item['items']=list(item['items'])
 return page

guide_page('Grant access with exactly three roles')['elements'][0]['rows'].insert(4,['Platform, certificates, notifications and recovery','No','No','Yes'])
for item in guide_page('Grant access with exactly three roles')['elements'][1]['items']:item['height']=125

guide_page('Open only the documented paths')['elements'][1]['rows'][2]=['Load balancer','Controller application ingress','TLS / TCP 8787 default','Reviewed local-node port changes are configurable']
guide_page('Open only the documented paths')['elements'][1]['rows'][3]=['Controller / local router','Appliance router / PG writer','PostgreSQL TLS / TCP 5433 → 5432','Managed shared storage; restrict both hops']
guide_page('Open only the documented paths')['elements'][-1]['text']+=' Review local port changes in Settings → Services.'
guide_page('Install the same appliance at each site')['elements'][1]['text']='cp .env.example basic.env\nchmod 600 basic.env\n# Set DATA_ROOT, NODE_ID, SITE, NODE_IP; optional Entra values.\nsudo scripts/install-controller.sh --env-file basic.env'
guide_page('Install the same appliance at each site')['elements'][2]['items'][2]='<b>Open trusted HTTPS.</b> Initial origin is normally <code>https://NODE_IP:8787</code>. The installer prints the initial setup token file path, never its value. Configure Entra before production policy/recovery approval; shared tokens cannot identify independent people.'

guide_page('Review CSV and subnet assignments')['elements'][-1]['text']='<b>Guardrails:</b> invalid imports apply nothing. Expiry, replayed nonces and relevant state changes reject apply. Exact CIDRs are unique after canonicalization; edit an existing mapping rather than duplicate it. The overlap/duplicate-address example later explains conflicts. Reports never supply business classification.'
guide_page('Discover each endpoint before learning')['elements'][3]['height']=90
guide_page('Discover each endpoint before learning')['elements'][-1]['text']='Observation uses runtime-only log rules with a firewalld timeout. No permanent collector rule or reload is used. Stop propagates at polling cadence; local expiry still ends collection offline. Inspect cleanup/loss receipts. Committed learned accepts have a separate lifecycle.'
guide_page('Enable the separate learned overlay')['elements'][1]['items'][0]='<b>Prepare the endpoint.</b> Use the signed 0.6 agent with learning capability, approved management sources and a working actual SSH/controller health vantage. Enable the local switches below only after the disposable-host review.'
guide_page('Validate, record evidence, then pilot')['elements'][1]['rows'][1]=['Discovery / enrollment','Ubuntu 24.04, Ubuntu 26.04 and RHEL UBI 9.8 ARM64 socket/mTLS/identity-reuse smoke.','Native OS/CPU matrix. UBI discovery is not RHEL firewalld/SELinux acceptance.']
guide_page('Validate, record evidence, then pilot')['elements'][1]['rows'][2]=['Firewall paths','Retained Ubuntu 24.04 systemd rollback/wire tests; Ubuntu 26.04/firewalld 2.3.1 real IPv4/IPv6 bank/readback and new TCP source-isolation checks.','Native RHEL 8/9, selected Ubuntu kernel/systemd, reload/reboot and actual bastion paths.']
guide_page('Validate, record evidence, then pilot')['elements'][1]['rows'][4]=['5,000-server target','5,000 virtual mTLS identities on local shared PostgreSQL; three two-worker cycles had no HTTP failures.','Real Linux agents, WAN/quorum latency, enrollment storms, kernel logging, large rollouts and long-duration load.']
guide_page('Validate, record evidence, then pilot')['elements'][-1]['text']='Live Entra/MFA, real provider delivery, native DB watchdog/fencing, physical site/WAN failure, target OS behavior and a measured 20-host pilot remain external acceptance. Role/tag-scoped administrative permissions beyond the three roles are not supplied. No fleet or production certification is claimed.'
guide_page('Validate, record evidence, then pilot')['elements'][0]['height']=45

guide_page('Record the recovery and release boundary')['elements'][-1]['text']='Implemented signing, lifecycle, reviewed notifications and supervised recovery have isolated evidence. Native fencing/site failure, actual tenant/provider integrations and target fleet acceptance still require deployment-specific results. Archive-only recovery without current trusted private material is blocked; no CA or safety ledger is invented.'

new_pages = [
 {'title':'Resolve subnet overlaps and duplicate addresses','subtitle':'Business classification is dashboard-owned; reported addresses do not establish ownership.','elements':[
  diagram('cidr','Illustrative longest-prefix classification without a manual override or exact-IP CSV profile.',128),
  table(['Mapping','Saved location','Example address result'],[
   ['10.0.0.0/8','Noida 81','10.23.5.9 → Noida 81'],
   ['10.241.0.0/16','Pune','10.241.2.7 → Pune'],
   ['10.241.1.0/24','AWS','10.241.1.21 → AWS'],
  ],[135,107,269]),
  steps(
   '<b>Keep one exact mapping.</b> Broad and narrow networks may coexist. The longest prefix wins per reported address. <code>10.241.0.1/16</code> canonicalizes to the existing <code>10.241.0.0/16</code>; a second copy is rejected even for the same DC. Edit the saved rule instead. /0 and missing locations are rejected.',
   '<b>Resolve multi-address disagreement.</b> If one endpoint has winning addresses in different DCs, classification is withheld with a visible conflict. Do not silently choose its first IP. Manual location overrides and exact-IP CSV values have their documented higher precedence.',
   '<b>Resolve shared addresses.</b> An exact-IP CSV profile is ambiguous when multiple endpoints report that IP, so its automatic values are withheld. Shared addresses within one DC are permitted; the same IP cannot represent different saved DCs. Later conflicting reports remain accepted as inventory while location conflicts are surfaced.'),
  note('Only authenticated agent payloads establish live inventory IPs. TCP peers, load-balancer/SNAT addresses and X-Forwarded-For/X-Real-IP never replace them. Manual reservations retain empty live IPs plus separately labelled planned/unverified addresses.','Address provenance'),
 ]},
 {'title':'Require two individual reviewers','subtitle':'An exact requester submission and a different current Entra person authorize a risky change.','elements':[
  diagram('approvals','Same digest, current nonce, live identities and immutable scope survive the handoff between reviewers.',118),
  shot('platform06-approvals','Actual 0.6 learned-access queue: no pending reviews or live Entra approvals.',135),
  table(['Workflow','Required people'],[
   ['Normal managed/restore and risky imported-rule changes','Requester plus a different enabled same-tenant Entra Admin or Super Admin.'],
   ['Manual learned grant, source edit/removal; initial auto-allow scope','Independent Entra requester/checker. Auto-generated exact hits can follow only after initial authority.'],
   ['Database recovery','Both requester and different approver must be live enabled Entra Super Admins. No shared-token production bypass.'],
  ],[190,321]),
  steps(
   '<b>Requester.</b> Create the immutable preview, inspect every target and source/service binding, then submit it. This first step grants no endpoint access or database restore.',
   '<b>Approver.</b> Sign in separately and open the same pending review. Check the exact digest, scope, blockers and expiry; type the displayed phrase. A maker cannot approve their own request. Stale data or role/session changes fail closed.',
   '<b>Verify runtime.</b> Approval is authority for that binding, not a successful change. Follow per-endpoint application/read-back or recovery job verification. Changed targets, sources, protection or evidence require a new review.'),
  note('Demo and explicit shared-token lab workflows are visibly single-actor fixtures. They cannot manufacture a second human identity or substitute for live tenant acceptance.','Identity boundary'),
 ]},
 {'title':'Verify packages and assignment signatures','subtitle':'Release trust, assignment authority, HTTPS and enrollment PKI are distinct.','elements':[
  diagram('signing','Pin release and assignment public trust independently of the artifacts or TLS endpoint they validate.',118),
  steps(
   '<b>Before extraction.</b> Obtain the release public manifest through an independent approved channel. Verify the exact archive filename, size, SHA256 and Ed25519 signature; an adjacent downloaded public key is not trusted merely because it arrived beside the archive.',
   '<b>Before mutation.</b> Agent 0.6 verifies an Ed25519 envelope binding the deployment, endpoint, version, exact sources/services, protection/approval, learning and polling assignment. Invalid, changed, foreign or expired authority blocks writes. Existing committed rules persist through controller outage.',
   '<b>Pin assignment trust.</b> Settings → Certificates shows public key IDs/fingerprints and downloads the public manifest. Distribute independently in protected <code>policy_signing_trust_file</code> or explicit keys/deployment ID. Authenticated first enrollment may pin initial trust; it does not replace previously pinned trust.'),
  code('python3 scripts/verify-release.py \\\n  --public-trust-file /trusted/release-public.json \\\n  --signature dist/prthak-agent-0.6.0-linux-amd64.tar.gz.signature.json \\\n  dist/prthak-agent-0.6.0-linux-amd64.tar.gz'),
  h('Optional isolated signing workstation'),
  p('Set both <code>SEG_POLICY_SIGNED_BUNDLES_DIR</code> and <code>SEG_POLICY_SIGNING_TRUST_FILE</code> for the offline provider. Export/review the complete unsigned assignment, sign with <code>scripts/sign-assignment.py</code> and the exact <code>SIGN REVIEWED ASSIGNMENT</code> phrase, then transfer the protected artifact. The controller holds public trust and reviewed artifacts only; no online-key fallback exists.'),
  note('Changed source membership, timing, authority or expiry requires a fresh signed artifact. The online signer uses a purpose-separated key, but a controller able to read that seed is not isolated from it. Unsigned outputs are lab artifacts. A local project release authority exists; it is not organization-approved or independently distributed. Adopt its public fingerprint through the approved DC process.','Signing operations'),
 ]},
 {'title':'Manage endpoint and node certificates','subtitle':'HTTPS replacement, endpoint identity, internal service leaves and issuer authority have separate lifecycles.','elements':[
  shot('platform06-certificates','Actual 0.6 endpoint lifecycle panel: no identities registered and no certificate operation.',168),
  table(['Credential','Operator lifecycle'],[
   ['Controller HTTPS','Import PEM/key (optional encrypted-key password), PKCS#12 or generate SAN material. Typed review; staged restart, readiness/fingerprint verification and old-pair rollback. Corporate imports need a verifiable complete issuer/root chain.'],
   ['Endpoint mTLS','90-day leaf, authenticated renewal inside the 30-day window, tracked 24-hour overlap and native client reconnect. Super Admin can revoke exact registered certificates or issue a 15-minute one-time recovery credential.'],
   ['Internal database/etcd/Patroni','Dedicated internal CA; 90-day leaves renew before 30 days with exact served-fingerprint checks and rollback. GUI reports expiry/renewal and typed member suspension.'],
  ],[145,366]),
  steps(
   '<b>Inspect actual identity.</b> Compare SANs, expiry, issuer and full fingerprint. Generated/imported material is not active until the runtime verifies the intended hostname and served pair; inspect actual router HTTPS too.',
   '<b>Revoke or recover an endpoint.</b> Review exact server identity/certificates and type the phrase. A recovery token is displayed once and is not saved in browser storage; it does not itself revoke a compromised old identity.',
   '<b>Suspend carefully.</b> Internal suspension blocks sync, renewal and routing admission. It does not revoke copied database credentials or the internal CA. Complete compromised-controller decommission requires fenced offline CA and all-secret recovery.'),
  note('Actual private native mTLS renewal/revocation, HTTPS PEM/PKCS#12 activation/restart/rollback and three-node internal leaf rollover were tested separately. A real organizational certificate/Entra/WAN deployment still needs its own acceptance.','Evidence boundary'),
 ]},
 {'title':'Review external alert destinations','subtitle':'Notifications default off. Configuration approval and provider acknowledgement are different states.','elements':[
  shot('platform06-notifications','Actual 0.6 notification settings: staged/disabled local demo, with no provider message sent.',160),
  steps(
   '<b>Super Admin configures.</b> Settings → Notifications: add Slack, HTTPS webhook or TLS SMTP, choose severity/event types and exact recipients. Review host, resolved addresses and recipients; type the exact destination phrase. Credentials remain masked and privately encrypted.',
   '<b>Use explicit sends.</b> A saved-destination test sends a real message only after its own confirmation. Normal delivery covers future matching alert occurrences. Down → recovered → down has distinct occurrence identities; acknowledgement updates do not create message floods. Recovery alerts are informational: choose Info plus <code>recovered</code> or <code>*</code>.',
   '<b>Inspect the outbox.</b> Pending/retry/failed/uncertain/provider-acknowledged states are durable. Known temporary failures back off with a bounded retry budget. Unknown post-send acknowledgement is held for explicit duplicate-aware retry unless the reviewed webhook guarantees idempotency.'),
  table(['Destination path','Required network/security'],[
   ['Controller → reviewed Slack/webhook','HTTPS TCP 443 or explicitly reviewed TLS port. Strict hostname/CA checks, pinned DNS addresses, no redirects; DNS changes require re-review.'],
   ['Controller → reviewed mail server','Explicit SMTP port, commonly 465 implicit TLS or 587 STARTTLS. Authentication/payload never fall back to plaintext.'],
   ['Private destinations','Explicit reviewed private-network opt-in. Loopback, metadata/link-local and transition-address bypasses are refused.'],
  ],[172,339]),
  note('Provider acknowledgement is not proof of inbox delivery. Stable delivery IDs, webhook Idempotency-Key/HMAC and SMTP Message-ID support tracing; SMTP/Slack cannot promise exactly once after an ambiguous network failure. Private TLS webhook/SMTP fixtures passed; real destinations remain operator acceptance.','Delivery semantics'),
 ]},
 {'title':'Recover a reviewed database archive','subtitle':'Two live Entra Super Admins authorize a supervised restore with the current safety ledger.','elements':[
  diagram('recovery','Writers are fenced/drained before verified candidates are released. A queued job is not restored data.',105),
  shot('platform06-recovery','Actual 0.6 Recovery page on the synthetic demo; restore is blocked and main data is unchanged.',135),
  steps(
   '<b>Prepare matching material.</b> Keep a complete verified archive on this controller and preserve current PKI, Vault, active profile and safety ledger. Archive-only or missing trusted private state blocks online recovery; it cannot invent replacement keys or claim offline DR.',
   '<b>Request and approve.</b> Settings → Recovery: select the exact local archive, give the incident reason and review its digest, backend, version and frozen controller scope. The requester submits; a different live enabled Entra Super Admin opens the same review and types its phrase.',
   '<b>Wait through draining.</b> Every writer/controller must pass its fence/profile/readiness barriers. HTTPS/APIs may be held or return 503. Transient helper failures retry the same immutable phase with durable backoff up to 60s; safety mismatches remain blocked. Original databases/private rollback material are retained.',
   '<b>Reconnect and verify.</b> Sign in again with Entra and inspect durable phase, node receipts/errors and verified completion. Sessions, unused credentials, pending approvals and auto-learning are invalidated. Current revocations, disabled users, retired identities and immutable history survive; policy application needs fresh review.'),
  note('Actual CLI/Gunicorn HTTPS SQLite recovery and crash-resume passed. Shared-PostgreSQL coordinator barriers and actual three-node PG 16 restore helpers were separate fixtures, not a complete physical WAN/fencing acceptance. Missing canonical hashes make older PG archives structural-only for this flow.','Recovery evidence'),
 ]},
]
# Web/server trust and endpoint issuer trust may be different after corporate TLS import.
agent_files['elements'][0]['height']=96
agent_files['elements'][1]['rows'][2]=['/etc/seg-agent/controller-ca.crt; endpoint-ca.crt','HTTPS trust; optional separate public endpoint issuer CA.']
agent_files['elements'][2]['text']='<b>Defaults:</b> control 60s, discovery 900s, request timeout 15s and 500 spool batches. Central signed polling settings can update cadence live. A changed local config needs --replace-config; keep state/identity and restricted management_sources. The installer does not enable firewalld or disable UFW.'
agent_files['elements'][3]['text']=agent_files['elements'][3]['text'].replace('  "interval_seconds": 60,','  "endpoint_ca_cert": "",\n  "interval_seconds": 60,')
agent_files['elements'][4]['text']='When web HTTPS and endpoint certificates have different issuers, set endpoint_ca_cert=/etc/seg-agent/endpoint-ca.crt and preinstall that trusted public issuer CA before preflight. Empty uses ca_cert. --ca-file installs web trust only; never transfer a CA private key.'
guide_page('Install the endpoint agent')['elements'][1]['items'][1]+=' If corporate/public HTTPS and endpoint issuing roots differ, preinstall the public endpoint CA and set endpoint_ca_cert separately before running the installer.'
new_pages[3]['elements'][0]['height']=142
new_pages[3]['elements'][2]['items']=list(new_pages[3]['elements'][2]['items'])
new_pages[3]['elements'][2]['items'][0]='<b>Pin each trust separately.</b> ca_cert verifies web HTTPS. If the endpoint issuer differs, set endpoint_ca_cert to its independently trusted public CA; the stock installer copies only web trust. Ed25519 assignment keys are a third pin. Renewal/recovery never accepts replacement roots from response material.'
new_pages[3]['elements'][-1]['text']='Actual Go-client loopback tests passed with same or separate web/endpoint CAs: renewal, immediate 403 on an already established revoked TLS connection and two fresh-key recoveries retaining the UUID. HTTPS PEM/PKCS#12 and three-node internal leaf rollback have separate private evidence; real target acceptance remains.'
new_pages[0]['elements'][0]['height']=76
new_pages[0]['elements'].insert(1,shot('platform06-subnet-ownership','Actual 0.6 location guidance: exact-CIDR uniqueness, longest prefix and conflicting IP/DC ownership.',95))

new_pages[2]['elements'][0]['height']=90
new_pages[2]['elements'].insert(1,shot('platform06-signing-download','Actual 0.6 public assignment-trust download. Private signing keys are never returned.',52))

# Place metadata clarification after assignment, authority/signatures before
# enforcement, and lifecycle/notification/recovery immediately before release.
for page in new_pages[:1]: PAGES.insert(next(i for i,p in enumerate(PAGES) if p['title']=='Reuse service/port groups'),page)
for page in new_pages[1:3]: PAGES.insert(next(i for i,p in enumerate(PAGES) if p['title']=='Enforce a normal managed bundle'),page)
for page in new_pages[3:]: PAGES.insert(next(i for i,p in enumerate(PAGES) if p['title']=='Record the recovery and release boundary'),page)

agent_files['elements'][3]['text']=agent_files['elements'][3]['text'].replace('  \"learning_auto_allow\": false,\n  \"allow_firewall_changes\": false','  \"learning_auto_allow\": false, \"allow_firewall_changes\": false')
guide_page('Operate HA, health and recovery')['elements'][2]['items'][0]='<b>Drills.</b> Test stable-URL enrollment, existing mTLS and Entra callback/session on each node. Stop one controller; verify readiness removal, continued service and unchanged identity.'

prerequisites=guide_page('Prerequisites first')['elements'][1]['rows']
prerequisites[1][1]='RHEL/Ubuntu selected native OS, matching Linux amd64/arm64 0.6 binary, root installation, systemd, ss, firewalld and journal access. The static Go endpoint and stock POSIX installer need no Python or Go runtime. Go 1.23+ is for builds only.'
prerequisites.insert(2,['Optional helper tools','Empty-bank preparation: Python 3.6+ stdlib and firewall-cmd, no cryptography. Release verification: Python 3.8+ syntax plus cryptography>=44; use an approved Python 3.10+ admin environment. RHEL 8 default Python 3.6 cannot run that verifier.'])
new_pages[2]['elements'].insert(2,p('Verify archives on an approved administration workstation before transfer/extraction. The verifier syntax needs Python 3.8+ and this release supports cryptography>=44; use Python 3.10+ for current tooling. Tested cryptography 50.0.2 itself requires Python 3.9+. The static endpoint has no Python dependency.'))

# Large source membership needs its own reviewed host preparation.
normal=guide_page('Enforce a normal managed bundle')
normal['elements'][0]['height']=85
normal['elements'][3]['text']='Small bundles admit 64 rich rules; larger capable-agent bundles need the prepared banks on the preceding page. Unsupported contexts block before mutation. The normal independent rollback deadline is 120 seconds; failed approvals remain held. Production requires different live Entra people; shared-token/demo authority is lab-only.'
banks={'title':'Prepare large source groups safely','subtitle':'Empty source banks are a separate maintenance prerequisite, not a live policy reload.','elements':[
 diagram('source-banks','Inactive-bank entry writes and rule references are journaled; the committed bank stays intact until verification.',112),
 table(['Capacity / context','Bounded 0.6 behavior'],[
  ['Ordinary small bundles','Up to 64 rich rules; no large-source adapter is implied.'],
  ['Managed source-set bundle','At most 128 rich rules, 32 distinct sets per address family, 10,000 entries/set and 40,000 entries/bundle. Identical source sets may be shared within one generation.'],
  ['Additive learning','Up to 10,000 exact source/port tuples across 64 services with learning_ipsets_v1. Separate learning banks preserve row-local sources and never create rejects.'],
 ],[153,358]),
 steps(
  '<b>Prepare in a maintenance window.</b> The one-time helper needs Python 3.6+ stdlib and firewall-cmd, no cryptography. Review baseline runtime/permanent state, actual management/bastion paths and console recovery. Run the helper below to inspect, then explicitly create only missing empty permanent hash:net definitions.',
  '<b>Activate deliberately.</b> firewalld cannot create supported runtime sets directly. Load the reviewed empty definitions through the separately approved host-maintenance procedure. Do not reload a live server merely to satisfy a pending policy. The agent never reloads firewalld during policy application.',
  '<b>Apply a fresh exact review.</b> The agent checks type/family/options, unrelated references and drift; fills/read-backs an inactive bank; stages rule references; checks management health; commits permanent state and verifies both scopes. Rollback restores references before exact previous bank contents.'),
 code('sudo python3 scripts/prepare-managed-ipsets.py\nsudo python3 scripts/prepare-managed-ipsets.py --apply \\\n  --confirm "PROVISION EMPTY PRTHAK SOURCE BANKS"'),
 note('Actual Ubuntu 26.04/firewalld 2.3.1 container checks passed IPv4/IPv6 set read-back, a 5,000-source bank switch, new TCP source isolation, failed-stage rollback and additive cleanup. Health/timer callbacks are test substitutes; native RHEL/Ubuntu/systemd and real DB watchdog/WAN tests remain.','Evidence boundary'),
]}
PAGES.insert(next(i for i,p in enumerate(PAGES) if p['title']=='Enforce a normal managed bundle'),banks)

# 0.6 current-node port control: actual CLI/Gunicorn and appliance publisher proof.
port_page={'title':'Change the application port safely','subtitle':'Super Admin changes this local listener/publisher; external dependencies remain explicit.','elements':[
 diagram('application-port','The configured public/SSO origin stays fixed. A new local listener needs its own verification.',85),
 shot('platform06-application-port','Actual 0.6 demo review 8787 to 9443; Apply is blocked and the current port is unchanged.',130),
 steps(
  '<b>Inspect this node.</b> Settings → Services → Application port shows last reported current, desired and last verified ports, bind address, configured origin and operation state. Range is 1-65535; appliance port 443 can be valid, while standalone permissions/collisions can block a low port before the old listener stops. Protected service/cluster ports stay blocked; no extra privilege is granted.',
  '<b>Review before changing.</b> Enter the exact port, create a revision-bound preview and inspect the current/proposed addresses. Only this local node changes. Acknowledge load-balancer targets, direct agent/controller URLs, Entra callback/origin, DNS and firewall dependencies; none is automatically rewritten.',
  '<b>Keep the new address.</b> Type the exact phrase and confirm dependencies. The proposed link is available before Apply because the old listener may close before its response. Unknown/queued/running is not active. No automatic browser redirect occurs; use the proposed address and inspect the durable verified outcome.',
  '<b>Verify or recover.</b> Active requires an exact matching verified port receipt. A verified rollback points to the restored previous address; failed compensation stays unverified. Test intended client/ingress paths independently before admitting traffic.'),
 note('Configured origin is preserved. Existing cookies may read a direct new URL while sign-in or authenticated changes still fail until the configured SSO origin is routable. Local bind/TLS/database readiness does not prove external routing or Microsoft sign-in.','Origin and network boundary'),
 note('Four private CLI/Gunicorn tests covered HTTPS handover/persisted restart, occupied-target rejection, failed-candidate HTTPS restoration and demo HTTP review/apply denial. Separate real Compose/router tests covered public mapping and rollback. External ingress/Entra remain deployment acceptance.','Isolated evidence'),
]}
PAGES.insert(next(i for i,p in enumerate(PAGES) if p['title']=='Review TLS and replication credentials'),port_page)

PAGES=json.loads(json.dumps(PAGES,ensure_ascii=False).replace('\u2011','-').replace('\u2013','-').replace('\u2014','-'))
TOTAL=len(PAGES)

# Original code-native diagram primitives. Coordinates use top-left origin.
def box(x,y,w,h,label,fill='#ffffff',stroke=LINE,size=11): return ('box',x,y,w,h,label,fill,stroke,size)
def edge(x1,y1,x2,y2,label=''): return ('edge',x1,y1,x2,y2,label)
def label(x,y,text,size=10,color=MUTED): return ('label',x,y,text,size,color)
def line_diagram(names, sub=None, width=610, height=110):
 items=[]; gap=17; w=(width-gap*(len(names)-1))/len(names)
 for i,name in enumerate(names):
  items.append(box(i*(w+gap),22,w,52,name,PALE if i==0 else '#ffffff',RED if i==0 else LINE,11))
  if i<len(names)-1: items.append(edge((i+1)*w+i*gap+2,48,(i+1)*(w+gap)-3,48))
 if sub: items.append(label(0,94,sub,9))
 return width,height,items

def diagram_spec(kind):
 if kind=='application-port': return line_diagram(['Exact local port\n+ revision review','Typed phrase +\ndependency check','Staged listener\n+ local readiness','Verified outcome\nor blocked'], 'Public/SSO origin is preserved; external clients and routing are not rewritten.',height=110)
 if kind=='cidr': return line_diagram(['10.0.0.0/8\nNoida 81','10.241.0.0/16\nPune','10.241.1.0/24\nAWS'],'Narrower matching prefixes override broader mappings for each reported IP.',height=110)
 if kind=='approvals': return line_diagram(['Exact frozen preview','Requester submits','Different Entra checks','Verified agent / job'],'Current enabled people + digest + nonce + typed phrase; a queued change is not applied.',height=110)
 if kind=='source-banks': return line_diagram(['Reviewed empty banks','Maintenance activation','Inactive bank + health','Read-back / commit'],'Missing banks block; initial definitions do not reload firewalld or open ports.',height=110)
 if kind=='recovery': return line_diagram(['Archive + current\nPKI / Vault','Two Super Admins','Drain + restore\nprivate readiness','Release + re-login'],'Public readiness stays held until the exact restored candidates are verified.',height=110)
 if kind=='signing':
  return 610,140,[box(0,2,165,48,'Release signer'),box(223,2,165,48,'Signed exact archive'),box(445,2,165,48,'Verify before install',PALE,RED),edge(165,26,223,26),edge(388,26,445,26),box(0,84,165,48,'Assignment signer\nonline or offline'),box(223,84,165,48,'Bound / expiring\nEd25519 envelope'),box(445,84,165,48,'Pinned agent trust',PALE,RED),edge(165,108,223,108),edge(388,108,445,108)]
 if kind=='readiness': return line_diagram(['Platform + trust','Identity + roles','Preview onboarding','Controlled lab'], 'Foundation checks precede changes to application access or endpoint rules.',height=105)
 if kind=='metadata': return line_diagram(['Manual override','Exact-IP CSV','Subnet location','Unassigned'], 'Highest applicable value wins per field. Return to automatic explicitly clears manual pins.',height=105)
 if kind=='enforcement': return line_diagram(['Preview + protect','Requester + checker','Runtime + health','Commit + read-back'], 'Journal + independent rollback timer cover the live mutation window; failure restores exact prior owned rules.',height=110)
 if kind=='learning_overlay': return line_diagram(['Fresh host scope','Eligible exact tuples','Learning-owned accepts','Verified agent result'], 'Separate authority; no automatic rejects, default-zone edits or normal-bundle approval.',height=110)
 if kind=='learning_evidence': return line_diagram(['Source + host + port','Durable evidence','Frozen target review','CSV: all session pairs'], 'Retained counts/verdicts/times and service/process identity; sampled observations are not connection success.',height=110)
 if kind=='service_sources':
  return 610,126,[box(0,4,178,48,'CIDRs + AND tags\n+ source server groups'),box(230,4,164,48,'Web service group'),box(447,4,160,48,'TCP 80 + 443',PALE,RED),edge(178,28,230,28),edge(394,28,447,28),box(0,77,178,40,'Database clients'),box(230,77,164,40,'Separate policy row'),box(447,77,160,40,'TCP 5432'),edge(178,97,230,97),edge(394,97,447,97)]
 if kind=='evidence': return 610,64,[box(i*156,8,142,42,name,PALE if i==0 else '#ffffff',RED if i==0 else LINE,12) for i,name in enumerate(['Implemented','Isolated lab','Live acceptance','Pilot + fleet'])]
 if kind=='network':
  return 610,178,[box(2,8,118,40,'Browser'),box(2,102,118,44,'Linux endpoint\nagent'),box(180,54,113,44,'Stable app/LB\nTCP 443',PALE,RED),box(353,54,113,44,'Controller\nTLS 8787'),box(510,54,98,44,'PostgreSQL\nTLS 5432'),edge(120,28,180,64,'443'),edge(120,122,180,87,'443 mTLS'),edge(294,76,353,76,'8787'),edge(466,76,510,76,'5432'),label(180,136,'Workload clients → endpoint application ports directly',10),label(180,157,'Controller → endpoint actual SSH port: health only',10)]
 if kind=='site-routing':
  return 610,190,[box(0,2,175,55,'Noida 81 clients\nlocal ready controllers',PALE,RED),box(217,2,175,55,'Pune clients\nlocal ready controllers'),box(434,2,175,55,'AWS clients\nlocal ready controllers'),box(0,117,175,53,'Voter A\nPG copy + etcd'),box(217,117,175,53,'Voter B\nPG copy + etcd'),box(434,117,175,53,'Voter C\nPG copy + etcd'),edge(87,58,87,117),edge(304,58,304,117),edge(521,58,521,117),edge(175,143,217,143),edge(392,143,434,143),label(48,84,'Preferred site pool + reviewed external fallback',10),label(78,187,'One PG writer; strict synchronous replication; three independent sites',9.6)]
 if kind=='controller':
  return 610,140,[box(0,44,124,45,'Stable HTTPS\napp hostname',PALE,RED),box(176,44,125,45,'L4 LB\nTCP passthrough'),box(354,2,118,45,'Controller A\nTLS 8787'),box(354,86,118,45,'Controller B\nTLS 8787'),box(513,44,95,45,'Shared\nmetadata/traffic',size=9.5),edge(124,67,176,67,'443'),edge(301,60,354,24),edge(301,76,354,107),edge(472,24,513,58),edge(472,108,513,76)]
 if kind=='files':
  return 610,140,[box(0,38,128,54,'Reviewed binary\nconfig + CA + token',PALE,RED),box(179,38,119,54,'Local installer\nroot + systemd'),box(354,1,253,37,'/etc/seg-agent  configuration + trust'),box(354,51,253,37,'/var/lib/seg-agent  identity + state'),box(354,101,253,37,'seg-agent.service  outbound HTTPS'),edge(129,64,179,64),edge(299,57,354,20),edge(299,66,354,69),edge(299,77,354,118)]
 if kind=='enrollment':
  return 610,120,[box(0,0,151,40,'Automatic token'),box(0,72,151,40,'Reserve exact hostname'),box(217,0,145,40,'Install local agent'),box(217,72,145,40,'Bound token + install'),box(443,36,164,42,'mTLS + real report\nLive inventory',PALE,RED),edge(151,20,217,20),edge(151,92,217,92),edge(362,20,443,48),edge(362,92,443,64)]
 if kind=='auth':
  lanes=[(40,'Browser'),(280,'Controller'),(535,'Entra')]; it=[]
  for x,txt in lanes:
   it.append(box(x-40,0,90,30,txt,PALE if txt=='Controller' else '#ffffff',RED if txt=='Controller' else LINE,12))
   it.append(('vline',x+5,32,x+5,240))
  it += [edge(45,54,285,54,'1  Start sign-in'),edge(285,82,45,82,'2  Redirect: state + PKCE'),edge(45,110,540,110,'3  Browser sign-in / MFA'),edge(540,138,45,138,'4  Redirect: code + state'),edge(45,166,285,166,'5  Callback: code + state'),edge(285,194,540,194,'6  HTTPS code exchange / JWKS'),edge(285,222,45,222,'7  Enabled DB role → session'),label(20,265,'Secret stays on server; verified tid:oid must match enabled application access',10)]
  return 610,278,it
 if kind=='ha':
  return 610,193,[box(0,69,96,49,'Agents +\nbrowsers'),box(143,69,108,49,'Redundant\nL4 ingress',PALE,RED),box(300,2,123,42,'DC controller A'),box(300,75,123,42,'DC controller B'),box(300,148,123,42,'DR/cloud node'),box(481,30,127,52,'One metadata\nwriter + replicas'),box(481,125,127,52,'One traffic\nwriter + replicas'),edge(96,94,143,94),edge(251,86,300,23),edge(251,94,300,96),edge(251,105,300,169),edge(424,23,481,48),edge(424,96,481,61),edge(424,96,481,142),edge(424,169,481,155)]
 raise ValueError(kind)

def svg_diagram(kind):
 width,height,items=diagram_spec(kind)
 parts=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(kind)} diagram"><defs><marker id="arrow-{kind}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="{RED}"/></marker></defs>']
 for item in items:
  if item[0]=='box':
   _,x,y,w,hh,txt,fill,stroke,size=item
   parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{hh}" rx="7" fill="{fill}" stroke="{stroke}"/>')
   lines=txt.split('\n'); first=y+hh/2-(len(lines)-1)*size*.63
   for j,t in enumerate(lines): parts.append(f'<text x="{x+w/2}" y="{first+j*size*1.26}" dominant-baseline="middle" text-anchor="middle" font-family="Arial,sans-serif" font-size="{size}" font-weight="600" fill="{INK}">{html.escape(t)}</text>')
  elif item[0]=='edge':
   _,a,b,c,d,txt=item;parts.append(f'<line x1="{a}" y1="{b}" x2="{c}" y2="{d}" stroke="{RED}" stroke-width="1.4" marker-end="url(#arrow-{kind})"/>')
   if txt:parts.append(f'<text x="{(a+c)/2}" y="{(b+d)/2-6}" text-anchor="middle" font-family="Arial,sans-serif" font-size="9" fill="{MUTED}">{html.escape(txt)}</text>')
  elif item[0]=='vline':
   _,a,b,c,d=item;parts.append(f'<line x1="{a}" y1="{b}" x2="{c}" y2="{d}" stroke="{LINE}" stroke-dasharray="3 3"/>')
  else:
   _,x,y,txt,size,color=item;parts.append(f'<text x="{x}" y="{y}" font-family="Arial,sans-serif" font-size="{size}" fill="{color}">{html.escape(txt)}</text>')
 return ''.join(parts)+'</svg>'


def load_manifest(path, allow_missing=False):
 if path and path.exists():
  manifest=json.loads(path.read_text())
  if not isinstance(manifest,dict):raise ValueError('Screenshot manifest must map keys to path/caption metadata')
 else: manifest={}
 # Require real source pixels for these new chapters. Root captures them before
 # final regeneration; merely knowing the filename never claims a capture.
 for key,meta in EXPECTED_SCREENSHOTS.items():
  if key not in manifest and (ROOT/meta['path']).is_file():manifest[key]=meta
 for key,meta in list(manifest.items()):
  if isinstance(meta,str):meta={'path':meta}
  src=Path(meta['path']); src=src if src.is_absolute() else ROOT/src
  if not src.is_file():raise FileNotFoundError(src)
  target=GUIDE/'images'/('screen-'+key+src.suffix.lower())
  target.parent.mkdir(parents=True,exist_ok=True)
  if src.resolve()!=target.resolve():shutil.copy2(src,target)
  manifest[key]={**meta,'path':str(target)}
 if not allow_missing:
  needed={shot_item['key'] for page in PAGES for e in page['elements'] for shot_item in ([e] if e['type']=='shot' else e['items'] if e['type']=='shots' else [])}
  absent=needed-set(manifest)
  if absent:raise ValueError('Actual screenshots required for final guide: '+', '.join(sorted(absent)))
 return manifest

def data_image(path):
 mime='image/jpeg' if Path(path).suffix.lower() in ('.jpg','.jpeg') else 'image/png'
 return f'data:{mime};base64,'+base64.b64encode(Path(path).read_bytes()).decode()

def html_element(e,manifest):
 t=e['type']
 if t=='p':return '<p>'+e['text']+'</p>'
 if t=='h':return '<h2>'+e['text']+'</h2>'
 if t in ('bullets','steps'):
  tag='ol' if t=='steps' else 'ul';return '<'+tag+'>'+''.join('<li>'+x+'</li>' for x in e['items'])+'</'+tag+'>'
 if t=='note':return '<aside><strong>'+e['label']+'</strong><p>'+e['text']+'</p></aside>'
 if t=='code':return '<pre>'+html.escape(e['text'])+'</pre>'
 if t=='table':
  total=sum(e['widths']) if e['widths'] else 0
  cols='<colgroup>'+''.join(f'<col style="width:{w/total*100:.2f}%">' for w in e['widths'])+'</colgroup>' if total else ''
  return '<table>'+cols+'<thead><tr>'+''.join('<th>'+html.escape(v).replace('\n','<br>')+'</th>' for v in e['headers'])+'</tr></thead><tbody>'+''.join('<tr>'+''.join('<td>'+html.escape(v).replace('\n','<br>')+'</td>' for v in row)+'</tr>' for row in e['rows'])+'</tbody></table>'
 if t=='diagram':return '<figure class="diagram">'+svg_diagram(e['kind'])+'<figcaption>'+e['caption']+'</figcaption></figure>'
 if t=='shots':return '<div class="shot-pair">'+''.join(html_element(item,manifest) for item in e['items'])+'</div>'
 if t=='shot':
  if e['key'] not in manifest:return '<div class="pending">Actual screenshot pending: '+e['key']+'</div>'
  meta=manifest[e['key']]; provenance=meta.get('provenance','Actual local application; synthetic demonstration data.')
  picture='<img alt="'+html.escape(e['caption'])+'" src="'+data_image(meta['path'])+'">'
  if meta.get('viewport'):
   from PIL import Image as PILImage
   iw,ih=PILImage.open(meta['path']).size;cx,cy,cw,ch=meta['viewport']
   picture=f'<svg viewBox="{cx} {cy} {cw} {ch}" role="img" aria-label="{html.escape(e["caption"])}"><image x="0" y="0" width="{iw}" height="{ih}" href="{data_image(meta["path"])}"/></svg>'
  return '<figure class="product">'+picture+'<figcaption><span class="synthetic">'+('RETAINED SYNTHETIC UI' if meta.get('historical') else 'SYNTHETIC DEMONSTRATION')+'</span> '+e['caption']+' <span>'+html.escape(provenance)+'</span></figcaption></figure>'
 raise ValueError(t)

CSS='''.shot-pair{display:flex;gap:12px;align-items:flex-start}.shot-pair>figure{flex:1;min-width:0}.shot-pair .product img{max-height:270px;object-fit:contain}.gallery img{width:100%;height:auto;border:1px solid #ddd}.gallery figure{margin:24px 0}.gallery figcaption{font-size:11px;color:#586779}@page{size:A4;margin:0}*{box-sizing:border-box}body{margin:0;background:#edf0f3;color:#152235;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.48}.toolbar{position:sticky;top:0;background:#152235;color:#fff;padding:12px 24px;z-index:2;font-size:13px}.toolbar button{float:right;border:0;background:#d71920;color:#fff;border-radius:5px;padding:6px 12px;cursor:pointer}.page{width:794px;min-height:1123px;margin:24px auto;padding:38px 54px 42px;background:#fff;box-shadow:0 8px 40px #15223518;position:relative;page-break-after:always}.brandline{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #dde3e9;padding-bottom:13px;margin-bottom:19px}.brandline img{width:118px;height:auto}.brand{font-weight:700;font-size:20px;color:#d71920}.edition{font-size:10px;color:#586779;text-align:right}.section{font-size:10px;color:#d71920;text-transform:uppercase;letter-spacing:1.4px;font-weight:700}h1{font-size:28px;line-height:1.12;margin:7px 0 8px;letter-spacing:-.6px}h2{font-size:15px;margin:16px 0 5px}p{margin:8px 0}.subtitle{font-size:13px;color:#586779;margin-bottom:16px}code{font-family:Consolas,monospace;font-size:.92em;overflow-wrap:anywhere}pre{background:#152235;color:#fff;border-radius:7px;padding:12px 14px;font:10px/1.55 Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;table-layout:fixed;margin:11px 0;font-size:12px;line-height:1.4}th{background:#f5f7fa;text-align:left;font-size:10px;color:#586779}th,td{padding:8px 9px;border:1px solid #dde3e9;vertical-align:top;overflow-wrap:anywhere}td:first-child{font-weight:600}aside{border-left:3px solid #d71920;background:#fff0f0;padding:10px 12px;margin:12px 0;font-size:11px}aside>strong{color:#ad1117;font-size:10px;text-transform:uppercase;letter-spacing:.5px}aside p{margin:4px 0 0}ol,ul{margin:10px 0;padding-left:20px}li{padding:0 0 7px 4px}li::marker{color:#d71920;font-weight:700}figure{margin:13px 0}.diagram{background:#fafbfc;border:1px solid #e9edf1;border-radius:8px;padding:12px}.diagram svg{display:block;width:100%;height:auto;max-height:205px}.product svg{display:block;width:100%;height:auto;border:1px solid #dde3e9;border-radius:7px}.product img{display:block;max-width:100%;width:100%;border:1px solid #dde3e9;border-radius:7px}.product figcaption,.diagram figcaption{font-size:9.3px;line-height:1.4;color:#586779;margin-top:6px}.synthetic{color:#a14b00;font-size:8px;font-weight:bold;letter-spacing:.3px}.product figcaption>span:last-child{display:none}.footer{display:flex;justify-content:space-between;border-top:1px solid #dde3e9;font-size:9px;color:#586779;padding-top:10px;margin-top:20px}.pending{border:2px dashed #d71920;padding:30px;color:#d71920}.references{width:794px;margin:24px auto;padding:24px 54px;background:#fff}.references a{color:#bc141b}@media(max-width:850px){.page,.references{width:100%;margin:0;min-height:auto;padding:28px 22px}.brandline img{width:100px}.page{border-bottom:8px solid #edf0f3}.toolbar{position:static}h1{font-size:24px}table{font-size:10px}th,td{padding:6px}}@media print{body{background:#fff}.toolbar,.references{display:none}.page{width:210mm;min-height:297mm;margin:0;box-shadow:none;padding:12mm 14mm}.footer{margin-top:5mm}h1{font-size:23px}body{font-size:10.5px}.diagram svg{max-height:170px}table{font-size:9.5px}th,td{padding:6px}li{padding-bottom:5px}}
'''

def build_html(manifest):
 logo=data_image(ROOT/'dashboard/assets/airtel-payments-bank.png')
 wordmark='data:image/svg+xml;base64,'+base64.b64encode((ROOT/'dashboard/assets/prthak-wordmark.svg').read_bytes()).decode()
 parts=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+TITLE+'</title><style>'+CSS+'</style></head><body><div class="toolbar">Prṛthak · Deployment & onboarding · '+STAMP+'<button onclick="window.print()">Print guide</button></div>']
 for num,page in enumerate(PAGES,1):
  parts.append('<section class="page" id="page-'+str(num)+'"><div class="brandline"><img src="'+logo+'" alt="Airtel Payments Bank"><span class="brand"><img src="'+wordmark+'" alt="Prṛthak · पृथक्"></span><span class="edition">DEPLOYMENT & ONBOARDING<br>LAB '+RELEASE+' · '+STAMP.upper()+'</span></div><div class="section">'+f'{num:02d} / {TOTAL}'+'</div><h1>'+page['title']+'</h1><p class="subtitle">'+page['subtitle']+'</p>')
  parts.extend(html_element(e,manifest) for e in page['elements'])
  parts.append('<div class="footer"><span>Precise access. Protected servers.</span><span>Prṛthak · '+str(num)+' / '+str(TOTAL)+'</span></div></section>')
 parts.append('<div class="references gallery"><h2>Actual product captures · full resolution</h2><p>These are local synthetic/staged UI illustrations. No Microsoft directory connection or real account creation is claimed. Open this HTML to inspect the original capture at full width.</p>')
 for key,meta in manifest.items():parts.append('<figure><img src="'+data_image(meta['path'])+'" alt="'+html.escape(meta.get('title',key))+'"><figcaption><b>'+('RETAINED SYNTHETIC UI' if meta.get('historical') else 'SYNTHETIC DEMONSTRATION')+'</b> · '+html.escape(meta.get('title',key))+' · '+html.escape(meta.get('provenance','Actual local application capture; demonstration data only.'))+'</figcaption></figure>')
 parts.append('</div>')
 parts.append('<div class="references"><strong>External identity configuration references</strong><p><a href="https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=client-secret">Microsoft: register an application</a> · <a href="https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri">Web redirect URI</a> · <a href="https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/what-is-access-management">Enterprise application access management</a></p><p>The bilingual product wordmark is the actual Prṛthak SVG used by the application. The official Airtel Payments Bank organizational asset is used unchanged; provenance is recorded in dashboard/assets/README.md. This manual is self-contained: its images and native diagrams are embedded. The companion PDF provides the fixed illustrated edition.</p></div></body></html>')
 target=GUIDE/'prthak-deployment-guide.html';target.write_text(''.join(parts));return target


def build_pdf(manifest, *, measure_only=False):
 from reportlab.pdfgen import canvas
 from reportlab.platypus import Paragraph, Table, TableStyle, Image, Spacer, Flowable, KeepTogether
 from reportlab.lib.styles import ParagraphStyle
 from reportlab.lib.colors import HexColor, white
 from reportlab.lib.utils import ImageReader
 from reportlab.pdfbase import pdfmetrics
 from reportlab.pdfbase.ttfonts import TTFont
 from reportlab.lib.enums import TA_LEFT
 from PIL import Image as PILImage
 for name,file in [('Guide','DejaVuSans.ttf'),('GuideBold','DejaVuSans-Bold.ttf'),('GuideMono','DejaVuSansMono.ttf')]:pdfmetrics.registerFont(TTFont(name,str(FONT_DIR/file)))
 pdfmetrics.registerFontFamily('Guide',normal='Guide',bold='GuideBold',italic='Guide',boldItalic='GuideBold')
 styles={
  'body':ParagraphStyle('body',fontName='Guide',fontSize=10.5,leading=14.5,textColor=HexColor(INK),spaceAfter=6),
  'small':ParagraphStyle('small',fontName='Guide',fontSize=8.4,leading=11.5,textColor=HexColor(MUTED),spaceAfter=5),
  'table':ParagraphStyle('table',fontName='Guide',fontSize=9.1,leading=12.4,textColor=HexColor(INK)),
  'thead':ParagraphStyle('thead',fontName='GuideBold',fontSize=9.0,leading=12.0,textColor=HexColor(MUTED)),
  'heading':ParagraphStyle('heading',fontName='GuideBold',fontSize=11,leading=14,textColor=HexColor(INK),spaceBefore=4,spaceAfter=5),
  'code':ParagraphStyle('code',fontName='GuideMono',fontSize=8.0,leading=11.2,textColor=white),
 }
 def plainmarkup(s):
  s=s.replace('<code>','<font name="GuideMono" size="8">').replace('</code>','</font>')
  return s.replace('→','-&gt;').replace(' · ',' / ')
 def para(s,style='body'):return Paragraph(plainmarkup(s),styles[style])
 class DiagramFlowable(Flowable):
  def __init__(self,kind,w,hh):super().__init__();self.kind=kind;self.width=w;self.height=hh
  def draw(self):
   c=self.canv;sw,sh,items=diagram_spec(self.kind);scale=min(self.width/sw,self.height/sh);c.saveState();c.translate((self.width-sw*scale)/2,self.height);c.scale(scale,-scale)
   for item in items:
    typ=item[0]
    if typ=='box':
     _,x,y,w,hh,txt,fill,stroke,size=item;c.setFillColor(HexColor(fill));c.setStrokeColor(HexColor(stroke));c.setLineWidth(.85);c.roundRect(x,y,w,hh,7,fill=1,stroke=1)
     lines=txt.split('\n');first=y+hh/2-(len(lines)-1)*size*.63
     for i,t in enumerate(lines):
      c.saveState();c.translate(x+w/2,first+i*size*1.26);c.scale(1,-1);c.setFillColor(HexColor(INK));c.setFont('GuideBold',size*.9);c.drawCentredString(0,-size*.3,t);c.restoreState()
    elif typ in ('edge','vline'):
     _,a,b,cc,d,*tail=item;c.setStrokeColor(HexColor(RED if typ=='edge' else LINE));c.setLineWidth(1.2)
     if typ=='vline':c.setDash(3,3)
     c.line(a,b,cc,d);c.setDash()
     if typ=='edge':
      angle=math.atan2(d-b,cc-a);length=5;path=c.beginPath();path.moveTo(cc,d);path.lineTo(cc-length*math.cos(angle-.5),d-length*math.sin(angle-.5));path.lineTo(cc-length*math.cos(angle+.5),d-length*math.sin(angle+.5));path.close();c.setFillColor(HexColor(RED));c.drawPath(path,fill=1,stroke=0)
      if tail and tail[0]:
       c.saveState();c.translate((a+cc)/2,(b+d)/2-6);c.scale(1,-1);c.setFont('Guide',10.0);c.setFillColor(HexColor(MUTED));c.drawCentredString(0,0,tail[0].replace('→','>'));c.restoreState()
    else:
     _,x,y,txt,size,col=item;c.saveState();c.translate(x,y);c.scale(1,-1);c.setFont('Guide',size*.9);c.setFillColor(HexColor(col));c.drawString(0,0,txt.replace('→','>'));c.restoreState()
   c.restoreState()
 class Screenshot(Flowable):
  def __init__(self,source,viewport,w,hh):super().__init__();self.source=source;self.viewport=viewport;self.width=w;self.height=hh
  def draw(self):
   c=self.canv;iw,ih=PILImage.open(self.source).size;cx,cy,cw,ch=self.viewport;scale=self.width/cw
   c.saveState();clip=c.beginPath();clip.rect(0,0,self.width,self.height);c.clipPath(clip,stroke=0);c.drawImage(ImageReader(self.source),-cx*scale,self.height-(ih-cy)*scale,width=iw*scale,height=ih*scale,mask='auto');c.restoreState()
 def components(e,avail_w):
  typ=e['type']
  if typ=='p':return [para(e['text'])]
  if typ=='h':return [para(e['text'],'heading')]
  if typ in ('steps','bullets'):
   result=[]
   for i,txt in enumerate(e['items'],1):
    marker=str(i)+'.' if typ=='steps' else '•'
    tab=Table([[para('<b>'+marker+'</b>'),para(txt)]],colWidths=[14,avail_w-14]);tab.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),0),('TOPPADDING',(0,0),(-1,-1),0),('BOTTOMPADDING',(0,0),(-1,-1),0)]));result.append(tab)
   return result
  if typ=='table':
   rows=[[para(escape(x).replace('\n','<br/>'),'thead') for x in e['headers']]]+[[para(escape(x).replace('\n','<br/>'),'table') for x in row] for row in e['rows']]
   widths=[w/sum(e['widths'])*avail_w for w in e['widths']] if e['widths'] else None
   tab=Table(rows,colWidths=widths,hAlign='LEFT');tab.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),HexColor('#f4f6f8')),('GRID',(0,0),(-1,-1),.45,HexColor(LINE)),('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]));return [tab,Spacer(1,7)]
  if typ=='code':
   # Preserve leading spaces without using an image or fake terminal screenshot.
   content=escape(e['text']).replace(' ','&#160;').replace('\n','<br/>')
   tab=Table([[Paragraph(content,styles['code'])]],colWidths=[avail_w]);tab.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),HexColor(INK)),('BOX',(0,0),(-1,-1),.5,HexColor(INK)),('LEFTPADDING',(0,0),(-1,-1),10),('RIGHTPADDING',(0,0),(-1,-1),10),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]));return [tab,Spacer(1,7)]
  if typ=='note':
   content=para('<b><font color="'+RED+'">'+e['label'].upper()+'</font></b><br/>'+e['text'],'small');tab=Table([[content]],colWidths=[avail_w]);tab.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),HexColor(PALE)),('LINEBEFORE',(0,0),(0,-1),2.3,HexColor(RED)),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),4)]));return [tab,Spacer(1,7)]
  if typ=='diagram':return [DiagramFlowable(e['kind'],avail_w,e['height']),para(e['caption'],'small'),Spacer(1,3)]
  if typ=='shots':
   gap=10;cell=(avail_w-gap)/2
   contents=[components(item,cell) for item in e['items']]
   tab=Table([contents],colWidths=[cell,cell],hAlign='LEFT');tab.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),gap),('TOPPADDING',(0,0),(-1,-1),0),('BOTTOMPADDING',(0,0),(-1,-1),0)]));return [tab]
  if typ=='shot':
   if measure_only and e['key'] not in manifest:
    # Conservative layout preflight while actual CUA captures are pending.
    # This branch never draws or publishes a PDF/placeholder screenshot.
    return [Spacer(1,e['height']),Spacer(1,4),para('SYNTHETIC DEMONSTRATION / '+e['caption'],'small'),Spacer(1,4)]
   meta=manifest[e['key']];source=meta['path'];iw,ih=PILImage.open(source).size
   if meta.get('viewport'):
    cx,cy,cw,ch=meta['viewport'];scale=min(avail_w/cw,e['height']/ch);image=Screenshot(source,meta['viewport'],cw*scale,ch*scale)
   else:
    scale=min(avail_w/iw,e['height']/ih);image=Image(source,width=iw*scale,height=ih*scale,hAlign='CENTER')
   cap='<font color="#a14b00"><b>'+('RETAINED SYNTHETIC UI' if meta.get('historical') else 'SYNTHETIC DEMONSTRATION')+'</b></font> / '+e['caption']
   image._guide_center=True
   return [image,Spacer(1,4),para(cap,'small'),Spacer(1,4)]
  raise ValueError(typ)
 page_w,page_h=595.276,841.89;left=42;right=42;inner=page_w-left-right;bottom=42
 problems=[]
 for n,page in enumerate(PAGES,1):
  title=Paragraph(page['title'],ParagraphStyle('measure-title',fontName='GuideBold',fontSize=20,leading=23,textColor=HexColor(INK)))
  _,th=title.wrap(inner,100);_,sh=para(page['subtitle'],'small').wrap(inner,100)
  flows=[f for e in page['elements'] for f in components(e,inner)]
  total=sum(f.wrap(inner,900)[1] for f in flows);available=page_h-122-th-sh-bottom-14
  if total>available:problems.append(f'Page {n}: overflow {total-available:.1f}pt ({page["title"]})')
 if problems:raise RuntimeError('\n'.join(problems))
 if measure_only:return {'pages':len(PAGES),'overflow':False}
 target=OUTPUT/'prthak-deployment-onboarding-guide.pdf';OUTPUT.mkdir(parents=True,exist_ok=True)
 c=canvas.Canvas(str(target),pagesize=(page_w,page_h));c.setTitle(TITLE);c.setAuthor('Prṛthak engineering');c.setSubject('Illustrated deployment, Entra RBAC, onboarding and managed-enforcement lab guide')
 def draw_product_mark(canvas, x, y, width, height):
  from PIL import ImageChops
  logo_path=GUIDE/'images/prthak-wordmark-rendered.png'
  logo=PILImage.open(logo_path).convert('RGB')
  bounds=ImageChops.difference(logo,PILImage.new('RGB',logo.size,'white')).getbbox()
  bx,by,bw,bh=bounds; scale=min(width/(bw-bx),height/(bh-by))
  canvas.saveState();clip=canvas.beginPath();clip.rect(x,y,width,height);canvas.clipPath(clip,stroke=0)
  canvas.drawImage(ImageReader(str(logo_path)),x-bx*scale,y-(logo.height-bh)*scale,width=logo.width*scale,height=logo.height*scale)
  canvas.restoreState()
 metrics=[]
 for num,page in enumerate(PAGES,1):
  c.bookmarkPage('section-'+str(num));c.addOutlineEntry(page['title'],'section-'+str(num),level=0)
  c.setFillColor(white);c.rect(0,0,page_w,page_h,fill=1,stroke=0)
  c.drawImage(ImageReader(str(ROOT/'dashboard/assets/airtel-payments-bank.png')),left,page_h-64,width=88,height=34,mask='auto',preserveAspectRatio=True)
  draw_product_mark(c, page_w/2-42, page_h-61, 84, 30)
  c.setFont('Guide',6.4);c.setFillColor(HexColor(MUTED));c.drawRightString(page_w-right,page_h-39,'DEPLOYMENT & ONBOARDING');c.drawRightString(page_w-right,page_h-50,'LAB '+RELEASE+' / '+STAMP.upper())
  c.setStrokeColor(HexColor(LINE));c.setLineWidth(.6);c.line(left,page_h-74,page_w-right,page_h-74)
  c.setFont('GuideBold',7.2);c.setFillColor(HexColor(RED));c.drawString(left,page_h-92,f'{num:02d} / {TOTAL}')
  title=Paragraph(page['title'],ParagraphStyle('title',fontName='GuideBold',fontSize=20,leading=23,textColor=HexColor(INK)))
  tw,th=title.wrap(inner,100);title.drawOn(c,left,page_h-104-th)
  sub=para(page['subtitle'],'small');_,sh=sub.wrap(inner,100);sub.drawOn(c,left,page_h-111-th-sh)
  y=page_h-122-th-sh
  flows=[]
  for e in page['elements']:flows.extend(components(e,inner))
  total_h=sum(f.wrap(inner,900)[1] for f in flows)
  available=y-bottom-14
  if total_h>available:
   raise RuntimeError(f'Page {num} overflows by {total_h-available:.1f}pt: used {total_h:.1f}, available {available:.1f}. Refine content/layout; do not shrink whole pages.')
  for f in flows:
   fw,hh=f.wrap(inner,900);y-=hh;f.drawOn(c,left+(inner-fw)/2 if getattr(f,'_guide_center',False) else left,y)
  c.setStrokeColor(HexColor(LINE));c.line(left,35,page_w-right,35);c.setFont('Guide',6.5);c.setFillColor(HexColor(MUTED));c.drawString(left,23,'Precise access. Protected servers.');c.drawRightString(page_w-right,23,f'Prṛthak / {num} of {TOTAL}')
  metrics.append({'page':num,'title':page['title'],'content_height':round(total_h,1),'free_space':round(available-total_h,1)})
  c.showPage()
 c.save();(GUIDE/'layout-metrics.json').write_text(json.dumps(metrics,indent=2));return target


def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--html-only',action='store_true');ap.add_argument('--screenshots',type=Path,default=GUIDE/'screenshots.json');args=ap.parse_args()
 if not args.html_only and VALIDATION_EVIDENCE.startswith('PENDING_'):
  raise RuntimeError('Final release verification is required before regenerating PDF/HTML')
 GUIDE.mkdir(parents=True,exist_ok=True)
 manifest=load_manifest(args.screenshots,allow_missing=args.html_only)
 # HTML is deliberately first; it is a standalone operational artifact too.
 print(build_html(manifest))
 for kind in {e['kind'] for page in PAGES for e in page['elements'] if e['type']=='diagram'}:(GUIDE/'images'/(kind+'.svg')).write_text(svg_diagram(kind))
 if not args.html_only:print(build_pdf(manifest))

if __name__=='__main__':main()
