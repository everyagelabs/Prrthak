#!/usr/bin/env python3
"""Build the current illustrated pilot workflow without relabeling old captures."""
import html
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from controller import __version__

PAGES = [
 ('Roles of the components', 'One GUI policy, local Linux enforcement',
  ['Admin dashboard', 'Controller API', 'Endpoint agent', 'Local firewalld'], [
  ('Dashboard', 'Administrators manage servers, locations, tags, service groups, source lists and policy. The browser uses the controller API; it never contacts endpoint firewalls.'),
  ('Controller and storage', 'The controller compiles exact versioned endpoint bundles, signs them and stores inventory, policy history, audit and traffic separately. Background jobs evaluate health, process traffic and run backup schedules.'),
  ('Agent and firewall', 'The compiled Go systemd agent reports authenticated local OS, interface IPs and listeners. It pulls periodic assignments and is the only component that changes local firewalld. It does not proxy application traffic.'),
  ('Scope', 'Host inbound TCP/UDP segmentation for RHEL 8/9 and Ubuntu 26.04. Container forwarding and outbound segmentation need a separate support design. These diagrams explain current workflows; they are not screenshots or native acceptance evidence.')]),
 ('Prerequisites and communication', 'Prepare trusted network paths before enrollment',
  ['Browser :8787', 'Agent pull :8788', 'Agent report :8789', 'Controller API'], [
  ('Controller VM', 'Start the 20-server pilot with 4 vCPU, 8 GiB RAM, 80 GiB OS disk and 100 GiB separate SSD data storage. The host needs genuine Linux systemd, root-owned Python 3.9+, local Docker Engine and Compose v2. Git is optional.'),
  ('Ports', 'Browser management uses HTTPS 8787. Agents pull policy, authorization and configuration checks over 8788. Enrollment, inventory and traffic uploads use 8789. Agents make outbound connections and expose no inbound control listener.'),
  ('Trust and load balancers', 'Use stable DNS, trusted hostname certificates and an L4/TCP path preserving endpoint mTLS. Control-path SNAT does not replace agent-reported inventory IPs. Firewall observations still see any NAT applied on the application path.'),
  ('HA prerequisites', 'Managed PostgreSQL HA uses three approved database voters with real watchdog support, one primary and synchronous replicas. Additional controllers share that writer. Database/quorum ports are 5432/5433, 2379/2380 and 8008 on approved internal paths.')]),
 ('Install and configure the controller', 'GUI configuration after one installer command',
  ['Verify release', 'Run installer', 'Settings / Setup', 'Entra sign-in'], [
  ('Verify first', 'Use independently approved public release trust to verify the matching controller archive and detached signature before extraction. Keep the extracted release root-owned. Adjacent public keys alone do not establish trust.'),
  ('Run once', 'From the verified controller release directory run the command below. Installation prints the local HTTPS setup URL and the private initial credential file location.'),
  ('Complete Setup', 'In Settings > Setup configure this node, hostname/origins, TLS and the persistent data root. The fixed manager writes protected configuration automatically. No manual .env editing is required.'),
  ('Set Entra and users', 'Verify the candidate Microsoft Entra sign-in and initial Super Admin identity. Read Only can inspect. Admin manages servers/tags/policies. Only Super Admin creates users or assigns roles and manages privileged platform settings.')],
  'sudo ./scripts/install-controller.sh --gui-setup'),
 ('Install the same agent on the fleet', 'One matching package and one reusable fleet setup',
  ['Install agent / Fleet', 'Private setup JSON', 'One install command', 'Auto-enrolled host'], [
  ('Generate in GUI', 'Choose Install agent > Fleet setup. Set controller, control and discovery origins, polling and enrollment expiry. Download one private setup file and reuse it on the 20 servers. Each endpoint generates its own key, certificate and identity.'),
  ('Choose OS and CPU', 'Verify and extract the matching amd64 or arm64 agent archive. Transfer the setup file privately as root-owned mode 0600 to /root/prthak-agent-setup.json. Run the matching command below from the extracted release.'),
  ('Optional preparation', 'Unchecked GUI options can authorize missing-package preparation and private UFW assessment/export. UFW is preserved; the installer does not cut over firewall managers or activate firewalld. Existing access must be preserved.'),
  ('Automatic discovery', 'The systemd service enrolls and appears in Servers automatically. Initial setup is monitor-only. An unassigned server can be classified centrally after discovery; enrollment does not supply business tags or DCs.')],
  'RHEL: sudo ./scripts/install-agent-rhel.sh --setup-file /root/prthak-agent-setup.json\nUbuntu: sudo ./scripts/install-agent-ubuntu.sh --setup-file /root/prthak-agent-setup.json'),
 ('Assign DCs and application tags', 'One saved location and several custom tags',
  ['Create Locations', 'Assign / import', 'Review every page', 'Apply exact plan'], [
  ('Locations first', 'Create each DC/cloud location name and geography in Locations. An endpoint has one location and multiple key=value tags. Renaming a location preserves its immutable ID and policy bindings.'),
  ('Manual and CSV', 'Use one server, select several servers, or import exact-IP CSV profiles. Blank CSV cells preserve existing values. The frozen before/after review is paged so all rows can be inspected before applying the complete unchanged plan.'),
  ('Subnet inheritance', 'Manual override wins, then exact-IP CSV, then the longest subnet match. A /24 assigned to Pune can override a Noida /16 or /8. An exact normalized network cannot be assigned twice. Conflicting DC ownership of the same reported IP is withheld and flagged.'),
  ('Groups and filters', 'Use application groups such as Billing/Payments and dynamic tag selectors for targets or sources. Categories combine with AND; values inside one category combine with OR. Return a pinned field to Automatic before inheritance can replace it.')]),
 ('Discover services and learn traffic', 'Monitoring and auto-allow are separate choices',
  ['Listeners found', 'Select ports', 'Observe sources', 'Review or auto-allow'], [
  ('Inventory and alerts', 'Process/unit discovery recognizes sshd on 2022 as SSH. Fast listener checks run every 5 seconds with successful changes reported promptly; full inventory defaults to 15 minutes. Restart refreshes OS/firewall/service facts. Missing heartbeats raise independent offline alerts.'),
  ('Temporary learning', 'Start learning for selected servers/groups and exact ports, for example 443 only while 22/80 remain outside the session. Capture accepted connections through conntrack and denied packets through verified NFLOG, with explicit coverage and separate count units.'),
  ('Auto-allow', 'Explicit Admin-authorized auto-allow can create visible additive policies for observed source/service pairs inside its exact active scope. Endpoint opt-ins and management protection remain mandatory. Protected management services are excluded from automatic grants.'),
  ('Continuous monitoring', 'Optional per-port monitoring is disabled by default. It provides a rolling last-hour view and up to 24-hour retention without creating access grants. Suggestions and scoped CSV exports remain available; gaps and unavailable native capture are shown explicitly.')]),
 ('Publish policy safely', 'Direct Admin action with protected local application',
  ['Sources + ports', 'Compile and sign', 'Runtime / health', 'Permanent / receipt'], [
  ('Policy form', 'Select servers, groups or tags. Add allowed source IPs/CIDRs/source groups and exact ports or saved service groups. The selected server is the destination; no destination field is required. Source sets remain aligned with their service rows.'),
  ('Protection and source banks', 'Configure restricted SSH/controller management sources and endpoint opt-ins through reviewed GUI configuration. For larger policies use Servers > Source-set preparation. This separate maintenance review may reload firewalld after safety checks; no bank-preparation CLI is required.'),
  ('Ordinary changes', 'One authorized Admin Save/Apply publishes ordinary intent. The agent checks current authority and local capabilities, journals runtime changes, verifies management health, then commits permanent rules. Normal policy updates do not restart or reload firewalld.'),
  ('Duplicates and removal', 'Exact duplicate permissions are merged; identical owned installed rules are read back and skipped. Foreign/conflicting ownership is reported. Policy removal needs an exact agent cleanup receipt. History is retained and restoring an earlier configuration creates a new version.')]),
 ('Follow rollouts and default deny', 'Applied state and traffic evidence stay separate',
  ['Pending / applying', 'Applied / present', 'Awaiting traffic', 'Verified / unavailable'], [
  ('Top-right Rollouts', 'Open Rollouts from any page. It tracks frozen endpoints and exact versions with paged server/port detail. Applied requires fresh rule readback; Already present identifies the verified no-access-write path. Failures, rollback and stale results remain distinct.'),
  ('Traffic verification', 'Each applicable allow and deny case on every port needs a qualifying native witness after arming. No traffic stays Awaiting and then Unverified. Missing kernel birth metadata stays Unavailable. Observe again opens a fresh passive window; it sends no business probe or grant.'),
  ('Whole-server deny', 'Use the dedicated selected-server/group review. Allow approved sources and ports, then manually tick the initially unchecked downtime acknowledgement before pushing the host fallback. This can interrupt business traffic. It never activates through an ordinary Save.'),
  ('Recovery and drift', 'SSH/controller safety checks and an independent rollback watchdog protect supported changes. Configuration restoration remains pending if restart fails and retries safely. Locally disabled enforcement is not labelled fresh enforcement; cached last-good state is historical.')]),
 ('Plan CPU memory and storage', 'Historical measurements and starting allocations',
  ['20 hosts / 4 vCPU', 'Controller / 8 GiB', 'Agent / 128 MiB', 'Learning / 256 MiB'], [
  ('Agent planning', 'Reserve 128 MiB for ordinary agent/helper monitoring and 256 MiB as a starting learning allowance. Traffic cardinality, configured discovery cadence and kernel/source-set memory can change the requirement. These are planning values, not enforced memory limits.'),
  ('Historical measurement', 'One earlier empty-policy ARM64 container run measured 10.42 MiB median agent RSS and 12.50 MiB maximum; active helpers raised the sampled peak to 56.79 MiB. Stabilized CPU was 0.046 percent of one core for the agent and 0.216 percent including completed helpers.'),
  ('Current workload', 'That 95-second passive sample predates current capture/enforcement and fast listener checks. Current-release CPU/RSS, learning bursts, rollback and endurance need target-host measurement. No fixed CPU percentage or CPUQuota/MemoryMax guarantee is supplied.'),
  ('Controller planning', 'For 5000 endpoints start at 8 vCPU / 16 GiB for a management-only controller, or 8 vCPU / 32 GiB for a combined database voter. Each voter stores a complete copy. Plan 300 GiB initial SSD data per voter plus OS/images and separate backup capacity; measure retention and WAN commit latency.')]),
 ('Operate the platform and pilot', 'GUI controls with explicit acceptance boundaries',
  ['Settings', 'Review / apply', 'Verify outcome', 'Retain recovery'], [
  ('Platform GUI', 'Settings manages polling defaults and scoped overrides, endpoint URL/configuration kits, PEM/PKCS#12 certificates or hostname generation, application port, data root, cluster joins, supported service operations and replication credentials.'),
  ('Backups and HA', 'Schedule daily/weekly/interval database backups and retention in GUI. Archives are private database backups; protect PKI/Vault/profile material separately for recovery. They are not encrypted backup payloads. GUI joins do not provision external LB/DNS or prove physical failover.'),
  ('Twenty-server sequence', 'After native acceptance, start with monitoring, confirm OS/IP/listeners and classification, check risky-port reasons, then test a small approved allow/deny change and rollback. Inspect per-server application and traffic outcomes before increasing scope. Leave controller/DB/LB infrastructure out of endpoint enforcement during this pilot.'),
  ('Evidence and remaining gates', 'Native RHEL 8/9 and Ubuntu 26.04 systemd/firewalld/SELinux, real SSH paths, live Entra/MFA, provider delivery, DC/WAN/quorum/watchdog/fencing and workload endurance remain separate acceptance. Sizing is planning guidance. Development release signatures and passing CI do not establish production or VA clearance.')]),
]


def main():
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas
    from reportlab.platypus import Paragraph
    out = ROOT / 'docs/guide'
    out.mkdir(parents=True, exist_ok=True)
    target = out / ('prthak-pilot-' + __version__ + '.pdf')
    pdf = canvas.Canvas(str(target), pagesize=(595.28, 841.89))
    pdf.setTitle('Prrthak ' + __version__ + ' illustrated pilot guide')
    pdf.setAuthor('Airtel Payments Bank')
    red, ink = colors.HexColor('#E40000'), colors.HexColor('#202124')
    body = ParagraphStyle('body', fontName='Helvetica', fontSize=10.2, leading=14.6, textColor=ink)
    foot = ParagraphStyle('foot', fontName='Helvetica', fontSize=8, leading=11, textColor=colors.HexColor('#61616C'))
    web = ['<!doctype html><html lang="en"><meta charset="utf-8"><title>Prṛthak '+__version__+' pilot guide</title><style>body{font:16px/1.55 system-ui;color:#202124;margin:0;background:#f5f5f7}section{max-width:900px;padding:36px;margin:24px auto;background:white;border-top:5px solid #e40000}h1{font-size:32px}h2{color:#e40000}svg{width:100%;height:auto}pre{white-space:pre-wrap;background:#f6f6f8;padding:16px}footer{border-top:1px solid #ddd;padding-top:18px;color:#666;font-size:13px}a{color:#b60000}@media print{section{break-after:page;margin:0}}</style><body>']
    for index, page in enumerate(PAGES, 1):
        title, subtitle, nodes, items, *command = page
        pdf.setFillColor(red); pdf.rect(0, 831, 595.28, 11, fill=1, stroke=0)
        pdf.setFillColor(ink); pdf.setFont('Helvetica-Bold', 16); pdf.drawString(43, 792, 'PRRTHAK')
        pdf.setFont('Helvetica', 9); pdf.drawString(43, 777, __version__+' / ILLUSTRATED PILOT OPERATIONS')
        pdf.drawImage(ImageReader(str(ROOT/'dashboard/assets/airtel-payments-bank.png')), 438, 770, width=112, height=48, preserveAspectRatio=True, mask='auto')
        y=738
        for text,size,font in ((title,23,'Helvetica-Bold'),(subtitle,11,'Helvetica')):
            p=Paragraph(html.escape(text),ParagraphStyle('heading',fontName=font,fontSize=size,leading=size+5,textColor=ink))
            _,height=p.wrap(509,80);p.drawOn(pdf,43,y-height);y-=height+12
        y-=8
        boxes=[]
        for n,label in enumerate(nodes):
            dx,dy=((n*175,0) if n<3 else (175,-77)) if index==2 else (n*130,0)
            x=43+dx;top=y+dy
            pdf.setStrokeColor(red);pdf.setFillColor(colors.HexColor('#FFF4F4'));pdf.roundRect(x,top-59,119,59,8,fill=1,stroke=1)
            p=Paragraph(html.escape(label),ParagraphStyle('node',fontName='Helvetica-Bold',fontSize=10,leading=13,textColor=ink,alignment=1));_,height=p.wrap(103,48);p.drawOn(pdf,x+8,top-30-height/2)
            sx,sy=(dx*1.23,-dy*1.05)
            boxes.append(f'<rect x="{sx}" y="{sy+5}" width="145" height="65" rx="10" fill="#fff4f4" stroke="#e40000"/><text x="{sx+72}" y="{sy+42}" text-anchor="middle" font-size="12" font-family="sans-serif">'+html.escape(label)+'</text>')
            if n<3:
                pdf.setStrokeColor(red)
                if index==2:
                    pdf.line(x+59,top-59,277,y-77)
                    boxes.append(f'<path d="M{sx+72} 70L287 86" stroke="#e40000" fill="none"/>')
                else:
                    pdf.line(x+120,y-29,x+129,y-29);pdf.line(x+126,y-26,x+129,y-29);pdf.line(x+126,y-32,x+129,y-29)
                    boxes.append('<path d="M'+str(n*160+146)+' 37h13l-4 -4m4 4l-4 4" stroke="#e40000" fill="none"/>')
        y-=160 if index==2 else 84
        web.append('<section><small>PRṚTHAK '+__version__+' / '+str(index)+' OF '+str(len(PAGES))+'</small><h1>'+html.escape(title)+'</h1><p>'+html.escape(subtitle)+'</p><svg viewBox="0 0 625 '+('150' if index==2 else '80')+'" role="img" aria-label="Workflow diagram">'+''.join(boxes)+'</svg>')
        for label,text in items:
            p=Paragraph('<b>'+html.escape(label)+'.</b> '+html.escape(text),body);_,height=p.wrap(509,600)
            assert y-height>101,(index,label,y,height)
            p.drawOn(pdf,43,y-height);y-=height+14
            web.append('<p><strong>'+html.escape(label)+'.</strong> '+html.escape(text)+'</p>')
        if command:
            lines=command[0].splitlines();height=len(lines)*14+19
            assert y-height>66,(index,y,height)
            pdf.setFillColor(colors.HexColor('#F4F4F7'));pdf.roundRect(43,y-height,509,height,6,fill=1,stroke=0)
            pdf.setFillColor(ink);pdf.setFont('Courier',8.1)
            for n,line in enumerate(lines):pdf.drawString(51,y-16-n*14,line)
            web.append('<pre>'+html.escape(command[0])+'</pre>')
        pdf.setStrokeColor(colors.HexColor('#DDDDDF'));pdf.line(43,57,552,57)
        p=Paragraph('© 2026 Airtel Payments Bank. All rights reserved.',foot);p.wrap(440,20);p.drawOn(pdf,43,40)
        pdf.setFillColor(ink);pdf.setFont('Helvetica',8);pdf.drawRightString(552,40,str(index)+' / '+str(len(PAGES)))
        pdf.showPage();web.append('<footer>© 2026 Airtel Payments Bank. All rights reserved. / '+str(index)+' of '+str(len(PAGES))+'</footer></section>')
    pdf.save();web.append('</body></html>')
    target.with_suffix('.html').write_text(''.join(web))
    print(str(target.relative_to(ROOT)))


if __name__ == '__main__':
    main()
