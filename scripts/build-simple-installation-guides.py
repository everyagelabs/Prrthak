#!/usr/bin/env python3
"""Build picture-led installation HTML/PDF from reviewed current UI captures.

Uses ReportLab and Pillow. Never installs software, contacts an IdP, starts an
agent, or changes a firewall. Run the PDF-authoring operation marker before
starting a new authoring task; do not repeat it for layout iterations.
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import shutil
from pathlib import Path

from PIL import Image
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / 'docs/guide/simple'
IMAGES = GUIDE / 'images'
PDF_OUTPUT = ROOT / 'output/pdf'
def font_directory():
    candidates = [
        Path(os.environ['PRTHAK_GUIDE_FONT_DIR']) if os.environ.get('PRTHAK_GUIDE_FONT_DIR') else None,
        Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/native/libreoffice-headless/libreoffice/LibreOfficeDev.app/Contents/Resources/fonts/truetype',
        Path('/usr/share/fonts/truetype/dejavu'),
    ]
    for candidate in candidates:
        if candidate and all((candidate/file).is_file() for file in ('DejaVuSans.ttf','DejaVuSans-Bold.ttf','DejaVuSansMono.ttf')):
            return candidate
    raise SystemExit('Set PRTHAK_GUIDE_FONT_DIR to an approved DejaVu font directory')


FONTS = font_directory()
STAMP = '3 November 2026'
AUTHOR = 'Created by Pratik Srivastava'
COPYRIGHT = '© 2026 Airtel Payments Bank. All rights reserved.'
RED, INK, MUTED, LINE = '#df101b', '#18181b', '#62626c', '#e4e4e7'
W, H = A4
MARGIN = 36
WIDTH = W - 2 * MARGIN


def text(value): return {'kind': 'text', 'value': value}
def pic(name, caption, height=330, screenshot=False):
    return {'kind': 'picture', 'name': name, 'caption': caption, 'height': height, 'screenshot': screenshot}
def command(value, label='Paste this command and press Enter'):
    return {'kind': 'command', 'value': value, 'label': label}
def page(title, subtitle, *items):
    return {'title': title, 'subtitle': subtitle, 'items': list(items)}


CONTROLLER = [
    page('Prepare one controller VM', 'Controller guide  |  Step 1 of 9',
         pic('controller-preparation.png', 'Give this picture to your server team. These are starting allocations for 20 servers.', 370),
         text('<b>You need a prepared Linux server first.</b> Ask your server team to confirm the items in the picture. The app installer does not install Docker or Python.'),
         text('Use <b>RHEL 9 or Ubuntu 26.04</b>. Keep SELinux enabled. Reserve UID/GID 10001 for the dedicated application account.'),
         text('The rest of this guide uses one installer command and the browser. Native OS and DC testing are still to be completed.')),
    page('Make three connections available', 'Controller guide  |  Step 2 of 9',
         pic('network-ports.png', 'These are destination TCP ports. Allow return traffic and restrict access to approved networks.', 380),
         text('Ask the network team for a <b>fixed IP, a stable name, correct time and trusted HTTPS</b>. The installer needs approved image/package download access; this is not an offline installer.'),
         text('The installer does not open host firewall ports. Keep backend, database and cluster ports private. An approved load balancer can provide different public URLs.')),
    page('Run the controller installer', 'Controller guide  |  Step 3 of 9',
         pic('controller-install.png', 'Installation illustration. Your server address and progress messages will differ.', 290),
         text('Ask your release/server team for <b>prthak-controller-0.16.0.tar.gz</b>. They must verify its signature, copy it privately and extract it into a protected root-owned folder using independently approved release trust.'),
         text('Open Terminal in that extracted folder. Paste the command below. If sudo asks for your Linux password, type it and press Enter; the password does not appear on screen.'),
         command('sudo ./scripts/install-controller.sh --gui-setup'),
         text('Wait for installation to finish. Keep the <b>HTTPS setup URL</b> that it prints. Do not create or edit an .env file.')),
    page('Sign in and change the password', 'Controller guide  |  Step 4 of 9',
         pic('first-login.png', 'Illustration of the current login fields. This is not a live installation screenshot.', 385),
         text('Open the <b>exact HTTPS URL printed by the installer</b>. Your server team must confirm the certificate identity before you enter credentials.'),
         text('A fresh installation uses <b>admin / admin</b>. Replace the password with <b>12 to 256 characters</b> before entering the workspace. Existing installations keep their existing users.'),
         text('The built-in admin cannot be deleted, disabled, renamed or demoted. Its password can be changed or reset.')),
    page('Finish the platform settings', 'Controller guide  |  Step 5 of 9',
         pic('platform-setup-focus.jpg', 'Current v0.16 synthetic preview. An installed controller enables its supported setup actions.', 295, True),
         text('<b>Click Platform settings → Setup.</b> Use <b>Site &amp; cluster settings</b> for this node, then <b>HTTPS certificates</b> to prepare the permanent application name and approved certificate.'),
         text('Use the <b>Storage</b> tab for the data location. Default: <b>/var/lib/prthak</b>. Mount storage first; moving active data uses the reviewed GUI operation.'),
         text('Leave workers on <b>AUTO</b>. Start with one standalone node. It runs the controller/router with SQLite; PostgreSQL HA is a separate three-voter setup stage.')),
    page('Choose who may use the app', 'Controller guide  |  Step 6 of 9',
         pic('roles.png', 'Local accounts and configured organisation sign-in use the same three roles.', 365),
         text('<b>Click Users &amp; access.</b> As Super Admin, add the named people who will use Prṛthak and select their role.'),
         text('You may start with local accounts. Configure optional <b>SAML</b> here, or <b>Microsoft Entra</b> through Platform settings → Setup. SSO needs your identity team and explicitly provisioned users.'),
         text('Users change their own local password through the <b>top-right account menu</b>. Only Super Admin manages other users and roles.')),
    page('Set the update interval', 'Controller guide  |  Step 7 of 9',
         pic('polling-focus.jpg', 'Current synthetic preview. Desired settings are separate from an agent receipt showing they were applied.', 330, True),
         text('<b>Click Platform settings → Agent polling.</b> Start with <b>30 seconds</b> for policy control and <b>900 seconds</b> for the full inventory fallback.'),
         text('Preview affected servers, save the settings, then check their <b>applied polling status</b>. Later you can change the whole fleet or selected groups/tags here.'),
         text('Agents pull new policies automatically. Polling includes timing variation and network work; a saved setting is not a guaranteed completion time.')),
    page('Confirm the dashboard is ready', 'Controller guide  |  Step 8 of 9',
         pic('overview-focus.jpg', 'Current synthetic preview. A fresh installation should show your own records, not these example servers.', 285, True),
         text('<b>Check:</b> trusted HTTPS opens, your new password works, and controller readiness is healthy. Keep the printed URL and the new password in your approved records.'),
         text('<b>Next:</b> create your real locations in <b>Locations</b>, then follow the separate <b>Agent installation guide</b>. Servers appear after installation and their first authenticated report.'),
         text('Create a backup schedule in <b>Platform settings → Backups</b>. Back up private trust/identity material separately as required by the recovery procedure.'),
         text('An empty server list is normal before agents connect. Do not add example records to make the dashboard look populated.')),
    page('If something does not work', 'Controller guide  |  Step 9 of 9',
         pic('troubleshooting.png', 'Take the error message to your server team. Do not disable security checks to make an install continue.', 395),
         text('<b>No dashboard?</b> Ask the server team to check installation completion, Docker, the address, HTTPS trust and TCP 8787 access.'),
         text('<b>Need help preparing Linux?</b> Share the prerequisite page and the official Docker RHEL/Ubuntu instructions linked in the browser guide. The one app command assumes that preparation is complete.'),
         text('This guide explains the current code and GUI. Your native RHEL/Ubuntu validation, actual 20-server pilot and DC/DR tests remain separate deployment work.')),
]

AGENT = [
    page('Start with the controller ready', 'Agent guide  |  Step 1 of 9',
         pic('onboarding-flow.png', 'One reusable setup file; a separate private identity for every server.', 340),
         text('Use an installed HTTPS controller and sign in as <b>Admin or Super Admin</b>. Ask the server team to confirm each server is <b>RHEL 8/9 or Ubuntu 26.04</b>, with systemd and sudo/root access.'),
         text('Ask which CPU package to use: <b>x86_64 = AMD64</b>; <b>aarch64 = ARM64</b>. The same CPU binary supports both Linux families. The agent binary needs no separate Go, Python or Git setup; firewalld uses its normal OS packages.'),
         text('Agents need outbound access to the approved <b>control 8788</b> and <b>discovery 8789</b> origins. There is no inbound agent management port.')),
    page('Create one reusable fleet setup', 'Agent guide  |  Step 2 of 9',
         pic('agent-setup-top.jpg', 'Current synthetic preview. Real setup downloads require the installed HTTPS controller.', 425, True),
         text('<b>Click Install agent.</b> Choose <b>Fleet setup · reusable</b>, enter a profile name and choose how long new enrollment is allowed.'),
         text('Choose the matching <b>Linux family</b> and <b>CPU architecture</b>. The release team provides the agent package; the GUI download button supplies only the private setup file. Do not generate 20 different agents.'),
         text('A fleet setup can be reused until it expires or is revoked. There is no fixed enrollment-count limit.')),
    page('Enter the correct controller addresses', 'Agent guide  |  Step 3 of 9',
         pic('agent-setup-middle-focus.jpg', 'Current synthetic preview. Replace example names with the actual trusted addresses provided by your team.', 405, True),
         text('For a direct default-port installation, use the same trusted name with these ports. The three addresses have different jobs:'),
         command('https://YOUR-CONTROLLER-NAME:8787\nhttps://YOUR-CONTROLLER-NAME:8788\nhttps://YOUR-CONTROLLER-NAME:8789', 'Management / Control / Discovery, in that order'),
         text('Use your actual LB URLs if they differ. Add the approved public HTTPS CA chain when required. Never upload a private key in the agent CA field.')),
    page('Choose preparation and download', 'Agent guide  |  Step 4 of 9',
         pic('agent-setup-bottom-focus.jpg', 'Current synthetic preview. The disabled download is a preview limitation, not the installed workflow.', 420, True),
         text('Keep <b>Control polling = 30</b> and <b>Full inventory fallback = 900</b>. Select <b>Install missing OS dependencies</b> only if your server team approves package installation. Otherwise, they must already provide firewalld, iproute/iproute2, ca-certificates and util-linux.'),
         text('If Ubuntu uses UFW, optionally select <b>Assess UFW and export migration data</b>. UFW stays active. Installing missing firewalld packages does not start it or switch firewall managers.'),
         text('Click <b>Download private setup file</b>. Keep <b>prthak-agent-setup.json</b> private. New installs stay monitor-only; installation does not authorize firewall changes.')),
    page('Copy the two items to each server', 'Agent guide  |  Step 5 of 9',
         pic('agent-copy.png', 'Use your approved private deployment or file-transfer tool. Do not email the enrollment file.', 375),
         text('Ask your release/server team for <b>prthak-agent-0.16.0-linux-amd64.tar.gz</b> or <b>prthak-agent-0.16.0-linux-arm64.tar.gz</b>. They must verify the signature with approved independent trust and extract the matching package into a protected <b>root-owned release folder</b> on each server.'),
         text('Copy the same private setup to <b>/root/prthak-agent-setup.json</b>, owned by root with permission <b>0600</b> (0400 is also accepted). The server team can set this in the transfer tool.'),
         text('Do not copy another server\'s existing agent credentials or state. Your deployment tool can repeat the transfer and installation across all 20 hosts.')),
    page('Run one matching installer', 'Agent guide  |  Step 6 of 9',
         pic('agent-install.png', 'Installation illustration. Run one matching command on each server, from its extracted release folder.', 250),
         command('sudo ./scripts/install-agent-rhel.sh ' + chr(92) + '\n  --setup-file /root/prthak-agent-setup.json', 'RHEL 8 or 9'),
         command('sudo ./scripts/install-agent-ubuntu.sh ' + chr(92) + '\n  --setup-file /root/prthak-agent-setup.json', 'Ubuntu 26.04'),
         text('Choose <b>one</b> command for that server. Wait for the result. The installer starts the <b>seg-agent</b> systemd service; it does not start firewalld or disable UFW.'),
         text('A successful file install can still be waiting for the first report. Check the dashboard before calling the endpoint connected.')),
    page('Find the server and its services', 'Agent guide  |  Step 7 of 9',
         pic('servers-focus.jpg', 'Current synthetic inventory. The example OS versions are fixture data, not additional installer support.', 310, True),
         text('<b>Click Servers.</b> Search for the hostname or its reported IP. Check a fresh heartbeat, correct OS and discovered service ports. Open its row for <b>Services &amp; health</b> and <b>Discovered services</b>.'),
         text('Example: SSH can be recognised on <b>2022</b> from the running process. The agent reports its interface IPs even when the controller connection crosses NAT.'),
         text('New listener checks run every <b>5 seconds</b> on supported native agents; full inventory normally refreshes every <b>15 minutes</b>. A missing heartbeat raises an offline alert.')),
    page('Assign the location and tags', 'Agent guide  |  Step 8 of 9',
         pic('locations.png', 'Create location names first. The example network ranges explain automatic assignment.', 350),
         text('In <b>Locations</b>, create each real DC/cloud location. In <b>Servers</b>, select one or more hosts and click <b>Assign tags &amp; location</b>. A host has one location and many tags.'),
         text('For automatic assignment, add a subnet mapping. A <b>/24</b> can override a larger <b>/16</b>. The same exact network cannot be allocated to two locations. Manual assignments remain in control.'),
         text('You can also use <b>Import CSV</b>. Business tags and DCs are managed in the dashboard, not sent by the agent.')),
    page('Start safely and know what to check', 'Agent guide  |  Step 9 of 9',
         pic('monitoring-vs-learning.png', 'Monitoring records activity. Automatic learned access needs its own explicit authorization and endpoint opt-in.', 340),
         text('<b>First check inventory in monitor-only mode.</b> Seeing a server does not mean firewalld enforcement is enabled. Use the reviewed configuration workflow before live policy changes.'),
         text('<b>Missing server?</b> Ask the server team to check setup-file ownership, expiry, clocks, trusted CA and the exact 8788/8789 URLs. Keep an existing firewall manager running while the issue is reviewed.'),
         text('<b>No traffic history?</b> Enable temporary learning or optional per-port monitoring separately. Neither is collecting by default. Agent CPU/memory depends on the workload; profile it during the pilot.'),
         text('Native RHEL/Ubuntu firewall, rollback and DC testing remain to be performed in your environment.')),
]


def prepare_crops():
    # Crops preserve source pixels; no example record, button state or warning is
    # painted over. The original synthetic captures remain beside their crops.
    crops = {
        'platform-setup-focus.jpg': ('platform-setup.jpg', (235, 105, 1260, 690)),
        'polling-focus.jpg': ('polling.jpg', (235, 108, 1260, 720)),
        'overview-focus.jpg': ('overview.jpg', (0, 0, 1280, 700)),
        'servers-focus.jpg': ('servers.jpg', (235, 108, 1260, 710)),
        'agent-setup-middle-focus.jpg': ('agent-setup-middle.jpg', (330, 43, 950, 677)),
        'agent-setup-bottom-focus.jpg': ('agent-setup-bottom.jpg', (330, 43, 950, 677)),
    }
    result = []
    for target, (source, bounds) in crops.items():
        src = IMAGES / source
        im = Image.open(src)
        assert 0 <= bounds[0] < bounds[2] <= im.width and 0 <= bounds[1] < bounds[3] <= im.height
        im.crop(bounds).save(IMAGES / target, quality=95, subsampling=0)
        result.append({'file': target, 'source': source, 'crop': list(bounds)})
    return result


def para(c, value, top, width=WIDTH, x=MARGIN, size=11, muted=False):
    style = ParagraphStyle('guide-body', fontName='Guide', fontSize=size, leading=size*1.42,
                           textColor=colors.HexColor(MUTED if muted else INK))
    p = Paragraph(value, style)
    _, height = p.wrap(width, H)
    p.drawOn(c, x, top-height)
    return top-height


def picture_size(item):
    im = Image.open(IMAGES / item['name'])
    factor = min(WIDTH/im.width, item['height']/im.height)
    return im.width*factor, im.height*factor


def render_pdf(kind, pages):
    path = PDF_OUTPUT / f'prthak-{kind}-installation-simple.pdf'
    c = canvas.Canvas(str(path), pagesize=A4, pageCompression=1, invariant=1)
    c.setTitle(f'Prṛthak {kind} installation guide')
    c.setAuthor('Pratik Srivastava')
    c.setSubject('Picture-led guide for the 0.16 pilot candidate; native OS and DC acceptance deferred')
    metrics = []
    for index, data in enumerate(pages, 1):
        c.bookmarkPage(f'step-{index}')
        c.addOutlineEntry(f'{index}. {data["title"]}', f'step-{index}', 0)
        c.setFillColor(colors.HexColor(RED)); c.setFont('GuideBold', 17)
        c.drawString(MARGIN, H-37, 'Prṛthak')
        c.setFillColor(colors.HexColor(MUTED)); c.setFont('Guide', 8)
        c.drawRightString(W-MARGIN, H-34, f'0.16  |  {STAMP}')
        c.drawRightString(W-MARGIN, H-47, 'Airtel Payments Bank')
        c.setStrokeColor(colors.HexColor(LINE)); c.line(MARGIN, H-61, W-MARGIN, H-61)
        c.setFillColor(colors.HexColor(RED)); c.setFont('GuideBold', 9)
        c.drawString(MARGIN, H-82, data['subtitle'].upper())
        top = para(c, html.escape(data['title']), H-96, size=23)
        top -= 17
        drawn_image_area = 0
        for item in data['items']:
            if item['kind'] == 'text':
                top = para(c, item['value'], top)-11
            elif item['kind'] == 'command':
                top = para(c, f'<b>{html.escape(item["label"])}</b>', top, size=10)-6
                lines = item['value'].splitlines()
                size, leading = 10.1, 15
                height = leading*len(lines)+20
                c.setFillColor(colors.HexColor('#f3f3f5')); c.roundRect(MARGIN, top-height, WIDTH, height, 5, fill=1, stroke=0)
                c.setFont('GuideMono', size); c.setFillColor(colors.HexColor(INK))
                for row, line in enumerate(lines):
                    assert pdfmetrics.stringWidth(line, 'GuideMono', size) < WIDTH-22, line
                    c.drawString(MARGIN+11, top-17-row*leading, line)
                top -= height+12
            else:
                iw, ih = picture_size(item)
                c.drawImage(ImageReader(str(IMAGES/item['name'])), MARGIN+(WIDTH-iw)/2, top-ih, iw, ih, mask='auto')
                drawn_image_area += iw*ih
                top -= ih+7
                label = '<b>SYNTHETIC PREVIEW</b> · ' if item['screenshot'] else ''
                top = para(c, label+html.escape(item['caption']), top, size=8.3, muted=True)-13
        if top < 65:
            raise ValueError(f'{kind} page {index} overflows: bottom={top:.1f}')
        c.setStrokeColor(colors.HexColor(LINE)); c.line(MARGIN, 52, W-MARGIN, 52)
        c.setFillColor(colors.HexColor(MUTED)); c.setFont('Guide', 8)
        c.drawString(MARGIN, 37, AUTHOR)
        c.drawRightString(W-MARGIN, 37, f'{index} / {len(pages)}')
        c.setFont('Guide', 7); c.drawString(MARGIN, 23, COPYRIGHT)
        metrics.append({'page': index, 'bottom_points': round(top, 2), 'picture_area_points': round(drawn_image_area, 1)})
        c.showPage()
    c.save()
    shutil.copyfile(path, GUIDE/f'{kind}-installation.pdf')
    return path, metrics


def data_uri(path):
    mime = 'image/png' if path.suffix == '.png' else 'image/jpeg'
    return f'data:{mime};base64,'+base64.b64encode(path.read_bytes()).decode('ascii')


CSS = '''*{box-sizing:border-box}body{margin:0;background:#eeeef1;color:#18181b;font:17px/1.5 Arial,Helvetica,sans-serif}nav{background:#fff;border-bottom:1px solid #ddd;padding:14px 24px;display:flex;gap:20px;align-items:center;flex-wrap:wrap}a{color:#ba0712}nav a{font-size:14px}nav strong{margin-right:auto}article{background:#fff;width:min(820px,100%);margin:24px auto;padding:38px 46px;box-shadow:0 4px 26px #00000009;break-after:page}.brand{display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #e4e4e7;padding-bottom:15px}.brand strong{font-size:27px;color:#df101b}.brand small{font-size:11px;color:#62626c;text-align:right}.eyebrow{color:#c10b16;font-size:12px;letter-spacing:1px;margin:20px 0 6px;text-transform:uppercase}h1{font-size:32px;line-height:1.2;margin:0 0 20px;color:#000}p{margin:12px 0 17px}figure{margin:0 0 20px;text-align:center}figure img{max-width:100%;max-height:500px;width:auto;height:auto;object-fit:contain}figcaption{font-size:12px;color:#62626c;text-align:left;line-height:1.4;margin-top:10px}.synthetic{color:#a55200;font-weight:bold}.command-label{font-size:14px;margin-bottom:6px}pre{background:#f3f3f5;padding:14px;border-radius:5px;white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.6 Consolas,monospace;margin:0}button.copy{margin-top:5px;background:#df101b;color:white;border:0;border-radius:4px;padding:6px 12px;cursor:pointer}footer{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;border-top:1px solid #ddd;margin-top:26px;padding-top:12px;font-size:11px;color:#62626c}footer small{flex-basis:100%;font-size:10px}.help{font-size:14px}.help p{margin:9px 0}@media(max-width:600px){article{margin:0 0 12px;padding:24px 19px}h1{font-size:26px}body{font-size:16px}nav{padding:12px 16px}figure img{max-height:none}}@page{size:A4;margin:12mm}@media print{body{background:#fff;font-size:10.5pt}nav,.copy,.help{display:none}article{width:auto;margin:0;padding:0;box-shadow:none;min-height:268mm;position:relative}h1{font-size:23pt}.brand strong{font-size:18pt}.brand{padding-bottom:10px}.eyebrow{margin-top:12px}figure img{max-height:145mm}figcaption{font-size:8pt}footer{margin-top:16px}p{margin:8px 0 11px}pre{font-size:9pt}}
'''


def render_html(kind, pages):
    other = 'agent' if kind == 'controller' else 'controller'
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
           f'<title>Prṛthak {kind} installation guide</title><style>{CSS}</style></head><body>',
           f'<nav><strong>Prṛthak {kind} guide</strong><a href="{kind}-installation.pdf">Download PDF</a><a href="{other}-installation.html">{other.title()} guide</a><a href="../../features-in-simple-language.md">Features explained</a><button type="button" onclick="window.print()">Print</button></nav>']
    for index, data in enumerate(pages, 1):
        out.extend([f'<article id="step-{index}" aria-labelledby="title-{index}"><div class="brand"><strong>Prṛthak</strong><small>0.16 · {STAMP}<br>Airtel Payments Bank</small></div>',
                    f'<p class="eyebrow">{html.escape(data["subtitle"])}</p><h1 id="title-{index}">{html.escape(data["title"])}</h1>'])
        for item in data['items']:
            if item['kind'] == 'text': out.append('<p>'+item['value']+'</p>')
            elif item['kind'] == 'command':
                out.append(f'<div class="command-label"><b>{html.escape(item["label"])}</b></div><pre><code>{html.escape(item["value"])}</code></pre><button class="copy" type="button">Copy text</button>')
            else:
                prefix = '<span class="synthetic">SYNTHETIC PREVIEW · </span>' if item['screenshot'] else ''
                out.append(f'<figure><img src="{data_uri(IMAGES/item["name"])}" alt="{html.escape(item["caption"],quote=True)}"><figcaption>{prefix}{html.escape(item["caption"])}</figcaption></figure>')
        out.append(f'<footer><span>{AUTHOR}</span><span>{index} / {len(pages)}</span><small>{COPYRIGHT}</small></footer></article>')
    out.append('<article class="help"><h2>More help</h2><p>Official Docker preparation: <a href="https://docs.docker.com/engine/install/rhel/">RHEL</a> · <a href="https://docs.docker.com/engine/install/ubuntu/">Ubuntu</a>.</p><p>Detailed project guides: <a href="../../controller-installation.md">Controller</a> · <a href="../../linux-agent-installation.md">Agent</a> · <a href="../../local-and-saml-login.md">Local and SSO login</a> · <a href="../../requirements-delivery-map.md">Requirement register</a>.</p><p>All screenshots show the existing local synthetic preview. Diagrams explain the workflow and do not represent a completed native deployment. No passwords, private setup files or real server changes were captured.</p><footer>'+AUTHOR+'</footer></article>')
    out.append('''<script>document.querySelectorAll('.copy').forEach(button=>button.addEventListener('click',async()=>{const value=button.previousElementSibling.textContent;try{await navigator.clipboard.writeText(value);button.textContent='Copied';}catch{button.textContent='Select the text above to copy';}}));</script></body></html>''')
    (GUIDE/f'{kind}-installation.html').write_text('\n'.join(out), encoding='utf-8')


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    GUIDE.mkdir(parents=True, exist_ok=True); PDF_OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, file in [('Guide','DejaVuSans.ttf'),('GuideBold','DejaVuSans-Bold.ttf'),('GuideMono','DejaVuSansMono.ttf')]:
        pdfmetrics.registerFont(TTFont(name, str(FONTS/file)))
    crops = prepare_crops()
    results = {}
    for kind, pages in [('controller', CONTROLLER), ('agent', AGENT)]:
        pdf, metrics = render_pdf(kind, pages)
        render_html(kind, pages)
        html_file = GUIDE/f'{kind}-installation.html'
        results[kind] = {'pages': len(pages), 'pdf': str(pdf.relative_to(ROOT)), 'pdf_sha256': digest(pdf),
                         'html': str(html_file.relative_to(ROOT)), 'html_sha256': digest(html_file), 'layout': metrics}
    captures = []
    for source in ('overview.jpg', 'platform-setup.jpg', 'polling.jpg', 'servers.jpg', 'agent-setup-top.jpg', 'agent-setup-middle.jpg', 'agent-setup-bottom.jpg'):
        file = IMAGES/source
        captures.append({'file': source, 'sha256': digest(file), 'dimensions': list(Image.open(file).size),
                         'provenance': 'Actual v0.16 local synthetic preview captured through the in-app browser on 3 November 2026. No real endpoints, setup download or enforcement.'})
    receipt = {'edition': '0.16 documentation guides', 'created_on': '2026-11-03', 'author': 'Pratik Srivastava',
               'guides': results, 'captures': captures, 'pixel_preserving_crops': crops,
               'all_html_images_embedded': True, 'historical_exports_unchanged': True,
               'native_os_acceptance_completed': False, 'dc_deployment_completed': False,
               'visual_review_completed': False}
    (GUIDE/'verification.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({key: {'pages': value['pages'], 'pdf_sha256': value['pdf_sha256']} for key,value in results.items()}))


if __name__ == '__main__': main()
