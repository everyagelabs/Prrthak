#!/usr/bin/env python3
"""Build the simple guide's matching SVG and high resolution PNG diagrams.

Run with the approved workspace Python runtime. Pillow is the only dependency.
PRTHAK_DIAGRAM_FONT_DIR may point at a directory containing DejaVuSans.ttf and
SourceCodePro-Regular.ttf. No images, fonts or other assets are downloaded.
"""

from __future__ import annotations

import argparse
import html
import math
import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "docs/guide/simple/images"
RED = "#E60012"
DARK = "#202127"
MUTED = "#686B78"
BORDER = "#DEE0E6"
PALE = "#FFF2F3"
LIGHT = "#F6F7FA"
GREEN = "#237755"
WHITE = "#FFFFFF"
INK = "#13151C"
SCALE = 2


def font_directory() -> Path:
    candidates = [
        Path(os.environ["PRTHAK_DIAGRAM_FONT_DIR"])
        if os.environ.get("PRTHAK_DIAGRAM_FONT_DIR") else None,
        Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/poppler/poppler/fonts",
        Path("/usr/share/fonts/truetype/dejavu"),
    ]
    for candidate in candidates:
        if candidate and (candidate / "DejaVuSans.ttf").is_file():
            return candidate
    raise SystemExit("Set PRTHAK_DIAGRAM_FONT_DIR to the approved bundled font directory")


FONT_DIR = font_directory()
FONT_REGULAR = FONT_DIR / "DejaVuSans.ttf"
FONT_MONO = FONT_DIR / "SourceCodePro-Regular.ttf"
if not FONT_MONO.is_file():
    FONT_MONO = FONT_REGULAR


class Canvas:
    def __init__(self, name: str, title: str, subtitle: str, height: int = 780):
        self.name, self.w, self.h = name, 1260, height
        self.im = Image.new("RGB", (self.w * SCALE, self.h * SCALE), WHITE)
        self.draw = ImageDraw.Draw(self.im)
        self.fonts: dict[tuple[int, bool], ImageFont.FreeTypeFont] = {}
        self.svg = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" viewBox="0 0 {self.w} {self.h}" role="img" aria-labelledby="title desc">',
            f'<title id="title">{html.escape(title)}</title>',
            f'<desc id="desc">{html.escape(subtitle)} Created by Pratik Srivastava.</desc>',
            f'<rect width="{self.w}" height="{self.h}" fill="{WHITE}"/>',
        ]
        self.text(44, 28, "Prṛthak  /  Simple visual guide", 17, RED, bold=True)
        self.text(44, 66, title, 35, INK, bold=True)
        self.text(44, 117, subtitle, 21, MUTED)

    def font(self, size: int, mono: bool = False):
        key = (size, mono)
        if key not in self.fonts:
            self.fonts[key] = ImageFont.truetype(str(FONT_MONO if mono else FONT_REGULAR), size * SCALE)
        return self.fonts[key]

    def rect(self, x, y, w, h, fill=WHITE, stroke=BORDER, radius=18, width=1.5):
        self.draw.rounded_rectangle(
            (x*SCALE, y*SCALE, (x+w)*SCALE, (y+h)*SCALE),
            radius=radius*SCALE, fill=fill,
            outline=stroke, width=max(1, round(width*SCALE)),
        )
        self.svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{stroke}" stroke-width="{width}"/>')

    def line(self, x1, y1, x2, y2, color=BORDER, width=2.5, dashed=False):
        self.draw.line((x1*SCALE, y1*SCALE, x2*SCALE, y2*SCALE), fill=color, width=max(1, round(width*SCALE)))
        dash = ' stroke-dasharray="7 7"' if dashed else ""
        self.svg.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{width}" stroke-linecap="round"{dash}/>')

    def polyline(self, points, color=RED, width=3):
        scaled = [(x*SCALE, y*SCALE) for x, y in points]
        self.draw.line(scaled, fill=color, width=round(width*SCALE), joint="curve")
        self.svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="{width}" stroke-linecap="round" stroke-linejoin="round"/>')

    def polygon(self, points, fill, stroke=None, width=2):
        self.draw.polygon([(x*SCALE, y*SCALE) for x,y in points], fill=fill)
        if stroke:
            self.draw.line([(x*SCALE, y*SCALE) for x,y in points+[points[0]]], fill=stroke, width=round(width*SCALE))
        self.svg.append(f'<polygon points="{" ".join(f"{x},{y}" for x,y in points)}" fill="{fill}" stroke="{stroke or fill}" stroke-width="{width}"/>')

    def circle(self, cx, cy, radius, fill=WHITE, stroke=RED, width=2):
        self.draw.ellipse(((cx-radius)*SCALE,(cy-radius)*SCALE,(cx+radius)*SCALE,(cy+radius)*SCALE), fill=fill, outline=stroke, width=round(width*SCALE))
        self.svg.append(f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="{fill}" stroke="{stroke}" stroke-width="{width}"/>')

    def text(self, x, y, value, size=24, color=DARK, bold=False, anchor="start", mono=False, line_height=None):
        lines = str(value).split("\n")
        lh = line_height or size * 1.35
        font = self.font(size, mono)
        for index, value_line in enumerate(lines):
            py = y + index * lh
            length = self.draw.textlength(value_line, font=font) / SCALE
            px = x - length / 2 if anchor == "middle" else x - length if anchor == "end" else x
            if px < -1 or px + length > self.w + 1 or py < -1 or py + size > self.h + 1:
                raise ValueError(f"Text outside {self.name}: {value_line!r} at {px},{py}")
            self.draw.text((px*SCALE, py*SCALE), value_line, font=font, fill=color,
                           anchor="lt", stroke_width=round(.28*SCALE) if bold else 0)
            family = "Source Code Pro,DejaVu Sans,monospace" if mono else "DejaVu Sans,sans-serif"
            self.svg.append(f'<text x="{x}" y="{py}" font-family="{family}" font-size="{size}" font-weight="{"600" if bold else "400"}" fill="{color}" text-anchor="{anchor}" dominant-baseline="text-before-edge">{html.escape(value_line)}</text>')

    def arrow(self, x1, y1, x2, y2, color=RED, width=3):
        self.line(x1,y1,x2,y2,color,width)
        angle = math.atan2(y2-y1,x2-x1)
        tip = 11
        self.polygon([(x2,y2),
                      (x2-tip*math.cos(angle-.5),y2-tip*math.sin(angle-.5)),
                      (x2-tip*math.cos(angle+.5),y2-tip*math.sin(angle+.5))], color)

    def step(self, x, y, n):
        self.circle(x,y,20,RED,RED)
        self.text(x,y-14,str(n),21,WHITE,True,"middle")

    def icon(self, kind, x, y, size=60, color=RED):
        """Line icons built from the same primitives for both output formats."""
        s=size/60
        def line(a,b,c,d,w=2.4):self.line(x+a*s,y+b*s,x+c*s,y+d*s,color,w)
        def rect(a,b,w,h,r=4):self.rect(x+a*s,y+b*s,w*s,h*s,WHITE,color,r*s,2.3)
        def circle(a,b,r,fill=WHITE):self.circle(x+a*s,y+b*s,r*s,fill,color,2.3)
        if kind in ("server","agent"):
            rect(8,6,44,19);rect(8,34,44,19)
            circle(16,15,2,color);circle(16,43,2,color)
            line(25,15,43,15);line(25,43,43,43)
            if kind=="agent":
                circle(49,48,10,WHITE);line(44,48,48,52);line(48,52,55,43)
        elif kind=="browser":
            rect(4,7,52,39);line(4,17,56,17)
            for a in (11,17,23):circle(a,12,1.2,color)
            line(24,47,24,54);line(36,47,36,54);line(18,54,42,54)
        elif kind=="shield":
            p=[(x+30*s,y+4*s),(x+51*s,y+13*s),(x+48*s,y+36*s),(x+41*s,y+48*s),(x+30*s,y+57*s),(x+19*s,y+48*s),(x+12*s,y+36*s),(x+9*s,y+13*s)]
            self.polygon(p,WHITE,color,2.4)
            line(20,29,28,37);line(28,37,41,22)
        elif kind=="database":
            rect(9,11,42,37,5)
            self.draw.ellipse(((x+9*s)*SCALE,(y+5*s)*SCALE,(x+51*s)*SCALE,(y+20*s)*SCALE),fill=WHITE,outline=color,width=round(2.3*SCALE))
            self.svg.append(f'<ellipse cx="{x+30*s}" cy="{y+12.5*s}" rx="{21*s}" ry="{7.5*s}" fill="white" stroke="{color}" stroke-width="2.3"/>')
            line(10,30,50,30);line(10,42,50,42)
        elif kind=="clock":
            circle(30,30,24);line(30,15,30,31);line(30,31,41,37)
        elif kind in ("file","policy","cert"):
            rect(12,5,36,49);line(20,22,40,22);line(20,31,40,31);line(20,40,33,40)
            if kind=="cert":circle(44,47,10,WHITE);line(40,47,43,50);line(43,50,49,43)
        elif kind=="key":
            circle(18,23,11);line(28,30,49,51,4);line(40,42,47,35);line(45,47,52,40)
        elif kind=="lock":
            rect(10,25,40,29);rect(18,5,24,28,11);rect(10,25,40,29);circle(30,38,3,color);line(30,41,30,47)
        elif kind=="tag":
            self.polygon([(x+5*s,y+9*s),(x+31*s,y+9*s),(x+56*s,y+34*s),(x+31*s,y+58*s),(x+5*s,y+32*s)],WHITE,color,2.4)
            circle(16,20,3)
        elif kind=="location":
            circle(30,23,18);circle(30,23,6);line(15,34,30,55);line(30,55,45,34)
        elif kind=="cloud":
            for a,b,r in [(18,31,13),(31,23,17),(46,32,12)]:circle(a,b,r)
            self.rect(x+12*s,y+29*s,40*s,16*s,WHITE,WHITE,0,1)
            line(9,43,52,43)
        elif kind=="user":
            circle(30,17,10);rect(12,33,36,22,13)
        elif kind=="eye":
            self.polyline([(x+3*s,y+30*s),(x+14*s,y+18*s),(x+30*s,y+12*s),(x+46*s,y+18*s),(x+57*s,y+30*s),(x+46*s,y+42*s),(x+30*s,y+48*s),(x+14*s,y+42*s),(x+3*s,y+30*s)],color,2.3)
            circle(30,30,9)
        elif kind=="learn":
            line(23,5,37,5);line(26,5,26,23);line(34,5,34,23)
            self.polyline([(x+26*s,y+23*s),(x+10*s,y+49*s),(x+12*s,y+54*s),(x+48*s,y+54*s),(x+50*s,y+49*s),(x+34*s,y+23*s)],color,2.3)
            line(18,40,42,40);circle(25,46,1.8,color);circle(36,47,1.5,color)
        elif kind=="backup":
            rect(8,9,44,43);line(8,22,52,22);line(20,9,20,22);line(40,9,40,22)
            line(29,29,29,44);line(23,38,29,44);line(29,44,35,38)
        elif kind=="terminal":
            rect(3,8,54,44);line(3,18,57,18);line(13,29,20,36);line(20,36,13,43);line(27,43,42,43)
        elif kind=="check":
            circle(30,30,24);line(16,30,26,40,3);line(26,40,45,20,3)
        elif kind=="alert":
            self.polygon([(x+30*s,y+5*s),(x+57*s,y+53*s),(x+3*s,y+53*s)],WHITE,color,2.4)
            line(30,21,30,35,3);circle(30,44,1.5,color)
        elif kind=="tools":
            for a in (15,30,45):line(a,7,a,53)
            for a,b in ((15,21),(30,39),(45,27)):rect(a-6,b-4,12,8,2)
        elif kind=="network":
            rect(22,5,16,14,3);line(30,19,30,30);line(10,30,50,30)
            for a in (10,30,50):line(a,30,a,40);rect(a-7,40,14,13,3)

    def card(self,x,y,w,h,title,body="",icon=None,number=None,accent=False,title_size=25,body_size=20):
        offset=24
        if number is not None:offset=64
        elif icon:offset=83
        bounded=[(title,title_size,w-offset-20)]
        bounded.extend((line,body_size,w-48) for line in body.split("\n"))
        for value,size,available in bounded:
            if self.draw.textlength(value,font=self.font(size))/SCALE>available:
                raise ValueError(f"Text exceeds its card in {self.name}: {value!r}")
        self.rect(x,y,w,h,PALE if accent else WHITE,RED if accent else BORDER)
        if number is not None:
            self.step(x+30,y+32,number);offset=64
        elif icon:
            self.icon(icon,x+22,y+20,45);offset=83
        self.text(x+offset,y+25,title,title_size,DARK,True)
        if body:self.text(x+24,y+85 if icon else y+76,body,body_size,MUTED)

    def footer(self, note):
        self.line(44,self.h-72,self.w-44,self.h-72,BORDER,1)
        self.text(44,self.h-57,note,15,MUTED)
        self.text(self.w-44,self.h-30,"Created by Pratik Srivastava",14,MUTED,anchor="end")

    def save(self, directory):
        self.svg.append("</svg>")
        (directory/f"{self.name}.svg").write_text("\n".join(self.svg)+"\n",encoding="utf-8")
        self.im.save(directory/f"{self.name}.png",optimize=True)


def architecture():
    c=Canvas("architecture","One dashboard for your Linux servers","Each server protects its own traffic. The controller coordinates the rules.",800)
    c.card(46,204,310,168,"Linux server","Small systemd agent\nFinds services and rules",icon="agent")
    c.card(478,204,326,168,"Controller","Signed policy versions\nHealth checks and history",icon="shield",accent=True,title_size=26,body_size=19)
    c.card(924,204,290,168,"Your browser","Inventory, rules and alerts\nLocal or SSO login",icon="browser",title_size=25,body_size=18)
    c.arrow(356,280,478,280);c.text(418,216,"8788 / 8789",16,RED,True,"middle")
    c.arrow(924,280,804,280);c.text(864,239,"8787",17,RED,True,"middle")
    c.card(46,482,310,154,"Local firewalld","Allows approved traffic\nApplies the selected policy",icon="shield",body_size=19)
    c.arrow(202,372,202,482);c.text(224,412,"Local operations",17,MUTED)
    c.card(478,482,326,154,"Saved data","Inventory and policy versions\nTraffic evidence stored apart",icon="database",title_size=25,body_size=18)
    c.arrow(640,372,640,482);c.text(665,412,"Persistent storage",17,MUTED)
    c.icon("lock",1014,480,68);c.text(1060,569,"Encrypted HTTPS",19,DARK,True,"middle")
    c.text(1060,600,"Agents connect outward",17,MUTED,anchor="middle")
    c.footer("Architecture illustration • application packets travel directly to each server, not through the controller.")
    return c


def policy_flow():
    c=Canvas("policy-flow","Save a policy and follow its progress","Use the same policy form for supported RHEL and Ubuntu servers.",780)
    titles=["Choose access","Prepare version","Agent downloads","Apply safely","See the result"]
    icons=["policy","cert","agent","shield","browser"]
    bodies=["Servers or groups\nSources and ports","Compile and sign\nOnly affected servers","Next control sync\nVerify signed policy","Check SSH access\nRead back live rules","Applied or blocked\nRollback if needed"]
    for i in range(5):
        x=44+i*240
        c.rect(x,207,214,297,PALE if i==3 else WHITE,RED if i==3 else BORDER)
        c.step(x+31,239,i+1);c.icon(icons[i],x+77,278,62)
        c.text(x+107,366,titles[i],21,DARK,True,"middle")
        for j,line in enumerate(bodies[i].split("\n")):c.text(x+107,411+j*31,line,16,MUTED,anchor="middle")
        if i<4:c.arrow(x+215,350,x+237,350)
    c.icon("backup",54,563,52);c.text(130,562,"Safety checks fail → restore the last working policy",25,DARK,True)
    c.text(130,604,"Whole server default deny needs a fresh manual downtime acknowledgement.",19,MUTED)
    c.footer("Process illustration • Applied means agent readback; traffic proof needs a matching observed connection or packet.")
    return c


def onboarding_flow():
    c=Canvas("onboarding-flow","One fleet setup can enroll many servers","Download once. Copy securely. Each server receives its own identity.",810)
    c.card(48,193,335,160,"Agent package","AMD64 or ARM64\nChoose the matching CPU",icon="file",title_size=24)
    c.card(450,193,360,160,"Private fleet setup","Reusable while profile is active\nNo hostname list required",icon="key",accent=True,title_size=24,body_size=18)
    c.arrow(384,273,450,273)
    c.card(884,193,328,160,"Deploy to servers","One installer on each host\nYour team can automate this",icon="network",title_size=23,body_size=17)
    c.arrow(810,273,884,273)
    c.line(1048,353,1048,415,RED,3);c.line(228,415,1048,415,RED,3)
    for x,label,number in [(58,"RHEL server",1),(465,"Ubuntu server",2),(872,"More servers",3)]:
        center=x+165;c.arrow(center,415,center,466)
        c.card(x,466,330,178,label,"Local private key\nOwn certificate and ID",icon="agent",title_size=24,body_size=19)
        c.text(center,673,"Automatically appears in Servers",17,GREEN,True,"middle")
    c.footer("Enrollment illustration • never copy an initialized agent identity or private key between servers.")
    return c


def locations():
    c=Canvas("locations","Create locations then map their networks","A server belongs to one location and can have many application or business tags.",790)
    c.card(44,200,368,205,"Noida 81 DC","Network: 10.241.0.0/16\nIncludes 10.241.9.4",icon="location",title_size=26,body_size=21)
    c.card(848,200,368,205,"Pune DR","Network: 10.241.24.0/24\nIncludes 10.241.24.18",icon="location",accent=True,title_size=26,body_size=21)
    c.icon("server",589,226,74);c.text(626,330,"10.241.24.18",26,DARK,True,"middle")
    c.arrow(700,300,848,300);c.text(768,235,"More specific",17,RED,True,"middle")
    c.text(630,462,"The smaller matching network wins",30,DARK,True,"middle")
    c.text(630,508,"A /24 can sit inside another location's /16.",24,MUTED,anchor="middle")
    c.line(100,566,1160,566,BORDER,1.5)
    c.icon("tag",112,595,42);c.text(178,596,"Billing + Production + Critical",23,DARK,True)
    c.text(178,635,"Add tags manually, in bulk or by CSV. Manual location choices stay pinned.",19,MUTED)
    c.footer("Mapping example • the same exact network cannot be assigned to two different locations.")
    return c


def monitoring_learning():
    c=Canvas("monitoring-vs-learning","Watching traffic and learning access are separate","Choose the exact server and port. Seeing a source does not mean it is trusted.",810)
    c.rect(44,198,566,443,WHITE,BORDER);c.rect(650,198,566,443,PALE,BORDER)
    c.icon("eye",75,226,65);c.text(164,234,"Port hit monitoring",28,DARK,True)
    c.text(77,323,"Who hit this port in the last hour?",24,DARK,True)
    c.text(77,373,"Source IP  →  port  →  count and time",21,MUTED)
    c.text(77,427,"Review history or export a CSV",22,MUTED)
    c.icon("clock",80,488,46);c.text(148,497,"Optional and off by default",22,DARK,True)
    c.text(78,575,"Does not create access rules",22,GREEN,True)
    c.icon("learn",681,226,65);c.text(770,234,"Temporary learning",28,DARK,True)
    c.text(683,323,"Build access from observed traffic",23,DARK,True)
    c.text(683,373,"Choose ports and an end time",22,MUTED)
    c.text(683,427,"Review suggestions or enable",22,MUTED)
    c.text(683,461,"the exact auto allow scope",22,MUTED)
    c.icon("policy",686,509,42);c.text(752,516,"Rules appear in Policies",22,DARK,True)
    c.text(684,575,"Stop learning → capture stops",21,RED,True)
    c.text(630,675,"Saved learned grants stay until you review and remove them.",21,MUTED,anchor="middle")
    c.footer("Feature illustration • capture reports gaps or dropped events; observed counts are not a guaranteed complete ledger.")
    return c


def roles():
    c=Canvas("roles","Three roles with clear responsibilities","Local accounts and organisation SSO use the same permissions.",780)
    records=[(44,"Read Only","Look at servers\nView rules and traffic\nRead alerts and history","eye"),
             (452,"Admin","Manage servers and tags\nCreate and apply policies\nRun approved learning","user"),
             (860,"Super Admin","Everything Admin can do\nCreate users and set roles\nManage platform settings","shield")]
    for x,title,body,icon in records:
        c.rect(x,207,356,319,PALE if title=="Super Admin" else WHITE,BORDER)
        c.icon(icon,x+140,237,68);c.text(x+178,339,title,29,DARK,True,"middle")
        for i,line in enumerate(body.split("\n")):c.text(x+178,402+i*35,line,20,MUTED,anchor="middle")
    c.icon("lock",72,578,51);c.text(148,576,"Built in admin is permanent",27,DARK,True)
    c.text(148,620,"Change or reset its password. It cannot be deleted, disabled, renamed or demoted.",19,MUTED)
    c.footer("Permission illustration • only Super Admin can create users or change any user's role.")
    return c


def platform():
    c=Canvas("platform","Manage platform settings in the GUI","The local manager writes protected configuration and supervises supported changes.",830)
    items=[("cert","Certificates","PEM, PKCS12 or generate"),("backup","Backups","Create, schedule, recover"),
           ("database","Storage","Choose a protected data path"),("network","Cluster","Join approved site nodes"),
           ("clock","Agent polling","Global, group or server scope"),("browser","Application port","Review and change the port"),
           ("tools","Services","Supported start and restart"),("user","Users and SSO","Local, Entra or SAML")]
    for i,(icon,title,body) in enumerate(items):
        x=44+(i%4)*302;y=201+(i//4)*224
        c.rect(x,y,276,195,WHITE,BORDER);c.icon(icon,x+21,y+22,50)
        c.text(x+21,y+95,title,24,DARK,True);c.text(x+21,y+140,body,16,MUTED)
    c.text(630,684,"No manual .env editing for normal configuration",24,RED,True,"middle")
    c.footer("Feature illustration • database HA needs three eligible voters and real fencing; physical DC acceptance is still pending.")
    return c


def controller_preparation():
    c=Canvas("controller-preparation","Ask your server team to prepare one VM","RHEL 9 or Ubuntu 26.04 • intended hosts • native OS validation is still pending.",900)
    specs=[("4","vCPU"),("8 GiB","RAM"),("80 GiB","OS + Docker disk"),("100 GiB","Separate data SSD")]
    for i,(value,label) in enumerate(specs):
        x=44+i*302;c.rect(x,198,276,142,PALE,BORDER)
        c.text(x+138,221,value,39,RED,True,"middle");c.text(x+138,283,label,23,MUTED,anchor="middle")
    c.text(48,387,"Already installed on the VM",28,DARK,True)
    tools=[("Python 3.9+","Root owned interpreter"),("Docker Engine","Local service running"),("Compose v2","Docker plugin installed"),("systemd + sudo","Linux service and root access")]
    for i,(title,body) in enumerate(tools):
        x=44+(i%2)*604;y=442+(i//2)*130
        c.icon("check",x+10,y+10,40,GREEN);c.text(x+76,y+7,title,25,DARK,True)
        c.text(x+76,y+52,body,24,MUTED)
    c.line(44,717,1216,717,BORDER,1.5)
    c.text(48,744,"Also arrange",23,DARK,True)
    c.text(246,744,"Stable IP and DNS  •  correct time  •  approved downloads",23,MUTED)
    c.text(48,786,"Mount storage first. Prṛthak does not install Python or Docker.",24,RED,True)
    c.footer("Pilot planning allocation • fresh standalone setup needs no database cluster or watchdog.")
    return c


def network_ports():
    c=Canvas("network-ports","Ask for these three controller connections","Use your approved hostname or load balancer address and include the configured port.",820)
    c.card(44,209,324,155,"Your browser","Admin access",icon="browser",title_size=26,body_size=24)
    c.card(44,449,324,191,"Endpoint agent","RHEL or Ubuntu\nConnects outward",icon="agent",title_size=25,body_size=24)
    c.rect(911,209,305,431,PALE,RED);c.icon("shield",1021,243,80)
    c.text(1063,351,"Controller",30,DARK,True,"middle")
    c.text(1063,404,"Three separate",24,MUTED,anchor="middle");c.text(1063,439,"HTTPS listeners",24,MUTED,anchor="middle")
    c.arrow(368,287,911,287);c.text(635,231,"8787  Dashboard",25,RED,True,"middle")
    c.arrow(368,500,911,500);c.text(635,446,"8788  Policy and control",25,RED,True,"middle")
    c.arrow(368,602,911,602);c.text(635,550,"8789  Enrollment and reports",24,RED,True,"middle")
    c.text(630,686,"No inbound agent control port is needed on your Linux servers.",23,DARK,True,"middle")
    c.footer("Network illustration • endpoint mTLS must be preserved; an SSH safety probe uses its separately approved service port.")
    return c


def controller_install():
    c=Canvas("controller-install","Run one controller installer command","Start in the verified release folder prepared by your server team.",830)
    c.step(68,211,1);c.text(107,194,"Verified archive extracted into a protected folder",25,DARK,True)
    c.icon("file",62,253,62);c.text(154,264,"prthak-controller-0.16.0",25,MUTED,mono=True)
    c.step(68,369,2);c.text(107,352,"Copy this command and press Enter once",25,DARK,True)
    c.rect(44,412,1172,116,INK,INK,16)
    c.text(72,450,"sudo ./scripts/install-controller.sh --gui-setup",27,WHITE,mono=True)
    c.step(68,591,3);c.text(107,574,"Open the HTTPS setup URL printed by the installer",25,DARK,True)
    c.text(107,629,"https://<CONTROLLER-IP>:8787/settings",27,RED,mono=True)
    c.text(107,681,"Verify its certificate identity before entering login details.",24,MUTED)
    c.footer("Installation illustration • Python, Docker and Compose must already be prepared; normal setup needs no .env file.")
    return c


def first_login():
    c=Canvas("first-login","Sign in then replace the temporary password","Illustration of the current first login screens • a fresh empty account database only.",960)
    c.rect(44,196,548,575,WHITE,BORDER);c.rect(667,196,548,575,WHITE,BORDER)
    c.text(72,225,"Sign in to Prṛthak",27,DARK,True)
    c.text(72,286,"Local username",24,MUTED);c.rect(72,323,490,59,LIGHT,BORDER,9)
    c.text(91,337,"admin",25,DARK)
    c.text(72,411,"Password",24,MUTED);c.rect(72,449,490,59,LIGHT,BORDER,9)
    c.text(91,465,"•••••",26,DARK)
    c.rect(72,556,490,59,RED,RED,10);c.text(317,574,"Sign in with local account",24,WHITE,True,"middle")
    c.text(72,654,"Temporary username: admin",24,MUTED)
    c.text(72,693,"Temporary password: admin",24,MUTED)
    c.arrow(603,473,655,473)
    c.text(695,225,"Change your password",27,DARK,True)
    for i,label in enumerate(["Current password","New password","Confirm new password"]):
        y=286+i*118;c.text(695,y,label,24,MUTED);c.rect(695,y+36,490,55,LIGHT,BORDER,9)
        c.text(714,y+50,"••••••••••••",23,DARK)
    c.rect(695,668,490,59,RED,RED,10);c.text(940,686,"Change password",23,WHITE,True,"middle")
    c.text(630,809,"Use a personal password of 12–256 characters before entering the workspace.",24,DARK,True,"middle")
    c.text(630,850,"Built in admin is permanent. Only its password can be changed or reset.",24,MUTED,anchor="middle")
    c.footer("UI illustration, not a screenshot • existing installations keep their existing users and passwords.")
    return c


def agent_copy():
    c=Canvas("agent-copy","Copy the same private setup to your servers","Your server team can distribute the files to all hosts with an approved deployment tool.",860)
    c.card(44,196,554,171,"Matching agent archive","AMD64 for x86_64\nARM64 for aarch64",icon="file",title_size=25,body_size=24)
    c.card(654,196,562,171,"One private fleet setup","/root/prthak-agent-setup.json\nRoot owned, private mode 0600",icon="key",title_size=25,body_size=24,accent=True)
    c.line(321,368,321,418,RED,3);c.line(935,368,935,418,RED,3)
    c.line(321,418,935,418,RED,3);c.line(630,418,630,456,RED,3)
    c.line(223,456,1037,456,RED,3)
    for x,label in [(44,"RHEL 8"),(451,"RHEL 9"),(858,"Ubuntu 26.04")]:
        c.arrow(x+179,456,x+179,502);c.rect(x,502,358,175,WHITE,BORDER)
        c.icon("server",x+30,532,62);c.text(x+117,542,label,25,DARK,True)
        c.text(x+179,629,"Local private key",24,MUTED,anchor="middle")
    c.text(630,718,"Do not create or download a different agent for every server.",24,DARK,True,"middle")
    c.text(630,759,"Never copy an enrolled agent's identity folder to another host.",24,RED,anchor="middle")
    c.footer("Deployment illustration • verify release signatures before extraction; keep the reusable enrollment setup private.")
    return c


def agent_install():
    c=Canvas("agent-install","Run the matching command on each server","Start in the verified extracted agent folder. Choose the command for that server's OS.",960)
    c.text(48,193,"RHEL 8 or RHEL 9",27,DARK,True)
    c.rect(44,242,1172,134,INK,INK,14)
    c.text(70,269,"sudo ./scripts/install-agent-rhel.sh \\\n  --setup-file /root/prthak-agent-setup.json",25,WHITE,mono=True,line_height=39)
    c.text(48,419,"Ubuntu 26.04",27,DARK,True)
    c.rect(44,468,1172,134,INK,INK,14)
    c.text(70,495,"sudo ./scripts/install-agent-ubuntu.sh \\\n  --setup-file /root/prthak-agent-setup.json",25,WHITE,mono=True,line_height=39)
    records=[(44,"seg-agent starts","Native systemd service","agent"),(451,"First report arrives","Authenticated report","lock"),(858,"Visible in Servers","OS, IP and services","browser")]
    for x,title,body,icon in records:
        c.rect(x,664,358,139,WHITE,BORDER);c.icon(icon,x+18,683,44)
        c.text(x+77,690,title,24,DARK,True);c.text(x+179,758,body,24,MUTED,anchor="middle")
        if x<858:c.arrow(x+359,734,x+405,734)
    c.text(630,838,"Installation starts in monitor only mode. Firewall enforcement stays off.",23,RED,True,"middle")
    c.footer("Command illustration • the backslash continues the command on the next line; run one matching command per host.")
    return c


def troubleshooting():
    c=Canvas("troubleshooting","If something does not look right","Pause and ask your server team before changing network security or firewall settings.",950)
    records=[("browser","Dashboard does not open","Check installation, Docker, URL\nand the approved network path."),
             ("cert","Certificate warning","Verify hostname and trusted CA.\nDo not bypass trust checks."),
             ("agent","Server does not appear","Check ports 8788 and 8789,\ntime and enrollment expiry."),
             ("file","Wrong OS or CPU package","Ask for the matching supported\nLinux family and CPU release."),
             ("shield","UFW is already active","Keep it running. Review a separate\nmigration before enforcement."),
             ("policy","Policy is not applied","Check monitor mode and the\nreason shown in rollout status.")]
    for i,(icon,title,body) in enumerate(records):
        x=44+(i%2)*604;y=194+(i//2)*212
        c.rect(x,y,568,188,WHITE,BORDER);c.icon(icon,x+20,y+22,45)
        c.text(x+85,y+29,title,24,DARK,True)
        c.text(x+24,y+101,body,24,MUTED,line_height=34)
    c.text(630,861,"A screenshot or installation message alone does not prove live firewall protection.",21,RED,True,"middle")
    c.footer("Troubleshooting illustration • native RHEL, Ubuntu and physical DC testing remain deployment acceptance work.")
    return c


BUILDERS = [architecture,policy_flow,onboarding_flow,locations,monitoring_learning,
            roles,platform,controller_preparation,network_ports,controller_install,
            first_login,agent_copy,agent_install,troubleshooting]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir",type=Path,default=DEFAULT_OUTPUT)
    args=parser.parse_args()
    args.output_dir.mkdir(parents=True,exist_ok=True)
    for builder in BUILDERS:
        canvas=builder();canvas.save(args.output_dir)
        print(f"{canvas.name}: {canvas.w}x{canvas.h} SVG; {canvas.w*SCALE}x{canvas.h*SCALE} PNG")


if __name__=="__main__":
    main()
