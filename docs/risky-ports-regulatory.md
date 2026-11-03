# Risky ports, reasons and regulatory context

**Risk & compliance** lists matching agent-reported listeners, with the endpoint, port/protocol, binding, severity, reason, recommended action and reference. Server rows and discovered-service details also show risk badges. Network-bound matches produce alerts; loopback matches remain visible without a network-listener alert. Stale discovery stays labelled and cannot prove that a service closed.

The initial catalogue has 29 configurable TCP/UDP rules. Admins can change severity, reasons, recommendations and ranges, disable defaults, or add organization-specific services. Saving uses a revision check so another Admin's changes cannot be overwritten accidentally. These are review indicators; catalogue changes do not install firewall rules.

| Review family | Initial examples | Why review |
| --- | --- | --- |
| Legacy administration | FTP21, Telnet23, TFTP69, remote-shell TCP514 | Potential weak transport or authentication; verify the actual service |
| Sharing/discovery | RPC111, NetBIOS137–139, SMB445, NFS2049 | Unnecessary cross-server access and reconnaissance paths |
| Remote desktops/displays | RDP3389, VNC5900–5909, X116000–6063 | Sensitive interactive access or screen/control exposure |
| Management/data APIs | Docker2375, etcd2379/2380, Elasticsearch9200 | Privileged operations or sensitive data need restricted clients |
| Databases/caches | SQL1433/3306/5432, Redis6379, MongoDB27017, Memcached11211 | Review client restrictions, authentication and transport |
| Monitoring/directory | SNMP161, LDAP389 | Verify secure versions and approved consumers |

Port numbers are service hints. An application may use a different port, and a familiar port may run a different application. For example, a PostgreSQL indicator asks for access review; it does not claim PostgreSQL itself is vulnerable or internet-accessible. The default severity/reason choices are product judgments informed by guidance, rather than a mandatory regulator-issued port blacklist.

The baseline references [CISA's remote-service guidance](https://www.cisa.gov/sites/default/files/publications/AA22-137A-Weak_Security_Controls_and_Practices_Routinely_Exploited_for_Initial_Access.pdf), [network hardening guidance](https://www.cisa.gov/sites/default/files/ar-16-20173.pdf), [IANA's port registry](https://www.iana.org/assignments/service-names-port-numbers/), [Docker daemon protection](https://docs.docker.com/engine/security/protect-access/) and [Redis security guidance](https://redis.io/docs/latest/operate/oss_and_stack/management/security/). The catalogue records references beside each rationale. References were checked on 1 November 2026.

## CERT-In and RBI

The dashboard maps selected operational requirements to available product support and explicit evidence gaps. It links directly to the [CERT-In directions](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf), [RBI IT Governance directions](https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12562) and [RBI Digital Payment Security Controls](https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12032). Applicability belongs to the regulated entity's assessment.

The mapping covers clock traceability, incident reporting/contact ownership, log custody, access, change recovery, audit, testing, tier separation and DR. It shows `partial` or `operator evidence/process required` when this tool cannot establish the requirement. It does not assign a compliance score or certify a deployment.

Temporary learning and the optional rolling hit history are operational discovery features. Their short retention does not establish the required security-log archive. Verify the organization's retention/location, log review and incident process separately. Entra integration does not establish that the tenant enforces MFA; configured HA does not establish that failover was tested. A risky listener is an indicator for investigation, not automatically a reportable incident.

## Scope and limits

The tool reads existing discovery data; it does not perform an intrusive port or vulnerability scan. All classified listeners use a compact cache, bounded by the endpoint’s 2,000-listener input limit. Risk-page filters and counts use that complete cache before pagination. Detailed endpoint panels retain the first 256 full reasons and mark the limit explicitly. Overlapping rules select the highest severity, then the narrower range; those choices are deterministic. Missing classification is shown as pending rather than a verified zero. Native discovery, actual network reachability, service encryption/authentication, independently reviewed VA/PT and DC/DR acceptance remain separate evidence.

<sub>Created by Pratik Srivastava</sub>
