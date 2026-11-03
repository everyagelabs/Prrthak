# Simple installation guides

Follow the controller guide first, then the agent guide. Each has nine short steps with pictures, four end-to-end command sheets, current preview screenshots and a small author note on every page.

| Install | Read and print | Copy commands in a browser |
|---|---|---|
| Controller on prepared RHEL 9 or Ubuntu 26.04 | [Controller PDF](controller-installation.pdf) | [Controller HTML](controller-installation.html) |
| Agent on RHEL 8/9 or Ubuntu 26.04 | [Agent PDF](agent-installation.pdf) | [Agent HTML](agent-installation.html) |

GitHub previews the PDFs. Download an HTML edition and open it in your browser for its copy buttons; all pictures are embedded. For a fresh machine, use **Command sheets 1–4 on pages 10–13** or the [end-to-end command runbook](../../installation-commands.md). Choose RHEL or Ubuntu preparation, then follow private file transfer, checksum verification, extraction, installation and status checks. The app's configuration stays in the GUI; no manual `.env` editing is required.

The commands require approved repositories, sudo/root, the signed pilot packages and independently approved release trust. They do not install on an unknown host automatically. Shell syntax and documentation are checked; native OS/DC execution remains pending.

![Controller guide first page](images/controller-guide-preview.png)

![Agent guide first page](images/agent-guide-preview.png)

For the rest of the product, read [all features in simple language](../../features-in-simple-language.md). The [detailed runbook](../../pilot-gui-installation.md) supplies technical steps. Synthetic preview screens and explanatory drawings are labelled. Native OS, real pilot and DC/DR testing remain pending.

<sub>Created by Pratik Srivastava</sub>
