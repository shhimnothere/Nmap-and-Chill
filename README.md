NmapAutomator v6.2 — Kali Linux + Obsidian
Version: 6.2  
Script: `NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh`  
Platform: Kali Linux (Bash 4+, Python 3, Nmap); Obsidian desktop for reviewing notes  
Purpose: Repeatable, authorized network discovery and reconnaissance with readable evidence, scan reuse, and a persistent assessment workflow.
> **Authorization:** Use this tool only against systems and networks that you are explicitly authorized to assess. `Vulns`, `--intrusive`, `--web-deep`, UDP sweeps, and aggressive timing can affect target performance. Treat automated findings as **observations**, not confirmed vulnerabilities.
---
1. What v6.2 does
Runs Nmap scan modes: `Quick`, `Basic`, `Full`, `UDP`, `Vulns`, `Recon`, `All`, and `Dashboard`.
Supports Nmap-style port selection and timing arguments, including `-p-`, `-p 22,80`, `--top-ports 100`, `-T4`, and `--max-retries 0`.
Reuses compatible scan evidence instead of rescanning completed modes by default; `--fresh` requests new measurements.
Uses previously discovered open ports for later service and reconnaissance steps when appropriate. Recon on an empty target first performs Quick discovery; it does not automatically perform a Basic service/version scan.
Generates browser-readable HTML reports, Nmap textual evidence, XML archives, and Obsidian-compatible Markdown notes.
Captures Recon tool output both live in the terminal and in raw evidence files.
Does not impose a global Recon process timeout. Tool-specific connection/request timeouts still apply.
Creates an assessment dashboard and persistent action notes organized as Needs Action → In Progress → Completed.
Preserves the analyst-owned sections of action notes during dashboard refreshes.
No Obsidian community plugin is required to use the generated dashboard or workflow. The optional plugins in Section 4 are conveniences, not dependencies.
2. Install on Kali Linux
2.1 Place the script
Put `NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh` in `~/htb/`:
```bash
mkdir -p ~/htb/scans
cd ~/htb
chmod +x NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh
bash -n NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh && echo 'PASS: Bash syntax'
```
`bash -n` checks Bash syntax only; it does not run Nmap or validate the embedded Python logic.
2.2 Install dependencies
```bash
sudo apt update
sudo apt install -y nmap python3 xsltproc curl nikto gobuster sslscan smbclient dnsutils snmp dirb
```
Required: `nmap`, `python3`, and `xsltproc` (for default HTML report generation). `bash` is already present on Kali.
Optional Recon tools: `curl`, `nikto`, `gobuster`, `sslscan`, `smbclient`, `dig` (provided by `dnsutils`), and `snmpwalk` (provided by `snmp`). Missing optional tools are logged as skipped.
Optional Nmap NSE correlation: `vulners.nse` if separately installed and supported in your Nmap scripts directory.
`dirb` typically supplies `/usr/share/wordlists/dirb/common.txt`, the wordlist v6.2 expects for Gobuster.
Check the installation:
```bash
nmap --version | head -2
python3 --version
command -v xsltproc nikto gobuster curl
bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh --help
```
3. Set up Obsidian as the scan-results vault
3.1 Open your existing scans folder
Install Obsidian from the official download page: https://obsidian.md/download.
Launch Obsidian on Kali.
Open Manage Vaults (vault switcher at the bottom of the left sidebar, if you already have a vault open).
Under Open folder as vault, choose Open.
Select the existing folder `/home/kali/htb/scans` (the same folder as `~/htb/scans` for the `kali` account).
Open the vault. Do not create a second `scans` folder or a nested vault.
Your target will then appear as a folder such as `10.129.100.150` in the left file explorer. The primary note is:
```text
10.129.100.150/00_TARGET_DASHBOARD.md
```
For other Linux usernames or a custom `--output` location, open that exact output directory as your vault. Obsidian reads the Markdown directly from disk; there is no export or import step.
Official guidance: https://obsidian.md/help/vault and https://obsidian.md/help/manage-vaults.
3.2 Turn on useful built-in (Core) plugins
Obsidian → Settings (gear) → Core plugins. Enable the following, if not already enabled:
Core plugin	Why it helps
File explorer	Navigate targets, `Runs/`, `Actions/`, and evidence notes.
Search	Find ports, services, CVEs, and observations across all scans.
Backlinks	See references to action notes and findings.
Bookmarks	Pin `00_TARGET_DASHBOARD.md` for quick access.
Outline	Jump between dashboard sections.
Page preview	Preview linked notes without leaving the dashboard.
File recovery	Recover accidentally edited Markdown notes when snapshots are available.
Properties view	Useful if you later add YAML properties to analyst notes.
Templates	Optional for creating your own manual finding or validation note templates.
These are Obsidian built-ins, not downloadable community plugins. A generated Markdown table does not need a table plugin to display correctly.
Core plugin reference: https://obsidian.md/help/plugins.
4. Install and configure optional Obsidian community plugins
4.1 Enable community plugin installation
In Obsidian, open Settings → Community plugins.
Select Turn on community plugins if prompted (this disables Restricted mode for community plugins).
Select Browse.
Search for a plugin by its exact name, select it, then choose Install.
Choose Enable. Verify it appears under Installed plugins and its toggle is on.
Repeat for the plugins you want below.
Community plugins execute third-party code and may access vault files or the network. Only enable plugins that your environment's security policy permits. For official instructions, see https://obsidian.md/help/community-plugins and https://obsidian.md/help/plugin-security.
4.2 Recommended plugins for this dashboard
Community plugin	Recommended use	Required by v6.2?
Homepage (mirnovov)	Open your target dashboard automatically when Obsidian starts.	No
Dataview (blacksmithgu)	Build an optional, separate cross-target note listing dashboards and action files.	No
Tasks (obsidian-tasks-group)	Maintain manual analyst checklists across notes.	No
Advanced Tables (Tony Grosinger)	Easier editing of your own Markdown tables.	No
Plugin pages: Homepage · Dataview · Tasks · Advanced Tables.
Configure Homepage (recommended)
Install and enable Homepage.
In Settings → Community plugins → Homepage, select the note to open on startup.
With `~/htb/scans` as your vault, choose `10.129.100.150/00_TARGET_DASHBOARD.md`.
Set the opening view to Reading if you prefer formatted dashboard tables.
Close and reopen Obsidian to confirm your assessment dashboard opens automatically.
If you rotate between targets, change Homepage to a manually maintained vault-level index rather than locking it to one IP.
Configure Dataview (optional cross-target index)
Install and enable Dataview.
Leave JavaScript queries disabled unless you explicitly need them; standard Dataview queries are sufficient for a simple index.
Create a new manual note at the top of your `scans` vault called `00_ASSESSMENTS_HOME.md`.
Paste the following Dataview block into that note (not into an auto-generated dashboard):
````markdown
# Assessment Home

## Target dashboards

```dataview
TABLE file.mtime AS "Last updated"
WHERE file.name = "00_TARGET_DASHBOARD"
SORT file.mtime DESC
```

## Recently edited action notes

```dataview
TABLE file.mtime AS "Last edited"
WHERE contains(file.path, "/Actions/")
SORT file.mtime DESC
LIMIT 30
```
````
Switch the new note to Reading view to see the tables. Dataview will index the existing Markdown files.
Important: v6.2's workflow status is stored in a plain Markdown line (`**Analyst status:** ...`), not a Dataview property. The example above is only a navigation index; Dataview does not automatically change the scanner's workflow groups.
Configure Tasks (optional manual checklist)
Install and enable Tasks.
Review its settings. Keep the global filter disabled initially unless you specifically want only `#task`-tagged checkboxes tracked.
Add manual Markdown checkboxes to your own notes, for example:
```markdown
- [ ] Validate the applicability of the Apache version advisory
- [ ] Review Nikto's HTTP header observations
- [ ] Document retest evidence
```
Optionally create a separate note containing this query:
````markdown
```tasks
not done
sort by filename
```
````
Tasks checkboxes do not replace `**Analyst status:**` and do not automatically update v6.2's three dashboard queues. To change a scanner action's queue, follow Section 7.
Configure Advanced Tables (optional)
Install and enable Advanced Tables if you frequently hand-edit tables in your own Markdown notes. It offers improved table navigation and formatting. Do not manually edit the generated tables in `00_TARGET_DASHBOARD.md`: the scanner regenerates that file.
4.3 Security guidance for plugins and assessment data
Consider running the core-only setup if your lab or organization disallows third-party plugin code.
Do not publish, sync to personal cloud services, or install automated upload integrations for assessment data without explicit authorization.
Treat unclassified data aggregation, credentials, host identifiers, and raw logs according to your applicable handling and classification guidance.
Back up `Actions/` and analyst-authored finding notes before experimenting with plugins that can modify vault files.
5. Quick-start scan sequence
Run these commands from `~/htb`. Replace the IP with an authorized target assigned to you.
```bash
cd ~/htb
SCRIPT=./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh
TARGET=10.129.100.150
```
Baseline (recommended for a clean target):
```bash
sudo bash "$SCRIPT" "$TARGET" Basic
```
Check evidence reuse:
```bash
sudo bash "$SCRIPT" "$TARGET" Basic
```
The second run should reuse a completed Basic scan of the same scope rather than repeating it.
Full TCP discovery:
```bash
sudo bash "$SCRIPT" "$TARGET" Full -p-
```
Vulnerability checks (CVE matches require validation):
```bash
sudo bash "$SCRIPT" "$TARGET" Vulns
```
Generate Recon recommendations without executing optional probes:
```bash
sudo bash "$SCRIPT" "$TARGET" Recon
```
Execute supported Recon probes and see live output:
```bash
sudo bash "$SCRIPT" "$TARGET" Recon --run-recon --web-deep
```
Fast, limited UDP survey:
```bash
sudo bash "$SCRIPT" "$TARGET" UDP --top-ports 100 -T4 --max-retries 0
```
Rebuild the Obsidian dashboard without network traffic:
```bash
bash "$SCRIPT" "$TARGET" Dashboard
```
Open `10.129.100.150/00_TARGET_DASHBOARD.md` in Obsidian afterward.
6. Command-line reference
6.1 Scan modes
Mode	What it does
`Quick`	Nmap's default TCP discovery scope.
`Basic`	Reuses prior open TCP discoveries if available; otherwise runs Quick, then service/version/default-script scan on detected ports.
`Full`	TCP discovery over all ports by default, then characterizes confirmed-open ports.
`UDP`	UDP discovery over Nmap's default UDP scope unless you select ports; investigates confirmed-open UDP ports.
`Vulns`	Runs NSE vulnerability checks on discovered open TCP ports; optionally uses `vulners.nse` if available.
`Recon`	Generates service-specific suggestions; executes supported probes only with `--run-recon`.
`All`	Runs the combined assessment modes; use with care because it can be time consuming.
`Dashboard`	Rebuilds notes, evidence links, and workflow lists; no scan launched.
6.2 Port scope and timing
```bash
# All UDP ports (slow)
sudo bash "$SCRIPT" "$TARGET" UDP -p-

# Top 100 UDP ports
sudo bash "$SCRIPT" "$TARGET" UDP --top-ports 100 -T4 --max-retries 0

# Equivalent friendly alias (scanner translates this to --top-ports)
sudo bash "$SCRIPT" "$TARGET" UDP -p top 100

# Named ports
sudo bash "$SCRIPT" "$TARGET" UDP -p 53,123,161,500,4500

# Port range
sudo bash "$SCRIPT" "$TARGET" UDP -p 1-1024

# TCP custom discovery
sudo bash "$SCRIPT" "$TARGET" Full -p 1-1024

# Cap each Nmap host to 10 minutes
sudo bash "$SCRIPT" "$TARGET" UDP --top-ports 100 --host-timeout 10m

# Force a new scan rather than using cached scan evidence
sudo bash "$SCRIPT" "$TARGET" Basic --fresh
```
The scanner explicitly accepts `-p-`, `-p VALUE`, `--top-ports N`, `-T0` through `-T5`, `--max-retries N`, `--host-timeout TIME`, `--min-rate N`, and `--max-rate N`. It does not accept arbitrary Nmap flags. Check `--help` for the full accepted list.
Coverage warning: `--top-ports 100` covers only a limited set; `--max-retries 0` can miss slow or filtered UDP services. A fast discovery sweep is not equivalent to a complete UDP assessment.
6.3 Recon switches
Option	Behavior
`--run-recon`	Execute supported follow-up probes and save results.
`--web-deep`	With `--run-recon`, also run Nikto and Gobuster where applicable.
`--snmp-community STRING`	Supply an explicitly authorized SNMP community string for eligible checks.
`--fresh`	Bypass compatible scan/probe caches and recollect evidence.
`--no-ping`	Use Nmap `-Pn`.
`--intrusive`	Permit broader vulnerability NSE checks; may be disruptive.
`--output DIR`	Set the output root; default is `./scans` relative to the current working directory.
`--no-html`	Do not generate HTML reports.
`--no-markdown`	Do not generate per-run Markdown notes (not recommended for Obsidian use).
`--max-hosts N`	Limit CIDR discovery targets; subnets broader than `/24` are unsupported.
Recon timeout behavior in v6.2: The old `--recon-timeout` option was removed. There is no scanner-enforced overall process cutoff. Individual tools still use their own connection/request timeouts; for example, Nikto uses `-timeout 10` (integer seconds per request), and Gobuster accepts `--timeout 10s` (duration syntax).
7. Use the three-stage Obsidian assessment workflow
Open your target dashboard. It contains Needs Action, In Progress, and Completed sections, with links to notes under `Actions/`.
7.1 Review a recommendation
Open `00_TARGET_DASHBOARD.md`.
Find an action under Needs Action, In Progress, or Completed.
Select Open action note.
Review the Purpose, Recommended command / procedure, Execution status, and Raw evidence link.
Write your analysis under Observations, Analyst validation notes, and Follow-up / disposition.
7.2 Move an action between queues
At the top of the individual `Actions/*.md` note, change the exact line:
```markdown
**Analyst status:** Auto
```
to one of:
```markdown
**Analyst status:** Needs Action
**Analyst status:** In Progress
**Analyst status:** Completed
```
Use only one `**Analyst status:**` line per note. `Auto` lets the script infer a queue from whether a probe has executed. A successful exit indicates execution, not a validated finding.
After saving the note, refresh the dashboard from Kali:
```bash
cd ~/htb
bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 10.129.100.150 Dashboard
```
The action moves to the selected group. Opening Obsidian by itself does not run commands or refresh Nmap evidence.
7.3 What the script can and cannot overwrite
Regenerated: `00_TARGET_DASHBOARD.md`, autogenerated scan summaries, and the section between `<!-- BEGIN GENERATED EVIDENCE -->` and `<!-- END GENERATED EVIDENCE -->` in an action note.
Preserved: `**Analyst status:**`, observations, analyst validation notes, follow-up/disposition, and the remaining analyst-authored text in `Actions/*.md`.
Analyst-authored findings: `01_FINDINGS.md` is created if absent and is not intended to be overwritten on each refresh.
Best practice: Do not edit the dashboard directly. Edit the underlying action note or findings note, and regenerate the dashboard.
8. File and evidence structure
```text
~/htb/scans/
└── 10.129.100.150/
    ├── 00_TARGET_DASHBOARD.md     # Auto-generated target overview
    ├── 01_FINDINGS.md             # Analyst-validated findings
    ├── Actions/                   # Persistent per-recommendation notes
    │   ├── recon_nikto_80.md
    │   ├── recon_http_headers_80.md
    │   └── coverage_*.md
    └── Runs/
        ├── 26-11-05_HH-MM-SS_Basic/
        │   ├── scan_summary.md
        │   ├── run.log
        │   ├── nmap/
        │   │   ├── quick.html
        │   │   ├── basic.html
        │   │   ├── quick.md
        │   │   ├── basic.md
        │   │   ├── quick.nmap
        │   │   ├── basic.nmap
        │   │   └── xml/
        │   │       ├── quick.xml
        │   │       └── basic.xml
        │   └── recon/
        └── 26-11-05_HH-MM-SS_Recon/
            ├── scan_summary.md
            ├── run.log
            └── recon/
                ├── recommendations.txt
                ├── 02_RECOMMENDED_ACTIONS.md
                ├── nikto_80.txt     # Raw stdout/stderr + command/metadata
                ├── nikto_80.status  # Tool exit code and elapsed time
                ├── nikto_80.md      # Readable Obsidian result
                ├── gobuster_80.txt
                └── gobuster_80.md
```
Folder timestamps and exact outputs vary by run. Original Nmap XML is kept under `nmap/xml/`; dashboard service entries link to HTML reports. HTML reports are web pages: depending on your Obsidian setup, open them in the system browser if Obsidian does not display them inline.
Recon result interpretation
Artifact	Meaning
`*.txt`	Captured raw tool output with identifying command header.
`*.status`	`EXIT=N DURATION_SECONDS=N` or an interrupted/running status.
`*.md`	Obsidian-readable result note linked from the dashboard/action.
`recommendations.txt`	Commands suggested from observed services.
`EXIT=0` means the command exited successfully, not that there are no vulnerabilities. Nonzero status requires investigation. A prior `EXIT=124` typically meant the old GNU `timeout` wrapper expired; v6.2 removes that wrapper.
9. Testing and verification
Use these after executing a scan:
```bash
cd ~/htb
TARGET_DIR="$HOME/htb/scans/10.129.100.150"

# Verify dashboard and workflow notes
ls -l "$TARGET_DIR/00_TARGET_DASHBOARD.md"
find "$TARGET_DIR/Actions" -type f -name '*.md' | sort

echo '=== Dashboard workflow queues ==='
grep -nE 'Needs Action|In Progress|Completed' "$TARGET_DIR/00_TARGET_DASHBOARD.md"

echo '=== HTML reports ==='
find "$TARGET_DIR/Runs" -name '*.html' | sort

echo '=== XML archives ==='
find "$TARGET_DIR/Runs" -name '*.xml' | sort

echo '=== Recon status files ==='
find "$TARGET_DIR/Runs" -name '*.status' | sort
```
Inspect the latest Nikto status and output, if present:
```bash
LATEST=$(find "$TARGET_DIR/Runs" -maxdepth 1 -type d -name '*_Recon*' | sort | tail -1)
if [[ -n "$LATEST" && -f "$LATEST/recon/nikto_80.status" ]]; then
  cat "$LATEST/recon/nikto_80.status"
  tail -50 "$LATEST/recon/nikto_80.txt"
else
  echo 'No Nikto output in the latest Recon run; it may have been reused from an older run.'
fi
```
Test that analyst notes survive refreshes
Open any `Actions/*.md` note.
Set `**Analyst status:** In Progress`.
Add a unique sentence under Analyst validation notes.
Run `Dashboard` mode.
Reopen the same note and verify the status and sentence remain intact.
10. Troubleshooting
Symptom	Likely cause / remedy
`bash -n` prints nothing	Normal for a syntax-valid Bash file.
`xsltproc` missing	Install `xsltproc`, or run with `--no-html` (not ideal for this dashboard).
Dashboard missing action notes	Run `Dashboard` mode and make sure you opened the actual `~/htb/scans` folder as the Obsidian vault.
Obsidian shows older content	Switch notes, use its command palette to reload the app if necessary, and verify the Markdown file changed on disk.
Running Basic again skips scanning	Expected cache behavior; use `--fresh` to collect new measurements.
Recon begins Quick on an empty target	Expected: Recon needs open-port discovery but does not automatically run Basic. Run Basic first for version enumeration.
No Nikto/Gobuster results	Deep web checks require `Recon --run-recon --web-deep`, eligible web ports, and the associated tool installed.
Nikto stops after 120 seconds	Verify you are running v6.2, not an older script with the global Recon timeout.
A tool appears stuck	v6.2 has no global Recon cutoff. Observe live output; stop manually with Ctrl+C if warranted, then review the saved `.status` and `.txt`.
`find: '/Runs': No such file or directory`	Your `$TARGET_DIR` variable is empty or unset. Set `TARGET_DIR="$HOME/htb/scans/10.129.100.150"`.
Cached results don't seem current	Use `--fresh` and check scan scope; cached observations are historical evidence.
HTML link does not render inside Obsidian	Open the corresponding `.html` from the file explorer in your browser. Markdown `.md` mirrors are available within Obsidian.
Community plugins unavailable	Check organizational restrictions and Obsidian's Restricted mode. Core functionality does not depend on community plugins.
11. Suggested operating practice
Baseline: Run `Basic`, then `Full` if all TCP ports must be covered.
Triage: Run `Vulns` and review CVE applicability manually.
Recommend: Run `Recon` to populate service actions.
Collect: Run `Recon --run-recon` and optionally `--web-deep` when within scope.
Cover gaps: Run a scoped UDP survey, then a wider scan if required.
Track: Open dashboard, annotate individual `Actions/` notes, and link confirmed issues in `01_FINDINGS.md`.
Revisit: Run `Dashboard` without scanning to rebuild the assessment view. Use `--fresh` only when a new measurement is needed.
Reminder: The script's generated recommendations and CVE matches are an analyst starting point. Verify affected configuration, exploit preconditions, security impact, and patches/backports before calling something a finding.
---
Reference documentation:
Obsidian official help
Obsidian community plugin installation and updates
Obsidian community-plugin security
Homepage plugin
Dataview plugin
Tasks plugin
Advanced Tables plugin
