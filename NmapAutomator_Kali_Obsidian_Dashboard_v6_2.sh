#!/usr/bin/env bash
# nmapAutomator v6.2 - live console + saved recon results; reproducible, per-run reconnaissance for explicitly authorized targets.
# Dependencies: bash 4+, nmap, python3. Optional recon tools: curl, gobuster, nikto, sslscan, smbclient, dig, snmpwalk.
set -Eeuo pipefail
umask 077

usage() {
  cat <<'HELP'
Usage: NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh <IPv4-or-CIDR> <Quick|Basic|UDP|Full|Vulns|Recon|All> [options]

Modes:
  Quick  Scan Nmap's default TCP ports.
  Basic  Quick discovery + TCP service/version/default-script scan.
  UDP    Scan Nmap's default UDP ports, then investigate confirmed-open UDP ports.
  Full   Scan all 65535 TCP ports, then investigate discovered ports.
  Vulns  Quick discovery + TCP service/version and non-intrusive vuln NSE checks;
         also run vulners if installed.
  Recon  Quick + Basic discovery, generate service-specific recon suggestions.
  All    Quick, Basic, UDP, Full, Vulns, Recon.
  Dashboard  Refresh recommendations, links and recon results (no scan performed).

Options:
  -p-             Scan all 65535 ports for the selected scan protocol.
  -p 53,123,161   Scan selected ports (also accepts -p53,123,161 or -p 1-1024).
  --top-ports N   Scan N most common ports (e.g. --top-ports 100).
  -p top 100     Friendly alias for --top-ports 100 (not native Nmap syntax).
  -T0..5         Nmap timing profile, e.g. -T4.
  --max-retries N    Nmap probe retransmission limit (e.g. 0 for fast UDP).
  --host-timeout TIME   Nmap per-host timeout, e.g. 10m.
  --min-rate N / --max-rate N   Nmap packet-rate controls.
  --run-recon     Execute supported recommendations (HTTP/TLS/SMB/DNS) and save notes.
                  By default Recon only writes suggestions.
  --web-deep      With --run-recon, also execute Nikto and Gobuster recommendations.
                  These tools can run for a long time; interrupt with Ctrl+C.
  --snmp-community STRING
                  With --run-recon, permit SNMP walk with supplied community.
                  Never assumes public or another community string.
  Recon tool processes have no scanner-enforced overall timeout.
                  Tool-specific connection/request timeouts remain (e.g. Nikto 10 seconds).
                  Recon stdout/stderr streams to the console AND raw evidence files.
  --intrusive     Permit Nmap's broader 'vuln' NSE category (may be disruptive).
  --no-ping       Use -Pn even if ICMP echo responds.
  --output DIR    Base output directory (default: ./scans).
  --max-hosts N   Maximum discovered hosts to scan in CIDR mode (default: 256).
  --no-markdown   Disable automatic Obsidian-compatible Markdown notes.
  --no-html       Disable automatic HTML reports (enabled by default).
  -h, --help      Show this help.

Run only against systems you are authorized to assess. By default each run creates
HTML reports from Nmap XML and Markdown notes for Obsidian. When run with sudo,
new scan files and directories are transferred to the invoking user on exit.
Results are never overwritten:
  <output>/<IP>/Runs/<local YY-MM-DD_HH-MM-SS>_<ScanType>/nmap/ and recon/
  XML is stored in nmap/xml; readable HTML reports remain in nmap/.
  A target dashboard and findings tracker live beside Runs/. Older folders remain in place.

Examples:
  ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 All
  ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 Recon --run-recon
  ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 Recon --run-recon --web-deep
  sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 UDP
  sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.86.0/24 Quick
  bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 Dashboard
  sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 UDP --top-ports 100
  sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 UDP -p-
  sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh 192.168.56.101 UDP -p 53,123,161 -T4 --max-retries 0
HELP
}

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG" >&2; }
warn() { log "WARNING: $*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
valid_ipv4() {
  local ip=$1 octet
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local -a octets
  IFS=. read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    [[ $octet =~ ^[0-9]{1,3}$ ]] || return 1
    (( 10#$octet <= 255 )) || return 1
  done
}

# Parse actual Nmap XML output, not human-formatted text. Print CSV port numbers.
# A port is included only when its state exactly equals 'open'.
xml_ports() {
  local protocol=$1; shift
  python3 - "$protocol" "$@" <<'PY'
import os, sys, xml.etree.ElementTree as ET
proto = sys.argv[1]
found = set()
for filename in sys.argv[2:]:
    if not os.path.isfile(filename):
        continue
    try:
        root = ET.parse(filename).getroot()
    except (ET.ParseError, OSError) as exc:
        print(f"WARNING: Cannot parse {filename}: {exc}", file=sys.stderr)
        continue
    for port in root.findall('.//port'):
        state = port.find('state')
        if port.get('protocol') == proto and state is not None and state.get('state') == 'open':
            found.add(int(port.get('portid')))
print(','.join(map(str, sorted(found))))
PY
}

# Load confirmed open ports from existing runs. Prefer the most recent Full/All
# TCP discovery, falling back to the union of other existing positive observations.
# Evidence is deliberately not copied or silently treated as a fresh scan.
cached_ports() {
  local proto=$1
  python3 - "$BASE_DIR/$TARGET" "$proto" <<'PYCACHE'
import json, pathlib, sys, xml.etree.ElementTree as ET
root, proto = pathlib.Path(sys.argv[1]), sys.argv[2]
runs=[]
for parent in (root/'Runs', root):
    if parent.exists():
        for folder in parent.iterdir():
            if not folder.is_dir() or not (folder/'nmap').is_dir(): continue
            meta=folder/'.scan_status.json'
            if meta.exists():
                try:
                    if json.loads(meta.read_text()).get('failures',1) != 0: continue
                except (OSError,ValueError): continue
            xmls=list((folder/'nmap'/'xml').glob('*.xml'))+list((folder/'nmap').glob('*.xml'))
            if xmls: runs.append((folder.stat().st_mtime,folder,xmls))
runs.sort(reverse=True)
# A Full TCP discovery is more complete than a Quick scan; use its open ports
# plus positive observations from newer runs, if any.
selected=runs
if proto=='tcp':
    for i,(_,folder,xmls) in enumerate(runs):
        if any(x.stem=='full_discovery' for x in xmls):
            selected=runs[:i+1]
            break
ports=set()
for _,_,xmls in selected:
    for f in xmls:
        try: node=ET.parse(f).getroot()
        except (OSError,ET.ParseError):continue
        for host in node.findall('.//host'):
            for p in host.findall('./ports/port'):
                state=p.find('state')
                if p.get('protocol')==proto and state is not None and state.get('state')=='open':
                    try:ports.add(int(p.get('portid')))
                    except (ValueError,TypeError):pass
print(','.join(map(str,sorted(ports))))
PYCACHE
}

# Reuse existing evidence rather than launch another discovery scan.
known_ports() {
  local proto=$1 result
  if (( ! FRESH && ! CUSTOM_SCOPE )); then
    result=$(cached_ports "$proto")
    if [[ -n $result ]]; then printf '%s\n' "$result"; return 0; fi
  fi
  if [[ $proto == tcp ]]; then
    xml_ports tcp "$NMAP_DIR/quick.xml" "$NMAP_DIR/full_discovery.xml" "$NMAP_DIR/basic.xml"
  else
    xml_ports udp "$NMAP_DIR/udp_discovery.xml" "$NMAP_DIR/udp_services.xml"
  fi
}

ensure_tcp_discovery() {
  local ports
  ports=$(known_ports tcp)
  if [[ -n $ports ]]; then
    log "Reusing previously discovered TCP ports: $ports (no Quick scan)"
  else
    log 'No reusable TCP ports found; performing Quick discovery'
    quick_scan
  fi
}

# Nmap is always invoked through argument arrays: no eval or shell-generated commands.
run_nmap() {
  local name=$1; shift
  local stem="$NMAP_DIR/$name"
  log "START $name: nmap $*"
  if nmap "${HOST_ARGS[@]}" "$@" "${NMAP_TUNING_ARGS[@]}" -oA "$stem" "$TARGET" 2>&1 | tee -a "$LOG"; then
    log "DONE $name (output: ${stem}.{nmap,xml,gnmap})"
  else
    local rc=${PIPESTATUS[0]}
    warn "$name failed (exit $rc); results may be incomplete"
    FAILURES=$((FAILURES + 1))
    return 1
  fi
}

quick_scan() {
  if (( CUSTOM_SCOPE )); then
    run_nmap quick -T4 --max-retries 1 --open "${PORT_ARGS[@]}"
  else
    run_nmap quick -T4 --max-retries 1 --open
  fi
}
basic_scan() {
  local ports
  ports=$(known_ports tcp)
  [[ -n $ports ]] || { warn 'No confirmed-open TCP ports from Quick; skipping Basic'; return 0; }
  run_nmap basic -sC -sV -p "$ports"
}

udp_scan() {
  if (( EUID != 0 )); then
    warn 'UDP scanning generally requires root/raw-socket privileges; use sudo'
    FAILURES=$((FAILURES + 1)); return 1
  fi
  if (( CUSTOM_SCOPE )); then
    run_nmap udp_discovery -sU --max-retries 1 --open "${PORT_ARGS[@]}" || return 1
  else
    run_nmap udp_discovery -sU --max-retries 1 --open || return 1
  fi
  local ports
  ports=$(xml_ports udp "$NMAP_DIR/udp_discovery.xml")
  if [[ -n $ports ]]; then
    run_nmap udp_services -sU -sC -sV -p "$ports" || return 1
  else
    log 'No confirmed-open UDP ports; open|filtered candidates remain in udp_discovery XML'
  fi
}

full_scan() {
  if (( CUSTOM_SCOPE )); then
    run_nmap full_discovery -T4 --max-retries 1 --max-rate 500 "${PORT_ARGS[@]}" || return 1
  else
    run_nmap full_discovery -p- -T4 --max-retries 1 --max-rate 500 || return 1
  fi
  local all_ports
  all_ports=$(known_ports tcp)
  [[ -n $all_ports ]] || { log 'No confirmed-open TCP ports found'; return 0; }
  # Scan all open ports with service/version detection: never lose coverage on Quick ports.
  run_nmap full_services -sC -sV -p "$all_ports"
}

vulns_scan() {
  local ports
  ports=$(known_ports tcp)
  [[ -n $ports ]] || { warn 'No confirmed-open TCP ports; skipping Vulns'; return 0; }
  local script_filter='vuln and not intrusive and not dos and not exploit and not brute'
  if (( INTRUSIVE )); then
    script_filter='vuln'
    warn 'Intrusive mode enabled: NSE vulnerability checks can affect target availability'
  fi
  run_nmap vuln_nse -sV --script "$script_filter" -p "$ports" || true
  if [[ -f /usr/share/nmap/scripts/vulners.nse ]] || nmap --script-help vulners >/dev/null 2>&1; then
    run_nmap vuln_cves -sV --script vulners --script-args mincvss=7.0 -p "$ports" || true
  else
    log 'Optional vulners.nse not installed; skipping CVE correlation'
  fi
}

have_port() {
  local ports=$1 sought=$2
  [[ ,$ports, == *,$sought,* ]]
}

# Explicit, allowlisted service-based recommendations. Suggestions are informational;
# the executor below uses fixed argument arrays, not eval and not shell input.
recommend() {
  local tcp udp port scheme url
  tcp=$(known_ports tcp)
  udp=$(known_ports udp)
  {
    printf '# Suggested follow-up for %s\n' "$TARGET"
    printf '# Confirmed TCP: %s | UDP: %s\n' "${tcp:-none}" "${udp:-none}"
    printf '# Use --run-recon to perform supported probes; add --web-deep for content discovery.\n'
    for port in 80 81 443 8000 8080 8081 8443 8888; do
      if have_port "$tcp" "$port"; then
        scheme=http; [[ $port == 443 || $port == 8443 ]] && scheme=https
        url="$scheme://$TARGET:$port/"
        printf 'curl --head --max-time 15 -- %q\n' "$url"
        printf 'nikto -host %q -timeout 10\n' "$url"
        printf 'gobuster dir -u %q -w /usr/share/wordlists/dirb/common.txt -t 5 --timeout 10s\n' "$url"
        [[ $scheme == https ]] && printf 'sslscan %q\n' "$TARGET:$port"
      fi
    done
    if have_port "$tcp" 445 || have_port "$tcp" 139; then
      printf 'smbclient -L %q -N\n' "//$TARGET/"
    fi
    if have_port "$tcp" 53 || have_port "$udp" 53; then
      printf 'dig @%q -x %q +time=3 +tries=1\n' "$TARGET" "$TARGET"
    fi
    if have_port "$udp" 161; then
      printf '# SNMP: run with --snmp-community COMMUNITY only when authorized.\n'
    fi
    [[ -n $tcp ]] || printf '# No confirmed TCP open ports; no TCP recon suggested.\n'
  } | tee "$RECON_DIR/recommendations.txt"
}

# Nikto sometimes exits zero after only printing help/usage text. Require a
# recognizable target header before considering its output a reusable scan.
# This also invalidates old v6 evidence created with `-timeout 10s`.
nikto_output_valid() {
  local file=$1
  [[ -s $file ]] && grep -Eq '^\+ Target (IP|Hostname|Port):' "$file"
}

# Save exit status, command, captured stdout/stderr, and elapsed time for every
# attempted probe. No shell/eval; command arrays are passed as argument vectors.
probe() {
  local name=$1 tool=$2; shift 2
  local out="$RECON_DIR/${name}.txt" status="$RECON_DIR/${name}.status" start=$SECONDS rc=0
  # Reuse successful previous probe evidence instead of repeating it.
  # A fresh run explicitly bypasses this cache.
  if (( ! FRESH )); then
    local oldstatus oldrun
    shopt -s nullglob
    for oldstatus in "$BASE_DIR/$TARGET"/Runs/*/recon/"${name}.status"; do
      [[ $oldstatus == "$status" ]] && continue
      if grep -q '^EXIT=0 ' "$oldstatus" && [[ -s ${oldstatus%.status}.txt ]]; then
        if [[ $tool == nikto ]] && ! nikto_output_valid "${oldstatus%.status}.txt"; then
          log "Ignoring invalid legacy Nikto output: ${oldstatus%.status}.txt"
          continue
        fi
        log "REUSE $name from ${oldstatus%/*} (add --fresh to rerun)"
        shopt -u nullglob
        return 0
      fi
    done
    shopt -u nullglob
  fi
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'SKIPPED: %s is not installed\n' "$tool" | tee "$out"
    printf 'SKIPPED missing=%s\n' "$tool" > "$status"
    log "SKIP $name ($tool missing)"
    return 0
  fi
  log "RECON $name: $tool (no overall process timeout; streaming live output)"
  # Header, stdout and stderr are visible in Kali AND saved verbatim as raw
  # evidence. The .status file is set before execution so interrupted runs
  # are never mistakenly reported as completed.
  {
    printf 'Target: %s\nProbe: %s\nUTC: %s\nCommand: ' "$TARGET" "$name" "$(date -u +%FT%TZ)"
    printf '%q ' "$tool" "$@"
    printf '\n\n'
  } | tee "$out"
  printf 'RUNNING STARTED_UTC=%s\n' "$(date -u +%FT%TZ)" > "$status"
  local -a pipeline_rc=(0 0)
  # Do not use GNU timeout here: slow Nikto/Gobuster/etc. scans may finish
  # naturally. Preserve the tool exit code, not tee's exit code.
  if "$tool" "$@" 2>&1 | tee -a "$out"; then
    pipeline_rc=(0 0)
  else
    pipeline_rc=("${PIPESTATUS[@]}")
  fi
  rc=${pipeline_rc[0]}
  if (( ${pipeline_rc[1]} != 0 )); then
    warn "Cannot save complete $name output (tee exited ${pipeline_rc[1]}): $out"
    (( rc == 0 )) && rc=74
  fi
  if (( rc == 0 )) && [[ $tool == nikto ]] && ! nikto_output_valid "$out"; then
    rc=65
    printf '\nERROR: Nikto did not produce a recognizable scan target header; possible usage-only output.\n' | tee -a "$out"
  fi
  printf 'EXIT=%s DURATION_SECONDS=%s\n' "$rc" "$((SECONDS-start))" > "$status"
  printf 'Probe result: %s | EXIT=%s | DURATION_SECONDS=%s | Raw evidence: %s\n' \
    "$name" "$rc" "$((SECONDS-start))" "$out" | tee -a "$out"
  if (( rc != 0 )); then
    warn "RECON $name returned $rc (tool error or interrupted run; see $out)"
    # Recon probes may fail on legitimate, access-controlled services; record,
    # but don't classify as scan failures or stop the workflow.
  else
    log "DONE RECON $name -> $out"
  fi
  return 0
}

run_recon() {
  local tcp udp port scheme url wordlist
  tcp=$(known_ports tcp)
  udp=$(known_ports udp)
  log 'Running allowlisted follow-up reconnaissance; results are under recon/'
  for port in 80 81 443 8000 8080 8081 8443 8888; do
    if have_port "$tcp" "$port"; then
      scheme=http; [[ $port == 443 || $port == 8443 ]] && scheme=https
      url="$scheme://$TARGET:$port/"
      probe "http_headers_${port}" curl --silent --show-error --head --connect-timeout 5 --max-time 15 -- "$url"
      if [[ $scheme == https ]]; then
        probe "tls_${port}" sslscan --no-colour "$TARGET:$port"
      fi
      if (( WEB_DEEP )); then
        probe "nikto_${port}" nikto -host "$url" -timeout 10 -nointeractive
        wordlist=/usr/share/wordlists/dirb/common.txt
        if [[ -f $wordlist ]]; then
          probe "gobuster_${port}" gobuster dir -u "$url" -w "$wordlist" -t 5 --timeout 10s -q -k
        else
          printf 'SKIPPED: wordlist %s missing\n' "$wordlist" | tee "$RECON_DIR/gobuster_${port}.txt"
          printf 'SKIPPED wordlist-missing\n' > "$RECON_DIR/gobuster_${port}.status"
          warn "gobuster skipped: wordlist not present at $wordlist"
        fi
      fi
    fi
  done
  if have_port "$tcp" 445 || have_port "$tcp" 139; then
    probe smb_shares smbclient -L "//$TARGET/" -N -g
  fi
  if have_port "$tcp" 53 || have_port "$udp" 53; then
    probe dns_reverse dig "@$TARGET" -x "$TARGET" +time=3 +tries=1
  fi
  if have_port "$udp" 161 && [[ -n $SNMP_COMMUNITY ]]; then
    probe snmp_system snmpwalk -v2c -c "$SNMP_COMMUNITY" -t 2 -r 0 "$TARGET" 1.3.6.1.2.1.1
  elif have_port "$udp" 161; then
    log 'SNMP found; community not supplied, so credentialed enumeration skipped'
  fi
}


# Build Markdown notes without modifying Nmap's original output. These Markdown files
# are readable in Obsidian without plugins, including on Windows-hosted WSL volumes.
# One .md mirror is produced per .nmap, plus an XML-derived host summary.
generate_markdown() {
  python3 - "$RUN_DIR" "$TARGET" "$TYPE" "$FAILURES" <<'PYMARKDOWN'
import pathlib, sys, xml.etree.ElementTree as ET
from datetime import datetime, timezone

run_dir, target, mode, failures = sys.argv[1:]
run_dir = pathlib.Path(run_dir)
nmap_dir = run_dir / 'nmap'

def mdcell(value):
    return str(value or '').replace('\n', ' ').replace('|', '\\|').strip()

def fenced(value):
    # Protect against accidental termination by backticks from scanner output.
    return '~~~~text\n' + value.rstrip() + '\n~~~~\n'

for nmap_file in sorted(nmap_dir.glob('*.nmap')):
    contents = nmap_file.read_text(encoding='utf-8', errors='replace')
    companion = nmap_file.with_suffix('.md')
    companion.write_text(
        '# ' + nmap_file.stem.replace('_', ' ').title() + ' — ' + target + '\n\n'
        + '**Original evidence:** [' + nmap_file.name + '](<' + nmap_file.name + '>) '
        + '| [XML](<xml/' + nmap_file.stem + '.xml>) '
        + '| [GNMAP](<' + nmap_file.stem + '.gnmap>)'
        + (' | [HTML report](<' + nmap_file.stem + '.html>)' if nmap_file.with_suffix('.html').exists() else '')
        + '\n\n'
        + fenced(contents), encoding='utf-8')

lines = [f'# Nmap assessment — {target}', '',
         f'**Scan mode:** {mode}',
         f'**Port scope / tuning:** {__import__("os").environ.get("NMAP_SCOPE_SIGNATURE","default")}',
         f'**UTC generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}',
         f'**Reported scan/probe failures:** {failures}', '',
         '## Discovered ports and services', '',
         '| Protocol | Port | State | Service | Product / Version | Evidence |',
         '| --- | ---: | --- | --- | --- | --- |']
rows = []
seen = set()
script_findings = []
for xml_file in sorted(set(nmap_dir.glob('xml/*.xml')) | set(nmap_dir.glob('*.xml'))):
    try:
        root = ET.parse(xml_file).getroot()
    except (OSError, ET.ParseError) as exc:
        lines.append(f'\n**Warning:** Could not parse `{xml_file.name}`: {mdcell(exc)}')
        continue
    for port in root.findall('.//port'):
        state_tag = port.find('state')
        if state_tag is None or state_tag.get('state') not in ('open', 'open|filtered'):
            continue
        state = state_tag.get('state')
        proto = port.get('protocol', '')
        number = port.get('portid', '')
        service = port.find('service')
        service_name = service.get('name', '') if service is not None else ''
        product_version = ' '.join(str(service.get(k)) for k in ('product', 'version', 'extrainfo') if service is not None and service.get(k))
        key = (proto, number, state, service_name, product_version)
        if key not in seen:
            seen.add(key)
            rows.append((proto, int(number), state, service_name, product_version, xml_file.stem))
        for script in port.findall('script'):
            output = script.get('output', '').strip()
            if output:
                script_findings.append((proto, number, script.get('id', 'unknown'), output, xml_file.stem))
    for script in root.findall('./host/hostscript/script'):
        output = script.get('output', '').strip()
        if output:
            script_findings.append(('host', '-', script.get('id', 'unknown'), output, xml_file.stem))
if rows:
    for proto, number, state, service_name, pv, scan in sorted(rows, key=lambda r: (r[0], r[1], r[5])):
        lines.append(f'| {mdcell(proto)} | {number} | {mdcell(state)} | {mdcell(service_name)} | {mdcell(pv)} | ' + (f'[HTML](<nmap/{scan}.html>)' if (nmap_dir / f'{scan}.html').exists() else f'[Readable text](<nmap/{scan}.md>)' if (nmap_dir / f'{scan}.md').exists() else f'[XML](<nmap/xml/{scan}.xml>)' if (nmap_dir / 'xml' / f'{scan}.xml').exists() else f'[XML](<nmap/{scan}.xml>)') + ' |')
else:
    lines.append('| — | — | No confirmed-open ports parsed | — | — | — |')
lines += ['', '## Available scan evidence', '']
for file in sorted(nmap_dir.iterdir()):
    if file.suffix == '.md':
        lines.append(f'- [{file.stem} — readable output](<nmap/{file.name}>)')
for file in sorted(set(nmap_dir.glob('xml/*.xml')) | set(nmap_dir.glob('*.xml'))):
    lines.append(f'- [{file.name} — original XML](<{file.relative_to(run_dir).as_posix()}>)')
for file in sorted(nmap_dir.glob('*.html')):
    lines.append(f'- [{file.name} — rendered HTML report](<nmap/{file.name}>)')
if script_findings:
    lines += ['', '## NSE script output', '',
              '> Raw script observations are not automatically validated vulnerabilities.', '']
    for proto, port, script, output, scan in script_findings:
        lines.append(f'### {script} ({proto}/{port}, {scan})')
        lines.append('')
        lines.append(fenced(output))
recon_dir = run_dir / 'recon'
for result in sorted(recon_dir.glob('*.txt')):
    if result.name == 'recommendations.txt':
        continue
    companion = result.with_suffix('.md')
    raw = result.read_text(encoding='utf-8', errors='replace')
    status_path = result.with_suffix('.status')
    status = status_path.read_text(encoding='utf-8', errors='replace').strip() if status_path.exists() else 'not available'
    companion.write_text('# Recon result: ' + result.stem.replace('_', ' ') + '\n\n'
                         + '**Target:** ' + target + '\n\n'
                         + '**Status:** `' + status + '`\n\n'
                         + '**Original evidence:** [' + result.name + '](<' + result.name + '>)\n\n'
                         + fenced(raw), encoding='utf-8')
recon_file = recon_dir / 'recommendations.txt'
if recon_file.exists():
    raw_recommendations = recon_file.read_text(encoding='utf-8', errors='replace')
    md_recommendations = recon_dir / '02_RECOMMENDED_ACTIONS.md'
    md_recommendations.write_text('# Recommended recon actions — ' + target + '\n\n'
        + '**Original commands:** [recommendations.txt](<recommendations.txt>)\n\n'
        + '> Commands are suggestions, not automatically validated findings.\n\n'
        + '```bash\n' + raw_recommendations.rstrip() + '\n```\n', encoding='utf-8')
    lines += ['', '## Recon recommendations', '', '[View recommended actions](<recon/02_RECOMMENDED_ACTIONS.md>)', '']
recon_notes = sorted(recon_dir.glob('*.md'))
if recon_notes:
    lines += ['', '## Executed follow-up reconnaissance', '',
              '> Tool output is an observation; manually validate security findings.', '']
    for note in recon_notes:
        status_path = note.with_suffix('.status')
        status = status_path.read_text(encoding='utf-8', errors='replace').strip() if status_path.exists() else 'status unavailable'
        lines.append(f'- [{note.stem.replace("_", " ")}](<recon/{note.name}>) — `{mdcell(status)}`')
lines += ['', '## Analyst notes', '', '- ', '', '## Findings to validate', '', '- ']
(run_dir / 'scan_summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
PYMARKDOWN
}

[[ ${1:-} == -h || ${1:-} == --help ]] && { usage; exit 0; }
(( $# >= 2 )) || { usage >&2; exit 2; }
TARGET=$1
TYPE=${2,,}
shift 2
# CIDR is supported by a bounded, discovery-first batch driver below.
if [[ $TARGET == */* ]]; then
  python3 - "$TARGET" <<'PYVALID' || die 'Target must be a valid IPv4 address or IPv4 CIDR subnet (maximum /24)'
import ipaddress,sys
try:
    n=ipaddress.IPv4Network(sys.argv[1],strict=False)
    assert n.prefixlen >= 24, 'CIDR networks broader than /24 are not supported'
except (ValueError, AssertionError):
    sys.exit(1)
PYVALID
else
  valid_ipv4 "$TARGET" || die 'Target must be a valid IPv4 address or IPv4 CIDR subnet'
fi
case $TYPE in quick|basic|udp|full|vulns|recon|all|dashboard) ;; *) usage >&2; die "Unknown mode: $TYPE";; esac
BASE_DIR=./scans
RUN_RECON=0
WEB_DEEP=0
SNMP_COMMUNITY=""
INTRUSIVE=0
NO_PING=0
FRESH=0
CUSTOM_SCOPE=0
PORT_SPEC=''
TOP_PORTS=''
PORT_ARGS=()
NMAP_TUNING_ARGS=()
SCOPE_SIGNATURE='default'
MAX_HOSTS=256
MARKDOWN=1
HTML_REPORTS=1
while (( $# )); do
  case $1 in
    --run-recon) RUN_RECON=1; shift ;;
    --web-deep) WEB_DEEP=1; shift ;;
    --snmp-community) (( $# >= 2 )) || die "--snmp-community requires a value"; SNMP_COMMUNITY=$2; shift 2 ;;
    --no-markdown) MARKDOWN=0; shift ;;
    --no-html) HTML_REPORTS=0; shift ;;
    --intrusive) INTRUSIVE=1; shift ;;
    --no-ping) NO_PING=1; shift ;;
    --fresh) FRESH=1; shift ;;
    -p-) [[ -z $PORT_SPEC && -z $TOP_PORTS ]] || die 'Only one port selector is allowed'; PORT_SPEC='-'; shift ;;
    -p) (( $# >= 2 )) || die '-p requires a port list'; [[ -z $PORT_SPEC && -z $TOP_PORTS ]] || die 'Only one port selector is allowed'
      if [[ $2 == top ]]; then
        (( $# >= 3 )) || die 'Use -p top NUMBER'; TOP_PORTS=$3; shift 3
      else
        PORT_SPEC=$2; shift 2
      fi ;;
    -p?*) [[ -z $PORT_SPEC && -z $TOP_PORTS ]] || die 'Only one port selector is allowed'; PORT_SPEC=${1#-p}; shift ;;
    --top-ports) (( $# >= 2 )) || die '--top-ports requires a number'; [[ -z $PORT_SPEC && -z $TOP_PORTS ]] || die 'Only one port selector is allowed'; TOP_PORTS=$2; shift 2 ;;
    -T[0-5]) NMAP_TUNING_ARGS+=("$1"); shift ;;
    --max-retries|--min-rate|--max-rate|--host-timeout)
      (( $# >= 2 )) || die "$1 requires a value"; NMAP_TUNING_ARGS+=("$1" "$2"); shift 2 ;;
    --max-retries=*|--min-rate=*|--max-rate=*|--host-timeout=*) NMAP_TUNING_ARGS+=("$1"); shift ;;
    --max-hosts) (( $# >= 2 )) || die '--max-hosts requires a number'; MAX_HOSTS=$2; shift 2 ;;
    --output) (( $# >= 2 )) || die '--output requires a directory'; BASE_DIR=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done
# Validate supported Nmap selectors and bounded tuning, without eval or arbitrary shell args.
if [[ -n $TOP_PORTS ]]; then
  [[ $TOP_PORTS =~ ^[0-9]+$ ]] && (( TOP_PORTS >= 1 && TOP_PORTS <= 65535 )) || die '--top-ports must be 1..65535'
  CUSTOM_SCOPE=1; PORT_ARGS=(--top-ports "$TOP_PORTS"); SCOPE_SIGNATURE="top:$TOP_PORTS"
elif [[ -n $PORT_SPEC ]]; then
  python3 - "$PORT_SPEC" <<'PYPORT' || die 'Invalid -p list (use -p-, -p 80,443, or -p 1-1024)'
import sys,re
x=sys.argv[1]
if x=='-':sys.exit(0)
if not re.fullmatch(r'[0-9,\-]+',x):sys.exit(1)
for item in x.split(','):
    if not item:sys.exit(1)
    bits=item.split('-')
    if len(bits)>2 or not all(b.isdigit() for b in bits):sys.exit(1)
    a=int(bits[0]);b=int(bits[-1])
    if a<1 or b>65535 or a>b:sys.exit(1)
PYPORT
  CUSTOM_SCOPE=1; PORT_ARGS=("-p$PORT_SPEC"); SCOPE_SIGNATURE="ports:$PORT_SPEC"
fi
# Normalize tuning for cache keys and reject malformed option values.
for ((i=0; i<${#NMAP_TUNING_ARGS[@]}; i++)); do
  opt=${NMAP_TUNING_ARGS[i]}; val=''
  if [[ $opt == *=* ]]; then val=${opt#*=}; opt=${opt%%=*}; else
    if [[ $opt == -T* ]]; then continue; fi
    (( ++i < ${#NMAP_TUNING_ARGS[@]} )) || die "Missing value after $opt"
    val=${NMAP_TUNING_ARGS[i]}
  fi
  case $opt in
    --max-retries) [[ $val =~ ^[0-9]+$ ]] && (( val <= 20 )) || die 'Invalid --max-retries (0..20)' ;;
    --min-rate|--max-rate) [[ $val =~ ^[0-9]+$ ]] && (( val > 0 && val <= 1000000 )) || die "Invalid $opt" ;;
    --host-timeout) [[ $val =~ ^[0-9]+(ms|s|m|h)?$ ]] || die 'Invalid --host-timeout (e.g. 10m)' ;;
  esac
done
if [[ $TYPE == dashboard && ( $CUSTOM_SCOPE == 1 || ${#NMAP_TUNING_ARGS[@]} -gt 0 ) ]]; then
  die 'Dashboard mode does not accept scan port or timing options'
fi
# Cache must distinguish full-port runs from limited top-port and tuned runs.
if (( ${#NMAP_TUNING_ARGS[@]} )); then
  printf -v tune_flat '%q ' "${NMAP_TUNING_ARGS[@]}"
  SCOPE_SIGNATURE="${SCOPE_SIGNATURE}|tuning:${tune_flat}"
fi
export NMAP_SCOPE_SIGNATURE="$SCOPE_SIGNATURE"
[[ $MAX_HOSTS =~ ^[0-9]+$ ]] && (( MAX_HOSTS >= 1 && MAX_HOSTS <= 256 )) || die '--max-hosts must be an integer from 1 to 256'
(( ! WEB_DEEP || RUN_RECON )) || die "--web-deep requires --run-recon"
[[ -z $SNMP_COMMUNITY || $RUN_RECON == 1 ]] || die "--snmp-community requires --run-recon"
[[ $TYPE == dashboard ]] || command -v nmap >/dev/null || die 'Install nmap first'
command -v python3 >/dev/null || die 'Install python3 first (XML parser)'
NMAP_XSL=${NMAP_XSL:-/usr/share/nmap/nmap.xsl}
if (( HTML_REPORTS )) && [[ $TYPE != dashboard ]]; then
  command -v xsltproc >/dev/null || die 'HTML reports require xsltproc: sudo apt install xsltproc (or use --no-html)'
  [[ -r $NMAP_XSL ]] || die "HTML reports require a readable Nmap XSL stylesheet at $NMAP_XSL (or use --no-html)"
fi

# Native Kali: running the scan with sudo should not leave output owned by root.
# Only the exact output tree created for THIS execution is traversed recursively.
# Parent folders are changed only when they were created by this invocation.
OUTPUT_USER_ID=''
OUTPUT_GROUP_ID=''
if (( EUID == 0 )) && [[ -n ${SUDO_USER:-} && ${SUDO_USER} != root ]]; then
  OUTPUT_USER_ID=$(id -u -- "$SUDO_USER") || die 'Cannot resolve SUDO_USER'
  OUTPUT_GROUP_ID=$(id -g -- "$SUDO_USER") || die 'Cannot resolve SUDO_USER group'
fi
OWNERSHIP_TREE=''
NEW_PARENTS=()
make_output_dir() {
  local path=$1 part current=''
  local absolute
  absolute=$(realpath -m -- "$path")
  # Build missing parent directories individually so only created ones get chown.
  IFS=/ read -r -a parts <<< "${absolute#/}"
  for part in "${parts[@]}"; do
    [[ -n $part ]] || continue
    current="$current/$part"
    if [[ ! -d $current ]]; then
      mkdir -- "$current" || return 1
      NEW_PARENTS+=("$current")
    fi
  done
}
restore_output_owner() {
  local rc=$?
  trap - EXIT
  if [[ -n $OUTPUT_USER_ID && -n $OWNERSHIP_TREE && -d $OWNERSHIP_TREE ]]; then
    # Avoid following any symbolic link to a tree outside our run.
    if [[ ! -L $OWNERSHIP_TREE ]]; then
      chown -R -- "$OUTPUT_USER_ID:$OUTPUT_GROUP_ID" "$OWNERSHIP_TREE"         || printf 'WARNING: could not restore output ownership: %s\n' "$OWNERSHIP_TREE" >&2
    fi
  fi
  if [[ -n $OUTPUT_USER_ID ]]; then
    local dir
    for dir in "${NEW_PARENTS[@]}"; do
      [[ -d $dir && ! -L $dir ]] && chown -- "$OUTPUT_USER_ID:$OUTPUT_GROUP_ID" "$dir"         || printf 'WARNING: could not restore directory owner: %s\n' "$dir" >&2
    done
  fi
  exit "$rc"
}
trap restore_output_owner EXIT

# Convert Nmap XML to readable HTML before archiving XML into the xml/ subfolder.
# The transform is performed locally and does not fetch remote resources.
convert_html_dir() {
  (( HTML_REPORTS )) || return 0
  local directory=$1 xml html rc=0
  shopt -s nullglob
  for xml in "$directory"/*.xml; do
    html="${xml%.xml}.html"
    if xsltproc --nonet -o "$html" "$NMAP_XSL" "$xml"; then
      printf 'HTML report: %s\n' "$html"
    else
      printf 'WARNING: HTML conversion failed for %s\n' "$xml" >&2
      rc=1
    fi
  done
  shopt -u nullglob
  return "$rc"
}

# Name scan folders using the Kali machine's LOCAL clock and the scan mode.
# Example: 26-11-05_13-36-00_Basic. Preserve existing runs by resolving collisions.
case $TYPE in
  udp) SCAN_LABEL=UDP ;;
  *) SCAN_LABEL=${TYPE^} ;;
esac
new_scan_folder() {
  local parent=$1 stamp candidate suffix=2
  stamp=$(date +%y-%m-%d_%H-%M-%S)
  candidate="$parent/${stamp}_${SCAN_LABEL}"
  while [[ -e $candidate || -L $candidate ]]; do
    candidate="$parent/${stamp}_${SCAN_LABEL}_${suffix}"
    suffix=$((suffix + 1))
  done
  printf '%s\n' "$candidate"
}

# Subnet scanning: discover responsive hosts first, then run the existing
# single-host workflow for each. Never pass a subnet into service/vuln scans.
if [[ $TARGET == */* ]]; then
  SCRIPT_PATH=$(readlink -f -- "$0")
  BATCH_DIR=$(new_scan_folder "$BASE_DIR/subnets/${TARGET//\//_}")
  make_output_dir "$BATCH_DIR"
  OWNERSHIP_TREE="$BATCH_DIR"
  printf 'Discovering responsive hosts in %s ...\n' "$TARGET"
  if ! nmap -sn -n -oX "$BATCH_DIR/discovery.xml" "$TARGET"; then
    die "Host discovery failed. See $BATCH_DIR/discovery.xml"
  fi
  mapfile -t LIVE_HOSTS < <(python3 - "$BATCH_DIR/discovery.xml" <<'PYHOSTS'
import sys,xml.etree.ElementTree as ET
try:
    root=ET.parse(sys.argv[1]).getroot()
    for host in root.findall('host'):
        status=host.find('status')
        if status is None or status.get('state') != 'up': continue
        for addr in host.findall('address'):
            if addr.get('addrtype') == 'ipv4':
                print(addr.get('addr')); break
except (ET.ParseError,OSError) as e:
    print(f'Cannot parse discovery XML: {e}',file=sys.stderr)
    sys.exit(1)
PYHOSTS
  )
  printf '%s\n' "${LIVE_HOSTS[@]}" > "$BATCH_DIR/live_hosts.txt"
  convert_html_dir "$BATCH_DIR" || true
  count=${#LIVE_HOSTS[@]}
  echo "Found $count responsive hosts. Discovery evidence: $BATCH_DIR"
  (( count > 0 )) || { echo 'No responding hosts; no per-host scans launched.'; exit 0; }
  (( count <= MAX_HOSTS )) || die "Found $count hosts, exceeding --max-hosts $MAX_HOSTS"
  failures=0
  for ip in "${LIVE_HOSTS[@]}"; do
    printf '\n===== Scanning %s (%s) =====\n' "$ip" "$TYPE"
    cmd=(bash "$SCRIPT_PATH" "$ip" "$TYPE" --output "$BASE_DIR")
    (( RUN_RECON )) && cmd+=(--run-recon)
    (( WEB_DEEP )) && cmd+=(--web-deep)
    [[ -n $SNMP_COMMUNITY ]] && cmd+=(--snmp-community "$SNMP_COMMUNITY")
    (( INTRUSIVE )) && cmd+=(--intrusive)
    (( NO_PING )) && cmd+=(--no-ping)
    (( FRESH )) && cmd+=(--fresh)
    (( CUSTOM_SCOPE )) && cmd+=("${PORT_ARGS[@]}")
    ((${#NMAP_TUNING_ARGS[@]})) && cmd+=("${NMAP_TUNING_ARGS[@]}")
    (( ! MARKDOWN )) && cmd+=(--no-markdown)
    (( ! HTML_REPORTS )) && cmd+=(--no-html)
    "${cmd[@]}" || failures=$(( failures + 1 ))
  done
  printf '\nSubnet run complete: %s hosts attempted, %s had errors.\n' "$count" "$failures"
  printf 'Discovery results: %s\n' "$BATCH_DIR"
  if (( MARKDOWN )); then
    python3 - "$BATCH_DIR" "$TARGET" "$BASE_DIR" "$failures" <<'PYBATCH'
import sys, pathlib, html, xml.etree.ElementTree as ET
folder, network, base, failures = sys.argv[1:]
folder = pathlib.Path(folder)
base = pathlib.Path(base)
lines = [f'# Network scan: {network}', '', f'**Hosts with scan errors:** {failures}', '',
         '## Discovered hosts', '', '| IP address | Scan results |', '| --- | --- |']
for addr in folder.joinpath('live_hosts.txt').read_text().splitlines():
    matches = sorted(list(base.joinpath(addr).glob('Runs/*/scan_summary.md')) + list(base.joinpath(addr).glob('*/scan_summary.md')), key=lambda p: p.stat().st_mtime, reverse=True)
    link = f'[Assessment note](<{pathlib.Path(__import__("os").path.relpath(matches[0], folder)).as_posix()}>)' if matches else 'No note found'
    lines.append(f'| {addr} | {link} |')
lines += ['', '## Discovery evidence', '', '[Nmap discovery XML](<discovery.xml>)',
          '[Rendered discovery HTML](<discovery.html>)' if folder.joinpath('discovery.html').exists() else '',
          '', '## Notes', '', '- ']
folder.joinpath('subnet_summary.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
PYBATCH
  fi
  (( failures == 0 ))
  exit $?
fi
# Build a per-target Obsidian index from existing and new scan evidence.
# Version 2: overview, prioritized unverified CVE associations, and evidence links.
# The index is generated; analyst findings are in a separate, never-overwritten note.
# Prior legacy run directories are linked in place, not moved or modified.
update_target_dashboard() {
  python3 - "$BASE_DIR/$TARGET" "${RUN_DIR:--}" "$TARGET" "$SCAN_LABEL" "${FAILURES:-0}" <<'PYDASH'
import datetime as dt
import fcntl
import json
import os
import pathlib
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

root = pathlib.Path(sys.argv[1]); current_arg = sys.argv[2]
target, mode, failures = sys.argv[3], sys.argv[4], int(sys.argv[5])
root.mkdir(parents=True, exist_ok=True)

def escape(text):
    return str(text).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ').strip()

def valid_link(path, label):
    import urllib.parse
    relative = path.relative_to(root).as_posix()
    return f'[{escape(label)}](<{urllib.parse.quote(relative, safe="/._-()") }>)'

with (root / '.dashboard.lock').open('a+') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    def save_atomic(path, content):
        fd, temp = tempfile.mkstemp(prefix='.dashboard-', dir=root)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f: f.write(content)
            os.chmod(temp, 0o600)
            if os.environ.get('SUDO_UID') and os.environ.get('SUDO_GID'):
                os.chown(temp, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
            os.replace(temp, path)
        finally:
            if os.path.exists(temp): os.unlink(temp)

    if current_arg != '-':
        current = pathlib.Path(current_arg)
        status_file = current / '.scan_status.json'
        status_file.write_text(json.dumps({'mode': mode, 'failures': failures,
            'scope': os.environ.get('NMAP_SCOPE_SIGNATURE','default'), 'completed_at': dt.datetime.now().astimezone().isoformat(timespec='seconds')}, indent=2)+'\n', encoding='utf-8')
        if os.environ.get('SUDO_UID') and os.environ.get('SUDO_GID'):
            os.chown(status_file, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))

    findings = root / '01_FINDINGS.md'
    if not findings.exists():
        save_atomic(findings, '# Findings — ' + target + '\n\n'
            '> Analyst-confirmed findings only. Automated matches are not confirmed vulnerabilities.\n\n'
            '## Validated findings\n\n- \n\n## Retest / verification notes\n\n- \n')

    folders=[]
    for parent in (root / 'Runs', root):
        if parent.is_dir():
            for folder in parent.iterdir():
                if folder.is_dir() and folder.name not in ('Runs','subnets') and ((folder/'nmap').is_dir() or (folder/'scan_summary.md').exists()):
                    folders.append(folder)

    def read_run(folder):
        metadata={}
        if (folder/'.scan_status.json').is_file():
            try: metadata=json.loads((folder/'.scan_status.json').read_text())
            except (ValueError, OSError): pass
        m = re.search(r'_(Quick|Basic|UDP|Full|Vulns|Recon|All)(?:_\d+)?$',folder.name,re.I)
        mode = metadata.get('mode') or (m.group(1) if m else 'Legacy')
        timestamp=metadata.get('completed_at')
        if not timestamp:
            if re.match(r'^\d{8}T\d{6}Z_',folder.name):
                timestamp=folder.name[:16]+' UTC'
            else:
                timestamp=dt.datetime.fromtimestamp(folder.stat().st_mtime).astimezone().isoformat(timespec='minutes')
        try:
            shown=dt.datetime.fromisoformat(timestamp).strftime('%b %d %H:%M')
        except ValueError: shown=timestamp[:19]
        files = sorted(set((folder/'nmap').glob('xml/*.xml')) | set((folder/'nmap').glob('*.xml')))
        # Best available service label from this run, preserving explicit open-only states.
        services={}; sources={}; nse=[]; xml_count=0
        for file in files:
            try: xml=ET.parse(file).getroot()
            except (ET.ParseError,OSError): continue
            xml_count += 1
            for host in xml.findall('.//host'):
                for port in host.findall('./ports/port'):
                    state=port.find('state')
                    if state is None or state.get('state')!='open': continue
                    try: key=(port.get('protocol',''),int(port.get('portid','')))
                    except (ValueError,TypeError):continue
                    svc=port.find('service')
                    desc=' '.join(svc.get(a,'') for a in ('name','product','version','extrainfo') if svc is not None and svc.get(a)).strip()
                    def quality(f):
                        parent=f.parent.parent if f.parent.name=='xml' else f.parent
                        html=(parent/(f.stem+'.html')).is_file()
                        return (bool(html), f.stem in ('full_services','basic','vuln_nse','vuln_cves'))
                    if key not in services or len(desc)>len(services[key]):
                        services[key]=desc or 'Unknown'
                    if key not in sources or quality(file)>quality(sources[key]):
                        sources[key]=file
                    if file.stem.startswith('vuln'):
                        for script in port.findall('script'):
                            if script.get('id')=='vulners':
                                for line in script.get('output','').splitlines():
                                    m=re.search(r'\b(CVE-\d{4}-\d{4,})\s+([0-9]+(?:\.[0-9]+)?)\s+https?://\S+',line,re.I)
                                    if m:
                                        score=float(m.group(2))
                                        if 0 <= score <= 10:
                                            nse.append((m.group(1).upper(),score,key,file))
        # Deduplicate CVEs across files; keep distinct affected ports.
        vulns={}
        for cve,score,key,file in nse:
            k=(cve,key)
            if k not in vulns or score>vulns[k][0]:vulns[k]=(score,file)
        return dict(path=folder,name=folder.name,mode=mode,scope=metadata.get('scope','default'),stamp=timestamp,display=shown,
            services=services,sources=sources,vulns=vulns,xml=xml_count,
            failures=metadata.get('failures'),meta=bool(metadata))

    runs=[read_run(f) for f in folders]
    # Sort by actual scan timestamp for modern metadata; legacy fallback to mtime.
    def order(d):
        try:return dt.datetime.fromisoformat(d['stamp']).timestamp()
        except ValueError:return d['path'].stat().st_mtime
    runs.sort(key=order,reverse=True)
    def summary(d):
        p=d['path']/'scan_summary.md'
        if p.is_file():return valid_link(p,d['name'])
        return valid_link(d['path']/'run.log',d['name']) if (d['path']/'run.log').is_file() else escape(d['name'])
    def readable_evidence(xml_file, label='HTML'):
        nmap_folder = xml_file.parent.parent if xml_file.parent.name == 'xml' else xml_file.parent
        html_file = nmap_folder / (xml_file.stem + '.html')
        note_file = nmap_folder / (xml_file.stem + '.md')
        raw_file = nmap_folder / (xml_file.stem + '.nmap')
        if html_file.is_file(): return valid_link(html_file, label)
        if note_file.is_file(): return valid_link(note_file, 'Readable text')
        if raw_file.is_file(): return valid_link(raw_file, 'Nmap output')
        return valid_link(xml_file, 'XML (HTML unavailable)')
    def state(d):
        return 'Completed' if d['failures']==0 else (f'Errors ({d["failures"]})' if d['failures'] is not None else 'Unverified legacy')

    complete=[d for d in runs if d['failures']==0 and d['xml']]
    recent=complete[0] if complete else None
    latest_tcp=next((d for d in complete if d['mode'].lower() in ('full','all') and d['scope'] in ('default','ports:-')),None)
    inventory_run=latest_tcp or recent
    vuln_run=next((d for d in complete if d['vulns']),None)
    observed=inventory_run['services'] if inventory_run else {}
    tcp=sum(k[0]=='tcp' for k in observed);udp=sum(k[0]=='udp' for k in observed)
    run_modes=', '.join(sorted({d['mode'] for d in complete})) or 'None'

    lines=[f'# {target} — Assessment Dashboard','',
        '> **Auto-generated evidence index.** Scanner observations are not validated vulnerabilities. Add analyst conclusions to [[01_FINDINGS]].','',
        '## At a glance','',
        '| Completed runs | Most recent | Latest broad TCP inventory | Observed TCP / UDP |',
        '| ---: | --- | --- | ---: |',
        f'| {len(complete)} | {recent["display"]+" ("+recent["mode"]+")" if recent else "—"} | {summary(latest_tcp) if latest_tcp else "Not performed"} | {tcp} / {udp} |','',
        f'**Modes recorded:** {escape(run_modes)}  ',
        '**Coverage note:** A count of zero UDP ports does **not** indicate a completed UDP assessment. Basic and Vulns use limited TCP discovery.','',
        ]
    # Evidence-driven recommendations; no new network traffic is generated here.
    available_stems={d['mode'].lower() for d in complete}
    evidence_stems=set()
    for d in complete:
        nm=d['path']/'nmap'
        evidence_stems.update(f.stem for f in nm.glob('xml/*.xml'))
        evidence_stems.update(f.stem for f in nm.glob('*.xml'))
    suggestions=[]
    def suggest(priority, action, reason, command):
        suggestions.append((priority,action,reason,command))
    if not (('quick' in evidence_stems) or ('full_discovery' in evidence_stems)):
        suggest('1','Initial TCP discovery','No reusable TCP discovery evidence found','Quick')
    if not any(d['mode'].lower() in ('full','all') and d['scope'] in ('default','ports:-') and (d['path']/'nmap'/'xml'/'full_discovery.xml').exists() for d in runs):
        suggest('1','Full TCP port coverage','No completed 65,535-port TCP discovery observed','Full')
    if 'basic' not in evidence_stems and 'full_services' not in evidence_stems:
        suggest('1','Identify services and versions','Open ports have not been characterized with service probes','Basic')
    if 'vuln_nse' not in evidence_stems:
        suggest('2','Run vulnerability checks','No NSE vulnerability scan output found; CVE matches still need validation','Vulns')
    elif vuln_run and vuln_run['vulns']:
        suggest('2','Manually validate vulnerability leads',f'{len(vuln_run["vulns"])} unverified port/CVE associations need applicability checks','Review findings')
    if 'udp_discovery' not in evidence_stems:
        suggest('2','Check UDP exposure','No UDP discovery evidence recorded','UDP')
    if 'recon' not in available_stems and not any((d['path']/'recon'/'recommendations.txt').exists() for d in runs):
        suggest('2','Generate service-specific recon actions','No stored enumeration recommendations','Recon')
    if 'full_discovery' in evidence_stems and 'vuln_nse' in evidence_stems:
        # Timestamp-only clue, not proof of complete port-level vulnerability coverage.
        full_item=next((d for d in runs if (d['path']/'nmap'/'xml'/'full_discovery.xml').exists() or (d['path']/'nmap'/'full_discovery.xml').exists()),None)
        vuln_item=next((d for d in runs if (d['path']/'nmap'/'xml'/'vuln_nse.xml').exists() or (d['path']/'nmap'/'vuln_nse.xml').exists()),None)
        if full_item and vuln_item and order(full_item)>order(vuln_item):
            suggest('2','Reassess newly found ports','Full discovery is newer than the vulnerability scan; check whether new ports need coverage','Vulns --fresh')
    lines += ['## Assessment workflow', '',
              '> Action notes are persistent. Edit **Analyst status** in each note to move it between queues. Dashboard refreshes never erase analyst observations.', '',
              '**Suggested scans and probes are tracked below; no network activity occurs when opening or refreshing this dashboard.**', '',
              '**Reuse:** Existing scan evidence is reused when the mode and scope match. Use `--fresh` for a new measurement.', '']
    recon_notes=[d['path']/'recon'/'recommendations.txt' for d in runs
                 if (d['path']/'recon'/'recommendations.txt').is_file()]
    if recon_notes:
        lines.extend([f'**Saved recon commands:** {valid_link(recon_notes[0],"View recommendations")} (no need to rerun discovery).',''])
    # Show actual recommended commands and links to their captured results on the
    # dashboard, rather than requiring the analyst to open a .txt file manually.
    # All evidence stays in the existing run's recon/ folder and is not modified.
    import shlex
    recommendation_files = [d['path']/'recon'/'recommendations.txt' for d in runs
                            if (d['path']/'recon'/'recommendations.txt').is_file()]
    latest_recommendations = recommendation_files[0] if recommendation_files else None
    lines += ['### Recon action plan and saved results', '',
              '> Commands below are for authorized assessments only. They are not executed by opening Obsidian. Run the scanner command shown below to capture their outputs.', '']
    lines += [f'**Run saved recommendations:** `sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh {target} Recon --run-recon --web-deep`', '',
              '**Without deeper web checks:** `sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh '
              + target + ' Recon --run-recon`', '',
              '**Refresh this page without network traffic:** `bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh '
              + target + ' Dashboard`', '']
    actions = []
    if latest_recommendations:
        # Use the latest recommendations as an action catalogue. Prefer the newest
        # executed result for each action across ALL runs, not just that catalogue's run.
        actions = []
        for raw in latest_recommendations.read_text(encoding='utf-8',errors='replace').splitlines():
            raw=raw.strip()
            if not raw or raw.startswith('#'):continue
            try: argv=shlex.split(raw)
            except ValueError:continue
            if not argv:continue
            tool=argv[0]
            if tool=='nikto' and '-timeout' in argv:
                timeout_idx=argv.index('-timeout')+1
                if timeout_idx < len(argv) and re.fullmatch(r'[0-9]+s',argv[timeout_idx]):
                    argv[timeout_idx]=argv[timeout_idx][:-1]
                    raw=shlex.join(argv)  # Display corrected syntax; leave stored evidence unchanged.
            if tool=='curl':
                url=next((a for a in argv if a.startswith(('http://','https://'))),'')
                m=re.search(r':(\d+)/?$',url)
                port=m.group(1) if m else ('443' if url.startswith('https:') else '80')
                name='http_headers_'+port; deep=False
            elif tool in ('nikto','gobuster'):
                url=next((a for a in argv if a.startswith(('http://','https://'))),'')
                m=re.search(r':(\d+)/?$',url)
                port=m.group(1) if m else ('443' if url.startswith('https:') else '80')
                name=tool+'_'+port; deep=True
            elif tool=='sslscan':
                name='tls_'+argv[-1].rsplit(':',1)[-1];deep=False
            elif tool=='smbclient':name='smb_shares';deep=False
            elif tool=='dig':name='dns_reverse';deep=False
            else:continue
            result=next((d['path']/'recon'/(name+'.md') for d in runs
                         if (d['path']/'recon'/(name+'.md')).is_file()),None)
            raw_result=next((d['path']/'recon'/(name+'.txt') for d in runs
                             if (d['path']/'recon'/(name+'.txt')).is_file()),None)
            status_path=next((d['path']/'recon'/(name+'.status') for d in runs
                              if (d['path']/'recon'/(name+'.status')).is_file()),None)
            status=status_path.read_text(errors='replace').strip() if status_path else 'Not run'
            if tool=='nikto' and re.search(r'\bEXIT=0\b',status):
                # Exit zero by itself is not evidence that Nikto performed a scan.
                valid=bool(raw_result and re.search(r'^\+ Target (?:IP|Hostname|Port):',
                              raw_result.read_text(encoding='utf-8',errors='replace'),re.M))
                if not valid:
                    status='UNVERIFIED: legacy Nikto output may be help text; rerun with v6.2'
            label='Deep web' if deep else 'Standard'
            link=valid_link(result,'Obsidian note') if result else (valid_link(raw_result,'Raw output') if raw_result else 'Not collected')
            actions.append((name,raw,label,status,link))
        if actions:
            lines += [f'**Recommendation source:** {valid_link(latest_recommendations,"Saved commands")}', '',
                      '| Action | Scope | Status | Saved evidence |', '| --- | --- | --- | --- |']
            for name,cmd,label,status,link in actions:
                lines.append(f'| `{escape(name)}` | {label} | {escape(status)} | {link} |')
            lines += ['', '**Commands to run or review:**', '']
            for name,cmd,label,status,link in actions:
                lines += [f'- **{name}** — `{cmd.replace("`", "")}`', '']
        else:
            lines += ['No supported recommendations could be read from the latest recommendations file.', '']
    else:
        lines += ['No recommendations file exists yet. Run `Recon` to generate one from existing discovery evidence.', '']
    results=[]
    for d in runs:
        for result in sorted((d['path']/'recon').glob('*.md')):
            if result.name=='02_RECOMMENDED_ACTIONS.md':continue
            results.append((d,result))
    if results:
        lines += ['### Executed reconnaissance history', '',
                  '| Run | Probe | Result note |', '| --- | --- | --- |']
        for d,result in results[:40]:
            lines.append(f'| {escape(d["display"])} | {escape(result.stem)} | {valid_link(result,"Open result")} |')
        lines.append('')
    else:
        lines += ['**No executed recon output yet.** Execute `Recon --run-recon` (and optionally `--web-deep`) to save output in timestamped `Runs/.../recon/` folders.', '']
    service_actions=[]
    for (proto,port),desc in sorted(observed.items()):
        d=desc.lower()
        if proto=='tcp' and (port in (80,81,443,8000,8080,8081,8443,8888) or 'http' in d):
            scheme='https' if (port in (443,8443) or 'https' in d or 'ssl' in d) else 'http'
            service_actions.append((f'{proto}/{port}', 'Inspect HTTP headers, authentication, and application routes',f'`curl -I --max-time 15 {scheme}://{target}:{port}/`'))
        elif proto=='tcp' and port in (139,445):
            service_actions.append((f'{proto}/{port}', 'Review SMB shares and access controls',f'`smbclient -L //{target}/ -N`'))
        elif port==53:
            service_actions.append((f'{proto}/{port}', 'Review DNS exposure and responses',f'`dig @{target} -x {target}`'))
        elif proto=='tcp' and port==22:
            service_actions.append((f'{proto}/{port}', 'Review SSH configuration, versions, and authentication', 'Manual validation'))
        elif proto=='udp' and port==161:
            service_actions.append((f'{proto}/{port}', 'Review SNMP access using authorized credentials', 'Manual validation'))
    # Persistent action cards. Regenerate ONLY the bounded automatic portion;
    # analyst status and free-form notes are not overwritten.
    action_dir = root / 'Actions'
    action_dir.mkdir(exist_ok=True)
    if os.environ.get('SUDO_UID') and os.environ.get('SUDO_GID'):
        os.chown(action_dir, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))

    def slug(text):
        return re.sub(r'[^a-z0-9_-]+', '_', text.lower()).strip('_')[:90]

    jobs = {}
    def register(key, title, purpose, command, raw_path=None, result_path=None,
                 execution='Not run', source='Recon', completed=False):
        jobs[key] = dict(title=title,purpose=purpose,command=command,
                         raw=raw_path,result=result_path,execution=execution,
                         source=source,completed=completed)

    # Explicit follow-up tasks remain until analyst closes them, even when scans exist.
    for priority,action,reason,cmd in suggestions:
        if cmd == 'Review findings':
            recommended_command='Manual CVE applicability and configuration review; record conclusions in [[01_FINDINGS]]'
        else:
            recommended_command=f'sudo bash ./NmapAutomator_Kali_Obsidian_Dashboard_v6_2.sh {target} {cmd}'
        register('coverage_'+slug(action),action,reason,recommended_command,source='Coverage / triage')

    # Capture latest executed results for each reconnaissance command.
    for name,command,label,status,link in actions:
        status_path=next((d['path']/'recon'/(name+'.status') for d in runs
                          if (d['path']/'recon'/(name+'.status')).is_file()),None)
        data_path=next((d['path']/'recon'/(name+'.txt') for d in runs
                        if (d['path']/'recon'/(name+'.txt')).is_file()),None)
        note_path=next((d['path']/'recon'/(name+'.md') for d in runs
                        if (d['path']/'recon'/(name+'.md')).is_file()),None)
        success=bool(status_path and re.search(r'\bEXIT=0\b',status) and data_path and data_path.is_file())
        register('recon_'+name,name.replace('_',' ').title(),
                 'Execute or review service-specific reconnaissance ('+label+').',command,
                 raw_path=data_path, result_path=note_path, execution=status,
                 source='Recon',completed=success)

    # Service follow-up work that is not automatically resolved by probe exit codes.
    for port,action,example in service_actions:
        key='service_'+slug(port+'_'+action)
        register(key,f'{port} — {action}',
                 'Analyst validation is required; an automated probe does not confirm security impact.',
                 example.strip('`'),source='Service review')

    auto_begin='<!-- BEGIN GENERATED EVIDENCE -->'
    auto_end='<!-- END GENERATED EVIDENCE -->'
    grouped={'Needs Action':[], 'In Progress':[], 'Completed':[]}
    for key,task in jobs.items():
        path=action_dir/(key+'.md')
        auto_status='Completed' if task['completed'] else ('In Progress' if task['execution']!='Not run' else 'Needs Action')
        evidence_note=valid_link(task['result'],'Result note') if task['result'] and task['result'].is_file() else 'Not available'
        raw_evidence=valid_link(task['raw'],'Raw output') if task['raw'] and task['raw'].is_file() else 'Not collected'
        # Links in action notes must be relative to their own folder, not dashboard root.
        def from_action(path_or_none,label):
            if path_or_none and path_or_none.is_file():
                import urllib.parse
                relative=os.path.relpath(path_or_none,action_dir).replace(os.sep,'/')
                return f'[{label}](<{urllib.parse.quote(relative,safe="/._-()") }>)'
            return 'Not collected'
        generated='\n'.join([
            auto_begin,
            f'**Purpose:** {task["purpose"]}', '',
            '**Recommended command / procedure:**', '',
            '```bash', task['command'].replace('```',''), '```', '',
            f'**Execution status:** {task["execution"]}', '',
            f'**Suggested workflow status:** {auto_status}', '',
            f'**Result note:** {from_action(task["result"],"Open Obsidian result")}', '',
            f'**Raw evidence:** {from_action(task["raw"],"Open raw output")}', '',
            f'**Evidence source:** {task["source"]}',
            auto_end])
        if not path.exists():
            initial=(f'# {task["title"]}\n\n'
                     '**Analyst status:** Auto\n\n'
                     '> Change Auto to Needs Action, In Progress, or Completed to override the generated status. '
                     'An exit code of zero means the tool ran; it does not validate a vulnerability.\n\n'
                     +generated+'\n\n'
                     '## Observations\n\n- \n\n'
                     '## Analyst validation notes\n\n- \n\n'
                     '## Follow-up / disposition\n\n- \n')
            save_atomic(path,initial)
        else:
            original=path.read_text(encoding='utf-8',errors='replace')
            if auto_begin in original and auto_end in original:
                front,tail=original.split(auto_begin,1)
                _old,back=tail.split(auto_end,1)
                new=front+generated+back
                if new!=original:save_atomic(path,new)
            # If an analyst removes the markers, preserve their entire custom note.
        content=path.read_text(encoding='utf-8',errors='replace')
        match=re.search(r'^\*\*Analyst status:\*\*\s*(.+)$',content,re.M|re.I)
        manual=match.group(1).strip().lower() if match else 'auto'
        allowed={'needs action':'Needs Action','in progress':'In Progress','completed':'Completed'}
        effective=allowed.get(manual,auto_status)
        grouped[effective].append((task,path,auto_status))

    # Keep historical action notes in the queue even when a later scan no longer
    # recommends them. Never silently discard analyst work.
    for old_path in sorted(action_dir.glob('*.md')):
        if old_path.stem in jobs:
            continue
        old_content=old_path.read_text(encoding='utf-8',errors='replace')
        matched=re.search(r'^\*\*Analyst status:\*\*\s*(.+)$',old_content,re.M|re.I)
        chosen=(matched.group(1).strip().lower() if matched else 'auto')
        prior={'needs action':'Needs Action','in progress':'In Progress','completed':'Completed'}
        old_group=prior.get(chosen,'Completed')
        old_title=old_content.splitlines()[0].lstrip('# ').strip() if old_content else old_path.stem
        grouped[old_group].append((dict(title=old_title,execution='Historical / review for relevance',completed=False),old_path,old_group))

    lines += ['### Needs Action → In Progress → Completed','',
              'Each action has a permanent note in `Actions/` with purpose, command, execution status, evidence links, observations, and editable analyst notes. '
              'Edit **Analyst status** in a note and refresh the dashboard to move it. `Auto` follows probe execution.', '']
    for group in ('Needs Action','In Progress','Completed'):
        entries=grouped[group]
        lines += [f'#### {group} ({len(entries)})','',
                  '| Action | Evidence / status | Action note |', '| --- | --- | --- |']
        for task,path,auto_status in sorted(entries,key=lambda x:x[0]['title']):
            status=task['execution']
            if task['completed']: status='Probe completed; validation may remain'
            elif status=='Not run':status='Not run / manual review'
            lines.append(f'| {escape(task["title"])} | {escape(status)} | {valid_link(path,"Open action note")} |')
        if not entries:lines.append('| — | — | — |')
        lines.append('')
    lines += [f'**Tracked recommendations:** {sum(map(len,grouped.values()))} · '
              f'Needs Action {len(grouped["Needs Action"])} · In Progress {len(grouped["In Progress"])} · Completed {len(grouped["Completed"])}', '']
    lines += ['## Service inventory','']
    if inventory_run:
        lines.extend([f'**Inventory source:** {summary(inventory_run)} ({inventory_run["mode"]}). This is one selected scan, not a union of historical ports.','',
            '| Protocol/port | Service / version | Readable report |', '| --- | --- | --- |'])
        for key,desc in sorted(observed.items()):
            lines.append(f'| {key[0]}/{key[1]} | {escape(desc)} | {readable_evidence(inventory_run["sources"][key])} |')
        if not observed:lines.append('| — | No open ports reported | — |')
    else: lines.append('No completed scan evidence available.')

    lines += ['', '## Potential vulnerability references (unverified)','']
    if vuln_run:
        refs=[]
        for (cve,key),(score,file) in vuln_run['vulns'].items(): refs.append((score,cve,key,file))
        refs.sort(key=lambda x:(-x[0],x[1],x[2]))
        uniq=len({x[1] for x in refs})
        lines += [f'**Source:** {summary(vuln_run)} · {uniq} distinct CVE IDs across {len(refs)} port/CVE associations. Showing the highest-scored 12 associations.','',
            '> Scores are supplied by the Vulners NSE output, not independently verified CVSS ratings. Version/CPE matching can yield false positives, particularly when vendor patches are backported. Review applicability and validate each item.','',
            '| CVE | Port | Scanner score | Evidence |', '| --- | --- | ---: | --- |']
        for score,cve,key,file in refs[:12]:
            lines.append(f'| {cve} | {key[0]}/{key[1]} | {score:g} | {readable_evidence(file,"NSE HTML")} |')
        if not refs:lines.append('| — | — | — | No parsable Vulners CVE entries |')
        lines += ['', f'For the full original scanner output, see {summary(vuln_run)}.']
    else:lines += ['No completed Vulners NSE output with parseable CVE/score entries yet. This does not mean no vulnerabilities exist.']

    lines += ['', '## Changes between comparable scans','']
    if recent:
        previous=next((x for x in complete[1:] if x['mode'].lower()==recent['mode'].lower()),None)
        if previous:
            before,after=previous['services'],recent['services']
            added=sorted(after.keys()-before.keys());missing=sorted(before.keys()-after.keys())
            changed=sorted(k for k in after.keys() & before.keys() if after[k]!=before[k])
            lines += [f'{summary(previous)} → {summary(recent)}','',
                '> Observed differences only. Scope, availability, and scan settings may vary; an absent port is not confirmed closed.','',
                '| Change | Port | Detail |', '| --- | --- | --- |']
            for k in added:lines.append(f'| Newly observed | {k[0]}/{k[1]} | {escape(after[k])} |')
            for k in missing:lines.append(f'| Not observed | {k[0]}/{k[1]} | Previously: {escape(before[k])} |')
            for k in changed:lines.append(f'| Service label changed | {k[0]}/{k[1]} | {escape(before[k])} → {escape(after[k])} |')
            if not added and not missing and not changed:lines.append('| No observed differences | — | Port/service labels unchanged |')
        else: lines.append(f'No previous completed **{recent["mode"]}** scan to compare with the latest run. Different scan types are not treated as equivalent coverage.')
    else:lines.append('No completed runs available.')

    lines += ['', '## Scan timeline','',
        '| Local time | Scan | Status | Observed TCP / UDP | Evidence |',
        '| --- | --- | --- | ---: | --- |']
    for d in runs:
        t=sum(k[0]=='tcp' for k in d['services']); u=sum(k[0]=='udp' for k in d['services'])
        lines.append(f'| {escape(d["display"])} | {escape(d["mode"])} ({escape(d["scope"])}) | {state(d)} | {t} / {u} | {summary(d)} |')
    if not runs:lines.append('| — | — | — | — | — |')
    lines += ['', '## Analyst workspace','',
        '- [[01_FINDINGS|Validated findings and retest notes]]',
        '- Scan artifacts remain inside `Runs/` (HTML reports and Markdown notes in `nmap/`, original XML in `nmap/xml/`, plus GNMAP, logs, and recon evidence).',
        '- Legacy scan folders remain in place and are linked when detected.','']
    save_atomic(root/'00_TARGET_DASHBOARD.md','\n'.join(lines)+'\n')
    if os.environ.get('SUDO_UID') and os.environ.get('SUDO_GID'):
        try:os.chown(root/'.dashboard.lock',int(os.environ['SUDO_UID']),int(os.environ['SUDO_GID']))
        except OSError:pass
PYDASH
}

# Rebuild the dashboard from existing XML without launching another scan.
if [[ $TYPE == dashboard ]]; then
  RUN_DIR=-
  update_target_dashboard
  printf 'Dashboard refreshed: %s\n' "$BASE_DIR/$TARGET/00_TARGET_DASHBOARD.md"
  exit 0
fi

# With evidence already present, repeated named modes are dashboard-only by
# default. --fresh explicitly forces a new measurement. Recon --run-recon is
# deliberately not skipped because optional probes might not have been run.
if (( ! FRESH && ! RUN_RECON )) && [[ $TYPE != all ]]; then
  CACHE_HIT=$(python3 - "$BASE_DIR/$TARGET" "$TYPE" "$SCOPE_SIGNATURE" <<'PYSKIP'
import json,pathlib,sys
root,mode,scope=pathlib.Path(sys.argv[1]),sys.argv[2],sys.argv[3]
names={'quick':['quick'],'basic':['basic'],'full':['full_discovery','full_services'],
       'vulns':['vuln_nse'],'udp':['udp_discovery'],'recon':['recommendations.txt']}
for p in (root/'Runs',root):
    if not p.is_dir():continue
    for run in p.iterdir():
        if not run.is_dir():continue
        st=run/'.scan_status.json'
        if not st.exists():continue
        try:meta=json.loads(st.read_text())
        except (OSError,ValueError):continue
        if meta.get('mode','').lower()!=mode or meta.get('failures')!=0 or meta.get('scope','default')!=scope:continue
        paths=(list((run/'nmap'/'xml').glob('*.xml'))+list((run/'nmap').glob('*.xml')))
        stems={x.stem for x in paths}
        if mode=='recon':ok=(run/'recon'/'recommendations.txt').exists()
        else:ok=all(x in stems for x in names.get(mode,[]))
        if ok and mode=='vulns' and scope=='default':
            # Invalidate old vuln coverage when a newer Full scan expanded discovery.
            newest_full=max((f.stat().st_mtime for q in (root/'Runs',root) if q.is_dir()
                             for r in q.iterdir() if r.is_dir()
                             for f in list((r/'nmap'/'xml').glob('full_discovery.xml'))+
                                      list((r/'nmap').glob('full_discovery.xml'))),default=0)
            if newest_full > run.stat().st_mtime: ok=False
        if ok:
            print(run)
            sys.exit(0)
PYSKIP
)
  if [[ -n $CACHE_HIT ]]; then
    echo "Reusing completed $TYPE evidence: $CACHE_HIT"
    update_target_dashboard
    echo 'Dashboard refreshed; no Nmap commands executed. Add --fresh to rescan.'
    exit 0
  fi
fi

RUN_DIR=$(new_scan_folder "$BASE_DIR/$TARGET/Runs")
NMAP_DIR="$RUN_DIR/nmap"
RECON_DIR="$RUN_DIR/recon"
make_output_dir "$NMAP_DIR"
make_output_dir "$RECON_DIR"
OWNERSHIP_TREE="$RUN_DIR"
LOG="$RUN_DIR/run.log"
FAILURES=0
HOST_ARGS=()
if (( NO_PING )); then
  HOST_ARGS=(-Pn)
elif command -v ping >/dev/null && ping -n -c 1 -W 2 "$TARGET" >/dev/null 2>&1; then
  log 'ICMP echo responded; using normal Nmap host discovery'
else
  HOST_ARGS=(-Pn)
  log 'ICMP echo unavailable; using -Pn (this does not prove host is up)'
fi
START=$SECONDS
log "Authorized target: $TARGET | mode: $TYPE | scope: $SCOPE_SIGNATURE | output: $RUN_DIR"

case $TYPE in
  quick) quick_scan || true ;;
  basic) if ensure_tcp_discovery; then basic_scan || true; fi ;;
  udp) udp_scan || true ;;
  full) full_scan || true ;;
  vulns) if ensure_tcp_discovery; then vulns_scan; fi ;;
  recon) if ensure_tcp_discovery; then recommend; if (( RUN_RECON )); then run_recon; fi; fi ;;
  all)
    if ensure_tcp_discovery; then basic_scan || true; fi
    udp_scan || true
    full_scan || true
    vulns_scan
    recommend
    if (( RUN_RECON )); then run_recon; fi
    ;;
esac
if ! convert_html_dir "$NMAP_DIR"; then
  FAILURES=$((FAILURES + 1))
fi
# Keep scanner evidence available at nmap/*.xml while scan stages execute.
# Once scanning and HTML conversion finish, archive the original XML separately.
mkdir -p -- "$NMAP_DIR/xml"
shopt -s nullglob
for xml_file in "$NMAP_DIR"/*.xml; do
  mv -- "$xml_file" "$NMAP_DIR/xml/"
done
shopt -u nullglob
log "Elapsed: $((SECONDS - START))s, failed Nmap/probes: $FAILURES"
log "Results: $RUN_DIR"
if (( MARKDOWN )); then
  if generate_markdown; then
    log "Obsidian notes: $RUN_DIR/scan_summary.md and nmap/*.md"
  else
    warn 'Markdown generation failed'
    FAILURES=$((FAILURES + 1))
  fi
fi
# Update the persistent Obsidian navigation even if the scan reported errors.
if ! update_target_dashboard; then
  warn 'Could not update target dashboard'
  FAILURES=$((FAILURES + 1))
fi
if (( FAILURES > 0 )); then exit 1; fi
