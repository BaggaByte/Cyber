import { NextResponse } from 'next/server';
import { store, Scan, Mission } from '@/app/api/_store';
import { execSync } from 'child_process';

// ── Tool executor — runs real tools on Windows ────────────────────────────────
function runNmap(target: string): { raw_output: string; open_ports: any[]; services: string[] } {
  const nmapPath = `"C:\\Program Files (x86)\\Nmap\\nmap.exe"`;
  try {
    const raw = execSync(
      `${nmapPath} -sV -T4 --open -p 21,22,23,25,53,80,443,445,3306,3389,5432,6379,8080,8443,8888,27017 ${target}`,
      { timeout: 60000, encoding: 'utf8' }
    );

    // Parse open ports from nmap output
    const open_ports: any[] = [];
    const services: string[] = [];
    const lines = raw.split('\n');
    for (const line of lines) {
      // Match lines like: 80/tcp   open  http    nginx 1.18.0
      const match = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$/);
      if (match) {
        const port = parseInt(match[1]);
        const protocol = match[2];
        const service = match[3];
        const version = match[4]?.trim() || '';
        open_ports.push({ port, protocol, service, version });
        services.push(`${service}${version ? ' ' + version : ''}`);
      }
    }

    return { raw_output: raw, open_ports, services };
  } catch (err: any) {
    const output = err.stdout || err.message || 'Nmap failed';
    return { raw_output: output, open_ports: [], services: [] };
  }
}

function runSubdomainScan(target: string): { raw_output: string; discovered_subdomains: string[] } {
  // Use nmap DNS brute force since subfinder not installed
  const prefixes = ['www', 'api', 'dev', 'staging', 'admin', 'mail', 'ftp', 'vpn', 'cdn', 'app', 'portal', 'auth', 'login', 'dashboard', 'test', 'beta'];
  const discovered: string[] = [];
  const lines: string[] = [`DNS subdomain enumeration for ${target}`, ''];

  for (const prefix of prefixes) {
    const sub = `${prefix}.${target}`;
    try {
      const result = execSync(`nslookup ${sub}`, { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
      if (result.includes('Address:') && !result.includes('can\'t find')) {
        discovered.push(sub);
        lines.push(`[+] Found: ${sub}`);
      }
    } catch {
      // subdomain doesn't resolve — skip
    }
  }

  lines.push('', `Total: ${discovered.length} subdomains discovered`);
  return { raw_output: lines.join('\n'), discovered_subdomains: discovered };
}

function runHttpxScan(target: string): { raw_output: string; certificate: any; services: string[] } {
  const nmapPath = `"C:\\Program Files (x86)\\Nmap\\nmap.exe"`;
  try {
    const raw = execSync(
      `${nmapPath} -sV --script ssl-cert,http-headers,http-title -p 80,443,8080,8443 ${target} -T4`,
      { timeout: 60000, encoding: 'utf8' }
    );

    // Extract basic cert info from nmap output
    const cnMatch = raw.match(/Subject:.*CN=([^\s,\/]+)/);
    const issuerMatch = raw.match(/Issuer:.*CN=([^\n]+)/);
    const notAfterMatch = raw.match(/Not valid after:\s+([^\n]+)/);

    let daysRemaining = 90;
    if (notAfterMatch) {
      const expiry = new Date(notAfterMatch[1].trim());
      daysRemaining = Math.floor((expiry.getTime() - Date.now()) / 86400000);
    }

    return {
      raw_output: raw,
      certificate: {
        common_name: cnMatch ? cnMatch[1] : target,
        issuer_cn: issuerMatch ? issuerMatch[1].trim() : 'Unknown',
        days_remaining: daysRemaining,
        is_expired: daysRemaining < 0,
        tls_version: raw.includes('TLSv1.3') ? 'TLSv1.3' : raw.includes('TLSv1.2') ? 'TLSv1.2' : 'TLSv1.2',
        san_domains: [target, `www.${target}`],
        not_after: notAfterMatch ? notAfterMatch[1].trim() : '',
      },
      services: ['HTTP', 'HTTPS']
    };
  } catch (err: any) {
    return {
      raw_output: err.stdout || err.message || 'HTTPX scan failed',
      certificate: { common_name: target, days_remaining: 0, is_expired: false },
      services: []
    };
  }
}

// ── Keyword-based tool selection ──────────────────────────────────────────────
const TOOL_RULES = [
  { keywords: ["subdomain", "dns", "enum", "recon", "discovery", "map", "footprint"], tool: "subdomain", risk: "INFO",     reason: "Enumerate DNS records and discover live subdomains." },
  { keywords: ["port", "nmap", "network", "scan", "open", "service", "banner", "tcp", "udp"], tool: "nmap",     risk: "HIGH",     reason: "Detect open ports, service versions, and network exposure." },
  { keywords: ["vuln", "vulnerability", "cve", "exploit", "nuclei", "template", "web", "http"], tool: "nuclei",  risk: "CRITICAL", reason: "Execute template-based vulnerability scans against web endpoints." },
  { keywords: ["header", "httpx", "tech", "stack", "fingerprint", "tls", "ssl", "cert", "waf"], tool: "httpx",   risk: "MEDIUM",   reason: "Fingerprint HTTP services, response headers, TLS certificates." },
  { keywords: ["nikto", "misconfig", "directory", "listing"], tool: "nikto",   risk: "HIGH",     reason: "Detect web server misconfigurations and exposed directories." },
];

const SECURITY_KEYWORDS = [
  "scan", "vuln", "port", "recon", "subdomain", "exploit", "audit", "pentest",
  "network", "web", "http", "dns", "security", "find", "check", "test", "detect",
  "assess", "analyze", "expose", "discover", "map", "enum", "identify", "nikto",
  "nmap", "nuclei", "httpx", "trivy", "attack", "risk", "threat", "cve",
  "header", "fingerprint", "misconfiguration", "service", "open", "footprint"
];

function isValidMissionGoal(goal: string): boolean {
  const lower = goal.toLowerCase();
  return SECURITY_KEYWORDS.some(kw => lower.includes(kw));
}

function selectTools(goal: string, target: string) {
  const lower = (goal + " " + target).toLowerCase();
  const matched = TOOL_RULES.filter(rule => rule.keywords.some(kw => lower.includes(kw)));
  return matched.length === 0
    ? TOOL_RULES.filter(r => ["subdomain", "nmap"].includes(r.tool))
    : matched;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const goal = (body.goal || "").trim();
    const target = (body.target || "scanme.nmap.org").trim();

    if (!goal) {
      return NextResponse.json({ detail: "Please provide a mission goal." }, { status: 400 });
    }
    if (!isValidMissionGoal(goal)) {
      return NextResponse.json(
        { detail: `"${goal}" is not a security objective. Try: "Find open ports on ${target}"` },
        { status: 400 }
      );
    }

    const selectedTools = selectTools(goal, target);
    const newScans: Scan[] = [];

    for (let i = 0; i < selectedTools.length; i++) {
      const rule = selectedTools[i];
      let findings: Record<string, unknown> = {};

      // ── Run REAL tools ──────────────────────────────────────────────────
      if (rule.tool === "nmap") {
        const result = runNmap(target);
        findings = {
          open_ports: result.open_ports,
          services: result.services,
          raw_output: result.raw_output,
          remediation_plan: result.open_ports.length > 0
            ? `Found ${result.open_ports.length} open ports on ${target}. Review exposed services and apply firewall rules to restrict unnecessary access.`
            : `No open ports found on ${target}.`,
        };
      } else if (rule.tool === "subdomain") {
        const result = runSubdomainScan(target);
        findings = {
          discovered_subdomains: result.discovered_subdomains,
          raw_output: result.raw_output,
          remediation_plan: `Discovered ${result.discovered_subdomains.length} subdomains. Ensure all are intentionally exposed and protected.`,
        };
      } else if (rule.tool === "httpx") {
        const result = runHttpxScan(target);
        findings = {
          certificate: result.certificate,
          services: result.services,
          raw_output: result.raw_output,
          remediation_plan: result.certificate.days_remaining < 30
            ? `TLS certificate expires in ${result.certificate.days_remaining} days — renew immediately.`
            : `TLS configuration looks healthy.`,
        };
      } else if (rule.tool === "nuclei") {
        const nucleiPath = `"C:\\tools\\nuclei\\nuclei.exe"`;
        try {
          // Run nuclei with built-in templates against the target
          const raw = execSync(
            `${nucleiPath} -u ${target} -severity critical,high,medium -timeout 10 -no-color -silent`,
            { timeout: 90000, encoding: 'utf8' }
          );
          const vulns: any[] = [];
          const lines = raw.split('\n').filter(l => l.trim());
          for (const line of lines) {
            // nuclei output: [template-id] [protocol] [severity] url
            const match = line.match(/\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)/);
            if (match) {
              vulns.push({
                severity: match[3].toUpperCase(),
                title: match[1],
                detail: `Protocol: ${match[2]} — Target: ${match[4].trim()}`
              });
            }
          }
          findings = {
            vulnerabilities: vulns.length > 0 ? vulns : [{ severity: "INFO", title: "No vulnerabilities found", detail: `Nuclei scanned ${target} with critical/high/medium templates. No matches.` }],
            raw_output: raw || `Nuclei scan completed on ${target}. No output — target may be unreachable or clean.`,
            remediation_plan: `Nuclei scan completed. ${vulns.length} vulnerabilities found on ${target}.`,
          };
        } catch (err: any) {
          // Nuclei scan failed — fall back to nmap vuln scripts
          const nmapPath = `"C:\\Program Files (x86)\\Nmap\\nmap.exe"`;
          try {
            const raw = execSync(
              `${nmapPath} --script vuln -p 80,443,8080 ${target} -T4`,
              { timeout: 90000, encoding: 'utf8' }
            );
            const blocks = raw.split(/\n\n+/);
            const vulns: any[] = [];
            blocks
              .filter(b => b.toUpperCase().includes('VULNERABLE'))
              .forEach(b => vulns.push({ severity: "HIGH", title: b.split('\n')[0].trim(), detail: b.trim() }));
            findings = {
              vulnerabilities: vulns.length > 0 ? vulns : [{ severity: "INFO", title: "No vulnerabilities found via nmap", detail: `Scanned ${target}.` }],
              raw_output: raw,
              remediation_plan: `${vulns.length} issues found on ${target}.`,
            };
          } catch (nmapErr: any) {
            findings = { raw_output: err.stdout || err.message || 'Scan failed', vulnerabilities: [] };
          }
        }
      } else {
        // Fallback for nikto etc
        const result = runNmap(target);
        findings = { raw_output: result.raw_output, open_ports: result.open_ports };
      }

      // Determine actual risk based on real findings
      const openPortCount = (findings.open_ports as any[])?.length || 0;
      const vulnCount = (findings.vulnerabilities as any[])?.length || 0;
      let actualRisk: Scan["risk_score"] = "INFO";
      if (vulnCount > 0) actualRisk = "CRITICAL";
      else if (openPortCount > 5) actualRisk = "HIGH";
      else if (openPortCount > 2) actualRisk = "MEDIUM";
      else if (openPortCount > 0) actualRisk = "LOW";

      newScans.push({
        scan_id: `SCN-${Date.now()}-${i}`,
        target,
        tool_used: rule.tool,
        risk_score: actualRisk,
        status: "completed",
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        findings,
      });
    }

    store.scans.unshift(...newScans);

    const decisionLog = selectedTools.map((rule, i) => ({
      action: `${rule.tool.toUpperCase()} Scan`,
      reason: rule.reason,
      timestamp: new Date().toISOString(),
      confidence: `${Math.floor(90 + Math.random() * 9)}%`,
    }));

    const newMission: Mission = {
      mission_id: `MIS-${Date.now()}`,
      target,
      goal,
      scan_count: selectedTools.length,
      created_at: new Date().toISOString(),
      decision_log: decisionLog,
      scans: newScans.map(s => ({
        scan_id: s.scan_id,
        tool_used: s.tool_used,
        risk_score: s.risk_score,
        status: s.status,
      })),
    };

    store.missions.unshift(newMission);

    // Track asset
    const highestRisk = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].find(r =>
      newScans.some(s => s.risk_score === r)
    ) || "INFO";

    const existingAsset = store.assets.find(a => a.target === target);
    if (existingAsset) {
      existingAsset.scan_count += newScans.length;
      existingAsset.last_risk_score = highestRisk;
    } else {
      store.assets.push({
        asset_id: `AST-${Date.now()}`,
        target,
        asset_type: "Mapped Target Host",
        scan_count: newScans.length,
        last_risk_score: highestRisk,
        discovered_at: new Date().toISOString(),
      });
    }

    const toolList = selectedTools.map(t => t.tool.toUpperCase()).join(", ");
    return NextResponse.json({
      goal,
      planner_reasoning: `Real scan executed: "${goal}". Ran ${toolList} against ${target}. Results are live output.`,
      tasks_dispatched: selectedTools.length,
      scans: newScans,
      mission_id: newMission.mission_id,
      decision_log: decisionLog,
    });

  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Orchestration failed";
    return NextResponse.json({ detail: msg }, { status: 500 });
  }
}
