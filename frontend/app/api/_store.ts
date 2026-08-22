export interface User {
  email: string;
  org_name: string;
  first_name?: string;
  last_name?: string;
  job_title?: string;
  role: string;
  org_tier: string;
}

export interface Scan {
  scan_id: string;
  target: string;
  tool_used: string;
  risk_score: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: "completed" | "running" | "failed" | "queued";
  started_at: string;
  completed_at?: string;
  findings?: Record<string, unknown>;
}

export interface Mission {
  mission_id: string;
  target: string;
  goal: string;
  scan_count: number;
  created_at: string;
  decision_log: Array<{ action: string; reason: string; timestamp: string; confidence?: string }>;
  scans: Array<{ scan_id: string; tool_used: string; risk_score: string; status: string }>;
}

export interface Asset {
  asset_id: string;
  target: string;
  asset_type: string;
  scan_count: number;
  last_risk_score: string;
  discovered_at: string;
}

export interface Schedule {
  id: string;
  target: string;
  tool: string;
  cron_expression: string;
  next_run: string;
}

class Store {
  currentUser: User = {
    email: "analyst@sentinel.ai",
    org_name: "Saga Enterprise",
    first_name: "Alex",
    last_name: "Vance",
    job_title: "Lead SecOps Engineer",
    role: "admin",
    org_tier: "enterprise",
  };

  scans: Scan[] = [
    {
      scan_id: "SCN-1092",
      target: "example.com",
      tool_used: "nmap",
      risk_score: "HIGH",
      status: "completed",
      started_at: new Date(Date.now() - 3600000 * 2).toISOString(),
      completed_at: new Date(Date.now() - 3600000 * 1.9).toISOString(),
      findings: {
        open_ports: [
          { port: 80, protocol: "tcp", service: "http", version: "nginx/1.18.0" },
          { port: 443, protocol: "tcp", service: "https", version: "nginx/1.18.0" },
          { port: 22, protocol: "tcp", service: "ssh", version: "OpenSSH 8.2p1" }
        ],
        vulnerabilities: [
          "CVE-2023-38408: OpenSSH PKCS#11 Remote Code Execution vulnerability",
          "Missing HTTP Security Headers (HSTS, Content-Security-Policy)"
        ]
      }
    },
    {
      scan_id: "SCN-1093",
      target: "api.internal.net",
      tool_used: "nuclei",
      risk_score: "CRITICAL",
      status: "completed",
      started_at: new Date(Date.now() - 3600000 * 5).toISOString(),
      completed_at: new Date(Date.now() - 3600000 * 4.8).toISOString(),
      findings: {
        vulnerabilities: [
          "CVE-2024-21626: runc Process Directory File Descriptor Leak (Container Escape)",
          "Exposed GraphQL Introspection Endpoint on /graphql"
        ]
      }
    },
    {
      scan_id: "SCN-1094",
      target: "staging.example.com",
      tool_used: "subdomain",
      risk_score: "INFO",
      status: "completed",
      started_at: new Date(Date.now() - 3600000 * 12).toISOString(),
      completed_at: new Date(Date.now() - 3600000 * 11.9).toISOString(),
      findings: {
        subdomains: [
          "api.staging.example.com",
          "admin.staging.example.com",
          "dev.staging.example.com",
          "auth.staging.example.com"
        ]
      }
    },
    {
      scan_id: "SCN-1095",
      target: "prod-db.internal.net",
      tool_used: "httpx",
      risk_score: "MEDIUM",
      status: "completed",
      started_at: new Date(Date.now() - 3600000 * 24).toISOString(),
      completed_at: new Date(Date.now() - 3600000 * 23.8).toISOString(),
      findings: {
        endpoints: [
          "HTTP/1.1 200 OK — Server: Apache/2.4.41",
          "SSL Certificate expires in 14 days"
        ]
      }
    }
  ];

  missions: Mission[] = [
    {
      mission_id: "MIS-501",
      target: "example.com",
      goal: "Map full attack surface and scan for critical CVEs",
      scan_count: 3,
      created_at: new Date(Date.now() - 3600000 * 3).toISOString(),
      decision_log: [
        {
          action: "Subdomain Enumeration",
          reason: "Enumerate passive and active subdomains prior to service profiling.",
          timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
          confidence: "98%"
        },
        {
          action: "Port & Service Fingerprinting",
          reason: "Scan open ports on discovered target hosts using Nmap.",
          timestamp: new Date(Date.now() - 3600000 * 2.8).toISOString(),
          confidence: "95%"
        },
        {
          action: "Vulnerability Scanning",
          reason: "Execute Nuclei template engine against identified web endpoints.",
          timestamp: new Date(Date.now() - 3600000 * 2.5).toISOString(),
          confidence: "92%"
        }
      ],
      scans: [
        { scan_id: "SCN-1094", tool_used: "subdomain", risk_score: "INFO", status: "completed" },
        { scan_id: "SCN-1092", tool_used: "nmap", risk_score: "HIGH", status: "completed" },
        { scan_id: "SCN-1093", tool_used: "nuclei", risk_score: "CRITICAL", status: "completed" }
      ]
    }
  ];

  assets: Asset[] = [
    {
      asset_id: "AST-101",
      target: "example.com",
      asset_type: "Primary Domain / Web App",
      scan_count: 14,
      last_risk_score: "HIGH",
      discovered_at: new Date(Date.now() - 86400000 * 10).toISOString()
    },
    {
      asset_id: "AST-102",
      target: "api.internal.net",
      asset_type: "API Gateway",
      scan_count: 8,
      last_risk_score: "CRITICAL",
      discovered_at: new Date(Date.now() - 86400000 * 8).toISOString()
    },
    {
      asset_id: "AST-103",
      target: "staging.example.com",
      asset_type: "Staging Server",
      scan_count: 5,
      last_risk_score: "INFO",
      discovered_at: new Date(Date.now() - 86400000 * 5).toISOString()
    }
  ];

  schedules: Schedule[] = [
    {
      id: "SCH-101",
      target: "example.com",
      tool: "nmap",
      cron_expression: "0 0 * * *",
      next_run: new Date(Date.now() + 86400000).toISOString()
    },
    {
      id: "SCH-102",
      target: "api.internal.net",
      tool: "nuclei",
      cron_expression: "0 12 * * *",
      next_run: new Date(Date.now() + 43200000).toISOString()
    }
  ];
}

export const store = new Store();
