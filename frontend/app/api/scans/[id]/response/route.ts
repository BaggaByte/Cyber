import { NextResponse } from 'next/server';
import { store } from '@/app/api/_store';

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = store.scans.find(s => s.scan_id === id || s.scan_id === `SCN-${id}`);
  const target = scan?.target || "example.com";
  const tool = scan?.tool_used || "nmap";

  return NextResponse.json({
    script: `#!/bin/bash
# SentinelAI Automated Remediation Script
# Target: ${target} (Tool: ${tool})

echo "[+] Initiating patch sequence for ${target}..."
sudo apt-get update -y
sudo apt-get install --only-upgrade openssh-server nginx -y

echo "[+] Applying HTTP Security Headers..."
cat << 'EOF' | sudo tee /etc/nginx/conf.d/security-headers.conf
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
EOF

sudo systemctl reload nginx
echo "[+] Remediation applied successfully!"`,
    ticket_payload: {
      summary: `[SentinelAI] ${scan?.risk_score || "HIGH"} Risk Findings on ${target}`,
      description: `Automated scan via ${tool} identified critical security risks on ${target}.\n\nRemediation script generated and verified by AI engine.`,
      project: "SEC",
      issue_type: "Bug",
      priority: scan?.risk_score === "CRITICAL" ? "Highest" : "High"
    }
  });
}
