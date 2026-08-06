import os
from crewai import Agent, Task, Crew, Process, LLM
from observability import get_logger

log = get_logger(__name__)

llm = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key=os.environ.get("GROQ_API_KEY"),
    temperature=0.0
)

class SentinelAgents:
    @staticmethod
    def recon_agent():
        return Agent(
            role='Senior Reconnaissance Specialist',
            goal='Identify all external assets and open attack surfaces for a given target.',
            backstory='You are a world-class OSINT and Recon expert. You excel at finding hidden subdomains and open ports.',
            verbose=True,
            allow_delegation=False,
            llm=llm
        )
        
    @staticmethod
    def vuln_agent():
        return Agent(
            role='Vulnerability Analyst',
            goal='Scan identified assets for known vulnerabilities and misconfigurations.',
            backstory='You are a meticulous vulnerability researcher who never misses a CVE. You use tools like Nuclei and Nikto effectively.',
            verbose=True,
            allow_delegation=False,
            llm=llm
        )

    @staticmethod
    def exploit_agent():
        return Agent(
            role='Exploit Specialist & Validator',
            goal='Validate vulnerabilities without causing harm, determining true risk and attack paths.',
            backstory='You are an ethical hacker specializing in safe exploitation and attack path validation.',
            verbose=True,
            allow_delegation=False,
            llm=llm
        )

    @staticmethod
    def dns_agent():
        return Agent(
            role='DNS & Infrastructure Analyst',
            goal='Identify misconfigurations in DNS, uncover hidden subdomains, and map infrastructure.',
            backstory='You are a specialist in DNS architecture. You understand zone transfers, DNS hijacking, and routing anomalies deeply.',
            verbose=True,
            allow_delegation=False,
            llm=llm
        )

    @staticmethod
    def certificate_agent():
        return Agent(
            role='PKI & SSL/TLS Specialist',
            goal='Analyze certificate chains, extract SANs, and identify related infrastructure.',
            backstory='You are an expert in cryptography and PKI. You can find hidden assets just by looking at certificate metadata.',
            verbose=True,
            allow_delegation=False,
            llm=llm
        )

    @staticmethod
    def fingerprint_agent():
        return Agent(
            role='Technology Stack Analyst',
            goal='Fingerprint web application firewalls (WAFs), backend technologies, and HTTP headers.',
            backstory='You are a reverse-engineer of web technologies. You can identify the exact version of a server just from its responses.',
            verbose=True,
            allow_delegation=False,
            llm=llm
        )

    @staticmethod
    def threatintel_agent():
        return Agent(
            role='Cyber Threat Intelligence Analyst',
            goal='Analyze discovered IPs, domains, and hashes against known threat actor infrastructure and botnets.',
            backstory='You are a CTI expert leveraging OSINT, AlienVault OTX, Abuse.ch, and PhishTank to detect malicious indicators of compromise (IOCs).',
            verbose=True,
            allow_delegation=False,
            llm=llm
        )

class SentinelTasks:
    @staticmethod
    def recon_task(agent, target: str):
        return Task(
            description=f'Perform comprehensive reconnaissance on the target: {target}. Identify subdomains, IPs, and open ports.',
            expected_output='A structured JSON list of tasks for the worker to execute (e.g., nmap, subdomain).',
            agent=agent
        )

    @staticmethod
    def vuln_task(agent, recon_results: str):
        return Task(
            description=f'Analyze the reconnaissance results: {recon_results}. Determine which vulnerability scanners to run.',
            expected_output='A structured JSON list of tasks for the worker to execute (e.g., nuclei, nikto).',
            agent=agent
        )

    @staticmethod
    def verification_task(agent, findings: dict, tool_used: str):
        findings_summary = str(findings)[:2000]
        return Task(
            description=f'''Analyze the following findings from {tool_used}. 
Determine if these findings are logically sound and represent genuine risks, or if they are likely false positives.
Findings: {findings_summary}''',
            expected_output='A JSON object with a single boolean key "is_verified". True if the findings seem legitimate, False if they are likely false positives.',
            agent=agent
        )

    @staticmethod
    def threatintel_task(agent, iocs: list):
        return Task(
            description=f'''Query the threat intelligence platforms for the following Indicators of Compromise (IOCs): {iocs}. 
Cross-reference IPs, domains, and hashes to determine if they are associated with botnets, phishing, or malware delivery.''',
            expected_output='A JSON report detailing which IOCs are malicious, listing their associated tags and sources.',
            agent=agent
        )
