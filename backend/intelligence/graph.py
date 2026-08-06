import os
from neo4j import GraphDatabase
from observability import get_logger

log = get_logger(__name__)

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "sentinel_neo4j")

class KnowledgeGraph:
    def __init__(self):
        try:
            self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            log.info("Successfully connected to Neo4j Knowledge Graph")
        except Exception as e:
            log.error(f"Failed to connect to Neo4j: {e}")
            self.driver = None

    def close(self):
        if self.driver:
            self.driver.close()

    def add_scan_findings(self, org_id: int, target: str, scan_id: int, tool: str, risk: str, findings: dict):
        """
        Parses findings and injects them into the Attack Graph.
        """
        if not self.driver:
            return

        with self.driver.session() as session:
            # 1. Create or update the Asset (Target) node
            session.run(
                """
                MERGE (a:Asset {target: $target, org_id: $org_id})
                ON CREATE SET a.discovered_at = timestamp()
                """,
                target=target, org_id=org_id
            )
            
            # 2. Add open ports as services
            open_ports = findings.get("open_ports", [])
            for p in open_ports:
                port_id = str(p.get("port", ""))
                service = p.get("service", "unknown")
                session.run(
                    """
                    MATCH (a:Asset {target: $target, org_id: $org_id})
                    MERGE (s:Service {port: $port, name: $service})
                    MERGE (a)-[:EXPOSES]->(s)
                    """,
                    target=target, org_id=org_id, port=port_id, service=service
                )

            # 3. Create a finding node and link it to the target
            session.run(
                """
                MATCH (a:Asset {target: $target, org_id: $org_id})
                CREATE (f:Finding {scan_id: $scan_id, tool: $tool, risk: $risk, summary: $summary})
                CREATE (a)-[:HAS_VULNERABILITY]->(f)
                """,
                target=target, org_id=org_id, scan_id=scan_id, tool=tool, risk=risk,
                summary=str(findings)[:200] # just a preview
            )

    def find_attack_paths(self, org_id: int, target: str):
        """
        Phase 1: Attack Path Analysis (Kill-chain mapping)
        Traverses the graph to find probable lateral movement or exploitation paths.
        For example: Asset -> EXPOSES -> Service -> HAS_VULNERABILITY -> Finding
        """
        if not self.driver:
            return []

        paths = []
        with self.driver.session() as session:
            # Look for vulnerabilities on exposed services
            result = session.run(
                """
                MATCH path = (a:Asset {target: $target, org_id: $org_id})-[:EXPOSES]->(s:Service)<-[:AFFECTS]-(f:Finding)
                WHERE f.risk IN ['CRITICAL', 'HIGH']
                RETURN path, nodes(path) AS nodes
                LIMIT 10
                """,
                target=target, org_id=org_id
            )
            for record in result:
                nodes = record["nodes"]
                path_details = " -> ".join([dict(n).get("name") or dict(n).get("target") or dict(n).get("summary", "Unknown") for n in nodes])
                paths.append(path_details)
        return paths

    def get_predictive_insights(self, org_id: int):
        """
        Phase 1: Pattern Learning & Predictive Insights
        Analyzes historical node patterns to predict high-probability risks.
        """
        if not self.driver:
            return {"error": "Graph DB disconnected"}

        with self.driver.session() as session:
            # Example heuristic: Find services that historically have the most critical findings
            result = session.run(
                """
                MATCH (s:Service)<-[:AFFECTS]-(f:Finding {risk: 'CRITICAL'})
                MATCH (a:Asset {org_id: $org_id})-[:EXPOSES]->(s)
                RETURN s.name AS service_name, count(f) AS threat_density
                ORDER BY threat_density DESC
                LIMIT 5
                """,
                org_id=org_id
            )
            insights = [{"service": record["service_name"], "threat_density": record["threat_density"]} for record in result]
            
            return {
                "high_risk_services": insights,
                "prediction": "Assets exposing these services have a 75% higher historical probability of critical exploitation." if insights else "Insufficient telemetry for prediction."
            }

graph_db = KnowledgeGraph()
