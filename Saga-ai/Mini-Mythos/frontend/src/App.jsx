import React, { useState, useEffect } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

function App() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  useEffect(() => {
    // In production, this would fetch from http://localhost:8000/graph/
    // Since the React app runs in the browser, we fetch from the exposed API port.
    fetch('http://localhost:8000/graph/')
      .then(res => res.json())
      .then(data => {
        setGraphData(data);
      })
      .catch(err => {
        console.error("Failed to fetch graph data:", err);
      });
  }, []);

  // Determine node color based on group
  const getNodeColor = (node) => {
    if (node.group === 1) return '#38bdf8'; // Target
    if (node.group === 2) return '#ef4444'; // Vulnerability
    if (node.group === 3) return '#fbbf24'; // Port
    return '#94a3b8';
  };

  return (
    <div style={{ height: '100vh', width: '100vw' }}>
      <div style={{ position: 'absolute', top: 20, left: 20, zIndex: 10, color: '#f8fafc', fontFamily: 'sans-serif' }}>
        <h1 style={{ margin: 0, color: '#38bdf8' }}>Nexus Graph Visualizer</h1>
        <p style={{ margin: 0, color: '#94a3b8' }}>Knowledge Graph Mapping</p>
        <div style={{ marginTop: 20, fontSize: '0.9rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 5 }}>
            <div style={{ width: 12, height: 12, backgroundColor: '#38bdf8', borderRadius: '50%', marginRight: 8 }}></div> Targets
          </div>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 5 }}>
            <div style={{ width: 12, height: 12, backgroundColor: '#fbbf24', borderRadius: '50%', marginRight: 8 }}></div> Open Ports
          </div>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <div style={{ width: 12, height: 12, backgroundColor: '#ef4444', borderRadius: '50%', marginRight: 8 }}></div> Vulnerabilities
          </div>
        </div>
      </div>
      
      <ForceGraph2D
        graphData={graphData}
        nodeLabel="name"
        nodeColor={getNodeColor}
        nodeRelSize={8}
        linkColor={() => '#334155'}
        linkWidth={2}
        backgroundColor="#0f172a"
      />
    </div>
  );
}

export default App;
