import type { TopologyEdge, TopologyNode } from "./resultAdapter";
import { formatBytes, stateLabel } from "./dashboardPanelUtils";

export function TopologyCanvas({
  nodes,
  edges
}: {
  readonly nodes: readonly TopologyNode[];
  readonly edges: readonly TopologyEdge[];
}) {
  const endpointNodes = nodes.filter((node) => node.layer.toLowerCase().includes("endpoint")).slice(0, 4);
  const externalNodes = nodes.filter((node) => node.layer.toLowerCase().includes("external")).slice(0, 5);
  const endpointPositions = positionNodes(endpointNodes, 150, 96, 328);
  const externalPositions = positionNodes(externalNodes, 800, 96, 328);
  const sourceLookup = new Map(endpointPositions.map((node) => [node.id, node]));
  const targetLookup = new Map(externalPositions.flatMap((node) => [[node.id, node], [node.label, node]]));
  const flows = edges.length ? edges.slice(0, 10) : [];

  return (
    <div className="topology-stage">
      <svg className="topology-svg" viewBox="0 0 1040 420" role="img" aria-label="Endpoint egress topology">
        <defs>
          <marker id="flow-arrow" markerHeight="7" markerWidth="8" orient="auto" refX="7" refY="3.5">
            <path className="flow-arrow" d="M 0 0 L 8 3.5 L 0 7 z" />
          </marker>
        </defs>
        <text className="lane-label" x="150" y="34" textAnchor="middle">Endpoint fleet</text>
        <text className="lane-label boundary-label" x="520" y="34" textAnchor="middle">Protected tenant boundary</text>
        <text className="lane-label" x="800" y="34" textAnchor="middle">External destinations</text>
        <rect className="boundary-box" height="248" rx="10" width="180" x="430" y="86" />
        <line className="boundary-axis" x1="430" x2="610" y1="210" y2="210" />
        <text className="boundary-title" x="520" y="194" textAnchor="middle">Tenant SIEM</text>
        <text className="boundary-state" x="520" y="218" textAnchor="middle">inspection boundary</text>
        {flows.map((edge, index) => {
          const source = sourceLookup.get(edge.source) ?? endpointPositions[index % Math.max(endpointPositions.length, 1)];
          const target = targetLookup.get(edge.target) ?? externalPositions[index % Math.max(externalPositions.length, 1)];
          if (!source || !target) return null;
          const path = `M ${source.x + 30} ${source.y} C 310 ${source.y}, 370 210, 430 210 S 720 ${target.y}, ${target.x - 42} ${target.y}`;
          return <path className={`flow-line ${edgeState(edge)}`} d={path} key={`${edge.source}-${edge.target}-${index}`} />;
        })}
        {endpointPositions.map((node) => <GraphNode key={node.id} node={node} side="left" />)}
        {externalPositions.map((node) => <GraphNode key={node.id} node={node} side="right" />)}
      </svg>
      <div className="topology-legend">
        <span><i className="dot alert" />alert</span>
        <span><i className="dot observed" />observed</span>
        <span><i className="dot not-detected" />not detected</span>
      </div>
      <div className="edge-list">
        {flows.slice(0, 5).map((edge, index) => (
          <div className={`edge-row ${edgeState(edge)}`} key={`${edge.source}-${edge.target}-${index}`}>
            <span>{edge.sourceLabel}</span>
            <strong>{edge.target}</strong>
            <small>{edge.protocol} / alerts {edge.alertCount} / {formatBytes(edge.bytesOut)}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function GraphNode({ node, side }: { readonly node: PositionedNode; readonly side: "left" | "right" }) {
  const textX = side === "left" ? -34 : 34;
  const anchor = side === "left" ? "end" : "start";
  return (
    <g className={`graph-node ${node.state}`} transform={`translate(${node.x} ${node.y})`}>
      <circle className="node-ring" r="25" />
      <circle className="node-core" r="11" />
      <text className="node-label" textAnchor={anchor} x={textX} y="2">{node.label}</text>
      <text className="node-state" textAnchor={anchor} x={textX} y="18">{stateLabel(node.state)}</text>
    </g>
  );
}

type PositionedNode = TopologyNode & { readonly x: number; readonly y: number };

function positionNodes(nodes: readonly TopologyNode[], x: number, minY: number, maxY: number): readonly PositionedNode[] {
  const visibleNodes = nodes.length ? nodes : [{ id: "empty", label: "No data", layer: "empty", state: "not-detected", riskScore: 0, alertCount: 0 }];
  const step = visibleNodes.length === 1 ? 0 : (maxY - minY) / (visibleNodes.length - 1);
  return visibleNodes.map((node, index) => ({
    ...node,
    x,
    y: visibleNodes.length === 1 ? (minY + maxY) / 2 : minY + step * index
  }));
}

function edgeState(edge: TopologyEdge): string {
  if (edge.alertCount > 0 || edge.state === "alert") return "alert";
  if (edge.state === "observed") return "observed";
  return "not-detected";
}
