import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import { ScanResult } from '../types';

interface NetworkTopologyProps {
    scan: ScanResult;
}

export const NetworkTopology: React.FC<NetworkTopologyProps> = ({ scan }) => {
    const svgRef = useRef<SVGSVGElement>(null);
    const containerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (!svgRef.current || !scan || !containerRef.current) return;

        // Clear previous
        d3.select(svgRef.current).selectAll("*").remove();

        const width = containerRef.current.clientWidth;
        const height = 400; // Fixed height

        // --- Data Prep ---
        const nodes: any[] = [];
        const links: any[] = [];
        let nodeId = 0;

        // Root
        const rootId = nodeId++;
        const hostname = new URL(scan.target).hostname;
        nodes.push({ id: rootId, label: hostname, type: 'root', r: 15 });

        // Children (Site Map)
        scan.site_map?.nodes.forEach(n => {
            if (n.type === 'CHILD') {
                const id = nodeId++;
                nodes.push({ id, label: new URL(n.url).pathname, type: 'child', r: 6 });
                links.push({ source: rootId, target: id });
            }
        });

        // Endpoints (Cluster)
        scan.endpoints.slice(0, 20).forEach(ep => {
             const id = nodeId++;
             // Simple dedup by url check needed? Skipping for perf
             nodes.push({ id, label: ep.method, type: 'endpoint', r: 4, status: ep.status });
             links.push({ source: rootId, target: id });
        });

        // Ghost Routes
        scan.security_audit?.ghost_routes.slice(0, 10).forEach((r: any) => {
             const label = typeof r === 'string' ? r : r.route;
             const id = nodeId++;
             nodes.push({ id, label, type: 'ghost', r: 5 });
             links.push({ source: rootId, target: id });
        });

        // --- D3 Setup ---
        const svg = d3.select(svgRef.current)
            .attr("viewBox", [0, 0, width, height])
            .attr("class", "w-full h-full select-none cursor-move");

        // Group for Zooming
        const g = svg.append("g");

        const zoom = d3.zoom()
            .scaleExtent([0.5, 4])
            .on("zoom", (event) => g.attr("transform", event.transform));
        
        svg.call(zoom as any);

        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id((d: any) => d.id).distance(60))
            .force("charge", d3.forceManyBody().strength(-200))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide(20).iterations(2));

        // Draw Links
        const link = g.append("g")
            .selectAll("line")
            .data(links)
            .join("line")
            .attr("stroke", "#cbd5e1")
            .attr("stroke-opacity", 0.6)
            .attr("stroke-width", 1.5);

        // Draw Nodes
        const node = g.append("g")
            .selectAll("circle")
            .data(nodes)
            .join("circle")
            .attr("r", (d: any) => d.r)
            .attr("fill", (d: any) => {
                if (d.type === 'root') return '#4f46e5'; // Indigo
                if (d.type === 'ghost') return '#ef4444'; // Red
                if (d.type === 'endpoint') return d.status >= 400 ? '#f59e0b' : '#3b82f6'; // Amber/Blue
                return '#10b981'; // Emerald
            })
            .attr("stroke", "#fff")
            .attr("stroke-width", 2)
            .call(drag(simulation) as any);

        // Tooltips
        node.append("title").text((d: any) => d.label);

        // Tick
        simulation.on("tick", () => {
            link
                .attr("x1", (d: any) => d.source.x)
                .attr("y1", (d: any) => d.source.y)
                .attr("x2", (d: any) => d.target.x)
                .attr("y2", (d: any) => d.target.y);

            node
                .attr("cx", (d: any) => d.x)
                .attr("cy", (d: any) => d.y);
        });

        function drag(simulation: any) {
            function dragstarted(event: any, d: any) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }
            function dragged(event: any, d: any) {
                d.fx = event.x;
                d.fy = event.y;
            }
            function dragended(event: any, d: any) {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }
            return d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended);
        }

    }, [scan]);

    return (
        <div ref={containerRef} className="w-full h-[400px] bg-slate-50/50 rounded-xl border border-slate-200 overflow-hidden relative shadow-inner">
             <div className="absolute inset-0 bg-[radial-gradient(#cbd5e1_1px,transparent_1px)] [background-size:16px_16px] opacity-30"></div>
             <svg ref={svgRef}></svg>
             <div className="absolute bottom-4 right-4 flex flex-col gap-2 bg-white/90 backdrop-blur p-3 border border-slate-200 rounded-lg shadow-sm">
                 <div className="flex items-center gap-2 text-[10px] text-slate-600 font-bold uppercase"><span className="w-2 h-2 rounded-full bg-indigo-500"></span> Target Root</div>
                 <div className="flex items-center gap-2 text-[10px] text-slate-600 font-bold uppercase"><span className="w-2 h-2 rounded-full bg-emerald-500"></span> Sub-Page</div>
                 <div className="flex items-center gap-2 text-[10px] text-slate-600 font-bold uppercase"><span className="w-2 h-2 rounded-full bg-blue-500"></span> API Endpoint</div>
                 <div className="flex items-center gap-2 text-[10px] text-slate-600 font-bold uppercase"><span className="w-2 h-2 rounded-full bg-red-500"></span> Ghost Route</div>
             </div>
        </div>
    );
};