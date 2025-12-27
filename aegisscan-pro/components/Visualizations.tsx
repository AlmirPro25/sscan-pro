import React from 'react';
import { 
    PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Legend 
} from 'recharts';
import { ScanResult } from '../types';

interface ChartProps {
    scan: ScanResult;
}

const COLORS = {
    CRITICAL: '#ef4444', // Red 500
    HIGH: '#f97316',     // Orange 500
    MEDIUM: '#eab308',   // Yellow 500
    LOW: '#3b82f6',      // Blue 500
    INFO: '#94a3b8'      // Slate 400
};

const STATUS_COLORS = {
    '2xx': '#10b981', // Emerald
    '3xx': '#3b82f6', // Blue
    '4xx': '#f59e0b', // Amber
    '5xx': '#ef4444'  // Red
};

export const VulnerabilityDistribution: React.FC<ChartProps> = ({ scan }) => {
    const vulns = scan.security_audit?.vulnerabilities;
    if (!vulns || vulns.total === 0) {
        return (
            <div className="h-64 flex flex-col items-center justify-center text-slate-400 bg-slate-50/50 rounded-xl border border-dashed border-slate-200">
                <i className="fas fa-shield-check text-4xl text-emerald-500 mb-2"></i>
                <span className="text-xs font-bold uppercase tracking-widest">System Secure</span>
            </div>
        );
    }

    const data = [
        { name: 'Critical', value: vulns.critical },
        { name: 'High', value: vulns.high },
        { name: 'Medium', value: vulns.medium },
    ].filter(d => d.value > 0);

    return (
        <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={data}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                    >
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[entry.name.toUpperCase() as keyof typeof COLORS]} />
                        ))}
                    </Pie>
                    <Tooltip 
                        contentStyle={{ backgroundColor: '#fff', borderRadius: '8px', border: '1px solid #e2e8f0', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
                        itemStyle={{ fontFamily: 'JetBrains Mono', fontSize: '12px', fontWeight: 'bold' }}
                    />
                    <Legend verticalAlign="bottom" height={36} iconType="circle" />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
};

export const StatusCodeDistribution: React.FC<ChartProps> = ({ scan }) => {
    const endpoints = scan.endpoints || [];
    
    const counts = endpoints.reduce((acc, ep) => {
        const status = ep.status || 0;
        if (status >= 200 && status < 300) acc['2xx']++;
        else if (status >= 300 && status < 400) acc['3xx']++;
        else if (status >= 400 && status < 500) acc['4xx']++;
        else if (status >= 500) acc['5xx']++;
        return acc;
    }, { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 });

    const data = Object.keys(counts).map(k => ({
        name: k,
        count: counts[k as keyof typeof counts]
    })).filter(d => d.count > 0);

    return (
        <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#e2e8f0" />
                    <XAxis type="number" hide />
                    <YAxis dataKey="name" type="category" tick={{fontSize: 10, fontFamily: 'JetBrains Mono'}} width={30} />
                    <Tooltip 
                        cursor={{fill: 'transparent'}}
                        contentStyle={{ backgroundColor: '#fff', borderRadius: '8px', border: '1px solid #e2e8f0' }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={20}>
                        {data.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={STATUS_COLORS[entry.name as keyof typeof STATUS_COLORS]} />
                        ))}
                    </Bar>
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
};