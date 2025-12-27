import { ScanResult, ScanDiff, DashboardStats } from '../types';

const API_BASE = "http://localhost:8080/api/v1";

export const apiService = {
    startScan: async (url: string): Promise<ScanResult> => {
        console.log("🔍 Starting scan for:", url);
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        if (!response.ok) {
            console.error("❌ Scan failed:", response.status, response.statusText);
            throw new Error("Falha na conexão com o backend Aegis");
        }
        const data = await response.json();
        console.log("✅ Scan completed:", data);

        // Normalize data if strings are returned instead of objects (Legacy compatibility)
        let endpoints = data.endpoints;
        if (typeof endpoints === 'string') try { endpoints = JSON.parse(endpoints); } catch { endpoints = []; }

        let metadata = data.metadata;
        if (typeof metadata === 'string') try { metadata = JSON.parse(metadata); } catch { metadata = {}; }

        // Merge flat structure
        return {
            ...data,
            endpoints: endpoints || [],
            ...metadata
        };
    },

    getDashboardStats: async (): Promise<DashboardStats> => {
        console.log("📊 Fetching dashboard stats...");
        const response = await fetch(`${API_BASE}/dashboard/stats`);
        if (!response.ok) {
            console.error("❌ Stats fetch failed:", response.status);
            throw new Error("Falha ao buscar estatísticas");
        }
        const data = await response.json();
        console.log("✅ Stats received:", data);
        return data;
    },

    compareScans: async (id1: number, id2: number): Promise<ScanDiff> => {
        const response = await fetch(`${API_BASE}/compare/${id1}/${id2}`);
        if (!response.ok) throw new Error("Comparação falhou");
        return response.json();
    },

    generateAIReport: async (scanId: number, model: string, apiKey: string) => {
        console.log("🤖 Generating AI report for scan:", scanId, "model:", model);
        const response = await fetch(`${API_BASE}/ai/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: scanId, model, api_key: apiKey })
        });
        if (!response.ok) {
            const errorText = await response.text();
            console.error("❌ AI Report failed:", errorText);
            throw new Error("Falha ao gerar relatório IA: " + errorText);
        }
        return response.json();
    },

    getExistingAIReport: async (scanId: number) => {
        const response = await fetch(`${API_BASE}/ai/report/${scanId}`);
        if (!response.ok) throw new Error("Relatório não encontrado");
        return response.json();
    },

    sendAIChatMessage: async (scanId: number, message: string, model: string, apiKey: string) => {
        const response = await fetch(`${API_BASE}/ai/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: scanId, message, model, api_key: apiKey })
        });
        if (!response.ok) throw new Error("Chat falhou");
        return response.json();
    },

    getPdfUrl: (scanId: number) => `${API_BASE}/pdf/${scanId}`,

    getHistory: async (): Promise<ScanResult[]> => {
        console.log("📜 Fetching scan history...");
        const response = await fetch(`${API_BASE}/history`);
        if (!response.ok) {
            console.error("❌ History fetch failed:", response.status);
            throw new Error("Falha ao buscar histórico");
        }
        const data = await response.json();
        console.log("✅ History received:", data?.length || 0, "scans");
        
        return (data || []).map((s: any) => {
            let endpoints = s.endpoints;
            if (typeof endpoints === 'string') try { endpoints = JSON.parse(endpoints); } catch { endpoints = []; }
            let metadata = s.metadata;
            if (typeof metadata === 'string') try { metadata = JSON.parse(metadata); } catch { metadata = {}; }
            return { ...s, endpoints: endpoints || [], ...metadata };
        }).reverse();
    }
};
