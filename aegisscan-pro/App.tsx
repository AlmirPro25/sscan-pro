import React, { useState, useEffect } from 'react';
import { apiService } from './services/apiService';
import { saveScanToVault, getAllScans, clearVault } from './services/dbService';
import { ScanResult, ScreenState, DashboardStats } from './types';

// Views
import { DashboardView } from './components/DashboardView';
import { ScanningView } from './components/ScanningView';
import { ReportView } from './components/ReportView';
import { HistoryView } from './components/HistoryView';
import { SettingsView } from './components/SettingsView';
import { CodeScannerView } from './components/CodeScannerView';
import { ProjectsView } from './components/ProjectsView';
import { AdvancedScanView } from './components/AdvancedScanView';
import { SCAView } from './components/SCAView';

const STEPS = [
    "INITIALIZING AEGIS KERNEL v2.0...",
    "HANDSHAKE: REMOTE SERVER...",
    "INJECTING PLAYWRIGHT PROBES...",
    "INTERCEPTING NETWORK TRAFFIC...",
    "DECRYPTING TLS BUFFERS...",
    "MAPPING GHOST PROTOCOLS...",
    "EXTRACTING ASSET MANIFESTS...",
    "RUNNING SECURITY MATRIX...",
    "FINALIZING INTEL PACKAGE..."
];

const App: React.FC = () => {
    // State
    const [screen, setScreen] = useState<ScreenState>(ScreenState.DASHBOARD);
    const [activeScan, setActiveScan] = useState<ScanResult | null>(null);
    const [vault, setVault] = useState<ScanResult[]>([]);
    const [stats, setStats] = useState<DashboardStats | null>(null);

    // Scanning State
    const [progress, setProgress] = useState(0);
    const [logStep, setLogStep] = useState(0);

    // Settings
    const [apiKey, setApiKey] = useState(localStorage.getItem('aegis_key') || 'AIzaSyD5fRNYxE2IaE40SMd7OgkUnVTIFwXME30');
    const [model, setModel] = useState(localStorage.getItem('aegis_model') || 'models/gemini-3-flash-preview');

    // Initialization - Always fetch fresh data from backend
    useEffect(() => {
        const init = async () => {
            console.log("🛡️ AegisScan Pro - Initializing...");
            await refreshVault();
        };
        init();
        
        // Auto-refresh every 30 seconds to keep data fresh
        const interval = setInterval(() => {
            refreshVault();
        }, 30000);
        
        return () => clearInterval(interval);
    }, []);

    const refreshVault = async () => {
        console.log("📡 Fetching data from backend...");
        try {
            // Always try backend first
            const history = await apiService.getHistory();
            console.log(`✅ Backend returned ${history.length} scans`);
            setVault(history);
            
            // Fetch stats separately for better reliability
            try {
                const statsData = await apiService.getDashboardStats();
                console.log("📊 Stats loaded:", statsData);
                setStats(statsData);
            } catch (statsErr) {
                console.warn("Stats API failed, calculating from history...");
                calculateLocalStats(history);
            }
        } catch (e) {
            console.warn("⚠️ Backend unavailable, using local IndexedDB...");
            const scans = await getAllScans();
            const sorted = scans.reverse();
            setVault(sorted);
            calculateLocalStats(sorted);
        }
    };

    const calculateLocalStats = (localScans: ScanResult[]) => {
        const total_scans = localScans.length;
        const total_endpoints = localScans.reduce((acc, s) => acc + (s.endpoints?.length || 0), 0);
        const avg_score = total_scans > 0
            ? Math.round(localScans.reduce((acc, s) => acc + (s.score || 0), 0) / total_scans)
            : 0;
        const score_trend = localScans.slice(0, 10).map(s => s.score || 0).reverse();
        setStats({ total_scans, total_endpoints, avg_score, score_trend });
    };

    const handleStartScan = async (url: string) => {
        if (!url.match(/^https?:\/\/.+/)) {
            alert("Protocolo Inválido (HTTP/HTTPS Required)");
            return;
        }

        setScreen(ScreenState.SCANNING);
        setProgress(0);

        const interval = setInterval(() => {
            setLogStep(prev => (prev + 1) % STEPS.length);
        }, 800);

        try {
            let p = 0;
            const progInterval = setInterval(() => {
                p += Math.random() * 8;
                if (p > 95) clearInterval(progInterval);
                setProgress(Math.min(Math.floor(p), 99));
            }, 300);

            const result = await apiService.startScan(url);

            clearInterval(progInterval);
            setProgress(100);
            clearInterval(interval);

            setTimeout(async () => {
                await saveScanToVault(result);
                await refreshVault(); // This will now prefer backend data
                setActiveScan(result);
                setScreen(ScreenState.REPORT);
            }, 600);

        } catch (e: any) {
            clearInterval(interval);
            setScreen(ScreenState.DASHBOARD);
            alert("Falha no Scan: " + e.message);
        }
    };

    return (
        <div className="min-h-screen pb-32 font-sans bg-[#f8fafc] text-slate-800 selection:bg-cyan-100 selection:text-cyan-900 relative">
            <div className="tech-grid"></div>
            {/* Header */}

            <header className="fixed top-0 inset-x-0 z-50 bg-white/80 backdrop-blur-md border-b border-slate-200 h-16 shadow-[0_2px_15px_-3px_rgba(0,0,0,0.05)]">
                <div className="max-w-7xl mx-auto h-full px-6 flex justify-between items-center">
                    <div className="flex items-center gap-3 cursor-pointer group" onClick={() => setScreen(ScreenState.DASHBOARD)}>
                        <div className="w-8 h-8 bg-gradient-to-br from-indigo-600 to-blue-500 rounded-lg flex items-center justify-center text-white shadow-lg group-hover:scale-105 transition-transform">
                            <i className="fas fa-shield-halved text-sm"></i>
                        </div>
                        <h1 className="text-xl font-black tracking-tight text-slate-900 font-mono">AEGIS<span className="text-indigo-600">SCAN</span></h1>
                    </div>

                    <div className="flex items-center gap-4">
                        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-slate-100 rounded-full border border-slate-200">
                            <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
                            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-wide">System Online</span>
                        </div>
                    </div>
                </div>
            </header>

            <main className="container mx-auto max-w-7xl px-4 mt-24">
                {screen === ScreenState.DASHBOARD && (
                    <DashboardView
                        stats={stats}
                        onStartScan={handleStartScan}
                        onNavigate={setScreen}
                    />
                )}

                {screen === ScreenState.SCANNING && (
                    <ScanningView
                        progress={progress}
                        step={STEPS[logStep]}
                    />
                )}

                {screen === ScreenState.REPORT && activeScan && (
                    <ReportView
                        scan={activeScan}
                        onBack={() => setScreen(ScreenState.DASHBOARD)}
                        model={model}
                        apiKey={apiKey}
                    />
                )}

                {screen === ScreenState.HISTORY && (
                    <HistoryView
                        vault={vault}
                        onSelectScan={(s) => { setActiveScan(s); setScreen(ScreenState.REPORT); }}
                    />
                )}

                {screen === ScreenState.SETTINGS && (
                    <SettingsView
                        model={model}
                        setModel={setModel}
                        apiKey={apiKey}
                        setApiKey={setApiKey}
                        onClearVault={async () => { await clearVault(); refreshVault(); alert("Vault Cleared"); }}
                    />
                )}

                {screen === ScreenState.CODE_SCANNER && (
                    <CodeScannerView
                        onBack={() => setScreen(ScreenState.DASHBOARD)}
                        apiKey={apiKey}
                    />
                )}

                {screen === ScreenState.PROJECTS && (
                    <ProjectsView
                        onBack={() => setScreen(ScreenState.DASHBOARD)}
                    />
                )}

                {screen === ScreenState.ADVANCED_SCAN && (
                    <AdvancedScanView
                        onBack={() => setScreen(ScreenState.DASHBOARD)}
                    />
                )}

                {screen === ScreenState.SCA_SCAN && (
                    <SCAView
                        onBack={() => setScreen(ScreenState.DASHBOARD)}
                    />
                )}
            </main>

            {/* Navigation Rail */}
            <nav className="fixed bottom-0 inset-x-0 bg-white/90 backdrop-blur border-t border-slate-200 z-50 h-20 shadow-[0_-5px_20px_-5px_rgba(0,0,0,0.05)]">
                <div className="max-w-xl mx-auto flex justify-around items-center h-full">
                    {[
                        { id: ScreenState.DASHBOARD, icon: 'chart-line', label: 'Monitor' },
                        { id: ScreenState.CODE_SCANNER, icon: 'code', label: 'Code' },
                        { id: ScreenState.ADVANCED_SCAN, icon: 'rocket', label: 'Advanced' },
                        { id: ScreenState.SCA_SCAN, icon: 'cubes', label: 'SCA' },
                        { id: ScreenState.PROJECTS, icon: 'project-diagram', label: 'Projects' },
                        { id: ScreenState.HISTORY, icon: 'database', label: 'Vault' },
                        { id: ScreenState.SETTINGS, icon: 'sliders-h', label: 'Config' },
                    ].map(item => (
                        <button
                            key={item.id}
                            onClick={() => setScreen(item.id)}
                            className={`flex flex-col items-center gap-1 w-20 py-2 rounded-xl transition-all ${screen === item.id ? 'text-indigo-600 bg-indigo-50 scale-110' : 'text-slate-400 hover:text-slate-600'}`}
                        >
                            <i className={`fas fa-${item.icon} text-lg`}></i>
                            <span className="text-[9px] font-bold uppercase tracking-wider">{item.label}</span>
                        </button>
                    ))}
                </div>
            </nav>
        </div>
    );
};

export default App;