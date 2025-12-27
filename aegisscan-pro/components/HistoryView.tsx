import React, { useState } from 'react';
import { ScanResult } from '../types';
import { apiService } from '../services/apiService';

interface HistoryViewProps {
    vault: ScanResult[];
    onSelectScan: (scan: ScanResult) => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({ vault, onSelectScan }) => {
    const [compareMode, setCompareMode] = useState(false);
    const [selectedForCompare, setSelectedForCompare] = useState<number[]>([]);
    const [comparisonData, setComparisonData] = useState<any>(null);

    const handleCompareToggle = () => {
        setCompareMode(!compareMode);
        setSelectedForCompare([]);
        setComparisonData(null);
    };

    const handleSelectForCompare = (id: number) => {
        if (selectedForCompare.includes(id)) {
            setSelectedForCompare(prev => prev.filter(i => i !== id));
        } else if (selectedForCompare.length < 2) {
            setSelectedForCompare(prev => [...prev, id]);
        }
    };

    const executeComparison = async () => {
        if (selectedForCompare.length !== 2) return;
        try {
            const data = await apiService.compareScans(selectedForCompare[0], selectedForCompare[1]);
            setComparisonData(data);
        } catch (e) {
            console.error(e);
            alert("Comparison failed or data unavailable");
        }
    };

    return (
        <div className="animate-[fadeIn_0.5s_ease-out] space-y-8">
            <div className="flex flex-col md:flex-row justify-between items-end gap-4 border-b border-slate-200 pb-6">
                <div>
                    <h2 className="text-3xl font-black text-slate-900 uppercase tracking-tight mb-2">Scan Vault</h2>
                    <p className="text-sm text-slate-500 font-medium">Secure storage of all previous reconnaissance missions.</p>
                </div>
                <button
                    onClick={handleCompareToggle}
                    className={`px-6 py-3 rounded-xl font-black text-[10px] uppercase tracking-[0.2em] transition-all shadow-sm ${compareMode ? 'bg-red-500 text-white' : 'glass-btn text-slate-700'}`}
                >
                    {compareMode ? 'Abort Comparison' : 'Initialize Compare'}
                </button>
            </div>

            {/* Comparison Modal */}
            {comparisonData && (
                <div className="fixed inset-0 z-[200] bg-slate-900/40 backdrop-blur-md flex items-center justify-center p-4">
                    <div className="bg-white/90 backdrop-blur-xl rounded-3xl shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden border border-white/50 flex flex-col">
                        <div className="flex justify-between items-center p-8 border-b border-slate-100 bg-white/50">
                            <div>
                                <h3 className="text-xl font-black text-slate-900 uppercase tracking-tight">Differential Analysis</h3>
                                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">Comparing Scan Signatures</p>
                            </div>
                            <button onClick={() => setComparisonData(null)} className="w-10 h-10 rounded-full bg-slate-100 flex items-center justify-center hover:bg-slate-200 transition-all">
                                <i className="fas fa-times text-slate-500"></i>
                            </button>
                        </div>

                        <div className="p-10 flex-1 overflow-y-auto">
                            <div className="grid grid-cols-2 gap-8 mb-10">
                                <div className="text-center p-8 bg-slate-50 rounded-2xl border border-slate-200 shadow-inner">
                                    <div className="text-[9px] font-black text-slate-400 uppercase tracking-[0.3em] mb-4">Baseline Scan</div>
                                    <div className="text-5xl font-black text-slate-700 mb-4 data-value">{comparisonData.scan1.score}</div>
                                    <div className="text-[10px] text-slate-500 font-mono truncate px-4">{comparisonData.scan1.target}</div>
                                </div>

                                <div className="text-center p-8 bg-indigo-600 rounded-2xl shadow-xl relative overflow-hidden text-white">
                                    <div className="absolute inset-0 bg-gradient-to-br from-indigo-500 to-purple-600 opacity-50"></div>
                                    <div className="relative z-10">
                                        <div className="text-[9px] font-black text-indigo-200 uppercase tracking-[0.3em] mb-4">Latest Scan</div>
                                        <div className="text-5xl font-black mb-4 data-value">{comparisonData.scan2.score}</div>
                                        <div className="text-[10px] text-indigo-100 font-mono truncate px-4">{comparisonData.scan2.target}</div>
                                    </div>
                                </div>
                            </div>

                            <div className={`p-8 rounded-2xl border-2 flex items-center gap-6 ${comparisonData.diff.score_change >= 0 ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-red-50 border-red-200 text-red-800'}`}>
                                <div className={`w-16 h-16 rounded-2xl flex items-center justify-center text-2xl shadow-lg ${comparisonData.diff.score_change >= 0 ? 'bg-emerald-500 text-white' : 'bg-red-500 text-white'}`}>
                                    <i className={`fas fa-${comparisonData.diff.score_change >= 0 ? 'shield-check' : 'shield-exclamation'}`}></i>
                                </div>
                                <div className="flex-1">
                                    <div className="font-black text-2xl uppercase tracking-tight mb-1">{comparisonData.diff.score_change >= 0 ? 'Optimization detected' : 'Degradation detected'}</div>
                                    <div className="text-sm font-medium opacity-80">
                                        Relative score delta: <span className="font-black px-2 py-0.5 bg-white/50 rounded">{comparisonData.diff.score_change > 0 ? '+' : ''}{comparisonData.diff.score_change}</span>
                                        over a period of {Math.round(comparisonData.diff.time_between / (1000 * 60 * 60 * 24))} days.
                                    </div>
                                </div>
                                <div className="text-right">
                                    <div className="text-[10px] font-black uppercase tracking-widest opacity-40 mb-1">Status</div>
                                    <div className="text-xs font-black uppercase tracking-tighter">{comparisonData.diff.score_change >= 0 ? 'SYSTEM_STABLE' : 'ACTION_REQUIRED'}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            <div className="grid grid-cols-1 gap-4">
                {vault.map(s => {
                    const isSelected = selectedForCompare.includes(s.id!);
                    return (
                        <div key={s.id}
                            onClick={() => compareMode ? handleSelectForCompare(s.id!) : onSelectScan(s)}
                            className={`group cyber-card flex items-center justify-between p-6 rounded-2xl cursor-pointer transition-all ${isSelected ? 'border-primary ring-2 ring-primary/20 bg-indigo-50/30' : 'border-slate-200 hover:border-indigo-300'}`}
                        >
                            <div className="flex items-center gap-6">
                                {compareMode && (
                                    <div className={`w-6 h-6 rounded-lg border-2 flex items-center justify-center transition-all ${isSelected ? 'bg-primary border-primary text-white scale-110 shadow-lg' : 'border-slate-300 bg-white'}`}>
                                        {isSelected && <i className="fas fa-check text-[10px]"></i>}
                                    </div>
                                )}
                                <div className={`w-16 h-16 rounded-xl flex items-center justify-center font-black text-2xl data-value shadow-sm ${s.score >= 80 ? 'bg-emerald-50 text-emerald-600 border border-emerald-100' : s.score >= 50 ? 'bg-amber-50 text-amber-600 border border-amber-100' : 'bg-red-50 text-red-600 border border-red-100'}`}>
                                    {s.score}
                                </div>
                                <div>
                                    <div className="font-black text-slate-800 text-lg tracking-tight truncate w-64 md:w-auto">{s.target}</div>
                                    <div className="flex items-center gap-3 mt-1.5">
                                        <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest bg-slate-50 px-2 py-0.5 rounded border border-slate-100">ID: #{s.id}</span>
                                        <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">{new Date(s.timestamp).toLocaleDateString()}</span>
                                        <span className="text-[9px] font-black text-indigo-500 uppercase tracking-widest">{s.endpoints.length} ENTS</span>
                                    </div>
                                </div>
                            </div>
                            <div className="flex items-center gap-4">
                                {!compareMode && <i className="fas fa-chevron-right text-slate-300 group-hover:text-indigo-500 transition-all group-hover:translate-x-1"></i>}
                                {isSelected && <span className="text-[9px] font-black text-indigo-600 uppercase tracking-widest animate-pulse">Selected</span>}
                            </div>
                        </div>
                    );
                })}

                {vault.length === 0 && (
                    <div className="py-20 text-center cyber-card rounded-2xl border-dashed border-2 border-slate-200">
                        <div className="w-16 h-16 bg-slate-50 text-slate-300 rounded-full flex items-center justify-center mx-auto mb-4">
                            <i className="fas fa-database text-2xl"></i>
                        </div>
                        <h3 className="text-lg font-black text-slate-900 uppercase mb-1">Vault Empty</h3>
                        <p className="text-xs text-slate-400 font-bold uppercase tracking-widest">No Reconnaissance Data Found</p>
                    </div>
                )}
            </div>

            {compareMode && selectedForCompare.length === 2 && (
                <div className="fixed bottom-24 left-1/2 -translate-x-1/2 z-[100] animate-[fadeIn_0.3s_ease-out]">
                    <button
                        onClick={executeComparison}
                        className="bg-slate-900 text-white px-10 py-4 rounded-2xl shadow-2xl font-black text-[10px] uppercase tracking-[0.2em] hover:bg-primary transition-all active:scale-95 flex items-center gap-3"
                    >
                        <i className="fas fa-bolt animate-pulse"></i> Analyze Differences
                    </button>
                </div>
            )}
        </div>
    );
};