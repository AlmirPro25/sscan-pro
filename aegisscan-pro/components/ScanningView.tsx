import React from 'react';

interface ScanningViewProps {
    progress: number;
    step: string;
}

export const ScanningView: React.FC<ScanningViewProps> = ({ progress, step }) => {
    return (
        <div className="h-[70vh] flex flex-col items-center justify-center relative cyber-card rounded-3xl shadow-2xl overflow-hidden">
            <div className="absolute inset-0 bg-slate-900/5 z-0"></div>
            <div className="absolute inset-0 bg-[radial-gradient(var(--primary)_1px,transparent_1px)] [background-size:20px_20px] opacity-10"></div>

            <div className="relative z-10 flex flex-col items-center w-full max-w-lg p-10">
                <div className="w-72 h-72 relative mb-12 flex items-center justify-center">
                    {/* Pulsing Rings */}
                    <div className="absolute inset-0 rounded-full border-2 border-indigo-500/20 animate-pulse-ring"></div>
                    <div className="absolute inset-4 rounded-full border-2 border-indigo-500/10 animate-pulse-ring [animation-delay:0.5s]"></div>

                    <svg className="w-full h-full transform -rotate-90 relative z-10">
                        <circle cx="144" cy="144" r="130" stroke="rgba(99, 102, 241, 0.1)" strokeWidth="12" fill="transparent" />
                        <circle
                            cx="144"
                            cy="144"
                            r="130"
                            stroke="url(#grad)"
                            strokeWidth="12"
                            fill="transparent"
                            strokeDasharray={816}
                            strokeDashoffset={816 - (816 * progress) / 100}
                            strokeLinecap="round"
                            className="transition-all duration-500 ease-out"
                        />
                        <defs>
                            <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" stopColor="#6366f1" />
                                <stop offset="100%" stopColor="#0891b2" />
                            </linearGradient>
                        </defs>
                    </svg>

                    <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
                        <span className="text-7xl font-black text-slate-900 data-value drop-shadow-sm">{progress}<span className="text-2xl opacity-50">%</span></span>
                        <div className="flex items-center gap-2 mt-2 px-3 py-1 bg-indigo-50 rounded-full border border-indigo-100 shadow-sm">
                            <i className="fas fa-circle-notch fa-spin text-indigo-500 text-[10px]"></i>
                            <span className="text-[10px] font-black text-indigo-600 uppercase tracking-widest">Scanning</span>
                        </div>
                    </div>
                </div>

                <div className="w-full bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-2xl relative">
                    <div className="absolute top-0 left-6 -translate-y-1/2 px-3 py-1 bg-slate-800 rounded-md border border-slate-700">
                        <div className="flex items-center gap-2 text-indigo-400 font-bold text-[9px] uppercase tracking-[0.2em]">
                            <i className="fas fa-terminal"></i> Aegis Kernel 2.1
                        </div>
                    </div>
                    <div className="text-xs font-mono text-emerald-400 flex flex-col gap-1 min-h-[60px] justify-center">
                        <div className="flex gap-2">
                            <span className="opacity-50">#</span>
                            <span className="animate-[pulse_1s_infinite]">{step}</span>
                        </div>
                        <div className="h-1.5 w-full bg-slate-800 mt-4 rounded-full overflow-hidden border border-slate-700/50">
                            <div className="h-full bg-indigo-500 shadow-[0_0_15px_rgba(99,102,241,0.5)] transition-all duration-500" style={{ width: `${progress}%` }}></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};