import React from 'react';

interface SettingsViewProps {
    model: string;
    setModel: (v: string) => void;
    apiKey: string;
    setApiKey: (v: string) => void;
    onClearVault: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ model, setModel, apiKey, setApiKey, onClearVault }) => {
    return (
        <div className="animate-[fadeIn_0.5s_ease-out] max-w-2xl mx-auto">
            <h2 className="text-3xl font-black text-slate-900 uppercase mb-8 pb-4 border-b border-slate-200">System Config</h2>
            
            <div className="bg-white rounded-2xl border border-slate-200 p-8 shadow-sm mb-6">
                <div className="flex items-center gap-3 mb-6">
                    <div className="w-10 h-10 rounded-full bg-indigo-50 text-indigo-600 flex items-center justify-center">
                        <i className="fas fa-brain"></i>
                    </div>
                    <div>
                        <h3 className="font-bold text-slate-900">AI Neural Engine</h3>
                        <p className="text-xs text-slate-500">Configure LLM parameters for analysis.</p>
                    </div>
                </div>
                
                <div className="space-y-4">
                    <div>
                        <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Model</label>
                        <select 
                            value={model}
                            onChange={(e) => { setModel(e.target.value); localStorage.setItem('aegis_model', e.target.value); }}
                            className="w-full bg-slate-50 border border-slate-200 rounded-lg px-4 py-3 text-sm font-bold text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                        >
                            <option value="models/gemini-3-flash-preview">Gemini 3 Flash (Recommended)</option>
                            <option value="models/gemini-robotics-er-1.5-preview">Gemini Robotics ER 1.5</option>
                        </select>
                    </div>
                    <div>
                        <label className="block text-xs font-bold text-slate-500 uppercase mb-2">API Key</label>
                        <input 
                            type="password"
                            value={apiKey}
                            onChange={(e) => { setApiKey(e.target.value); localStorage.setItem('aegis_key', e.target.value); }}
                            className="w-full bg-slate-50 border border-slate-200 rounded-lg px-4 py-3 text-sm font-mono text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
                            placeholder="AIzaSy..."
                        />
                    </div>
                </div>
            </div>

            <div className="bg-red-50 rounded-2xl border border-red-100 p-8">
                <h3 className="font-bold text-red-900 mb-2">Danger Zone</h3>
                <p className="text-xs text-red-700 mb-6">Irreversible actions regarding local data persistence.</p>
                <button 
                    onClick={() => { if(confirm("Are you sure? This will wipe all scan history.")) onClearVault(); }}
                    className="w-full bg-white border border-red-200 text-red-600 py-3 rounded-lg font-bold text-xs uppercase tracking-widest hover:bg-red-600 hover:text-white transition-all"
                >
                    <i className="fas fa-trash-alt mr-2"></i> Wipe Local Vault
                </button>
            </div>
        </div>
    );
};