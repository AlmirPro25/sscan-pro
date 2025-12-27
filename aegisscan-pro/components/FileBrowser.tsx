import React, { useState, useEffect } from 'react';

interface FileInfo {
    name: string;
    path: string;
    is_dir: boolean;
    size: number;
    modified: string;
    children?: number;
}

interface BrowseResponse {
    current_path: string;
    parent_path: string;
    items: FileInfo[];
    drives: string[];
}

interface Props {
    onSelect: (path: string) => void;
    onClose: () => void;
}

export const FileBrowser: React.FC<Props> = ({ onSelect, onClose }) => {
    const [currentPath, setCurrentPath] = useState('');
    const [items, setItems] = useState<FileInfo[]>([]);
    const [drives, setDrives] = useState<string[]>([]);
    const [parentPath, setParentPath] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [recentPaths, setRecentPaths] = useState<string[]>([]);
    const [showRecent, setShowRecent] = useState(true);

    useEffect(() => {
        loadDirectory('');
        loadRecentPaths();
    }, []);

    const loadDirectory = async (path: string) => {
        setLoading(true);
        setError(null);
        setShowRecent(false);

        try {
            const url = path 
                ? `http://localhost:8080/api/v1/browse?path=${encodeURIComponent(path)}`
                : 'http://localhost:8080/api/v1/browse';
            
            const response = await fetch(url);
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Failed to browse directory');
            }

            const data: BrowseResponse = await response.json();
            setCurrentPath(data.current_path);
            setParentPath(data.parent_path);
            setItems(data.items);
            setDrives(data.drives);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    const loadRecentPaths = async () => {
        try {
            const response = await fetch('http://localhost:8080/api/v1/browse/recent');
            if (response.ok) {
                const data = await response.json();
                setRecentPaths(data.paths || []);
            }
        } catch (e) {
            console.error('Failed to load recent paths');
        }
    };

    const handleItemClick = (item: FileInfo) => {
        if (item.is_dir && item.children !== -1) {
            loadDirectory(item.path);
        }
    };

    const handleSelectFolder = () => {
        if (currentPath) {
            onSelect(currentPath);
        }
    };

    const formatSize = (bytes: number) => {
        if (bytes === 0) return '-';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    };

    return (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-3xl max-h-[80vh] flex flex-col">
                {/* Header */}
                <div className="flex items-center justify-between p-4 border-b border-slate-200">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-indigo-100 rounded-xl flex items-center justify-center">
                            <i className="fas fa-folder-open text-indigo-600"></i>
                        </div>
                        <div>
                            <h2 className="font-bold text-slate-900">Selecionar Pasta</h2>
                            <p className="text-xs text-slate-500">Navegue até a pasta do projeto</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="p-2 hover:bg-slate-100 rounded-lg">
                        <i className="fas fa-times text-slate-500"></i>
                    </button>
                </div>

                {/* Breadcrumb / Path */}
                <div className="px-4 py-3 bg-slate-50 border-b border-slate-200">
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => { setShowRecent(true); setCurrentPath(''); }}
                            className="px-3 py-1.5 text-sm bg-white border border-slate-200 rounded-lg hover:bg-slate-50 flex items-center gap-2"
                        >
                            <i className="fas fa-home text-slate-400"></i>
                            Início
                        </button>
                        
                        {parentPath && (
                            <button
                                onClick={() => loadDirectory(parentPath)}
                                className="px-3 py-1.5 text-sm bg-white border border-slate-200 rounded-lg hover:bg-slate-50 flex items-center gap-2"
                            >
                                <i className="fas fa-arrow-up text-slate-400"></i>
                                Voltar
                            </button>
                        )}
                        
                        <div className="flex-1 px-3 py-1.5 bg-white border border-slate-200 rounded-lg font-mono text-sm text-slate-600 truncate">
                            {currentPath || 'Selecione um drive ou pasta recente'}
                        </div>
                    </div>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-4">
                    {loading ? (
                        <div className="flex items-center justify-center py-12">
                            <i className="fas fa-spinner fa-spin text-2xl text-indigo-500"></i>
                        </div>
                    ) : error ? (
                        <div className="text-center py-12 text-red-500">
                            <i className="fas fa-exclamation-circle text-3xl mb-3"></i>
                            <p>{error}</p>
                        </div>
                    ) : showRecent ? (
                        <div className="space-y-6">
                            {/* Drives */}
                            <div>
                                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
                                    Drives Disponíveis
                                </h3>
                                <div className="grid grid-cols-4 gap-3">
                                    {drives.map(drive => (
                                        <button
                                            key={drive}
                                            onClick={() => loadDirectory(drive)}
                                            className="p-4 bg-slate-50 border border-slate-200 rounded-xl hover:bg-indigo-50 hover:border-indigo-300 transition-colors text-center"
                                        >
                                            <i className="fas fa-hdd text-2xl text-slate-400 mb-2"></i>
                                            <div className="font-mono font-bold text-slate-700">{drive}</div>
                                        </button>
                                    ))}
                                </div>
                            </div>

                            {/* Recent Paths */}
                            {recentPaths.length > 0 && (
                                <div>
                                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
                                        <i className="fas fa-history mr-2"></i>
                                        Pastas Recentes
                                    </h3>
                                    <div className="space-y-2">
                                        {recentPaths.map((path, idx) => (
                                            <button
                                                key={idx}
                                                onClick={() => onSelect(path)}
                                                className="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl hover:bg-indigo-50 hover:border-indigo-300 transition-colors text-left flex items-center gap-3"
                                            >
                                                <i className="fas fa-folder text-yellow-500"></i>
                                                <span className="font-mono text-sm text-slate-700 truncate">{path}</span>
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : (
                        <div className="space-y-1">
                            {items.length === 0 ? (
                                <div className="text-center py-12 text-slate-400">
                                    <i className="fas fa-folder-open text-4xl mb-3"></i>
                                    <p>Pasta vazia</p>
                                </div>
                            ) : (
                                items.map((item, idx) => (
                                    <div
                                        key={idx}
                                        onClick={() => handleItemClick(item)}
                                        className={`flex items-center gap-3 p-3 rounded-lg transition-colors ${
                                            item.is_dir && item.children !== -1
                                                ? 'hover:bg-indigo-50 cursor-pointer'
                                                : item.children === -1
                                                ? 'opacity-50 cursor-not-allowed'
                                                : 'opacity-60'
                                        }`}
                                    >
                                        <i className={`fas ${
                                            item.is_dir 
                                                ? item.children === -1 
                                                    ? 'fa-folder-minus text-slate-400' 
                                                    : 'fa-folder text-yellow-500'
                                                : 'fa-file text-slate-400'
                                        } text-lg`}></i>
                                        <div className="flex-1 min-w-0">
                                            <div className="font-medium text-slate-700 truncate">{item.name}</div>
                                            {item.is_dir && item.children !== -1 && (
                                                <div className="text-xs text-slate-400">{item.children} itens</div>
                                            )}
                                            {item.children === -1 && (
                                                <div className="text-xs text-slate-400">Ignorado (node_modules, etc)</div>
                                            )}
                                        </div>
                                        {!item.is_dir && (
                                            <div className="text-xs text-slate-400">{formatSize(item.size)}</div>
                                        )}
                                        <div className="text-xs text-slate-400">{item.modified}</div>
                                    </div>
                                ))
                            )}
                        </div>
                    )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between p-4 border-t border-slate-200 bg-slate-50">
                    <div className="text-sm text-slate-500">
                        {currentPath && (
                            <span className="font-mono">{items.filter(i => i.is_dir).length} pastas, {items.filter(i => !i.is_dir).length} arquivos</span>
                        )}
                    </div>
                    <div className="flex gap-3">
                        <button
                            onClick={onClose}
                            className="px-4 py-2 text-slate-600 hover:bg-slate-200 rounded-lg transition-colors"
                        >
                            Cancelar
                        </button>
                        <button
                            onClick={handleSelectFolder}
                            disabled={!currentPath}
                            className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                        >
                            <i className="fas fa-check"></i>
                            Selecionar Esta Pasta
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};
