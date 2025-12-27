import React, { useState } from 'react';
import { ScanResult } from '../types';

interface AssetExplorerProps {
    scan: ScanResult;
}

type AssetTab = 'video' | 'image' | 'doc';

import Hls from 'hls.js';

interface VideoPlayerProps {
    url: string;
}

const VideoPlayer: React.FC<VideoPlayerProps> = ({ url }) => {
    const videoRef = React.useRef<HTMLVideoElement>(null);

    React.useEffect(() => {
        if (!videoRef.current) return;
        const video = videoRef.current;

        if (url.includes('.m3u8')) {
            if (Hls.isSupported()) {
                const hls = new Hls();
                hls.loadSource(url);
                hls.attachMedia(video);
                return () => hls.destroy();
            } else if (video.canPlayType('application/vnd.apple.mpegurl')) {
                video.src = url;
            }
        } else {
            video.src = url;
        }
    }, [url]);

    return <video ref={videoRef} controls className="w-full h-full bg-black" crossOrigin="anonymous" />;
};

export const AssetExplorer: React.FC<AssetExplorerProps> = ({ scan }) => {
    const [activeTab, setActiveTab] = useState<AssetTab>('video');

    const videos = scan.media?.streams || [];
    const images = [...new Set([
        ...(scan.assets?.images?.map(i => i.url) || []),
        ...(scan.dom_images?.map(i => i.src) || [])
    ])];
    const docs = [
        ...(scan.assets?.documents || []),
        ...(scan.assets?.fonts || []).map(f => ({ type: 'FONT', url: f }))
    ];

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-xl h-[650px] flex flex-col">
            {/* Header Tabs */}
            <div className="flex bg-slate-50/50 p-1">
                {[
                    { id: 'video', label: 'Streams', count: videos.length, icon: 'film', color: 'indigo' },
                    { id: 'image', label: 'Gallery', count: images.length, icon: 'images', color: 'emerald' },
                    { id: 'doc', label: 'Assets', count: docs.length, icon: 'file-contract', color: 'amber' },
                ].map(t => (
                    <button
                        key={t.id}
                        onClick={() => setActiveTab(t.id as AssetTab)}
                        className={`flex-1 py-3 px-4 rounded-xl text-[10px] font-black uppercase tracking-[0.15em] transition-all flex items-center justify-center gap-2 ${activeTab === t.id ? `bg-white text-${t.color}-600 shadow-sm border border-slate-200` : 'text-slate-400 hover:text-slate-600'}`}
                    >
                        <i className={`fas fa-${t.icon}`}></i> {t.label} <span className="opacity-40">{t.count}</span>
                    </button>
                ))}
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-y-auto p-6 custom-scroll">

                {/* VIDEO TAB */}
                {activeTab === 'video' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {videos.length === 0 ? (
                            <div className="col-span-full flex flex-col items-center justify-center h-full text-slate-400 opacity-60">
                                <i className="fas fa-video-slash text-4xl mb-4"></i>
                                <span className="text-[10px] font-bold uppercase tracking-widest">No Active Streams Detected</span>
                            </div>
                        ) : (
                            videos.map((v, i) => (
                                <div key={i} className="cyber-card rounded-2xl overflow-hidden shadow-sm group border border-slate-200">
                                    <div className="p-3 bg-slate-50 border-b border-slate-100 flex justify-between items-center">
                                        <div className="flex items-center gap-2 min-w-0">
                                            <span className="px-2 py-1 bg-indigo-500 text-white rounded text-[8px] font-black uppercase tracking-tighter">LIVE</span>
                                            <span className="text-[10px] font-mono text-slate-500 truncate">{v.url}</span>
                                        </div>
                                        <button onClick={() => copyToClipboard(v.url)} className="text-slate-400 hover:text-indigo-600 p-1"><i className="fas fa-copy"></i></button>
                                    </div>
                                    <div className="aspect-video bg-black relative group">
                                        <VideoPlayer url={v.url} />
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                )}


                {/* IMAGE TAB */}
                {activeTab === 'image' && (
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                        {images.length === 0 ? (
                            <div className="col-span-full flex flex-col items-center justify-center h-64 text-slate-400 opacity-60">
                                <i className="fas fa-image text-4xl mb-4"></i>
                                <span className="text-[10px] font-bold uppercase tracking-widest">No Images Scraped</span>
                            </div>
                        ) : (
                            images.map((img, i) => (
                                <div key={i} className="aspect-square bg-slate-100 rounded-2xl overflow-hidden relative group border border-slate-200 cyber-card shadow-sm">
                                    <div className="absolute inset-0 flex items-center justify-center bg-slate-50">
                                        <i className="fas fa-image text-slate-200 text-3xl"></i>
                                    </div>
                                    <img
                                        src={img}
                                        alt={`Asset ${i}`}
                                        className="w-full h-full object-cover relative z-10 transition-transform duration-500 group-hover:scale-110"
                                        loading="lazy"
                                        onError={(e) => { (e.target as HTMLImageElement).style.visibility = 'hidden'; }}
                                    />
                                    <div className="absolute inset-0 bg-slate-900/60 opacity-0 group-hover:opacity-100 transition-opacity flex flex-col items-center justify-center gap-2 z-20 backdrop-blur-[2px]">
                                        <a href={img} target="_blank" className="bg-white text-slate-900 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase hover:bg-indigo-500 hover:text-white transition-all">Open</a>
                                        <button onClick={() => copyToClipboard(img)} className="bg-slate-800 text-white px-3 py-1.5 rounded-lg text-[10px] font-black uppercase hover:bg-slate-700 transition-all">Copy</button>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                )}

                {/* DOCS TAB */}
                {activeTab === 'doc' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {docs.length === 0 ? (
                            <div className="col-span-full flex flex-col items-center justify-center h-64 text-slate-400 opacity-60">
                                <i className="fas fa-folder-open text-4xl mb-4"></i>
                                <span className="text-[10px] font-bold uppercase tracking-widest">No Documents detected</span>
                            </div>
                        ) : (
                            docs.map((d: any, i) => (
                                <div key={i} className="flex items-center justify-between p-4 bg-white rounded-2xl border border-slate-200 hover:border-amber-400 transition-all shadow-sm cyber-card">
                                    <div className="flex items-center gap-4 overflow-hidden">
                                        <div className="w-10 h-10 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center flex-shrink-0 border border-amber-100">
                                            <i className={`fas fa-${typeof d === 'string' ? 'font' : 'file-alt'} text-lg`}></i>
                                        </div>
                                        <div className="min-w-0">
                                            <div className="text-xs font-black text-slate-800 truncate">{typeof d === 'string' ? d.split('/').pop() : d.url.split('/').pop()}</div>
                                            <div className="text-[9px] text-slate-400 font-black uppercase tracking-widest mt-0.5">{typeof d === 'string' ? 'FONT' : d.type}</div>
                                        </div>
                                    </div>
                                    <a href={typeof d === 'string' ? d : d.url} target="_blank" className="w-8 h-8 rounded-lg bg-slate-100 text-slate-400 flex items-center justify-center hover:bg-amber-100 hover:text-amber-600 transition-all"><i className="fas fa-external-link-alt text-xs"></i></a>
                                </div>
                            ))
                        )}
                    </div>
                )}
            </div>
        </div>
    );
};