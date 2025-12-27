import { ScanResult } from '../types';

const DB_NAME = 'AegisVault';
const STORE_NAME = 'scans';
const VERSION = 1;

export const initDB = (): Promise<IDBDatabase> => {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, VERSION);
        request.onupgradeneeded = (e) => {
            const db = (e.target as IDBOpenDBRequest).result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
            }
        };
        request.onsuccess = (e) => resolve((e.target as IDBOpenDBRequest).result);
        request.onerror = (e) => reject((e.target as IDBOpenDBRequest).error);
    });
};

export const saveScanToVault = async (scan: ScanResult): Promise<number> => {
    const db = await initDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const request = store.add(scan);
        request.onsuccess = () => resolve(request.result as number);
        request.onerror = () => reject(request.error);
    });
};

export const getAllScans = async (): Promise<ScanResult[]> => {
    const db = await initDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const request = store.getAll();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
};

export const getScanById = async (id: number): Promise<ScanResult | undefined> => {
    const db = await initDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const store = tx.objectStore(STORE_NAME);
        const request = store.get(id);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
};

export const clearVault = async (): Promise<void> => {
    const db = await initDB();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const request = store.clear();
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
};
