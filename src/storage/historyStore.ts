import { ScanSnapshot } from '../detectors/types';

export interface KeyValueStorage {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown): Promise<void>;
}

export class ChromeLocalStorage implements KeyValueStorage {
  get(key: string): Promise<unknown> {
    return new Promise((resolve) => {
      chrome.storage.local.get([key], (result) => resolve(result[key]));
    });
  }
  set(key: string, value: unknown): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [key]: value }, () => resolve());
    });
  }
}

const MAX_HISTORY_PER_DOMAIN = 20;

export class HistoryStore {
  constructor(private storage: KeyValueStorage) {}

  private keyFor(domain: string): string {
    return `history:${domain}`;
  }

  async getHistory(domain: string): Promise<ScanSnapshot[]> {
    const raw = await this.storage.get(this.keyFor(domain));
    return Array.isArray(raw) ? (raw as ScanSnapshot[]) : [];
  }

  async getLatest(domain: string): Promise<ScanSnapshot | null> {
    const history = await this.getHistory(domain);
    return history.length > 0 ? history[history.length - 1] : null;
  }

  async appendSnapshot(domain: string, snapshot: ScanSnapshot): Promise<void> {
    const history = await this.getHistory(domain);
    history.push(snapshot);
    while (history.length > MAX_HISTORY_PER_DOMAIN) history.shift();
    await this.storage.set(this.keyFor(domain), history);
  }
}
