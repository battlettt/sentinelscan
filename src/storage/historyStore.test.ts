import { describe, it, expect } from 'vitest';
import { HistoryStore, KeyValueStorage } from './historyStore';
import { ScanSnapshot } from '../detectors/types';

class InMemoryStorage implements KeyValueStorage {
  private map = new Map<string, unknown>();
  async get(key: string) {
    return this.map.get(key);
  }
  async set(key: string, value: unknown) {
    this.map.set(key, value);
  }
}

function snapshot(domain: string, timestamp: number, grade = 'A'): ScanSnapshot {
  return {
    domain,
    timestamp,
    headerFlags: {},
    cookieFlags: { secure: true, sameSite: true },
    secretsCount: 0,
    grade,
  };
}

describe('HistoryStore', () => {
  it('returns an empty history for a domain with no scans', async () => {
    const store = new HistoryStore(new InMemoryStorage());
    expect(await store.getHistory('example.com')).toEqual([]);
    expect(await store.getLatest('example.com')).toBeNull();
  });

  it('appends a snapshot and returns it as the latest', async () => {
    const store = new HistoryStore(new InMemoryStorage());
    await store.appendSnapshot('example.com', snapshot('example.com', 1000));
    const latest = await store.getLatest('example.com');
    expect(latest?.timestamp).toBe(1000);
  });

  it('trims history beyond 20 entries per domain', async () => {
    const store = new HistoryStore(new InMemoryStorage());
    for (let i = 0; i < 25; i++) {
      await store.appendSnapshot('example.com', snapshot('example.com', i));
    }
    const history = await store.getHistory('example.com');
    expect(history).toHaveLength(20);
    expect(history[0].timestamp).toBe(5);
    expect(history[19].timestamp).toBe(24);
  });
});
