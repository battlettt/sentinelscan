import { Finding } from './types';

export interface ScriptRef {
  url: string;
  isCrossOrigin: boolean;
  hasIntegrity: boolean;
}

export function analyzeSupplyChain(scripts: ScriptRef[]): Finding[] {
  const unprotected = scripts.filter((s) => s.isCrossOrigin && !s.hasIntegrity);
  if (unprotected.length === 0) return [];

  return [
    {
      id: 'missing-sri',
      title: `${unprotected.length} cross-origin script(s) with no Subresource Integrity check`,
      description:
        'These scripts are loaded from another origin with no cryptographic hash to verify they were not tampered with. This is the exact gap exploited in supply-chain attacks like the 2018 British Airways breach, where a compromised third-party script was silently modified to skim payment data.',
      severity: 'medium',
      category: 'supply-chain',
    },
  ];
}
