import { Finding } from './types';

interface AttackMapping {
  techniqueId: string;
  techniqueName: string;
}

const FINDING_TO_ATTACK: Record<string, AttackMapping> = {
  'missing-csp': { techniqueId: 'T1189', techniqueName: 'Drive-by Compromise' },
  'weak-csp': { techniqueId: 'T1189', techniqueName: 'Drive-by Compromise' },
  'missing-content-type-options': { techniqueId: 'T1189', techniqueName: 'Drive-by Compromise' },
  'missing-hsts': { techniqueId: 'T1557', techniqueName: 'Adversary-in-the-Middle' },
  'mixed-content': { techniqueId: 'T1557', techniqueName: 'Adversary-in-the-Middle' },
  'missing-frame-protection': { techniqueId: 'T1185', techniqueName: 'Browser Session Hijacking' },
  'cookie-missing-samesite': { techniqueId: 'T1185', techniqueName: 'Browser Session Hijacking' },
  'missing-sri': { techniqueId: 'T1195', techniqueName: 'Supply Chain Compromise' },
};

export function applyAttackMappings(findings: Finding[]): Finding[] {
  return findings.map((f) => {
    const mapping = FINDING_TO_ATTACK[f.id];
    return mapping ? { ...f, attackTechniqueId: mapping.techniqueId, attackTechniqueName: mapping.techniqueName } : f;
  });
}
