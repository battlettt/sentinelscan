export type Severity = 'high' | 'medium' | 'low' | 'info';
export type FindingCategory = 'header' | 'secret' | 'drift';

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: FindingCategory;
  attackTechniqueId?: string;
  attackTechniqueName?: string;
}

export interface ScanSnapshot {
  domain: string;
  timestamp: number;
  headerFlags: Record<string, boolean>;
  cookieFlags: { secure: boolean; sameSite: boolean };
  secretsCount: number;
  grade: string;
}

export interface ScanResult {
  domain: string;
  timestamp: number;
  grade: string;
  findings: Finding[];
  driftFindings: Finding[];
  scannedScriptCount: number;
  skippedScriptCount: number;
}
