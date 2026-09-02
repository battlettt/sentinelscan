export const GRADE_ORDER = ['F', 'D', 'C', 'B-', 'B', 'B+', 'A', 'A+'];

export const GRADE_COLORS: Record<string, string> = {
  'A+': '#22C55E',
  A: '#22C55E',
  'B+': '#84CC16',
  B: '#F59E0B',
  'B-': '#F59E0B',
  C: '#F97316',
  D: '#EF4444',
  F: '#EF4444',
};

export function gradeColor(grade: string): string {
  return GRADE_COLORS[grade] ?? '#94A3B8';
}

export function gradeRank(grade: string): number {
  const idx = GRADE_ORDER.indexOf(grade);
  return idx === -1 ? 0 : idx;
}

export function rankToGrade(rank: number): string {
  const idx = Math.max(0, Math.min(GRADE_ORDER.length - 1, Math.round(rank)));
  return GRADE_ORDER[idx];
}
