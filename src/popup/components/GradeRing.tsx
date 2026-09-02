const GRADE_COLORS: Record<string, string> = {
  'A+': '#22C55E',
  A: '#22C55E',
  'B+': '#84CC16',
  B: '#F59E0B',
  'B-': '#F59E0B',
  C: '#F97316',
  D: '#EF4444',
  F: '#EF4444',
};

const GRADE_ORDER = ['F', 'D', 'C', 'B-', 'B', 'B+', 'A', 'A+'];

function gradeToPercent(grade: string): number {
  const idx = GRADE_ORDER.indexOf(grade);
  return idx === -1 ? 0 : ((idx + 1) / GRADE_ORDER.length) * 100;
}

export default function GradeRing({ grade }: { grade: string }) {
  const color = GRADE_COLORS[grade] ?? '#94A3B8';
  const percent = gradeToPercent(grade);
  const circumference = 2 * Math.PI * 16;
  const dash = (percent / 100) * circumference;

  return (
    <div className="grade-ring">
      <svg viewBox="0 0 36 36" width="46" height="46">
        <circle cx="18" cy="18" r="16" fill="none" stroke="#272F42" strokeWidth="3" />
        <circle
          cx="18"
          cy="18"
          r="16"
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
          transform="rotate(-90 18 18)"
        />
      </svg>
      <span className="grade-ring-label" style={{ color }}>
        {grade}
      </span>
    </div>
  );
}
