import { GRADE_ORDER, gradeRank, gradeColor } from '../../detectors/gradeScale';

function gradeToPercent(grade: string): number {
  return ((gradeRank(grade) + 1) / GRADE_ORDER.length) * 100;
}

export default function GradeRing({ grade }: { grade: string }) {
  const color = gradeColor(grade);
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
