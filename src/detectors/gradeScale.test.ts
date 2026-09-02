import { describe, it, expect } from 'vitest';
import { gradeRank, rankToGrade, GRADE_ORDER } from './gradeScale';

describe('gradeRank', () => {
  it('ranks F as lowest and A+ as highest', () => {
    expect(gradeRank('F')).toBe(0);
    expect(gradeRank('A+')).toBe(GRADE_ORDER.length - 1);
  });

  it('treats an unrecognized grade as the lowest rank', () => {
    expect(gradeRank('Z')).toBe(0);
  });
});

describe('rankToGrade', () => {
  it('round-trips every rank back to its grade', () => {
    GRADE_ORDER.forEach((grade, rank) => {
      expect(rankToGrade(rank)).toBe(grade);
    });
  });

  it('rounds a fractional rank to the nearest grade', () => {
    expect(rankToGrade(3.6)).toBe(GRADE_ORDER[4]);
  });

  it('clamps out-of-range ranks instead of throwing', () => {
    expect(rankToGrade(-5)).toBe('F');
    expect(rankToGrade(99)).toBe('A+');
  });
});
