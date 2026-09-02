import { describe, it, expect } from 'vitest';
import { applyAttackMappings } from './attackMapper';
import { Finding } from './types';

function baseFinding(id: string): Finding {
  return { id, title: 't', description: 'd', severity: 'medium', category: 'header' };
}

describe('applyAttackMappings', () => {
  it('attaches a technique to a known finding id', () => {
    const [result] = applyAttackMappings([baseFinding('missing-csp')]);
    expect(result.attackTechniqueId).toBe('T1189');
    expect(result.attackTechniqueName).toBe('Drive-by Compromise');
  });

  it('leaves an unmapped finding id unchanged', () => {
    const [result] = applyAttackMappings([baseFinding('missing-permissions-policy')]);
    expect(result.attackTechniqueId).toBeUndefined();
  });
});
