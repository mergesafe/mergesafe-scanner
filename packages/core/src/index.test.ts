import { describe, expect, test } from 'vitest';
import { AVAILABLE_ENGINES, DEFAULT_ENGINES } from './index.js';

describe('engine constants', () => {
  test('DEFAULT_ENGINES remains the canonical default engine set', () => {
    expect(DEFAULT_ENGINES).toEqual(['mergesafe', 'semgrep', 'gitleaks', 'cisco', 'osv']);
  });

  test('DEFAULT_ENGINES is a subset of AVAILABLE_ENGINES', () => {
    for (const engine of DEFAULT_ENGINES) {
      expect(AVAILABLE_ENGINES).toContain(engine);
    }
  });
});
