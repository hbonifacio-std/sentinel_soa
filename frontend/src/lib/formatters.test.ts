import { describe, it, expect } from 'vitest';
import { formatDate, formatScore, formatBytes } from './formatters';

describe('formatters', () => {
  describe('formatDate', () => {
    it('should format a valid date string correctly', () => {
      const date = new Date('2026-07-08T09:40:00Z');
      const expected = formatDate(date.toISOString());
      expect(expected).toContain('2026-07-08');
    });

    it('should return original value if date is invalid', () => {
      expect(formatDate('invalid-date')).toBe('invalid-date');
    });
  });

  describe('formatScore', () => {
    it('should format score as percentage', () => {
      expect(formatScore(50, 100)).toBe('50.0%');
      expect(formatScore(75, 100)).toBe('75.0%');
    });

    it('should handle custom maxScore', () => {
      expect(formatScore(5, 10)).toBe('50.0%');
    });

    it('should clamp values between 0% and 100%', () => {
      expect(formatScore(-10, 100)).toBe('0.0%');
      expect(formatScore(150, 100)).toBe('100.0%');
    });
  });

  describe('formatBytes', () => {
    it('should return "-" when bytes is null', () => {
      expect(formatBytes(null)).toBe('-');
    });

    it('should format bytes less than 1024', () => {
      expect(formatBytes(512)).toBe('512 B');
    });

    it('should format kilobytes', () => {
      expect(formatBytes(1536)).toBe('1.5 KB');
    });

    it('should format megabytes', () => {
      expect(formatBytes(1048576 * 2.5)).toBe('2.5 MB');
    });
  });
});
