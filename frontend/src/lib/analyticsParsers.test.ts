import { describe, it, expect } from 'vitest';
import {
  parsePaginatedResponse,
  mapTelemetryRow,
  mapReportRow,
  parseTelemetryPage,
  parseReportsPage,
} from './analyticsParsers';

describe('analyticsParsers', () => {
  describe('parsePaginatedResponse', () => {
    it('handles null or invalid payload by returning empty arrays', () => {
      const result = parsePaginatedResponse(null, 1, 10, (row) => row);
      expect(result.results).toEqual([]);
      expect(result.info.total_records).toBe(0);
      expect(result.info.page).toBe(1);
    });

    it('handles raw array payload by wrapping it with fallback page info', () => {
      const payload = [{ val: 1 }, { val: 2 }];
      const result = parsePaginatedResponse(payload, 1, 2, (row: any) => row.val * 2);
      expect(result.results).toEqual([2, 4]);
      expect(result.info.total_records).toBe(2);
      expect(result.info.next_page).toContain('page=2');
    });

    it('handles structured paginated payload with results and info properties', () => {
      const payload = {
        results: [{ id: 'a' }, { id: 'b' }],
        info: {
          total_records: 100,
          page: 2,
          limit: 10,
          next_page: 'next-url',
          prev_page: 'prev-url',
        },
      };
      const result = parsePaginatedResponse(payload, 2, 10, (row: any) => row.id);
      expect(result.results).toEqual(['a', 'b']);
      expect(result.info.total_records).toBe(100);
      expect(result.info.page).toBe(2);
      expect(result.info.next_page).toBe('next-url');
      expect(result.info.prev_page).toBe('prev-url');
    });
  });

  describe('mapTelemetryRow', () => {
    it('maps standard raw telemetry row with default values', () => {
      const raw = {
        id: 'log-1',
        source_id: 'src-abc',
        source_ip: '192.168.1.5',
        method: 'POST',
        request_uri: '/login',
        status: 200,
        user_agent: 'Firefox',
        timestamp: '2026-07-08T09:40:00Z',
        bytes_sent: 1024,
      };

      const result = mapTelemetryRow(raw, 0);
      expect(result.id).toBe('log-1');
      expect(result.source_id).toBe('src-abc');
      expect(result.source_ip).toBe('192.168.1.5');
      expect(result.http_method).toBe('POST');
      expect(result.request_uri).toBe('/login');
      expect(result.response_code).toBe(200);
      expect(result.user_agent).toBe('Firefox');
      expect(result.timestamp).toBe('2026-07-08T09:40:00Z');
      expect(result.bytes_sent).toBe(1024);
    });

    it('uses fallback properties and nested network/http objects', () => {
      const raw = {
        http: {
          method: 'PATCH',
          path: '/resource',
          query: 'id=5',
          status_code: 201,
          response_size_bytes: 512,
          user_agent: 'Chrome',
        },
        network: {
          client_ip: '10.0.0.1',
        },
        timestamp_utc: '2026-07-08T09:41:00Z',
      };

      const result = mapTelemetryRow(raw, 1);
      expect(result.source_ip).toBe('10.0.0.1');
      expect(result.http_method).toBe('PATCH');
      expect(result.request_uri).toBe('/resource?id=5');
      expect(result.response_code).toBe(201);
      expect(result.user_agent).toBe('Chrome');
      expect(result.timestamp).toBe('2026-07-08T09:41:00Z');
      expect(result.bytes_sent).toBe(512);
    });

    it('falls back to default values when raw data is missing or invalid', () => {
      const result = mapTelemetryRow(null, 5);
      expect(result.source_id).toBe('unknown');
      expect(result.source_ip).toBe('N/A');
      expect(result.http_method).toBe('GET');
      expect(result.request_uri).toBe('/');
      expect(result.response_code).toBe(0);
      expect(result.bytes_sent).toBeNull();
    });
  });

  describe('mapReportRow', () => {
    it('maps standard raw report row correctly', () => {
      const raw = {
        id: 'threat-1',
        source_id: 'src-99',
        source_ip: '172.16.0.4',
        threat_level: 'HIGH',
        threat_score: 85,
        targeted_asset: 'Database',
        kill_chain_phase: 'Exploitation',
        mitre_tactic: 'Initial Access',
        mitre_tactic_id: 'TA0001',
        mitre_technique: 'Phishing',
        mitre_technique_id: 'T1566',
        indicators_found: ['suspicious-link.com', 'bad-attachment.pdf'],
        reasoning_summary: 'Detected multiple phishing indicators',
        recommendation: 'Isolate host',
        suggested_mitigations: ['Block domain', 'Reset credentials'],
        created_at_utc: '2026-07-08T09:00:00Z',
        reviewed: true,
        resolved: false,
        actions: ['sent email alert', { comment: 'investigating', timestamp: '2026-07-08T09:10:00Z' }],
      };

      const result = mapReportRow(raw, 0);
      expect(result.id).toBe('threat-1');
      expect(result.source_id).toBe('src-99');
      expect(result.source_ip).toBe('172.16.0.4');
      expect(result.threat_level).toBe('HIGH');
      expect(result.threat_score).toBe(85);
      expect(result.targeted_asset).toBe('Database');
      expect(result.kill_chain_phase).toBe('Exploitation');
      expect(result.mitre_tactic).toBe('Initial Access');
      expect(result.mitre_technique_id).toBe('T1566');
      expect(result.indicators_found).toEqual(['suspicious-link.com', 'bad-attachment.pdf']);
      expect(result.reviewed).toBe(true);
      expect(result.resolved).toBe(false);
      expect(result.status).toBe('reviewing');
      expect(result.actions).toHaveLength(2);
      expect(result.actions?.[0].comment).toBe('sent email alert');
      expect(result.actions?.[1].comment).toBe('investigating');
    });

    it('normalizes legacy and invalid threat levels and kill chain phases', () => {
      const raw = {
        id: 'threat-2',
        threat_level: 'invalid-level',
        kill_chain_phase: 'command-and-control',
        resolved: true,
        resolved_at_utc: '2026-07-08T09:20:00Z',
      };

      const result = mapReportRow(raw, 1);
      expect(result.threat_level).toBe('LOW');
      expect(result.kill_chain_phase).toBe('Command and Control');
      expect(result.status).toBe('resolved');
      expect(result.resolved_at_utc).toBe('2026-07-08T09:20:00Z');
    });

    it('handles nested fallback threat actors and details for source IP', () => {
      const raw = {
        id: 'threat-3',
        threat_actor: {
          ip_address: '1.2.3.4',
        },
      };
      const result = mapReportRow(raw, 2);
      expect(result.source_ip).toBe('1.2.3.4');
    });

    it('handles nested fallback details for source IP', () => {
      const raw = {
        id: 'threat-4',
        details: {
          source_ip: '5.6.7.8',
        },
      };
      const result = mapReportRow(raw, 3);
      expect(result.source_ip).toBe('5.6.7.8');
    });
  });

  describe('parseTelemetryPage & parseReportsPage', () => {
    it('correctly maps pages via telemetry/reports wrapper', () => {
      const telemetryResult = parseTelemetryPage([{ id: 'tel-1' }], 1, 10);
      expect(telemetryResult.results[0].id).toBe('tel-1');

      const reportsResult = parseReportsPage([{ id: 'rep-1' }], 1, 10);
      expect(reportsResult.results[0].id).toBe('rep-1');
    });
  });
});
