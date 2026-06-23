import type { LogEntry } from '@/types/logEntry';

export const mockLogs: LogEntry[] = [
  {
    _id: 'mock-1',
    source_id: 'sensor-alpha',
    source_ip: '10.10.20.5',
    http_method: 'POST',
    request_uri: '/admin/login',
    response_code: 401,
    user_agent: 'sqlmap/1.7.8#stable',
    timestamp: '2026-06-19T19:12:00.000Z',
    bytes_sent: 923,
  },
  {
    _id: 'mock-2',
    source_id: 'sensor-alpha',
    source_ip: '172.16.0.8',
    http_method: 'POST',
    request_uri: '/auth/login',
    response_code: 500,
    user_agent: 'python-requests/2.32',
    timestamp: '2026-06-19T21:19:00.000Z',
    bytes_sent: 1432,
  },
  {
    _id: 'mock-3',
    source_id: 'sensor-alpha',
    source_ip: '172.16.0.8',
    http_method: 'PUT',
    request_uri: '/admin/upload',
    response_code: 401,
    user_agent: 'python-requests/2.32',
    timestamp: '2026-06-19T21:45:00.000Z',
    bytes_sent: 1188,
  },
  {
    _id: 'mock-4',
    source_id: 'sensor-alpha',
    source_ip: '192.168.50.44',
    http_method: 'GET',
    request_uri: '/internal/share',
    response_code: 302,
    user_agent: 'curl/8.7.1',
    timestamp: '2026-06-19T22:03:00.000Z',
    bytes_sent: 764,
  },
];

