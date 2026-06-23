import type { StatsResponse } from '@/types/api';

export const mockStats: StatsResponse = {
  threat_levels: [
    { _id: 'CRITICAL', count: 2 },
    { _id: 'HIGH', count: 5 },
    { _id: 'MEDIUM', count: 7 },
    { _id: 'LOW', count: 3 },
  ],
  kill_chain_phases: [
    { _id: 'reconnaissance', count: 3 },
    { _id: 'delivery', count: 4 },
    { _id: 'exploitation', count: 5 },
  ],
  top_attackers: [
    { _id: '10.10.20.5', count: 17 },
    { _id: '172.16.0.8', count: 11 },
  ],
  mitre_tactics: [
    { _id: 'Initial Access', count: 6 },
    { _id: 'Execution', count: 7 },
    { _id: 'Persistence', count: 3 },
    { _id: 'Lateral Movement', count: 2 },
  ],
};

