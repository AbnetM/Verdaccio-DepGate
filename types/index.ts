import { Config } from '@verdaccio/types';

export interface CustomConfig extends Config {
  /** Absolute or relative path to policy.json (whitelist / blacklist). */
  policyPath?: string;
  /** If true, deny downloads when OSV is unreachable. Default: false (fail open). */
  failClosedOnOsvError?: boolean;
  /** Block when CVSS score is >= this value. Default: 9.0 */
  cvssBlockThreshold?: number;
  /** Optional contact line shown in 403 messages. */
  contact?: string;
}
