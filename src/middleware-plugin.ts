/* eslint-disable @typescript-eslint/no-unused-vars */
import { type Express, type Request, type Response, type NextFunction } from 'express';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import type { Auth } from '@verdaccio/auth';
import { pluginUtils } from '@verdaccio/core';
import { Logger } from '@verdaccio/types';

import { CustomConfig } from '../types';

type Policy = {
  whitelist: string[];
  blacklist: string[];
};

export default class DepGateMiddleware
  extends pluginUtils.Plugin<CustomConfig>
  implements pluginUtils.ExpressMiddleware<CustomConfig, {}, Auth>
{
  readonly logger: Logger;
  private readonly policyPath: string;
  private readonly failClosedOnOsvError: boolean;
  private readonly cvssBlockThreshold: number;
  private readonly contact: string;

  public constructor(config: CustomConfig, options: pluginUtils.PluginOptions) {
    super(config, options);
    this.logger = options.logger;
    this.policyPath = config.policyPath || path.join(process.cwd(), 'policy.json');
    this.failClosedOnOsvError = config.failClosedOnOsvError === true;
    this.cvssBlockThreshold =
      typeof config.cvssBlockThreshold === 'number' ? config.cvssBlockThreshold : 9.0;
    this.contact = config.contact || 'your security team';
  }

  private getPolicy(): Policy {
    try {
      if (fs.existsSync(this.policyPath)) {
        const parsed = JSON.parse(fs.readFileSync(this.policyPath, 'utf8'));
        return {
          whitelist: Array.isArray(parsed.whitelist) ? parsed.whitelist : [],
          blacklist: Array.isArray(parsed.blacklist) ? parsed.blacklist : [],
        };
      }
      this.logger.error({ path: this.policyPath }, '[DepGate] policy.json missing');
    } catch (e: any) {
      this.logger.error({ error: e?.message }, '[DepGate] Failed to read policy.json');
    }
    return { whitelist: [], blacklist: [] };
  }

  private isListed(list: string[], pkgName: string, version: string): boolean {
    return (
      list.includes(`${pkgName}@${version}`) ||
      list.includes(`${pkgName}@*`) ||
      list.includes(pkgName)
    );
  }

  private isWhitelisted(list: string[], pkgName: string, version: string): boolean {
    return list.includes(`${pkgName}@${version}`) || list.includes(`${pkgName}@*`);
  }

  private extractCvssScore(vuln: any): number {
    const dbScore = vuln?.database_specific?.cvss?.score ?? vuln?.database_specific?.cvss_score;
    if (typeof dbScore === 'number' && !Number.isNaN(dbScore)) {
      return dbScore;
    }

    const severities = Array.isArray(vuln?.severity) ? vuln.severity : [];
    for (const s of severities) {
      if (typeof s?.score === 'number') {
        return s.score;
      }
      if (typeof s?.score !== 'string') {
        continue;
      }

      if (/^\d+(?:\.\d+)?$/.test(s.score.trim())) {
        return parseFloat(s.score);
      }

      const spaced = s.score.match(/CVSS:[^\s]+\s+(\d+(?:\.\d+)?)/i);
      if (spaced) {
        return parseFloat(spaced[1]);
      }
    }

    return NaN;
  }

  private isCriticalVuln(vuln: any): boolean {
    const textSeverity = String(vuln?.database_specific?.severity || '').toUpperCase();
    if (textSeverity === 'CRITICAL') {
      return true;
    }

    const score = this.extractCvssScore(vuln);
    return !Number.isNaN(score) && score >= this.cvssBlockThreshold;
  }

  private deny(res: Response, message: string): void {
    res.status(403).json({ error: message });
  }

  private async enforcePackageGate(
    req: Request,
    res: Response,
    next: NextFunction,
    pkgName: string,
    filename: string,
  ): Promise<void> {
    const versionMatch = filename.match(/-(\d+\.\d+\.\d+.*)\.tgz$/);
    const version = versionMatch ? versionMatch[1] : null;

    if (!version) {
      return next();
    }

    const { whitelist, blacklist } = this.getPolicy();

    if (this.isListed(blacklist, pkgName, version)) {
      this.logger.warn({ pkgName, version }, '[DepGate] MANUAL BLOCK: Package is blacklisted');
      return this.deny(
        res,
        `
**********************************************************
[DEPGATE SECURITY POLICY BLOCK]
PACKAGE: ${pkgName}@${version}
REASON: This package has been manually blacklisted.
CONTACT: ${this.contact}
**********************************************************`,
      );
    }

    if (this.isWhitelisted(whitelist, pkgName, version)) {
      this.logger.info({ pkgName, version }, '[DepGate] WHITELISTED: Skipping security scan');
      return next();
    }

    try {
      const response = await axios.post(
        'https://api.osv.dev/v1/query',
        { version, package: { name: pkgName, ecosystem: 'npm' } },
        { timeout: 4000 },
      );

      const vulnList = response.data?.vulns;
      if (Array.isArray(vulnList) && vulnList.length > 0) {
        const blockedVulns = vulnList.filter((v: any) => this.isCriticalVuln(v));

        if (blockedVulns.length > 0) {
          const cveIds = blockedVulns.map((v: any) => v.id).join(', ');
          this.logger.warn(
            { pkgName, version, cveIds, count: blockedVulns.length },
            '[DepGate] OSV BLOCK: Critical vulnerability',
          );
          return this.deny(
            res,
            `
**********************************************************
[DEPGATE SECURITY POLICY BLOCK]
PACKAGE: ${pkgName}@${version}
REASON: Found ${blockedVulns.length} CRITICAL vulnerability(ies).
CVEs: ${cveIds}
POLICY: Downloads blocked for CVSS >= ${this.cvssBlockThreshold} or severity CRITICAL.
CONTACT: ${this.contact}
**********************************************************`,
          );
        }
      }
    } catch (error: any) {
      this.logger.error({ error: error.message, pkgName, version }, '[DepGate] OSV API Error');
      if (this.failClosedOnOsvError) {
        return this.deny(
          res,
          `
**********************************************************
[DEPGATE SECURITY POLICY BLOCK]
PACKAGE: ${pkgName}@${version}
REASON: Vulnerability check unavailable (OSV error). Download denied (fail-closed).
CONTACT: ${this.contact}
**********************************************************`,
        );
      }
      this.logger.warn({ pkgName, version }, '[DepGate] OSV unavailable - failing open');
    }

    next();
  }

  public register_middlewares(app: Express, _auth: Auth): void {
    app.get('/:package/-/:filename', async (req, res, next) => {
      try {
        const pkgName = req.params.package;
        const filename = req.params.filename;
        await this.enforcePackageGate(req, res, next, pkgName, filename);
      } catch (e: any) {
        this.logger.error({ error: e?.message }, '[DepGate] Unhandled error');
        next();
      }
    });

    app.get('/@:scope/:package/-/:filename', async (req, res, next) => {
      try {
        const pkgName = `@${req.params.scope}/${req.params.package}`;
        const filename = req.params.filename;
        await this.enforcePackageGate(req, res, next, pkgName, filename);
      } catch (e: any) {
        this.logger.error({ error: e?.message }, '[DepGate] Unhandled error');
        next();
      }
    });
  }
}
