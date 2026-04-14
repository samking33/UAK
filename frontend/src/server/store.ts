import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import path from 'path';
import { buildAuditResponse, countryCoords } from './audit-engine';
import type { AuditBuildResult, DashboardOverviewResult, ListIocQuery, ListScanQuery, ReportPayload, StoreState, StoredScan, ThreatDomainRow, ThreatIpRow, ThreatMapResponse } from './types';
import type { IOCRecord, ScanMode, ScanRecord } from '@/types';

const STORE_DIR = path.resolve(process.env.UAK_DATA_DIR || path.join(process.cwd(), '.uak-data'));
const STORE_FILE = path.join(STORE_DIR, 'audit-store.json');

function defaultState(): StoreState {
  return {
    version: 1,
    nextScanId: 1,
    nextIOCId: 1,
    scans: [],
  };
}

function toStoredScan(payload: AuditBuildResult, scanId: number, createdAt: string): StoredScan {
  const iocs = payload.iocs.map((ioc, index) => ({
    ...ioc,
    id: ioc.id || index + 1,
    scan_id: scanId,
  }));

  return {
    id: scanId,
    target_url: payload.target_url,
    scan_mode: payload.scan_mode || 'scan',
    risk_score: payload.risk_score || 0,
    risk_level: payload.risk_level || 'LOW',
    verdict: payload.verdict || 'BENIGN',
    total_checks: payload.total_checks || payload.results.length,
    pass_count: payload.summary_cards.find((item) => item.status === 'PASS')?.count || 0,
    warn_count: payload.summary_cards.find((item) => item.status === 'WARN')?.count || 0,
    fail_count: payload.summary_cards.find((item) => item.status === 'FAIL')?.count || 0,
    info_count: payload.summary_cards.find((item) => item.status === 'INFO')?.count || 0,
    skip_count: payload.summary_cards.find((item) => item.status === 'SKIP')?.count || 0,
    ai_verdict: payload.ai_threat_report?.verdict || null,
    ai_summary: payload.ai_threat_report?.executive_summary || null,
    duration_ms: payload.duration_ms || 0,
    created_at: createdAt,
    checks: payload.checks.map((check) => ({ ...check })),
    iocs,
    summary_cards: payload.summary_cards.map((card) => ({ ...card })),
    grouped_results: payload.grouped_results.map((group) => ({
      name: group.name,
      checks: group.checks.map((check) => ({ ...check })),
    })),
    ai_threat_report: payload.ai_threat_report || null,
    ai_metadata: payload.ai_metadata || null,
    ai_error: null,
    report: payload.report,
  };
}

function ensureStoreDir(): void {
  mkdirSync(STORE_DIR, { recursive: true });
}

function atomicWrite(filePath: string, content: string): void {
  const tempPath = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tempPath, content, 'utf8');
  renameSync(tempPath, filePath);
}

function loadState(): StoreState {
  ensureStoreDir();
  if (!existsSync(STORE_FILE)) {
    const seeded = defaultState();
    atomicWrite(STORE_FILE, JSON.stringify(seeded, null, 2));
    return seeded;
  }

  try {
    const raw = readFileSync(STORE_FILE, 'utf8');
    return normalizeState(JSON.parse(raw) as StoreState);
  } catch {
    const seeded = defaultState();
    atomicWrite(STORE_FILE, JSON.stringify(seeded, null, 2));
    return seeded;
  }
}

function normalizeState(state: Partial<StoreState> | null | undefined): StoreState {
  const scans = Array.isArray(state?.scans) ? state.scans : [];
  return {
    version: 1,
    nextScanId: typeof state?.nextScanId === 'number' ? state.nextScanId : scans.reduce((max, scan) => Math.max(max, scan.id), 0) + 1,
    nextIOCId: typeof state?.nextIOCId === 'number' ? state.nextIOCId : scans.reduce((max, scan) => Math.max(max, ...scan.iocs.map((ioc) => ioc.id), 0), 0) + 1,
    scans: scans.map((scan) => ({
      ...scan,
      summary_cards: Array.isArray(scan.summary_cards) ? scan.summary_cards : [],
      grouped_results: Array.isArray(scan.grouped_results) ? scan.grouped_results : [],
      checks: Array.isArray(scan.checks) ? scan.checks : [],
      iocs: Array.isArray(scan.iocs) ? scan.iocs : [],
      report: scan.report || {
        scan_summary: {
          target_url: scan.target_url,
          scan_mode: scan.scan_mode,
          risk_score: scan.risk_score,
          risk_level: scan.risk_level,
          verdict: scan.verdict,
          created_at: scan.created_at,
          duration_ms: scan.duration_ms,
          total_checks: scan.total_checks,
        },
        indicators_of_compromise: scan.iocs,
        domain_intelligence: scan.checks.filter((check) => (check.section || '').toLowerCase() === 'domain intelligence'),
        risk_assessment: {
          pass_count: scan.pass_count,
          warn_count: scan.warn_count,
          fail_count: scan.fail_count,
          info_count: scan.info_count,
          skip_count: scan.skip_count,
          risk_score: scan.risk_score,
          risk_level: scan.risk_level,
        },
        recommendations: scan.ai_threat_report?.recommendations || [],
        grouped_checks: scan.grouped_results,
        threat_report: scan.ai_threat_report || null,
      },
    })),
  };
}

function persistState(nextState: StoreState): void {
  ensureStoreDir();
  atomicWrite(STORE_FILE, JSON.stringify(nextState, null, 2));
}

async function withWriteLock<T>(fn: () => T | Promise<T>): Promise<T> {
  return await fn();
}

function matchesList(value: string, list: string): boolean {
  if (!list.trim()) return true;
  const values = list
    .split(',')
    .map((item) => item.trim().toUpperCase())
    .filter(Boolean);
  return values.length === 0 || values.includes(value.toUpperCase());
}

function buildPage(total: number, page: number, pageSize: number) {
  return {
    total,
    page,
    page_size: pageSize,
    total_pages: Math.max(1, Math.ceil(total / Math.max(pageSize, 1))),
  };
}

function sortRecords<T>(items: T[], sortBy: string, sortOrder: 'asc' | 'desc', validFields: Record<string, keyof T>): T[] {
  const key = validFields[sortBy] || validFields.created_at || (Object.keys(validFields)[0] as keyof T);
  const direction = sortOrder === 'asc' ? 1 : -1;
  return [...items].sort((left, right) => {
    const a = left[key];
    const b = right[key];
    if (a === b) return 0;
    return a < b ? -1 * direction : 1 * direction;
  });
}

function toScanRecord(scan: StoredScan): ScanRecord {
  return {
    id: scan.id,
    target_url: scan.target_url,
    scan_mode: scan.scan_mode,
    risk_score: scan.risk_score,
    risk_level: scan.risk_level,
    verdict: scan.verdict,
    total_checks: scan.total_checks,
    pass_count: scan.pass_count,
    warn_count: scan.warn_count,
    fail_count: scan.fail_count,
    info_count: scan.info_count,
    skip_count: scan.skip_count,
    ai_verdict: scan.ai_verdict,
    ai_summary: scan.ai_summary,
    duration_ms: scan.duration_ms,
    created_at: scan.created_at,
  };
}

function getRecentScans(state: StoreState): StoredScan[] {
  return [...state.scans].sort((a, b) => b.created_at.localeCompare(a.created_at));
}

export async function createAudit(url: string, scanMode: ScanMode): Promise<AuditBuildResult> {
  return withWriteLock(async () => {
    const state = await loadState();
    const createdAt = new Date().toISOString();
    const scanId = state.nextScanId;
    const payload = buildAuditResponse(url, scanMode, createdAt, scanId);
    const stored = toStoredScan(payload, scanId, createdAt);
    stored.iocs = stored.iocs.map((ioc, index) => ({
      ...ioc,
      id: state.nextIOCId + index,
      scan_id: scanId,
    }));

    const nextState: StoreState = {
      ...state,
      nextScanId: scanId + 1,
      nextIOCId: state.nextIOCId + stored.iocs.length,
      scans: [stored, ...state.scans],
    };
    await persistState(nextState);

    return {
      ...payload,
      scan_id: scanId,
      ioc_count: stored.iocs.length,
      iocs: stored.iocs,
      report: stored.report,
    };
  });
}

export async function getDashboardOverview(range: string): Promise<DashboardOverviewResult> {
  const state = await loadState();
  const window = (range || '24h').toLowerCase();
  const now = Date.now();
  const since = window === '7d' ? now - 7 * 24 * 60 * 60 * 1000 : window === '30d' ? now - 30 * 24 * 60 * 60 * 1000 : now - 24 * 60 * 60 * 1000;
  const scans = getRecentScans(state).filter((scan) => new Date(scan.created_at).getTime() >= since);

  const totals = {
    total_scans: scans.length,
    malicious_urls: scans.filter((scan) => scan.risk_level === 'HIGH' || scan.risk_level === 'CRITICAL').length,
    suspicious_domains: scans.filter((scan) => scan.risk_level === 'MEDIUM').length,
    safe_urls: scans.filter((scan) => scan.risk_level === 'LOW').length,
  };

  const levels: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const threatDistribution = levels.map((label) => ({
    label,
    value: scans.filter((scan) => scan.risk_level === label).length,
  }));

  const bucketMap = new Map<string, { total: number; malicious: number; safe: number }>();
  for (const scan of scans) {
    const date = new Date(scan.created_at);
    const bucket =
      window === '24h'
        ? date.toISOString().slice(0, 13).replace('T', ' ')
        : date.toISOString().slice(0, 10);
    if (!bucketMap.has(bucket)) {
      bucketMap.set(bucket, { total: 0, malicious: 0, safe: 0 });
    }
    const entry = bucketMap.get(bucket)!;
    entry.total += 1;
    if (scan.risk_level === 'HIGH' || scan.risk_level === 'CRITICAL') entry.malicious += 1;
    if (scan.risk_level === 'LOW') entry.safe += 1;
  }

  return {
    range,
    totals,
    threat_distribution: threatDistribution,
    scan_activity: Array.from(bucketMap.entries())
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([bucket, counts]) => ({ bucket, ...counts })),
    recent_scans: scans.slice(0, 10).map((scan) => ({
      id: scan.id,
      target_url: scan.target_url,
      risk_score: scan.risk_score,
      risk_level: scan.risk_level,
      verdict: scan.verdict,
      created_at: scan.created_at,
    })),
  };
}

export async function listScans(query: ListScanQuery = {}) {
  const state = await loadState();
  const page = Math.max(1, query.page || 1);
  const pageSize = Math.max(1, Math.min(query.pageSize || 20, 200));
  const filtered = state.scans.filter((scan) => {
    const q = (query.q || '').trim().toLowerCase();
    const risk = query.risk || '';
    const status = query.status || '';

    if (q && !scan.target_url.toLowerCase().includes(q)) return false;
    if (!matchesList(scan.risk_level, risk)) return false;
    if (!matchesList(scan.verdict, status)) return false;
    return true;
  });

  const sorted = sortRecords(
    filtered,
    query.sortBy || 'created_at',
    query.sortOrder || 'desc',
    {
      created_at: 'created_at',
      risk_score: 'risk_score',
      target_url: 'target_url',
      verdict: 'verdict',
      risk_level: 'risk_level',
      id: 'id',
    }
  );

  const start = (page - 1) * pageSize;
  const items = sorted.slice(start, start + pageSize).map(toScanRecord);
  return {
    items,
    ...buildPage(sorted.length, page, pageSize),
  };
}

export async function getScan(scanId: number) {
  const state = await loadState();
  const scan = state.scans.find((item) => item.id === scanId);
  if (!scan) return null;
  return {
    ...toScanRecord(scan),
    summary_cards: scan.summary_cards,
    checks: scan.checks,
    iocs: scan.iocs,
    ai_threat_report: scan.ai_threat_report,
    ai_metadata: scan.ai_metadata,
    ai_error: scan.ai_error,
    grouped_results: scan.grouped_results,
  };
}

export async function getScanReport(scanId: number): Promise<ReportPayload | null> {
  const state = await loadState();
  const scan = state.scans.find((item) => item.id === scanId);
  return scan?.report || null;
}

export async function listIocs(query: ListIocQuery = {}) {
  const state = await loadState();
  const page = Math.max(1, query.page || 1);
  const pageSize = Math.max(1, Math.min(query.pageSize || 20, 200));
  const allIocs = state.scans.flatMap((scan) =>
    scan.iocs.map((ioc) => ({
      ...ioc,
      scan_id: scan.id,
      target_url: scan.target_url,
      risk_level: scan.risk_level,
      risk_score: scan.risk_score,
    }))
  );

  const filtered = allIocs.filter((ioc) => {
    const q = (query.q || '').trim().toLowerCase();
    if (q && !ioc.indicator.toLowerCase().includes(q)) return false;
    if (!matchesList(ioc.indicator_type, query.type || '')) return false;
    if (!matchesList(ioc.severity, query.severity || '')) return false;
    return true;
  });

  const sorted = sortRecords(
    filtered,
    query.sortBy || 'created_at',
    query.sortOrder || 'desc',
    {
      created_at: 'created_at',
      severity: 'severity',
      indicator: 'indicator',
      indicator_type: 'indicator_type',
      id: 'id',
    }
  );

  const start = (page - 1) * pageSize;
  return {
    items: sorted.slice(start, start + pageSize),
    ...buildPage(sorted.length, page, pageSize),
  };
}

export async function getThreatMap(range: string): Promise<ThreatMapResponse> {
  const state = await loadState();
  const window = (range || '24h').toLowerCase();
  const now = Date.now();
  const since = window === '7d' ? now - 7 * 24 * 60 * 60 * 1000 : window === '30d' ? now - 30 * 24 * 60 * 60 * 1000 : now - 24 * 60 * 60 * 1000;
  const map = new Map<string, { country: string; count: number; critical: number; high: number; medium: number; low: number }>();

  for (const scan of state.scans) {
    for (const ioc of scan.iocs) {
      if (new Date(ioc.created_at).getTime() < since) continue;
      const country = (ioc.country || '').toUpperCase();
      if (!country) continue;
      const existing = map.get(country) || { country, count: 0, critical: 0, high: 0, medium: 0, low: 0 };
      existing.count += 1;
      if (ioc.severity === 'CRITICAL') existing.critical += 1;
      if (ioc.severity === 'HIGH') existing.high += 1;
      if (ioc.severity === 'MEDIUM') existing.medium += 1;
      if (ioc.severity === 'LOW') existing.low += 1;
      map.set(country, existing);
    }
  }

  const points = Array.from(map.values())
    .map((entry) => {
      const coords = countryCoords(entry.country);
      if (!coords) return null;
      return {
        country: entry.country,
        lat: coords.lat,
        lng: coords.lng,
        count: entry.count,
        critical: entry.critical,
        high: entry.high,
        medium: entry.medium,
        low: entry.low,
      };
    })
    .filter((item): item is NonNullable<typeof item> => Boolean(item))
    .sort((left, right) => right.count - left.count);

  return { range, points };
}

export async function getTopMaliciousDomains(limit = 20): Promise<{ items: ThreatDomainRow[] }> {
  const state = await loadState();
  const aggregated = new Map<string, ThreatDomainRow>();

  for (const scan of state.scans) {
    for (const ioc of scan.iocs) {
      if (ioc.indicator_type !== 'DOMAIN' || !(ioc.severity === 'HIGH' || ioc.severity === 'CRITICAL')) continue;
      const domain = ioc.indicator.toLowerCase();
      const current = aggregated.get(domain) || { domain, hits: 0, last_seen: ioc.created_at };
      current.hits += 1;
      current.last_seen = current.last_seen > ioc.created_at ? current.last_seen : ioc.created_at;
      aggregated.set(domain, current);
    }
  }

  return {
    items: Array.from(aggregated.values())
      .sort((left, right) => right.hits - left.hits || right.last_seen.localeCompare(left.last_seen))
      .slice(0, Math.max(1, Math.min(limit, 200))),
  };
}

export async function getIpReputation(limit = 20): Promise<{ items: ThreatIpRow[] }> {
  const state = await loadState();
  const aggregated = new Map<string, ThreatIpRow>();

  for (const scan of state.scans) {
    for (const ioc of scan.iocs) {
      if (ioc.indicator_type !== 'IP') continue;
      const ip = ioc.indicator;
      const current = aggregated.get(ip) || {
        ip,
        sightings: 0,
        critical_hits: 0,
        high_hits: 0,
        medium_hits: 0,
        last_seen: ioc.created_at,
      };
      current.sightings += 1;
      if (ioc.severity === 'CRITICAL') current.critical_hits += 1;
      if (ioc.severity === 'HIGH') current.high_hits += 1;
      if (ioc.severity === 'MEDIUM') current.medium_hits += 1;
      current.last_seen = current.last_seen > ioc.created_at ? current.last_seen : ioc.created_at;
      aggregated.set(ip, current);
    }
  }

  return {
    items: Array.from(aggregated.values())
      .sort((left, right) => right.critical_hits - left.critical_hits || right.high_hits - left.high_hits || right.sightings - left.sightings)
      .slice(0, Math.max(1, Math.min(limit, 200))),
  };
}
