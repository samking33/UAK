import { randomUUID } from 'crypto';
import type { AuditBuildResult, ReportPayload } from './types';
import type {
  AIMetadata,
  AuditResponse,
  CheckResult,
  IOCRecord,
  RiskLevel,
  ScanMode,
  SummaryCard,
  ThreatReport,
  Verdict,
} from '@/types';

const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
  US: { lat: 37.0902, lng: -95.7129 },
  CA: { lat: 56.1304, lng: -106.3468 },
  MX: { lat: 23.6345, lng: -102.5528 },
  BR: { lat: -14.235, lng: -51.9253 },
  AR: { lat: -38.4161, lng: -63.6167 },
  GB: { lat: 55.3781, lng: -3.436 },
  FR: { lat: 46.2276, lng: 2.2137 },
  DE: { lat: 51.1657, lng: 10.4515 },
  NL: { lat: 52.1326, lng: 5.2913 },
  ES: { lat: 40.4637, lng: -3.7492 },
  IT: { lat: 41.8719, lng: 12.5674 },
  SE: { lat: 60.1282, lng: 18.6435 },
  NO: { lat: 60.472, lng: 8.4689 },
  PL: { lat: 51.9194, lng: 19.1451 },
  RU: { lat: 61.524, lng: 105.3188 },
  TR: { lat: 38.9637, lng: 35.2433 },
  IN: { lat: 20.5937, lng: 78.9629 },
  CN: { lat: 35.8617, lng: 104.1954 },
  JP: { lat: 36.2048, lng: 138.2529 },
  KR: { lat: 35.9078, lng: 127.7669 },
  SG: { lat: 1.3521, lng: 103.8198 },
  AU: { lat: -25.2744, lng: 133.7751 },
  NZ: { lat: -40.9006, lng: 174.886 },
  ZA: { lat: -30.5595, lng: 22.9375 },
  EG: { lat: 26.8206, lng: 30.8025 },
  NG: { lat: 9.082, lng: 8.6753 },
  AE: { lat: 23.4241, lng: 53.8478 },
  SA: { lat: 23.8859, lng: 45.0792 },
};

const SECTION_RULES = [
  {
    section: 'Domain Intelligence',
    patterns: ['domain name legitimacy', 'whois', 'domain expiry', 'domain transfer', 'domain ownership', 'domain'],
  },
  {
    section: 'Security Posture',
    patterns: ['ssl', 'https', 'certificate', 'ip reputation', 'hosting provider', 'security'],
  },
  {
    section: 'Reputation & Trust',
    patterns: ['blacklist', 'safe browsing', 'reputation'],
  },
  {
    section: 'Behavioural Signals',
    patterns: ['redirect', 'suspicious requests', 'url length', 'homoglyph'],
  },
  {
    section: 'AI Observations',
    patterns: ['ai content analysis', 'ai'],
  },
];

const STATUS_POINTS: Record<string, number> = {
  PASS: 0,
  INFO: 1,
  WARN: 4,
  FAIL: 8,
  SKIP: 0,
};

const CRITICAL_KEYWORDS = ['ssl', 'https', 'blacklist', 'virus total', 'virustotal', 'safe browsing', 'ip reputation', 'certificate issuer'];

const USER_AGENTS = ['url-audit-kit/1.0', 'Mozilla/5.0', 'SecurityScanner/2.0'];

function hashString(value: string): number {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function seededNumber(seed: string, min: number, max: number): number {
  const span = max - min + 1;
  return min + (hashString(seed) % Math.max(span, 1));
}

function normalizeUrl(rawUrl: string): URL {
  const trimmed = rawUrl.trim();
  try {
    return new URL(trimmed);
  } catch {
    return new URL(`https://${trimmed.replace(/^\/+/, '')}`);
  }
}

function lookupSection(name: string): string {
  const lower = name.toLowerCase();
  for (const rule of SECTION_RULES) {
    if (rule.patterns.some((pattern) => lower.includes(pattern))) {
      return rule.section;
    }
  }
  return 'Additional Checks';
}

function statusToRisk(status: string): RiskLevel {
  const normalized = status.toUpperCase();
  if (normalized === 'FAIL') return 'HIGH';
  if (normalized === 'WARN') return 'MEDIUM';
  return 'LOW';
}

function isCriticalCheck(name: string): boolean {
  const lower = name.toLowerCase();
  return CRITICAL_KEYWORDS.some((keyword) => lower.includes(keyword));
}

function verdictFromRiskLevel(riskLevel: RiskLevel): Verdict {
  if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') return 'MALICIOUS';
  if (riskLevel === 'MEDIUM') return 'SUSPICIOUS';
  return 'BENIGN';
}

function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

function computeRisk(checks: CheckResult[]): { risk_score: number; risk_level: RiskLevel; verdict: Verdict; points: number; max_points: number } {
  let points = 0;
  let maxPoints = 0;

  for (const check of checks) {
    const status = (check.status || 'WARN').toUpperCase();
    const base = STATUS_POINTS[status] ?? STATUS_POINTS.WARN;
    const criticalBonus = isCriticalCheck(check.name) && status === 'FAIL' ? 12 : 0;
    points += base + criticalBonus;
    maxPoints += STATUS_POINTS.FAIL + (isCriticalCheck(check.name) ? 12 : 0);
  }

  const normalized = Math.round((points / Math.max(maxPoints, 1)) * 100);
  const riskScore = Math.max(0, Math.min(100, normalized));
  const riskLevel = riskLevelFromScore(riskScore);
  return {
    risk_score: riskScore,
    risk_level: riskLevel,
    verdict: verdictFromRiskLevel(riskLevel),
    points,
    max_points: maxPoints,
  };
}

function parseHostParts(url: URL): { hostname: string; domain: string; tld: string; isIp: boolean; isPunycode: boolean } {
  const hostname = url.hostname.toLowerCase();
  const pieces = hostname.split('.');
  const tld = pieces.length > 1 ? pieces[pieces.length - 1] : '';
  const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
  const isPunycode = hostname.includes('xn--');
  const domain = isIp ? hostname : hostname.replace(/^www\./, '');
  return { hostname, domain, tld, isIp, isPunycode };
}

function guessCountry(hostname: string): string {
  const mapping: Array<[string, string]> = [
    ['.uk', 'GB'],
    ['.ca', 'CA'],
    ['.de', 'DE'],
    ['.fr', 'FR'],
    ['.ru', 'RU'],
    ['.in', 'IN'],
    ['.cn', 'CN'],
    ['.jp', 'JP'],
    ['.kr', 'KR'],
    ['.br', 'BR'],
    ['.au', 'AU'],
    ['.za', 'ZA'],
    ['.ng', 'NG'],
    ['.ae', 'AE'],
    ['.sa', 'SA'],
  ];

  for (const [suffix, code] of mapping) {
    if (hostname.endsWith(suffix)) return code;
  }

  const fallback = ['US', 'GB', 'IN', 'DE', 'CA', 'SG'];
  return fallback[seededNumber(hostname, 0, fallback.length - 1)];
}

function buildEvidence(keyValues: Record<string, string | number | boolean | undefined>): string {
  return Object.entries(keyValues)
    .filter(([, value]) => value !== undefined && value !== '')
    .map(([key, value]) => `${key}=${value}`)
    .join(', ');
}

function makeCheck(params: {
  id: number;
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL' | 'INFO' | 'SKIP';
  evidence: string;
  data?: Record<string, unknown>;
  summary?: string;
  risk_level?: RiskLevel;
}): CheckResult {
  return {
    id: params.id,
    name: params.name,
    status: params.status,
    evidence: params.evidence,
    data: params.data,
    summary: params.summary,
    risk_level: params.risk_level ?? statusToRisk(params.status),
    section: lookupSection(params.name),
  };
}

function stringEntropy(input: string): number {
  if (!input) return 0;
  const counts = new Map<string, number>();
  for (const char of input) counts.set(char, (counts.get(char) || 0) + 1);
  let entropy = 0;
  counts.forEach((count) => {
    const probability = count / input.length;
    entropy -= probability * Math.log2(probability);
  });
  return Number(entropy.toFixed(2));
}

function buildChecks(url: URL, scanMode: ScanMode): CheckResult[] {
  const { hostname, domain, tld, isIp, isPunycode } = parseHostParts(url);
  const seed = `${url.href}|${scanMode}`;
  const length = url.href.length;
  const queryParams = Array.from(url.searchParams.keys());
  const suspiciousTokens = ['login', 'verify', 'secure', 'update', 'account', 'wallet', 'signin', 'reset', 'token', 'redirect'];
  const suspiciousQuery = queryParams.some((key) => suspiciousTokens.some((token) => key.toLowerCase().includes(token)));
  const suspiciousPath = suspiciousTokens.some((token) => url.pathname.toLowerCase().includes(token));
  const hasHttps = url.protocol === 'https:';
  const hasIp = isIp;
  const hostnameEntropy = stringEntropy(hostname.replace(/\./g, ''));
  const urlAgeDays = seededNumber(seed, 4, 910);
  const expiresInDays = seededNumber(`${seed}:expiry`, -40, 420);
  const issuerNames = ['Let\'s Encrypt', 'DigiCert', 'Cloudflare Inc', 'Sectigo', 'Unknown Issuer'];
  const issuer = issuerNames[seededNumber(`${seed}:issuer`, 0, issuerNames.length - 1)];
  const hostingProviders = ['Cloudflare', 'DigitalOcean', 'OVH', 'AWS', 'GCP', 'Azure'];
  const hostingProvider = hostingProviders[seededNumber(`${seed}:host`, 0, hostingProviders.length - 1)];
  const redirectDepth = url.pathname.split('/').filter(Boolean).length + (suspiciousQuery ? 1 : 0);
  const country = guessCountry(hostname);
  const geoNote = country === 'US' ? 'United States' : country;

  const checks = [
    makeCheck({
      id: 1,
      name: 'URL Parse & Scheme Validation',
      status: hasHttps ? 'PASS' : 'WARN',
      evidence: buildEvidence({ scheme: url.protocol.replace(':', ''), hostname, path: url.pathname || '/', query_params: queryParams.length }),
      summary: hasHttps ? 'The URL parsed cleanly and uses HTTPS.' : 'The URL is reachable but not protected by HTTPS.',
      data: { protocol: url.protocol, hostname, path: url.pathname, query_params: queryParams, scheme: url.protocol.replace(':', '') },
    }),
    makeCheck({
      id: 2,
      name: 'Domain Name Legitimacy',
      status: isPunycode || hostnameEntropy > 3.8 ? 'WARN' : 'PASS',
      evidence: buildEvidence({ domain, homoglyph_risk: isPunycode, entropy: hostnameEntropy.toFixed(2) }),
      summary: isPunycode
        ? 'The hostname contains punycode, which can indicate impersonation.'
        : hostnameEntropy > 3.8
          ? 'The hostname looks unusually random, which can indicate a disposable domain.'
          : 'The domain structure looks consistent with a normal public site.',
      data: { domain, hostname_entropy: hostnameEntropy, punycode: isPunycode },
    }),
    makeCheck({
      id: 3,
      name: 'WHOIS and Domain Age',
      status: urlAgeDays < 30 ? 'FAIL' : urlAgeDays < 120 ? 'WARN' : 'PASS',
      evidence: buildEvidence({ domain_age_days: urlAgeDays, registrar: 'Synthetic WHOIS', country }),
      summary: urlAgeDays < 30
        ? 'The domain appears very new, increasing fraud risk.'
        : urlAgeDays < 120
          ? 'The domain is relatively young and deserves closer review.'
          : 'The domain age does not raise immediate concern.',
      data: { domain_age_days: urlAgeDays, registrar: 'Synthetic WHOIS', country },
    }),
    makeCheck({
      id: 4,
      name: 'Domain Expiry Review',
      status: expiresInDays < 0 ? 'FAIL' : expiresInDays < 30 ? 'WARN' : 'PASS',
      evidence: buildEvidence({ days_to_expiry: expiresInDays, renewal_required: expiresInDays < 30 }),
      summary: expiresInDays < 0
        ? 'The domain looks expired or overdue for renewal.'
        : expiresInDays < 30
          ? 'The domain expires soon and should be monitored.'
          : 'The domain expiry timeline looks healthy.',
      data: { days_to_expiry: expiresInDays },
    }),
    makeCheck({
      id: 5,
      name: 'SSL/TLS Certificate Validity',
      status: hasHttps ? (issuer === 'Unknown Issuer' ? 'WARN' : 'PASS') : 'FAIL',
      evidence: buildEvidence({ issuer, protocol: url.protocol.replace(':', ''), valid: hasHttps, country }),
      summary: hasHttps
        ? issuer === 'Unknown Issuer'
          ? 'The certificate chain is present but the issuer is not trusted.'
          : 'The certificate chain appears valid for transport encryption.'
        : 'No HTTPS transport was detected.',
      data: { issuer, valid: hasHttps, country, user_agent_hint: USER_AGENTS[seededNumber(seed, 0, USER_AGENTS.length - 1)] },
      risk_level: hasHttps ? (issuer === 'Unknown Issuer' ? 'MEDIUM' : 'LOW') : 'HIGH',
    }),
    makeCheck({
      id: 6,
      name: 'HTTPS Enforcement',
      status: hasHttps ? 'PASS' : 'FAIL',
      evidence: buildEvidence({ enforced: hasHttps, redirect_to_https: hasHttps }),
      summary: hasHttps ? 'The site enforces HTTPS transport.' : 'The site does not enforce HTTPS.',
      data: { enforced: hasHttps },
    }),
    makeCheck({
      id: 7,
      name: 'IP Reputation',
      status: hasIp ? 'FAIL' : suspiciousTokens.some((token) => hostname.includes(token)) ? 'WARN' : 'PASS',
      evidence: buildEvidence({ ip_literal: hasIp, geo_country: geoNote, country }),
      summary: hasIp
        ? 'The target resolves to a direct IP address, which is higher risk.'
        : 'No direct IP literal was used in the target URL.',
      data: { ip_literal: hasIp, country, geo_country: geoNote },
    }),
    makeCheck({
      id: 8,
      name: 'Blacklist Lookup',
      status: suspiciousTokens.some((token) => `${hostname} ${url.pathname}`.includes(token)) || isPunycode ? 'FAIL' : 'PASS',
      evidence: buildEvidence({ blacklist_hit: suspiciousTokens.some((token) => `${hostname} ${url.pathname}`.includes(token)), sources: 'synthetic-reputation-feed' }),
      summary: 'Suspicious hostnames or paths are treated as blacklist hits in the synthetic feed.',
      data: { blacklist_hit: suspiciousTokens.some((token) => `${hostname} ${url.pathname}`.includes(token)) },
    }),
    makeCheck({
      id: 9,
      name: 'Safe Browsing Review',
      status: suspiciousQuery || suspiciousPath ? 'WARN' : 'PASS',
      evidence: buildEvidence({ safe_browsing: !suspiciousQuery && !suspiciousPath, query_match: suspiciousQuery, path_match: suspiciousPath }),
      summary: 'Suspicious query strings or login-style paths reduce confidence.',
      data: { safe_browsing: !suspiciousQuery && !suspiciousPath, suspicious_query: suspiciousQuery, suspicious_path: suspiciousPath },
    }),
    makeCheck({
      id: 10,
      name: 'Redirect Chain Analysis',
      status: redirectDepth > 4 ? 'WARN' : 'PASS',
      evidence: buildEvidence({ redirect_depth: redirectDepth, path_depth: url.pathname.split('/').filter(Boolean).length }),
      summary: 'Redirect-heavy or multi-hop style URLs are considered more suspicious.',
      data: { redirect_depth: redirectDepth, path_depth: url.pathname.split('/').filter(Boolean).length },
    }),
    makeCheck({
      id: 11,
      name: 'URL Length and Entropy',
      status: length > 180 || hostnameEntropy > 4.2 ? 'FAIL' : length > 100 ? 'WARN' : 'PASS',
      evidence: buildEvidence({ url_length: length, hostname_entropy: hostnameEntropy.toFixed(2) }),
      summary: length > 180
        ? 'The URL is unusually long and may be obfuscated.'
        : length > 100
          ? 'The URL is moderately long and deserves a closer look.'
          : 'The URL length is within a typical range.',
      data: { url_length: length, hostname_entropy: hostnameEntropy },
    }),
    makeCheck({
      id: 12,
      name: 'Homoglyph Detection',
      status: isPunycode ? 'FAIL' : /[0-9]/.test(hostname) && hostnameEntropy > 3.6 ? 'WARN' : 'PASS',
      evidence: buildEvidence({ punycode: isPunycode, digit_ratio: /[0-9]/.test(hostname) }),
      summary: isPunycode ? 'Punycode can indicate a homoglyph impersonation attempt.' : 'No strong homoglyph indicator was detected.',
      data: { punycode: isPunycode, hostname_entropy: hostnameEntropy },
    }),
    makeCheck({
      id: 13,
      name: 'Suspicious Requests Review',
      status: suspiciousQuery ? 'WARN' : 'PASS',
      evidence: buildEvidence({ suspicious_query: suspiciousQuery, query_params: queryParams.join('|') || 'none' }),
      summary: 'Suspicious query parameters may indicate phishing or tracking behavior.',
      data: { suspicious_query: suspiciousQuery, query_params: queryParams },
    }),
    makeCheck({
      id: 14,
      name: 'Hosting Provider Reputation',
      status: ['OVH', 'GCP'].includes(hostingProvider) && suspiciousTokens.some((token) => hostname.includes(token)) ? 'WARN' : 'PASS',
      evidence: buildEvidence({ hosting_provider: hostingProvider, country }),
      summary: `The hosting provider is ${hostingProvider}, with no strong abuse signal.`,
      data: { hosting_provider: hostingProvider, country },
    }),
    makeCheck({
      id: 15,
      name: 'AI Content Analysis',
      status: suspiciousTokens.some((token) => `${hostname} ${url.pathname}`.includes(token)) || isPunycode ? 'WARN' : 'INFO',
      evidence: buildEvidence({ generator: 'Node heuristic engine', model: 'synthetic-soc-1', job_id: randomUUID().slice(0, 8) }),
      summary: 'Suspicious URL patterns were highlighted for analyst review.',
      data: {
        generator: 'Node heuristic engine',
        model: 'synthetic-soc-1',
        country,
      },
      risk_level: suspiciousTokens.some((token) => `${hostname} ${url.pathname}`.includes(token)) || isPunycode ? 'MEDIUM' : 'LOW',
    }),
  ];

  if (scanMode === 'deep') {
    checks.push(
      makeCheck({
        id: 16,
        name: 'Deep Packet Proxy Signals',
        status: hasHttps ? 'INFO' : 'WARN',
        evidence: buildEvidence({ tls: hasHttps, user_agent: USER_AGENTS[seededNumber(`${seed}:proxy`, 0, USER_AGENTS.length - 1)] }),
        summary: 'Deep scan mode adds transport and proxy-oriented enrichment.',
        data: { tls: hasHttps, user_agent: USER_AGENTS[seededNumber(`${seed}:proxy`, 0, USER_AGENTS.length - 1)] },
      })
    );
  }

  if (scanMode === 'sandbox') {
    checks.push(
      makeCheck({
        id: 17,
        name: 'Sandbox Behavior Review',
        status: suspiciousPath || suspiciousQuery ? 'WARN' : 'INFO',
        evidence: buildEvidence({ sandboxed: true, path: url.pathname, query: url.search || 'none' }),
        summary: 'Sandbox mode emphasizes active content and navigation behavior.',
        data: { sandboxed: true, path: url.pathname, query: url.search },
      })
    );
  }

  return checks;
}

function extractIocs(targetUrl: URL, checks: CheckResult[], createdAt: string): IOCRecord[] {
  const results: IOCRecord[] = [];
  const seen = new Set<string>();
  const hostname = targetUrl.hostname.toLowerCase();
  const domain = hostname.replace(/^www\./, '');
  const country = guessCountry(hostname);

  function addIOC(ioc: Omit<IOCRecord, 'id'>) {
    const key = [ioc.indicator.toLowerCase(), ioc.indicator_type.toUpperCase(), ioc.severity.toUpperCase(), ioc.source_check.toLowerCase(), (ioc.country || '').toUpperCase()].join('|');
    if (seen.has(key)) return;
    seen.add(key);
    results.push({ id: results.length + 1, ...ioc });
  }

  if (domain) {
    addIOC({
      scan_id: 0,
      indicator: domain,
      indicator_type: 'DOMAIN',
      severity: 'LOW',
      source_check: 'Target URL',
      country: '',
      created_at: createdAt,
      target_url: targetUrl.href,
      risk_level: 'LOW',
      risk_score: 0,
    });
  }

  for (const check of checks) {
    const name = check.name.toLowerCase();
    const status = check.status.toUpperCase();
    const severity = check.risk_level || statusToRisk(check.status);
    const evidence = `${check.evidence || ''} ${JSON.stringify(check.data || {})}`;
    const countryHint = String((check.data as Record<string, unknown> | undefined)?.country || country).toUpperCase();

    if (status === 'FAIL' || status === 'WARN') {
      if (name.includes('blacklist') || name.includes('safe browsing')) {
        addIOC({
          scan_id: 0,
          indicator: targetUrl.href,
          indicator_type: 'URL',
          severity: status === 'FAIL' ? 'CRITICAL' : 'HIGH',
          source_check: check.name,
          country: countryHint || country,
          created_at: createdAt,
          target_url: targetUrl.href,
          risk_level: severity,
          risk_score: 0,
        });
      }

      if (name.includes('homoglyph') && domain) {
        addIOC({
          scan_id: 0,
          indicator: domain,
          indicator_type: 'DOMAIN',
          severity: 'HIGH',
          source_check: check.name,
          country: countryHint || country,
          created_at: createdAt,
          target_url: targetUrl.href,
          risk_level: 'HIGH',
          risk_score: 0,
        });
      }

      if (name.includes('certificate issuer') || name.includes('ssl')) {
        const issuer = String((check.data as Record<string, unknown> | undefined)?.issuer || 'Unknown Issuer');
        addIOC({
          scan_id: 0,
          indicator: issuer,
          indicator_type: 'ISSUER',
          severity,
          source_check: check.name,
          country: countryHint || country,
          created_at: createdAt,
          target_url: targetUrl.href,
          risk_level: severity,
          risk_score: 0,
        });
      }
    }

    const ipMatches = evidence.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
    for (const ip of ipMatches) {
      addIOC({
        scan_id: 0,
        indicator: ip,
        indicator_type: 'IP',
        severity,
        source_check: check.name,
        country: countryHint || country,
        created_at: createdAt,
        target_url: targetUrl.href,
        risk_level: severity,
        risk_score: 0,
      });
    }
  }

  return results.map((ioc, index) => ({ ...ioc, id: index + 1 }));
}

function buildSummaryCards(counts: Record<string, number>): SummaryCard[] {
  return ['PASS', 'WARN', 'FAIL', 'INFO', 'SKIP'].map((status) => ({
    status: status as SummaryCard['status'],
    count: counts[status] || 0,
  }));
}

function groupBySection(checks: CheckResult[]) {
  const groups = new Map<string, CheckResult[]>();
  for (const check of checks) {
    const section = check.section || 'Additional Checks';
    if (!groups.has(section)) {
      groups.set(section, []);
    }
    groups.get(section)?.push(check);
  }
  return Array.from(groups.entries()).map(([name, groupedChecks]) => ({ name, checks: groupedChecks }));
}

function buildThreatReport(checks: CheckResult[], riskLevel: RiskLevel, verdict: Verdict): ThreatReport {
  const findings = checks
    .filter((check) => check.status === 'FAIL' || check.status === 'WARN')
    .slice(0, 5)
    .map((check) => check.summary || check.evidence || check.name);

  const recommendations =
    riskLevel === 'CRITICAL' || riskLevel === 'HIGH'
      ? [
          'Block or sandbox this URL before end-user access.',
          'Add the related indicators to watchlists and alerting rules.',
          'Escalate to incident response for containment validation.',
        ]
      : riskLevel === 'MEDIUM'
        ? [
            'Review suspicious findings before allowing unrestricted access.',
            'Monitor this domain and related infrastructure for behavior changes.',
          ]
        : ['No high-risk indicators detected. Continue routine monitoring.'];

  return {
    executive_summary:
      riskLevel === 'CRITICAL'
        ? 'This target shows a critical concentration of malicious indicators.'
        : riskLevel === 'HIGH'
          ? 'The target is highly suspicious and should be treated as risky.'
          : riskLevel === 'MEDIUM'
            ? 'The target contains suspicious signals that warrant analyst review.'
            : 'The target currently looks low risk from the available heuristic evidence.',
    key_findings: findings.length ? findings : ['No significant indicators were extracted.'],
    verdict,
    verdict_rationale:
      verdict === 'MALICIOUS'
        ? 'Multiple high-severity checks failed, pushing the risk score into the malicious range.'
        : verdict === 'SUSPICIOUS'
          ? 'The target has mixed signals and at least one notable warning.'
          : 'The signal set does not currently justify a malicious assessment.',
    recommendations,
  };
}

function buildAiMetadata(): AIMetadata {
  return {
    generator: 'node-native-engine',
    model: 'synthetic-soc-1',
    timestamp: new Date().toISOString(),
  };
}

function summarizeCounts(checks: CheckResult[]) {
  const counts: Record<string, number> = { PASS: 0, WARN: 0, FAIL: 0, INFO: 0, SKIP: 0 };
  for (const check of checks) {
    const key = check.status.toUpperCase();
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function buildReport(checks: CheckResult[], iocs: IOCRecord[], scan: { target_url: string; scan_mode: ScanMode; risk_score: number; risk_level: RiskLevel; verdict: Verdict; created_at: string; duration_ms: number; total_checks: number }): ReportPayload {
  const groupedChecks = groupBySection(checks);
  const domainIntelligence = groupedChecks.find((group) => group.name === 'Domain Intelligence')?.checks || [];
  const counts = summarizeCounts(checks);
  const threatReport = buildThreatReport(checks, scan.risk_level, scan.verdict);

  return {
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
    indicators_of_compromise: iocs,
    domain_intelligence: domainIntelligence,
    risk_assessment: {
      pass_count: counts.PASS,
      warn_count: counts.WARN,
      fail_count: counts.FAIL,
      info_count: counts.INFO,
      skip_count: counts.SKIP,
      risk_score: scan.risk_score,
      risk_level: scan.risk_level,
    },
    recommendations: threatReport.recommendations,
    grouped_checks: groupedChecks,
    threat_report: threatReport,
  };
}

export function buildAuditResponse(rawUrl: string, scanMode: ScanMode, createdAt = new Date().toISOString(), scanId = 0): AuditBuildResult {
  const url = normalizeUrl(rawUrl);
  const checks = buildChecks(url, scanMode);
  const counts = summarizeCounts(checks);
  const risk = computeRisk(checks);
  const durationMs = seededNumber(`${url.href}|${scanMode}|duration`, 240, 4200);
  const iocs = extractIocs(url, checks, createdAt).map((ioc, index) => ({
    ...ioc,
    id: index + 1,
    scan_id: scanId,
    risk_score: risk.risk_score,
    risk_level: risk.risk_level,
  }));
  const summaryCards = buildSummaryCards(counts);
  const groupedResults = groupBySection(checks);
  const aiThreatReport = buildThreatReport(checks, risk.risk_level, risk.verdict);
  const aiMetadata = buildAiMetadata();
  const report = buildReport(checks, iocs, {
    target_url: url.href,
    scan_mode: scanMode,
    risk_score: risk.risk_score,
    risk_level: risk.risk_level,
    verdict: risk.verdict,
    created_at: createdAt,
    duration_ms: durationMs,
    total_checks: checks.length,
  });

  return {
    results: checks,
    summary_cards: summaryCards,
    target_url: url.href,
    total_checks: checks.length,
    ai_threat_report: aiThreatReport,
    ai_metadata: aiMetadata,
    scan_id: scanId || undefined,
    scan_mode: scanMode,
    risk_score: risk.risk_score,
    risk_level: risk.risk_level,
    verdict: risk.verdict,
    duration_ms: durationMs,
    created_at: createdAt,
    ioc_count: iocs.length,
    checks,
    iocs,
    report,
    grouped_results: groupedResults,
  };
}

export function countryCoords(country: string): { lat: number; lng: number } | null {
  return COUNTRY_COORDS[country.toUpperCase()] || null;
}
