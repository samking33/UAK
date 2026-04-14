import type {
  AuditResponse,
  DashboardOverview,
  IOCRecord,
  PagedResponse,
  ScanMode,
  ScanRecord,
  ScanProgressMessage,
  ThreatMapPoint,
} from '@/types';

export interface RunAuditOptions {
  url: string;
  scanMode: ScanMode;
  onProgress?: (message: ScanProgressMessage) => void;
}

type ProgressStage = {
  percent: number;
  label: string;
};

const PROGRESS_STAGES: Record<ScanMode, ProgressStage[]> = {
  scan: [
    { percent: 8, label: 'Preparing standard scan...' },
    { percent: 20, label: 'Resolving target and collecting headers...' },
    { percent: 36, label: 'Checking DNS, SSL, and response signals...' },
    { percent: 54, label: 'Scanning reputation and blacklist indicators...' },
    { percent: 72, label: 'Correlating threat telemetry...' },
    { percent: 88, label: 'Finalizing risk score and report...' },
  ],
  deep: [
    { percent: 8, label: 'Preparing deep analysis...' },
    { percent: 18, label: 'Resolving target and collecting headers...' },
    { percent: 32, label: 'Inspecting TLS posture and certificate chain...' },
    { percent: 48, label: 'Evaluating DNS, redirects, and page behavior...' },
    { percent: 66, label: 'Running extended reputation checks...' },
    { percent: 86, label: 'Synthesizing findings and scoring risk...' },
  ],
  sandbox: [
    { percent: 8, label: 'Preparing sandbox analysis...' },
    { percent: 18, label: 'Capturing target metadata...' },
    { percent: 34, label: 'Executing containment-safe checks...' },
    { percent: 52, label: 'Reviewing behavioral and network indicators...' },
    { percent: 70, label: 'Cross-checking IOC matches...' },
    { percent: 88, label: 'Finalizing sandbox report...' },
  ],
};

function fetchJSON<T>(path: string): Promise<T> {
  return fetch(path, {
    method: 'GET',
    cache: 'no-store',
  }).then((response) => {
    if (!response.ok) {
      throw new Error(`Request failed (${response.status})`);
    }
    return response.json() as Promise<T>;
  });
}

function startProgressSimulation(options: RunAuditOptions) {
  const stages = PROGRESS_STAGES[options.scanMode];
  const timers: ReturnType<typeof setTimeout>[] = [];
  let finished = false;
  let currentPercent = 0;

  const emit = (message: ScanProgressMessage) => {
    if (!finished) {
      options.onProgress?.(message);
    }
  };

  emit({
    type: 'start',
    percent: stages[0]?.percent ?? 5,
    label: stages[0]?.label ?? 'Preparing scan...',
  });
  currentPercent = stages[0]?.percent ?? 5;

  stages.slice(1).forEach((stage, index) => {
    timers.push(
      setTimeout(() => {
        if (finished) return;
        currentPercent = Math.max(currentPercent, stage.percent);
        emit({
          type: 'progress',
          step: index + 2,
          total: stages.length,
          percent: currentPercent,
          label: stage.label,
        });
      }, 400 + index * 550)
    );
  });

  const holdTimer = setInterval(() => {
    if (finished) return;
    const lastStage = stages[stages.length - 1];
    if (!lastStage) return;
    const nextPercent = Math.min(currentPercent + 1, 92);
    if (nextPercent !== currentPercent) {
      currentPercent = nextPercent;
      emit({
        type: 'progress',
        step: stages.length,
        total: stages.length,
        percent: currentPercent,
        label: lastStage.label,
      });
    }
  }, 700);

  return {
    complete(label = 'Scan complete') {
      if (finished) return;
      finished = true;
      timers.forEach(clearTimeout);
      clearInterval(holdTimer);
      options.onProgress?.({
        type: 'complete',
        percent: 100,
        label,
      });
    },
    fail(message = 'Scan failed') {
      if (finished) return;
      finished = true;
      timers.forEach(clearTimeout);
      clearInterval(holdTimer);
      options.onProgress?.({
        type: 'error',
        percent: currentPercent,
        label: 'Scan failed',
        message,
      });
    },
  };
}

export async function runAudit(options: RunAuditOptions): Promise<AuditResponse> {
  const progress = startProgressSimulation(options);

  const formData = new FormData();
  formData.append('url', options.url);
  formData.append('scan_mode', options.scanMode);

  try {
    const response = await fetch('/api/audit', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`Audit failed (${response.status})`);
    }

    const payload = (await response.json()) as AuditResponse;
    progress.complete();
    return payload;
  } catch (error) {
    progress.fail(error instanceof Error ? error.message : 'Audit failed');
    throw error;
  }
}

export async function getDashboardOverview(range: string): Promise<DashboardOverview> {
  return fetchJSON<DashboardOverview>(`/api/dashboard/overview?range=${encodeURIComponent(range)}`);
}

export async function getScans(params: {
  page: number;
  pageSize: number;
  q: string;
  risk: string;
  status: string;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
}): Promise<PagedResponse<ScanRecord>> {
  const searchParams = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
    q: params.q,
    risk: params.risk,
    status: params.status,
    sort_by: params.sortBy,
    sort_order: params.sortOrder,
  });
  return fetchJSON<PagedResponse<ScanRecord>>(`/api/scans?${searchParams.toString()}`);
}

export async function getScan(scanId: number): Promise<ScanRecord & { checks: any[]; iocs: IOCRecord[] }> {
  return fetchJSON(`/api/scans/${scanId}`);
}

export async function getScanReport(scanId: number): Promise<any> {
  return fetchJSON(`/api/scans/${scanId}/report`);
}

export async function getIOCs(params: {
  page: number;
  pageSize: number;
  q: string;
  type: string;
  severity: string;
  sortBy: string;
  sortOrder: 'asc' | 'desc';
}): Promise<PagedResponse<IOCRecord>> {
  const searchParams = new URLSearchParams({
    page: String(params.page),
    page_size: String(params.pageSize),
    q: params.q,
    type: params.type,
    severity: params.severity,
    sort_by: params.sortBy,
    sort_order: params.sortOrder,
  });
  return fetchJSON<PagedResponse<IOCRecord>>(`/api/iocs?${searchParams.toString()}`);
}

export async function getThreatMap(range: string): Promise<{ points: ThreatMapPoint[] }> {
  return fetchJSON(`/api/threat-intelligence/map?range=${encodeURIComponent(range)}`);
}

export async function getThreatDomains(limit = 20): Promise<{ items: Array<{ domain: string; hits: number; last_seen: string }> }> {
  return fetchJSON(`/api/threat-intelligence/domains?limit=${limit}`);
}

export async function getThreatIpReputation(
  limit = 20
): Promise<{ items: Array<{ ip: string; sightings: number; critical_hits: number; high_hits: number; medium_hits: number; last_seen: string }> }> {
  return fetchJSON(`/api/threat-intelligence/ip-reputation?limit=${limit}`);
}
