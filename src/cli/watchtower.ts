import { WatchtowerScanArtifact } from './watchtower-artifact';

export interface WatchtowerEnrollment {
  apiKey: string | null;
  baseUrl: string;
  dashboardUrl: string;
  email: string;
  endpointPath: string;
  message?: string;
  status: 'created' | 'existing';
}

function isLoopbackHost(host: string): boolean {
  return ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host.toLowerCase());
}

export function buildWatchtowerApiUrl(baseUrl: string, endpointPath: string): string {
  let parsedBaseUrl: URL;

  try {
    parsedBaseUrl = new URL(baseUrl);
  } catch {
    throw new Error('REINS_WATCHTOWER_BASE_URL is not a valid URL.');
  }

  if (parsedBaseUrl.protocol !== 'https:' && !(parsedBaseUrl.protocol === 'http:' && isLoopbackHost(parsedBaseUrl.hostname))) {
    throw new Error('REINS_WATCHTOWER_BASE_URL must use HTTPS unless it targets localhost, 127.0.0.1, or ::1.');
  }

  parsedBaseUrl.pathname = `${parsedBaseUrl.pathname.replace(/\/+$/, '')}${endpointPath}`;
  return parsedBaseUrl.toString();
}

function readStringField(payload: unknown, ...keys: string[]): string | null {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const record = payload as Record<string, unknown>;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }

  return null;
}

async function readErrorBody(response: Response): Promise<string> {
  try {
    return (await response.text()).trim();
  } catch {
    return '';
  }
}

async function postWatchtowerConnectRequest(
  baseUrl: string,
  endpointPath: string,
  body: string
): Promise<Response> {
  const connectUrl = buildWatchtowerApiUrl(baseUrl, endpointPath);
  return fetch(connectUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body,
  });
}

export async function connectWatchtowerAccount(
  baseUrl: string,
  email: string,
  artifact: WatchtowerScanArtifact
): Promise<WatchtowerEnrollment> {
  const requestBody = JSON.stringify({
    email,
    repository: {
      displayName: artifact.target.display_name,
      id: artifact.target.id,
    },
    source: artifact.source,
  });
  const candidateEndpoints = ['/api/auth/signup-cli', '/api/watchtower/connect'];
  let response: Response | null = null;
  let endpointPath = candidateEndpoints[0];
  let lastError: string | null = null;

  for (const candidateEndpoint of candidateEndpoints) {
    endpointPath = candidateEndpoint;
    response = await postWatchtowerConnectRequest(baseUrl, candidateEndpoint, requestBody);

    if (response.status !== 404 && response.status !== 405) {
      break;
    }

    lastError = await readErrorBody(response);
    response = null;
  }

  if (!response) {
    throw new Error(
      `Watchtower connect failed. No supported connect endpoint found at ${candidateEndpoints.join(' or ')}${lastError ? `: ${lastError}` : '.'}`
    );
  }

  if (!response.ok) {
    const body = await readErrorBody(response);
    throw new Error(`Watchtower connect failed. ${response.status} ${response.statusText}${body ? `: ${body}` : ''}`);
  }

  const payload = (await response.json()) as unknown;
  const apiKey = readStringField(payload, 'apiKey', 'api_key');
  const dashboardUrl = readStringField(payload, 'dashboardUrl', 'dashboard_url');
  const message = readStringField(payload, 'message');

  if (!dashboardUrl) {
    throw new Error('Watchtower connect failed. Response missing dashboardUrl.');
  }

  return {
    apiKey,
    baseUrl,
    dashboardUrl,
    endpointPath,
    email,
    message: message || undefined,
    status: apiKey ? 'created' : 'existing',
  };
}

export async function uploadWatchtowerArtifact(
  baseUrl: string,
  accessToken: string,
  artifact: WatchtowerScanArtifact
): Promise<{ ingestUrl: string }> {
  const ingestUrl = buildWatchtowerApiUrl(baseUrl, '/api/scan-artifacts/ingest');
  const response = await fetch(ingestUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify(artifact),
  });

  if (!response.ok) {
    const body = await readErrorBody(response);
    throw new Error(`Watchtower upload failed. ${response.status} ${response.statusText}${body ? `: ${body}` : ''}`);
  }

  return { ingestUrl };
}
