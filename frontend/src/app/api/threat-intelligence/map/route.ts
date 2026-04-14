import { NextResponse } from 'next/server';
import { getThreatMap } from '@/server/store';

export const runtime = 'nodejs';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const range = searchParams.get('range') || '24h';
  return NextResponse.json(await getThreatMap(range));
}
