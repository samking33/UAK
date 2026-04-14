import { NextResponse } from 'next/server';
import { getTopMaliciousDomains } from '@/server/store';

export const runtime = 'nodejs';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const limit = Number(searchParams.get('limit') || '20');
  return NextResponse.json(await getTopMaliciousDomains(limit));
}
