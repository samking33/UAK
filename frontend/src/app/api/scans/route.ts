import { NextResponse } from 'next/server';
import { listScans } from '@/server/store';

export const runtime = 'nodejs';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const payload = await listScans({
    page: Number(searchParams.get('page') || '1'),
    pageSize: Number(searchParams.get('page_size') || '20'),
    q: searchParams.get('q') || '',
    risk: searchParams.get('risk') || '',
    status: searchParams.get('status') || '',
    sortBy: searchParams.get('sort_by') || 'created_at',
    sortOrder: searchParams.get('sort_order') === 'asc' ? 'asc' : 'desc',
  });
  return NextResponse.json(payload);
}
