import { NextResponse } from 'next/server';
import { getScan } from '@/server/store';

export const runtime = 'nodejs';

export async function GET(_request: Request, { params }: { params: { scanId: string } }) {
  const { scanId } = params;
  const id = Number(scanId);
  if (!Number.isFinite(id)) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  const payload = await getScan(id);
  if (!payload) {
    return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
  }

  return NextResponse.json(payload);
}
