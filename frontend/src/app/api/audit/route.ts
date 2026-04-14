import { NextResponse } from 'next/server';
import { createAudit } from '@/server/store';

export const runtime = 'nodejs';

export async function POST(request: Request) {
  const formData = await request.formData();
  const url = String(formData.get('url') || '').trim();
  const scanMode = String(formData.get('scan_mode') || 'scan').toLowerCase();

  if (!url) {
    return NextResponse.json({ error: 'Please enter a URL to audit.' }, { status: 400 });
  }

  const safeMode = scanMode === 'deep' || scanMode === 'sandbox' ? scanMode : 'scan';

  try {
    const payload = await createAudit(url, safeMode);
    return NextResponse.json(payload);
  } catch (error) {
    return NextResponse.json(
      {
        error: `Failed to audit URL: ${error instanceof Error ? error.message : 'Unknown error'}`,
      },
      { status: 500 }
    );
  }
}
