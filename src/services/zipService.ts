import JSZip from 'jszip';
import { InvestigationResult } from '../types/investigation';

export async function packageInvestigationZip(result: InvestigationResult): Promise<{
  blob: Blob;
  filename: string;
  sizeFormatted: string;
}> {
  const zip = new JSZip();
  const safeEntity = result.scope.entity.trim().replace(/[^a-zA-Z0-9_-]/g, '_') || 'target';
  const timestampStr = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const zipFilename = `investigation_${safeEntity}_${timestampStr}.zip`;

  // Place inside root folder: investigation_<entity>/
  const rootFolder = zip.folder(`investigation_${safeEntity}`);

  for (const file of result.files) {
    if (rootFolder) {
      rootFolder.file(file.filename, file.content);
    } else {
      zip.file(file.filename, file.content);
    }
  }

  const blob = await zip.generateAsync({
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 }
  });

  const sizeKb = blob.size / 1024;
  const sizeFormatted = sizeKb > 1024 ? `${(sizeKb / 1024).toFixed(2)} MB` : `${sizeKb.toFixed(1)} KB`;

  return {
    blob,
    filename: zipFilename,
    sizeFormatted
  };
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
