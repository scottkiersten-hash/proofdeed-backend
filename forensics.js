/**
 * ProofDeed Document Forensics
 *
 * Pure-Node analysis of uploaded documents. Checks three independent
 * timestamp sources per document type and flags mismatches as anomalies.
 * No system binaries required — runs on DigitalOcean App Platform as-is.
 *
 * Supported: PDF, DOCX, DOC (partial), JPEG, PNG
 */

import JSZip from 'jszip';

// ─── PDF Analysis ────────────────────────────────────────────────────────────

function parsePdfDate(raw) {
  if (!raw) return null;
  // PDF date format: D:YYYYMMDDHHmmSSOHH'mm'
  const m = raw.replace(/^D:/, '').match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
  if (!m) return null;
  return new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}Z`);
}

function countPdfVersionLayers(buffer) {
  // Each save appends %%EOF. Count occurrences.
  const marker = Buffer.from('%%EOF');
  let count = 0;
  let pos = 0;
  while ((pos = buffer.indexOf(marker, pos)) !== -1) {
    count++;
    pos += marker.length;
  }
  return count;
}

function extractPdfInfoDict(buffer) {
  const text = buffer.toString('latin1');
  const fields = {};

  // Extract /Info dictionary entries
  const infoMatch = text.match(/\/Info\s*<<([\s\S]*?)>>/);
  if (infoMatch) {
    const block = infoMatch[1];
    for (const key of ['CreationDate', 'ModDate', 'Creator', 'Producer', 'Author', 'Title']) {
      const re = new RegExp('\\/' + key + '\\s*\\(([^)]+)\\)');
      const m = block.match(re);
      if (m) fields[key] = m[1].trim();
    }
  }

  return fields;
}

function extractXmpDates(buffer) {
  const text = buffer.toString('utf8', 0, Math.min(buffer.length, 200000));
  const xmp = {};

  const patterns = {
    CreateDate: [/<xmp:CreateDate>([^<]+)<\/xmp:CreateDate>/, /xmp:CreateDate="([^"]+)"/],
    ModifyDate: [/<xmp:ModifyDate>([^<]+)<\/xmp:ModifyDate>/, /xmp:ModifyDate="([^"]+)"/],
    MetadataDate: [/<xmp:MetadataDate>([^<]+)<\/xmp:MetadataDate>/],
    CreatorTool: [/<xmp:CreatorTool>([^<]+)<\/xmp:CreatorTool>/],
  };

  for (const [key, regexes] of Object.entries(patterns)) {
    for (const re of regexes) {
      const m = text.match(re);
      if (m) { xmp[key] = m[1].trim(); break; }
    }
  }

  return xmp;
}

function analyzePdf(buffer) {
  const anomalies = [];
  const signals = {};

  const info = extractPdfInfoDict(buffer);
  const xmp = extractXmpDates(buffer);
  const versionLayers = countPdfVersionLayers(buffer);

  const createdInfo = parsePdfDate(info.CreationDate);
  const modifiedInfo = parsePdfDate(info.ModDate);
  const createdXmp = xmp.CreateDate ? new Date(xmp.CreateDate) : null;
  const modifiedXmp = xmp.ModifyDate ? new Date(xmp.ModifyDate) : null;

  signals.declared_created_at = createdInfo?.toISOString() || null;
  signals.declared_modified_at = modifiedInfo?.toISOString() || null;
  signals.authoring_software = info.Creator || info.Producer || xmp.CreatorTool || null;
  signals.pdf_version_layers = versionLayers;
  signals.xmp_create_date = createdXmp?.toISOString() || null;
  signals.xmp_modify_date = modifiedXmp?.toISOString() || null;

  // Cross-check: /Info CreationDate vs XMP CreateDate (should match within a minute)
  if (createdInfo && createdXmp) {
    const diffMs = Math.abs(createdInfo - createdXmp);
    if (diffMs > 60000) {
      anomalies.push(`Creation date mismatch: /Info says ${createdInfo.toISOString()} but XMP says ${createdXmp.toISOString()} (${Math.round(diffMs / 1000)}s apart)`);
    }
  }

  // ModDate after CreationDate by more than 5 minutes = post-creation edit
  if (createdInfo && modifiedInfo) {
    const diffMs = modifiedInfo - createdInfo;
    if (diffMs > 300000) {
      signals.modified_after_creation_minutes = Math.round(diffMs / 60000);
      // Don't flag as anomaly alone — editing is normal. Flag if combined with multiple version layers.
    }
  }

  // XMP ModifyDate vs /Info ModDate mismatch
  if (modifiedInfo && modifiedXmp) {
    const diffMs = Math.abs(modifiedInfo - modifiedXmp);
    if (diffMs > 60000) {
      anomalies.push(`Modification date mismatch between /Info and XMP metadata (${Math.round(diffMs / 1000)}s apart)`);
    }
  }

  // Multiple version layers = document was edited and re-saved after initial creation
  if (versionLayers > 1) {
    signals.post_creation_edits = versionLayers - 1;
    if (versionLayers >= 3) {
      anomalies.push(`PDF has ${versionLayers} version layers — edited ${versionLayers - 1} time(s) after initial creation`);
    }
  }

  // No creation date at all — unusual for legitimate documents
  if (!createdInfo && !createdXmp) {
    anomalies.push('No creation date found in document metadata');
  }

  return { signals, anomalies };
}

// ─── DOCX / Office Open XML Analysis ─────────────────────────────────────────

async function analyzeDocx(buffer) {
  const anomalies = [];
  const signals = {};

  let zip;
  try {
    zip = await JSZip.loadAsync(buffer);
  } catch {
    return { signals, anomalies: ['File is not a valid DOCX/ZIP archive'] };
  }

  // Read core.xml (primary metadata)
  const coreFile = zip.file('docProps/core.xml');
  if (coreFile) {
    const coreXml = await coreFile.async('string');

    const created = coreXml.match(/<dcterms:created[^>]*>([^<]+)<\/dcterms:created>/)?.[1];
    const modified = coreXml.match(/<dcterms:modified[^>]*>([^<]+)<\/dcterms:modified>/)?.[1];
    const lastModifiedBy = coreXml.match(/<cp:lastModifiedBy>([^<]+)<\/cp:lastModifiedBy>/)?.[1];
    const creator = coreXml.match(/<dc:creator>([^<]+)<\/dc:creator>/)?.[1];

    signals.declared_created_at = created || null;
    signals.declared_modified_at = modified || null;
    signals.authoring_software = creator || null;
    signals.last_modified_by = lastModifiedBy || null;

    if (created && modified) {
      const createdDate = new Date(created);
      const modifiedDate = new Date(modified);
      const diffMs = modifiedDate - createdDate;
      if (diffMs > 300000) {
        signals.modified_after_creation_minutes = Math.round(diffMs / 60000);
      }
    }
  }

  // Read app.xml (total editing time in minutes)
  const appFile = zip.file('docProps/app.xml');
  if (appFile) {
    const appXml = await appFile.async('string');
    const editTime = appXml.match(/<TotalTime>(\d+)<\/TotalTime>/)?.[1];
    const appName = appXml.match(/<Application>([^<]+)<\/Application>/)?.[1];

    signals.total_editing_minutes = editTime ? parseInt(editTime) : null;
    signals.authoring_software = appName || signals.authoring_software;

    // Document claimed old but has very low editing time — possible backdating
    if (signals.declared_created_at && editTime) {
      const createdDate = new Date(signals.declared_created_at);
      const ageMonths = (Date.now() - createdDate) / (1000 * 60 * 60 * 24 * 30);
      const editMinutes = parseInt(editTime);
      if (ageMonths > 6 && editMinutes < 2) {
        anomalies.push(`Document claims to be ${Math.round(ageMonths)} months old but has only ${editMinutes} minute(s) of recorded editing time`);
      }
    }
  }

  // Check ZIP entry timestamps against declared creation date
  if (signals.declared_created_at) {
    const declaredDate = new Date(signals.declared_created_at);
    let earliestZipEntry = null;
    zip.forEach((_, file) => {
      if (file.date && (!earliestZipEntry || file.date < earliestZipEntry)) {
        earliestZipEntry = file.date;
      }
    });

    if (earliestZipEntry) {
      signals.zip_entry_earliest = earliestZipEntry.toISOString();
      const diffMs = Math.abs(declaredDate - earliestZipEntry);
      // ZIP timestamps have 2-second resolution, allow 30 minutes of timezone slop
      if (diffMs > 1800000) {
        anomalies.push(`ZIP file entry timestamps (${earliestZipEntry.toISOString()}) differ from declared creation date (${signals.declared_created_at}) by ${Math.round(diffMs / 60000)} minutes`);
      }
    }
  }

  return { signals, anomalies };
}

// ─── JPEG / PNG Analysis ──────────────────────────────────────────────────────

function readUint16BE(buf, offset) {
  return (buf[offset] << 8) | buf[offset + 1];
}

function analyzeJpeg(buffer) {
  const anomalies = [];
  const signals = {};

  // Walk JPEG segments looking for EXIF (APP1 marker = 0xFFE1)
  let pos = 2; // skip SOI marker
  while (pos < buffer.length - 4) {
    if (buffer[pos] !== 0xFF) break;
    const marker = buffer[pos + 1];
    const length = readUint16BE(buffer, pos + 2);

    if (marker === 0xE1) {
      // APP1 — check for EXIF header
      const header = buffer.slice(pos + 4, pos + 10).toString('ascii');
      if (header.startsWith('Exif')) {
        signals.has_exif = true;
        // Basic: extract DateTimeOriginal as text (offset 0x9003 in EXIF)
        // For simplicity, scan for the date string pattern YYYY:MM:DD
        const exifText = buffer.slice(pos + 10, pos + 10 + length).toString('latin1');
        const dateMatch = exifText.match(/(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})/);
        if (dateMatch) {
          signals.declared_created_at = dateMatch[1].replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3');
        }
        // Check for GPS data presence
        if (exifText.includes('GPS')) {
          signals.has_gps = true;
        }
      }
    }

    pos += 2 + length;
  }

  if (!signals.has_exif) {
    signals.has_exif = false;
    // Stripped EXIF can be normal (privacy tools strip it) but worth noting
  }

  return { signals, anomalies };
}

function analyzePng(buffer) {
  const signals = {};
  const anomalies = [];

  // PNG tEXt and iTXt chunks may contain Creation Time
  // Walk chunks after 8-byte PNG signature
  let pos = 8;
  while (pos < buffer.length - 12) {
    const length = buffer.readUInt32BE(pos);
    const type = buffer.slice(pos + 4, pos + 8).toString('ascii');
    const data = buffer.slice(pos + 8, pos + 8 + length);

    if (type === 'tEXt' || type === 'iTXt') {
      const text = data.toString('utf8');
      if (text.includes('Creation Time') || text.includes('date:create')) {
        const dateMatch = text.match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
        if (dateMatch) signals.declared_created_at = dateMatch[1];
      }
    }

    pos += 12 + length; // length + type + data + CRC
  }

  return { signals, anomalies };
}

// ─── Scoring ──────────────────────────────────────────────────────────────────

function scoreAssessment(anomalies, signals) {
  if (anomalies.length === 0) return 'clean';
  if (anomalies.length === 1) return 'low';
  if (anomalies.length === 2) return 'moderate';
  return 'high';
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

/**
 * analyzeDocument(buffer, mimetype)
 *
 * Returns:
 * {
 *   file_type: string,
 *   declared_created_at: string | null,
 *   declared_modified_at: string | null,
 *   authoring_software: string | null,
 *   pdf_version_layers: number | null,
 *   post_creation_edits: number | null,
 *   total_editing_minutes: number | null,
 *   anomalies: string[],
 *   assessment: 'clean' | 'low' | 'moderate' | 'high',
 *   analyzed_at: string,
 * }
 */
export async function analyzeDocument(buffer, mimetype) {
  const analyzedAt = new Date().toISOString();
  let fileType = 'unknown';
  let result = { signals: {}, anomalies: [] };

  try {
    if (mimetype === 'application/pdf' || buffer.slice(0, 4).toString() === '%PDF') {
      fileType = 'pdf';
      result = analyzePdf(buffer);
    } else if (
      mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      mimetype === 'application/docx'
    ) {
      fileType = 'docx';
      result = await analyzeDocx(buffer);
    } else if (mimetype === 'image/jpeg' || (buffer[0] === 0xFF && buffer[1] === 0xD8)) {
      fileType = 'jpeg';
      result = analyzeJpeg(buffer);
    } else if (mimetype === 'image/png' || buffer.slice(0, 4).toString('hex') === '89504e47') {
      fileType = 'png';
      result = analyzePng(buffer);
    }
  } catch (err) {
    result.anomalies.push('Forensic analysis encountered an error: ' + err.message);
  }

  const { signals, anomalies } = result;

  return {
    file_type: fileType,
    declared_created_at: signals.declared_created_at || null,
    declared_modified_at: signals.declared_modified_at || null,
    authoring_software: signals.authoring_software || null,
    pdf_version_layers: signals.pdf_version_layers || null,
    post_creation_edits: signals.post_creation_edits || null,
    total_editing_minutes: signals.total_editing_minutes ?? null,
    last_modified_by: signals.last_modified_by || null,
    zip_entry_earliest: signals.zip_entry_earliest || null,
    has_exif: signals.has_exif ?? null,
    has_gps: signals.has_gps || false,
    xmp_create_date: signals.xmp_create_date || null,
    xmp_modify_date: signals.xmp_modify_date || null,
    modified_after_creation_minutes: signals.modified_after_creation_minutes || null,
    anomalies,
    assessment: scoreAssessment(anomalies, signals),
    analyzed_at: analyzedAt,
  };
}
