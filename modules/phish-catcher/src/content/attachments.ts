/**
 * Attachment risk classification (doc 07 §3.2 `content.attachment_risk`):
 * double extensions, macro-enabled types, ISO/IMG/HTA, executable types.
 * Operates on metadata only (filename, contentType, macroDetected) — the
 * attachment bytes never leave the client (§5.4: hash + type only).
 */

import type { AttachmentMeta } from "../core/evidence.js";

export type AttachmentRiskCategory =
  | "double_extension"
  | "macro_enabled"
  | "disk_image_or_hta"
  | "executable"
  | "archive";

export interface AttachmentRisk {
  category: AttachmentRiskCategory;
  severity: "info" | "low" | "medium" | "high" | "critical";
  weight: number;
  detail: string;
}

const DOUBLE_EXT_RE = /\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|zip|rar)\.[a-z0-9]{1,5}$/i;
const MACRO_EXT_RE = /\.(?:docm|xlsm|pptm|docb|xlam|pptm)$/i;
const LEGACY_OLE_RE = /\.(?:doc|xls|ppt)$/i;
const DISK_IMAGE_HTA_RE = /\.(?:iso|img|vhd|vhdx|hta)$/i;
const EXECUTABLE_RE = /\.(?:exe|scr|bat|cmd|com|pif|msi|msp|ps1|vbs|vbe|js|jse|wsf|wsh|jar|apk|dll|cpl|reg|lnk)$/i;
const ARCHIVE_RE = /\.(?:zip|rar|7z|tar|gz|cab|ace)$/i;

/** Classify one attachment; returns the highest-severity applicable risk. */
export function classifyAttachment(att: AttachmentMeta): AttachmentRisk | null {
  const name = att.filename.toLowerCase();
  const risks: AttachmentRisk[] = [];

  if (DOUBLE_EXT_RE.test(name)) {
    risks.push({
      category: "double_extension",
      severity: "high",
      weight: 20,
      detail: `attachment "${att.filename}" uses a double extension`,
    });
  }
  if (att.macroDetected === true || MACRO_EXT_RE.test(name)) {
    risks.push({
      category: "macro_enabled",
      severity: "high",
      weight: 25,
      detail: `attachment "${att.filename}" is macro-enabled`,
    });
  } else if (LEGACY_OLE_RE.test(name)) {
    risks.push({
      category: "macro_enabled",
      severity: "medium",
      weight: 15,
      detail: `attachment "${att.filename}" is a legacy OLE type that can carry macros`,
    });
  }
  if (DISK_IMAGE_HTA_RE.test(name)) {
    risks.push({
      category: "disk_image_or_hta",
      severity: "critical",
      weight: 30,
      detail: `attachment "${att.filename}" is a disk-image/HTA type abused by lure campaigns`,
    });
  }
  if (EXECUTABLE_RE.test(name)) {
    risks.push({
      category: "executable",
      severity: "high",
      weight: 30,
      detail: `attachment "${att.filename}" is an executable type`,
    });
  }
  if (risks.length === 0 && ARCHIVE_RE.test(name)) {
    risks.push({
      category: "archive",
      severity: "info",
      weight: 4,
      detail: `attachment "${att.filename}" is an archive (contents unknown)`,
    });
  }
  if (risks.length === 0) return null;
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  risks.sort((a, b) => rank[b.severity] - rank[a.severity] || b.weight - a.weight);
  return risks[0] ?? null;
}
