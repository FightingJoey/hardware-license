// Canonical JSON, matching internal/license/canonical.go. The two
// implementations MUST stay byte-for-byte compatible because we hash
// the output of each to drive signatures and HMACs.
//
// Rules:
//   - object keys sorted by UTF-16 code units
//   - no whitespace
//   - integers only (we never serialise floats); reject anything else
//   - mandatory string escapes only (\b \t \n \f \r \" \\ \uXXXX for
//     control chars), all other code points emitted as raw UTF-8

export function canonicalJSON(value: unknown): Buffer {
  const out: string[] = [];
  encode(value, out);
  return Buffer.from(out.join(''), 'utf8');
}

function encode(v: unknown, out: string[]): void {
  if (v === null || v === undefined) {
    out.push('null');
    return;
  }
  switch (typeof v) {
    case 'boolean':
      out.push(v ? 'true' : 'false');
      return;
    case 'string':
      out.push(encodeString(v));
      return;
    case 'number':
      if (!Number.isFinite(v) || Math.trunc(v) !== v) {
        throw new Error(`canonical: only integers are supported (got ${v})`);
      }
      out.push(v.toString(10));
      return;
    case 'bigint':
      out.push(v.toString(10));
      return;
    case 'object':
      if (Array.isArray(v)) {
        out.push('[');
        v.forEach((item, i) => {
          if (i > 0) out.push(',');
          encode(item, out);
        });
        out.push(']');
        return;
      }
      // Plain object
      const obj = v as Record<string, unknown>;
      const keys = Object.keys(obj).sort(compareUtf16);
      out.push('{');
      keys.forEach((k, i) => {
        if (i > 0) out.push(',');
        out.push(encodeString(k));
        out.push(':');
        encode(obj[k], out);
      });
      out.push('}');
      return;
  }
  throw new Error(`canonical: unsupported type ${typeof v}`);
}

function compareUtf16(a: string, b: string): number {
  // String comparison in JS is already UTF-16 code-unit lexicographic.
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function encodeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    switch (cp) {
      case 0x22:
        out += '\\"';
        break;
      case 0x5c:
        out += '\\\\';
        break;
      case 0x08:
        out += '\\b';
        break;
      case 0x09:
        out += '\\t';
        break;
      case 0x0a:
        out += '\\n';
        break;
      case 0x0c:
        out += '\\f';
        break;
      case 0x0d:
        out += '\\r';
        break;
      default:
        if (cp < 0x20) {
          out += '\\u' + cp.toString(16).padStart(4, '0');
        } else {
          out += ch;
        }
    }
  }
  out += '"';
  return out;
}
