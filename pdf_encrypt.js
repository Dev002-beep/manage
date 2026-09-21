/**
 * AMG Ultra-Secure PDF Encryption Engine (Standard ISO 32000-1 RC4 128-bit Permissions Security)
 * Restricts Adobe Acrobat Pro / Nitro / Foxit from editing, OCR-modifying, or copying text
 * while preserving 100% full original 2.7MB vector fidelity.
 */

(function(global) {
  'use strict';

  // Permission Flags (ISO 32000-1 / ISO 32000-2 Table 22)
  const PERM_FLAGS = {
    PRINT:              0x00000004, // Bit 3
    MODIFY:             0x00000008, // Bit 4
    COPY:               0x00000010, // Bit 5
    ANNOTATE:           0x00000020, // Bit 6
    FILL_FORMS:         0x00000100, // Bit 9
    EXTRACT:            0x00000200, // Bit 10
    ASSEMBLE:           0x00000400, // Bit 11
    PRINT_HIGH_QUALITY: 0x00000800, // Bit 12
  };

  // Build the 32-bit signed /P value
  function buildPermissions(options = {}) {
    let P = 0xFFFFF000 | 0x000000C0;

    if (options.allowPrinting !== false) P |= PERM_FLAGS.PRINT;
    if (options.allowModifying === true) P |= PERM_FLAGS.MODIFY;
    if (options.allowCopying === true) P |= PERM_FLAGS.COPY;
    if (options.allowAnnotating === true) P |= PERM_FLAGS.ANNOTATE;
    if (options.allowFillingForms === true) P |= PERM_FLAGS.FILL_FORMS;
    if (options.allowExtraction === true) P |= PERM_FLAGS.EXTRACT;
    if (options.allowAssembly === true) P |= PERM_FLAGS.ASSEMBLE;
    if (options.allowHighQualityPrint !== false) P |= PERM_FLAGS.PRINT_HIGH_QUALITY;

    return P | 0;
  }

  // Standard PDF padding string (32 bytes)
  const PADDING = new Uint8Array([
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A
  ]);

  // Minimal MD5 implementation
  function md5(data) {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    
    const S = [
      7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    
    const K = new Uint32Array([
      0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
      0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
      0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
      0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
      0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
      0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
      0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
      0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
      0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
      0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
      0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
      0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
      0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
      0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
      0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
      0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]);
    
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    
    const msgLen = bytes.length;
    const msgBitLen = msgLen * 8;
    const msgLenPadded = ((msgLen + 9 + 63) & ~63);
    const msg = new Uint8Array(msgLenPadded);
    msg.set(bytes);
    msg[msgLen] = 0x80;
    
    const dataView = new DataView(msg.buffer);
    dataView.setUint32(msgLenPadded - 8, msgBitLen, true);
    dataView.setUint32(msgLenPadded - 4, 0, true);
    
    for (let offset = 0; offset < msgLenPadded; offset += 64) {
      const chunk = new Uint32Array(msg.buffer, offset, 16);
      let a = a0, b = b0, c = c0, d = d0;
      
      for (let i = 0; i < 64; i++) {
        let f, g;
        if (i < 16) {
          f = (b & c) | ((~b) & d);
          g = i;
        } else if (i < 32) {
          f = (d & b) | ((~d) & c);
          g = (5 * i + 1) % 16;
        } else if (i < 48) {
          f = b ^ c ^ d;
          g = (3 * i + 5) % 16;
        } else {
          f = c ^ (b | (~d));
          g = (7 * i) % 16;
        }
        
        f = (f + a + K[i] + chunk[g]) >>> 0;
        a = d;
        d = c;
        c = b;
        b = (b + ((f << S[i]) | (f >>> (32 - S[i])))) >>> 0;
      }
      
      a0 = (a0 + a) >>> 0;
      b0 = (b0 + b) >>> 0;
      c0 = (c0 + c) >>> 0;
      d0 = (d0 + d) >>> 0;
    }
    
    const result = new Uint8Array(16);
    const view = new DataView(result.buffer);
    view.setUint32(0, a0, true);
    view.setUint32(4, b0, true);
    view.setUint32(8, c0, true);
    view.setUint32(12, d0, true);
    
    return result;
  }

  // RC4 Cipher Engine
  class RC4 {
    constructor(key) {
      this.s = new Uint8Array(256);
      this.i = 0;
      this.j = 0;
      for (let i = 0; i < 256; i++) {
        this.s[i] = i;
      }
      let j = 0;
      for (let i = 0; i < 256; i++) {
        j = (j + this.s[i] + key[i % key.length]) & 0xFF;
        [this.s[i], this.s[j]] = [this.s[j], this.s[i]];
      }
    }
    
    process(data) {
      const result = new Uint8Array(data.length);
      for (let k = 0; k < data.length; k++) {
        this.i = (this.i + 1) & 0xFF;
        this.j = (this.j + this.s[this.i]) & 0xFF;
        [this.s[this.i], this.s[this.j]] = [this.s[this.j], this.s[this.i]];
        const t = (this.s[this.i] + this.s[this.j]) & 0xFF;
        result[k] = data[k] ^ this.s[t];
      }
      return result;
    }
  }

  function bytesToHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function padPassword(password = '') {
    const pwdBytes = new TextEncoder().encode(password);
    const padded = new Uint8Array(32);
    if (pwdBytes.length >= 32) {
      padded.set(pwdBytes.slice(0, 32));
    } else {
      padded.set(pwdBytes);
      padded.set(PADDING.slice(0, 32 - pwdBytes.length), pwdBytes.length);
    }
    return padded;
  }

  function computeOwnerKey(ownerPassword, userPassword) {
    const paddedOwner = padPassword(ownerPassword || userPassword || '');
    let hash = md5(paddedOwner);
    for (let i = 0; i < 50; i++) {
      hash = md5(hash);
    }
    const paddedUser = padPassword(userPassword || '');
    let result = new Uint8Array(paddedUser);
    for (let i = 0; i < 20; i++) {
      const key = new Uint8Array(hash.length);
      for (let j = 0; j < hash.length; j++) {
        key[j] = hash[j] ^ i;
      }
      const rc4 = new RC4(key.slice(0, 16));
      result = rc4.process(result);
    }
    return result;
  }

  function computeEncryptionKey(userPassword, ownerKey, permissions, fileId) {
    const paddedPwd = padPassword(userPassword || '');
    const hashInput = new Uint8Array(paddedPwd.length + ownerKey.length + 4 + fileId.length);
    let offset = 0;
    hashInput.set(paddedPwd, offset);
    offset += paddedPwd.length;
    hashInput.set(ownerKey, offset);
    offset += ownerKey.length;
    
    hashInput[offset++] = permissions & 0xFF;
    hashInput[offset++] = (permissions >> 8) & 0xFF;
    hashInput[offset++] = (permissions >> 16) & 0xFF;
    hashInput[offset++] = (permissions >> 24) & 0xFF;
    hashInput.set(fileId, offset);
    
    let hash = md5(hashInput);
    for (let i = 0; i < 50; i++) {
      hash = md5(hash.slice(0, 16));
    }
    return hash.slice(0, 16);
  }

  function computeUserKey(encryptionKey, fileId) {
    const hashInput = new Uint8Array(PADDING.length + fileId.length);
    hashInput.set(PADDING);
    hashInput.set(fileId, PADDING.length);
    const hash = md5(hashInput);
    
    const rc4 = new RC4(encryptionKey);
    let result = rc4.process(hash);
    
    for (let i = 1; i <= 19; i++) {
      const key = new Uint8Array(encryptionKey.length);
      for (let j = 0; j < encryptionKey.length; j++) {
        key[j] = encryptionKey[j] ^ i;
      }
      const rc4iter = new RC4(key);
      result = rc4iter.process(result);
    }
    
    const finalResult = new Uint8Array(32);
    finalResult.set(result);
    return finalResult;
  }

  function encryptObject(data, objectNum, generationNum, encryptionKey) {
    const keyInput = new Uint8Array(encryptionKey.length + 5);
    keyInput.set(encryptionKey);
    keyInput[encryptionKey.length] = objectNum & 0xFF;
    keyInput[encryptionKey.length + 1] = (objectNum >> 8) & 0xFF;
    keyInput[encryptionKey.length + 2] = (objectNum >> 16) & 0xFF;
    keyInput[encryptionKey.length + 3] = generationNum & 0xFF;
    keyInput[encryptionKey.length + 4] = (generationNum >> 8) & 0xFF;
    
    const objectKey = md5(keyInput);
    const rc4 = new RC4(objectKey.slice(0, Math.min(encryptionKey.length + 5, 16)));
    return rc4.process(data);
  }

  function bytesToPDFStringValue(bytes) {
    const out = new Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b === 0x5c) out[i] = '\\\\';
      else if (b === 0x28) out[i] = '\\(';
      else if (b === 0x29) out[i] = '\\)';
      else if (b === 0x0d) out[i] = '\\r';
      else if (b === 0x0a) out[i] = '\\n';
      else out[i] = String.fromCharCode(b);
    }
    return out.join('');
  }

  function isSignatureDict(dict, PDFName, PDFArray) {
    const type = dict.get(PDFName.of('Type'));
    const typeName = type && typeof type.asString === 'function' ? type.asString() : null;
    if (typeName === '/Sig' || typeName === '/DocTimeStamp') return true;
    if (typeName !== null) return false;
    const byteRange = dict.get(PDFName.of('ByteRange'));
    return byteRange instanceof PDFArray && byteRange.size() === 4 && dict.has(PDFName.of('Contents'));
  }

  function skipKey(keyName, isSigDict) {
    if (keyName === '/Length' || keyName === '/Filter' || keyName === '/DecodeParms') return true;
    return isSigDict && keyName === '/Contents';
  }

  function encryptStringsInObject(obj, objectNum, generationNum, encryptionKey, seen, PDFLib) {
    if (!obj || seen.has(obj)) return;
    const { PDFString, PDFHexString, PDFDict, PDFArray, PDFName } = PDFLib;

    if (obj instanceof PDFString) {
      seen.add(obj);
      const originalBytes = obj.asBytes();
      const encrypted = encryptObject(originalBytes, objectNum, generationNum, encryptionKey);
      obj.value = bytesToPDFStringValue(encrypted);
    } else if (obj instanceof PDFHexString) {
      seen.add(obj);
      const originalBytes = obj.asBytes();
      const encrypted = encryptObject(originalBytes, objectNum, generationNum, encryptionKey);
      obj.value = bytesToHex(encrypted);
    } else if (obj instanceof PDFDict) {
      seen.add(obj);
      const isSigDict = isSignatureDict(obj, PDFName, PDFArray);
      for (const [key, value] of obj.entries()) {
        if (!skipKey(key.asString(), isSigDict)) {
          encryptStringsInObject(value, objectNum, generationNum, encryptionKey, seen, PDFLib);
        }
      }
    } else if (obj instanceof PDFArray) {
      seen.add(obj);
      for (const element of obj.asArray()) {
        encryptStringsInObject(element, objectNum, generationNum, encryptionKey, seen, PDFLib);
      }
    }
  }

  /**
   * Apply Permissions Encryption to a PDF (Keeps 100% Vector Quality & Disables Acrobat Pro Editing)
   */
  async function encryptPDFDocument(pdfBytes, options = {}) {
    const PDFLib = global.PDFLib || require('pdf-lib');
    const { PDFDocument, PDFName, PDFHexString, PDFNumber, PDFRawStream, PDFDict, PDFArray } = PDFLib;

    const userPassword = options.userPassword || '';
    // Generate a strong random owner password if not supplied
    const ownerPassword = options.ownerPassword || ('AMG_OWNER_LOCK_' + Math.random().toString(36).substring(2) + Date.now().toString(36));

    const pdfDoc = await PDFDocument.load(pdfBytes, {
      ignoreEncryption: true,
      updateMetadata: false
    });

    const context = pdfDoc.context;
    const trailer = context.trailerInfo;
    
    // Get / Generate File ID
    let fileId;
    const idArray = trailer.ID;
    const firstId = idArray instanceof PDFArray ? idArray.get(0)
      : (Array.isArray(idArray) && idArray.length > 0) ? idArray[0]
      : undefined;

    if (firstId && typeof firstId.asBytes === 'function' && firstId.asBytes().length > 0) {
      fileId = firstId.asBytes();
    } else {
      fileId = new Uint8Array(16);
      if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
        crypto.getRandomValues(fileId);
      } else {
        for (let i = 0; i < 16; i++) fileId[i] = Math.floor(Math.random() * 256);
      }
      const idHex1 = PDFHexString.of(bytesToHex(fileId));
      const idHex2 = PDFHexString.of(bytesToHex(fileId));
      trailer.ID = [idHex1, idHex2];
    }

    // Disallow editing, copying, annotating, form filling; Allow high-quality printing
    const permissions = buildPermissions({
      allowPrinting: true,
      allowHighQualityPrint: true,
      allowModifying: false,
      allowCopying: false,
      allowAnnotating: false,
      allowFillingForms: false,
      allowExtraction: false,
      allowAssembly: false,
      ...options
    });

    const ownerKey = computeOwnerKey(ownerPassword, userPassword);
    const encryptionKey = computeEncryptionKey(userPassword, ownerKey, permissions, fileId);
    const userKey = computeUserKey(encryptionKey, fileId);

    const indirectObjects = context.enumerateIndirectObjects();
    const seen = new WeakSet();

    for (const [ref, obj] of indirectObjects) {
      const objectNum = ref.objectNumber;
      const generationNum = ref.generationNumber || 0;

      if (obj instanceof PDFDict) {
        const filter = obj.get(PDFName.of('Filter'));
        if (filter && filter.asString() === '/Standard') continue;
      }

      if (obj instanceof PDFRawStream && obj.dict) {
        const type = obj.dict.get(PDFName.of('Type'));
        if (type) {
          const typeName = type.toString();
          if (typeName === '/XRef' || typeName === '/Sig') continue;
        }
      }

      if (obj instanceof PDFRawStream) {
        const streamData = obj.contents;
        const encrypted = encryptObject(streamData, objectNum, generationNum, encryptionKey);
        obj.contents = encrypted;

        if (obj.dict) {
          encryptStringsInObject(obj.dict, objectNum, generationNum, encryptionKey, seen, PDFLib);
        }
      }

      if (!(obj instanceof PDFRawStream)) {
        encryptStringsInObject(obj, objectNum, generationNum, encryptionKey, seen, PDFLib);
      }
    }

    const encryptDict = context.obj({
      Filter: PDFName.of('Standard'),
      V: PDFNumber.of(2),
      R: PDFNumber.of(3),
      Length: PDFNumber.of(128),
      P: PDFNumber.of(permissions),
      O: PDFHexString.of(bytesToHex(ownerKey)),
      U: PDFHexString.of(bytesToHex(userKey))
    });

    const encryptRef = context.register(encryptDict);
    trailer.Encrypt = encryptRef;

    const encryptedBytes = await pdfDoc.save({
      useObjectStreams: false,
      updateFieldAppearances: false
    });

    return encryptedBytes;
  }

  // Export to global / window or module
  global.encryptPDFDocument = encryptPDFDocument;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { encryptPDFDocument };
  }
})(typeof window !== 'undefined' ? window : globalThis);
