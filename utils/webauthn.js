// utils/webauthn.js - CommonJS 版本

/**
 * 将 base64url 编码的字符串转换为 Uint8Array
 */
function fromBase64URL(base64urlString) {
  // 替换 URL 安全字符并补足填充
  let base64 = base64urlString
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  // 补充 base64 填充字符 =
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }

  const binaryString = Buffer.from(base64, 'base64').toString('binary');
  const len = binaryString.length;
  const bytes = new Uint8Array(len);

  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
}

/**
 * 将 ArrayBuffer 或 Uint8Array 转换为 base64url 字符串
 */
function toBase64URL(buffer) {
  const uint8Array = new Uint8Array(buffer);
  const binString = Array.from(uint8Array, byte =>
    String.fromCharCode(byte)
  ).join('');
  return btoa(binString)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

module.exports = {
  fromBase64URL,
  toBase64URL,
};