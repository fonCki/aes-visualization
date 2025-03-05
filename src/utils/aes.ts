import CryptoJS from 'crypto-js';

// AES mode enum
export enum AesMode {
  ECB = 'ECB',
  CBC = 'CBC',
  CTR = 'CTR'
}

// Padding enum
export enum PaddingType {
  PKCS7 = 'PKCS7',
  ANSI_X923 = 'ANSI X.923',
  NONE = 'None'
}

// Output format enum
export enum OutputFormat {
  BASE64 = 'Base64',
  HEX = 'Hex',
  BINARY = 'Binary'
}

// Key length enum
export enum KeyLength {
  AES_128 = 128,
  AES_192 = 192,
  AES_256 = 256
}

// AES S-Box
export const SBOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// AES Rcon (Round Constants)
export const RCON = [
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
];

// Used in MixColumns
export const GALOIS_MUL_2 = [
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
  0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
  0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
  0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
  0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
  0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
  0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
  0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
  0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
  0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
  0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
  0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
  0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
  0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
  0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
  0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5,
];

export const GALOIS_MUL_3 = [
  0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
  0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
  0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
  0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
  0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
  0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
  0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
  0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
  0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
  0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
  0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
  0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
  0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
  0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
  0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
  0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a,
];

// Convert text to a state matrix - returns array of bytes
export const textToState = (text: string): number[] => {
  const wordArray = CryptoJS.enc.Utf8.parse(text);
  const bytes = [];
  for (let i = 0; i < wordArray.words.length; i++) {
    const word = wordArray.words[i];
    bytes.push((word >>> 24) & 0xff);
    bytes.push((word >>> 16) & 0xff);
    bytes.push((word >>> 8) & 0xff);
    bytes.push(word & 0xff);
  }
  
  // Pad to 16 bytes if needed
  while (bytes.length < 16) {
    bytes.push(0);
  }
  
  // Only use the first 16 bytes
  return bytes.slice(0, 16);
};

// Convert a hex key to array of bytes
export const keyToBytes = (key: string): number[] => {
  // Remove spaces and convert to lowercase
  const cleanKey = key.replace(/\s/g, '').toLowerCase();
  
  // If it's a hex string, convert it
  if (/^[0-9a-f]+$/.test(cleanKey)) {
    const bytes = [];
    for (let i = 0; i < Math.min(cleanKey.length, 32); i += 2) {
      bytes.push(parseInt(cleanKey.substr(i, 2), 16));
    }
    // Pad to 16 bytes if needed
    while (bytes.length < 16) {
      bytes.push(0);
    }
    return bytes.slice(0, 16);
  } 
  
  // Otherwise, treat as UTF-8 text
  return textToState(key);
};

// Generate a random key as byte array based on key length
export const generateRandomKey = (keyLength: KeyLength = KeyLength.AES_128): number[] => {
  const keyBytes = keyLength / 8;
  const bytes = [];
  for (let i = 0; i < keyBytes; i++) {
    bytes.push(Math.floor(Math.random() * 256));
  }
  return bytes;
};

// Format bytes as hex
export const bytesToHex = (bytes: number[], joinChar: string = ' '): string => {
  return bytes.map(byte => byte.toString(16).padStart(2, '0')).join(joinChar);
};

// Format bytes as binary
export const bytesToBinary = (bytes: number[], joinChar: string = ' '): string => {
  return bytes.map(byte => byte.toString(2).padStart(8, '0')).join(joinChar);
};

// SubBytes operation - substitute each byte with its S-box value
export const subBytes = (state: number[]): number[] => {
  return state.map(byte => SBOX[byte]);
};

// ShiftRows operation - rotate rows of the state matrix
export const shiftRows = (state: number[]): number[] => {
  const result = [...state];
  // Row 1: shift 1 position left
  [result[1], result[5], result[9], result[13]] = [result[5], result[9], result[13], result[1]];
  // Row 2: shift 2 positions left
  [result[2], result[6], result[10], result[14]] = [result[10], result[14], result[2], result[6]];
  // Row 3: shift 3 positions left
  [result[3], result[7], result[11], result[15]] = [result[15], result[3], result[7], result[11]];
  return result;
};

// MixColumns operation - mix data within columns
export const mixColumns = (state: number[]): number[] => {
  const result = [...state];
  for (let i = 0; i < 4; i++) {
    const col = i * 4;
    const s0 = state[col];
    const s1 = state[col + 1];
    const s2 = state[col + 2];
    const s3 = state[col + 3];
    
    result[col] = GALOIS_MUL_2[s0] ^ GALOIS_MUL_3[s1] ^ s2 ^ s3;
    result[col + 1] = s0 ^ GALOIS_MUL_2[s1] ^ GALOIS_MUL_3[s2] ^ s3;
    result[col + 2] = s0 ^ s1 ^ GALOIS_MUL_2[s2] ^ GALOIS_MUL_3[s3];
    result[col + 3] = GALOIS_MUL_3[s0] ^ s1 ^ s2 ^ GALOIS_MUL_2[s3];
  }
  return result;
};

// AddRoundKey operation - XOR state with round key
export const addRoundKey = (state: number[], roundKey: number[]): number[] => {
  return state.map((byte, i) => byte ^ roundKey[i]);
};

// Key expansion - generate round keys
export const keyExpansion = (key: number[], keyLength: KeyLength = KeyLength.AES_128): number[][] => {
  const keyWords = key.length / 4;
  const numRounds = keyLength === KeyLength.AES_128 ? 10 : 
                    keyLength === KeyLength.AES_192 ? 12 : 14;
  
  const roundKeys: number[][] = [key.slice()]; // First round key is the original key
  
  for (let round = 1; round <= numRounds; round++) {
    const prevKey = roundKeys[round - 1];
    const newKey = prevKey.slice();
    
    // Rotate the last word and apply S-box
    const lastIndex = prevKey.length - 4;
    const lastWord = [prevKey[lastIndex], prevKey[lastIndex + 1], prevKey[lastIndex + 2], prevKey[lastIndex + 3]];
    const rotWord = [lastWord[1], lastWord[2], lastWord[3], lastWord[0]];
    const subWord = rotWord.map(byte => SBOX[byte]);
    
    // Apply Rcon to the first byte
    subWord[0] ^= RCON[round];
    
    // Generate the first word of the new key
    newKey[0] = prevKey[0] ^ subWord[0];
    newKey[1] = prevKey[1] ^ subWord[1];
    newKey[2] = prevKey[2] ^ subWord[2];
    newKey[3] = prevKey[3] ^ subWord[3];
    
    // Generate the rest of the words
    for (let i = 1; i < keyWords; i++) {
      const offset = i * 4;
      // Special handling for AES-256 where every 4th word needs S-box transformation
      if (keyLength === KeyLength.AES_256 && i === 4) {
        const tempWord = [newKey[offset - 4], newKey[offset - 3], newKey[offset - 2], newKey[offset - 1]];
        const subTempWord = tempWord.map(byte => SBOX[byte]);
        
        newKey[offset] = prevKey[offset] ^ subTempWord[0];
        newKey[offset + 1] = prevKey[offset + 1] ^ subTempWord[1];
        newKey[offset + 2] = prevKey[offset + 2] ^ subTempWord[2];
        newKey[offset + 3] = prevKey[offset + 3] ^ subTempWord[3];
      } else {
        newKey[offset] = newKey[offset - 4] ^ prevKey[offset];
        newKey[offset + 1] = newKey[offset - 3] ^ prevKey[offset + 1];
        newKey[offset + 2] = newKey[offset - 2] ^ prevKey[offset + 2];
        newKey[offset + 3] = newKey[offset - 1] ^ prevKey[offset + 3];
      }
    }
    
    roundKeys.push(newKey);
  }
  
  return roundKeys;
};

// Perform one round of AES
export const aesRound = (state: number[], roundKey: number[], isLastRound: boolean): number[] => {
  let newState = subBytes(state);
  newState = shiftRows(newState);
  if (!isLastRound) {
    newState = mixColumns(newState);
  }
  newState = addRoundKey(newState, roundKey);
  return newState;
};

// Complete AES encryption
export const aesEncrypt = (plaintext: string, key: number[]): number[] => {
  // Initial state
  const state = textToState(plaintext);
  
  // Key expansion
  const roundKeys = keyExpansion(key);
  
  // Initial round - just AddRoundKey
  let currentState = addRoundKey(state, roundKeys[0]);
  
  // Main rounds
  for (let round = 1; round <= 10; round++) {
    currentState = aesRound(currentState, roundKeys[round], round === 10);
  }
  
  return currentState;
};

// Apply ANSI X.923 padding
export const applyAnsiX923Padding = (data: number[]): number[] => {
  const padded = [...data];
  const paddingLength = 16 - (data.length % 16);
  
  // Add padding bytes (0x00) except the last byte
  for (let i = 0; i < paddingLength - 1; i++) {
    padded.push(0x00);
  }
  
  // Add the padding length as the last byte
  padded.push(paddingLength);
  
  return padded;
};

// Remove ANSI X.923 padding
export const removeAnsiX923Padding = (data: number[]): number[] => {
  const paddingLength = data[data.length - 1];
  return data.slice(0, data.length - paddingLength);
};

// Get IV for CBC mode
export const generateIV = (): number[] => {
  const iv = [];
  for (let i = 0; i < 16; i++) {
    iv.push(Math.floor(Math.random() * 256));
  }
  return iv;
};

// Get all intermediate states for visualization
export type AesStep = {
  description: string;
  state: number[];
  activeIndices?: number[];  // For highlighting specific cells
  explanation?: string;      // More detailed explanation
  roundKey?: number[];
};

export const getAesSteps = (
  plaintext: string, 
  key: number[], 
  mode: AesMode = AesMode.ECB,
  padding: PaddingType = PaddingType.PKCS7
): {
  steps: AesStep[],
  finalCiphertext: {
    base64: string;
    hex: string;
    binary: string;
  },
  iv?: number[]
} => {
  const steps: AesStep[] = [];
  let iv: number[] | undefined;
  
  // Convert plaintext to bytes
  let plaintextBytes = textToState(plaintext);
  steps.push({ 
    description: 'Original Plaintext', 
    state: plaintextBytes,
    explanation: `The plaintext "${plaintext}" is converted to bytes and represented as a 4×4 matrix.`
  });
  
  // Apply padding if needed
  if (padding === PaddingType.ANSI_X923) {
    plaintextBytes = applyAnsiX923Padding(plaintextBytes);
    steps.push({ 
      description: 'After ANSI X.923 Padding', 
      state: plaintextBytes,
      explanation: 'ANSI X.923 padding adds null bytes and puts the count of padding bytes at the end.'
    });
  }
  
  // Generate IV for CBC mode
  if (mode === AesMode.CBC) {
    iv = generateIV();
    steps.push({ 
      description: 'Initialization Vector (IV)', 
      state: iv,
      explanation: 'For CBC mode, a random 16-byte IV is generated to add randomness to the encryption.'
    });
  }
  
  // Start encryption process
  const initialState = plaintextBytes;
  
  // Key expansion
  const roundKeys = keyExpansion(key);
  
  // Initial setup based on mode
  let currentState: number[];
  
  switch (mode) {
    case AesMode.CBC:
      if (!iv) iv = generateIV(); // Failsafe
      // XOR plaintext with IV
      currentState = initialState.map((byte, i) => byte ^ iv![i])

      steps.push({ 
        description: 'Initial State XOR IV', 
        state: currentState,
        activeIndices: Array.from(Array(16).keys()),
        explanation: 'In CBC mode, the plaintext is first XORed with the IV before encryption starts.'
      });
      break;
    case AesMode.CTR:
      // In CTR mode, we encrypt a counter value instead of the plaintext
      const counter = iv || generateIV();
      if (!iv) iv = counter;
      
      steps.push({ 
        description: 'Counter Value', 
        state: counter,
        explanation: 'In CTR mode, a counter value is encrypted instead of the plaintext.'
      });
      
      currentState = counter;
      break;
    default: // ECB
      currentState = initialState;
      steps.push({ 
        description: 'Initial State (plaintext)', 
        state: currentState,
        explanation: 'In ECB mode, the plaintext blocks are encrypted independently.'
      });
      break;
  }
  
  // Initial round - just AddRoundKey
  const afterInitialRound = addRoundKey(currentState, roundKeys[0]);
  steps.push({ 
    description: 'After Initial AddRoundKey', 
    state: afterInitialRound,
    activeIndices: Array.from(Array(16).keys()),
    explanation: 'The first step is to XOR the state with the initial round key (Round Key 0).',
    roundKey: roundKeys[0],
  });
  
  currentState = afterInitialRound;
  
  // Main rounds
  for (let round = 1; round <= 10; round++) {
    // SubBytes
    const afterSubBytes = subBytes(currentState);
    steps.push({ 
      description: `Round ${round} - After SubBytes`, 
      state: afterSubBytes,
      activeIndices: Array.from(Array(16).keys()),
      explanation: `Each byte is substituted with its corresponding value in the S-box. This is the only non-linear operation in AES.`
    });
    
    // ShiftRows
    const afterShiftRows = shiftRows(afterSubBytes);
    steps.push({ 
      description: `Round ${round} - After ShiftRows`, 
      state: afterShiftRows,
      activeIndices: [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15],
      explanation: `The rows of the state are shifted: row 0 by 0, row 1 by 1, row 2 by 2, and row 3 by 3 positions to the left.`
    });
    
    if (round < 10) {
      // MixColumns (not in final round)
      const afterMixColumns = mixColumns(afterShiftRows);
      steps.push({ 
        description: `Round ${round} - After MixColumns`, 
        state: afterMixColumns,
        activeIndices: Array.from(Array(16).keys()),
        explanation: `Each column is transformed using a linear transformation over Galois Field. This provides diffusion in the cipher.`
      });
      
      // AddRoundKey
      currentState = addRoundKey(afterMixColumns, roundKeys[round]);
    } else {
      // Final round has no MixColumns
      currentState = addRoundKey(afterShiftRows, roundKeys[round]);
    }
    
    steps.push({ 
      description: `Round ${round} - After AddRoundKey`, 
      state: currentState,
      activeIndices: Array.from(Array(16).keys()),
      explanation: `The state is XORed with Round Key ${round}.`,
      roundKey: roundKeys[round],
    });
  }
  
  // Final output based on mode
  let finalState: number[];
  
  switch (mode) {
    case AesMode.CBC:
      // Output is the current state (already completed encryption)
      finalState = currentState;
      break;
    case AesMode.CTR:
      // XOR the encrypted counter with plaintext
      finalState = currentState.map((byte, i) => byte ^ initialState[i]);
      steps.push({ 
        description: 'Plaintext XOR Encrypted Counter', 
        state: finalState,
        activeIndices: Array.from(Array(16).keys()),
        explanation: 'In CTR mode, the final step is to XOR the encrypted counter with the plaintext to produce the ciphertext.'
      });
      break;
    default: // ECB
      finalState = currentState;
      break;
  }
  
  steps.push({ 
    description: 'Final Ciphertext', 
    state: finalState,
    explanation: `The final encrypted output using AES-128 in ${mode} mode.`
  });
  
  // Convert the final state to the requested output format
  const finalWordArray = CryptoJS.lib.WordArray.create(
    new Uint8Array(finalState) as any
  );
  
  const finalCiphertextBase64 = CryptoJS.enc.Base64.stringify(finalWordArray);
  const finalCiphertextHex = CryptoJS.enc.Hex.stringify(finalWordArray);
  const finalCiphertextBinary = bytesToBinary(finalState, '');
  
  return { 
    steps, 
    finalCiphertext: {
      base64: finalCiphertextBase64,
      hex: finalCiphertextHex,
      binary: finalCiphertextBinary
    }, 
    iv 
  };
};

// Get key expansion steps with detailed explanations
export const getKeyExpansionSteps = (key: number[]): { 
  description: string, 
  key: number[],
  explanation?: string,
  highlightedCells?: number[]
}[] => {
  const roundKeys = keyExpansion(key);
  const steps = [];
  
  steps.push({
    description: 'Initial Key',
    key: roundKeys[0],
    explanation: 'This is the original 128-bit key provided by the user.'
  });
  
  for (let round = 1; round <= 10; round++) {
    const prevKey = roundKeys[round - 1];
    const currentKey = roundKeys[round];
    
    // Calculate the transformations for a more detailed explanation
    const lastWord = [prevKey[12], prevKey[13], prevKey[14], prevKey[15]];
    const rotWord = [lastWord[1], lastWord[2], lastWord[3], lastWord[0]];
    const sboxWord = rotWord.map(byte => SBOX[byte]);
    const rconValue = RCON[round];
    const transformedWord = [...sboxWord];
    transformedWord[0] ^= rconValue;
    // Calculate the first word of the previous key and its XOR with the transformed word
    const firstWordPrev = [prevKey[0], prevKey[1], prevKey[2], prevKey[3]];
    const xorResult = firstWordPrev.map((byte, index) => byte ^ transformedWord[index]);


    // Show the key with highlighted cells for the new word
    steps.push({
      description: `Round Key ${round}`,
      key: currentKey,
      explanation: `
        Key expansion process for Round ${round}:
        1. Take the last word of the previous key: [${lastWord.map(b => b.toString(16).padStart(2, '0')).join(', ')}]
        2. Rotate the word: [${rotWord.map(b => b.toString(16).padStart(2, '0')).join(', ')}]
        3. Apply the S-box to the rotated word: [${sboxWord.map(b => b.toString(16).padStart(2, '0')).join(', ')}]
        4. Apply the RCON (Round Constant 0x${rconValue.toString(16)}) to the first byte:
           Resulting in: [${transformedWord.map(b => b.toString(16).padStart(2, '0')).join(', ')}]
        5. XOR the first word of the previous key: [${firstWordPrev.map(b => b.toString(16).padStart(2, '0')).join(', ')}] with the transformed word: [${transformedWord.map(b => b.toString(16).padStart(2, '0')).join(', ')}] resulting in: [${xorResult.map(b => b.toString(16).padStart(2, '0')).join(', ')}]. Then generate the remaining words accordingly.
      `,
      highlightedCells: [0, 1, 2, 3] // Highlight the first word that's directly transformed
    });
  }
  
  return steps;
};

// Real AES encryption using CryptoJS for verification
export const realAesEncrypt = (
  plaintext: string,
  key: string,
  mode: AesMode = AesMode.ECB,
  padding: PaddingType = PaddingType.PKCS7,
  outputFormat: OutputFormat = OutputFormat.BASE64,
  keyLength: KeyLength = KeyLength.AES_128,
  ivString?: string
): { ciphertext: string, iv?: string, formats: { base64: string, hex: string, binary: string } } => {
  // Handle case where key is shorter than required by keyLength
  const cleanKey = key.replace(/\s/g, '');
  let keyHex = cleanKey.length % 2 === 1 ? cleanKey + '0' : cleanKey;
  
  // Ensure key is of correct length for the selected key length
  const requiredHexChars = keyLength / 4; // Each hex char is 4 bits
  if (keyHex.length < requiredHexChars) {
    // Pad key if too short
    keyHex = keyHex.padEnd(requiredHexChars, '0');
  } else if (keyHex.length > requiredHexChars) {
    // Truncate key if too long
    keyHex = keyHex.substring(0, requiredHexChars);
  }
  
  const keyWordArray = CryptoJS.enc.Hex.parse(keyHex);
  
  let paddingOption: any;
  switch (padding) {
    case PaddingType.ANSI_X923:
      paddingOption = { padding: CryptoJS.pad.AnsiX923 };
      break;
    case PaddingType.NONE:
      paddingOption = { padding: CryptoJS.pad.NoPadding };
      break;
    default:
      paddingOption = {}; // default is PKCS7
  }
  
  let modeOption: any;
  let iv: any;
  
  switch (mode) {
    case AesMode.CBC:
      if (ivString) {
        iv = CryptoJS.enc.Hex.parse(ivString.replace(/\s/g, ''));
      } else {
        iv = CryptoJS.lib.WordArray.random(16);
      }
      modeOption = { 
        mode: CryptoJS.mode.CBC,
        iv: iv,
        ...paddingOption
      };
      break;
    case AesMode.CTR:
      if (ivString) {
        iv = CryptoJS.enc.Hex.parse(ivString.replace(/\s/g, ''));
      } else {
        iv = CryptoJS.lib.WordArray.random(16);
      }
      modeOption = {
        mode: CryptoJS.mode.CTR,
        iv: iv,
        counter: CryptoJS.lib.WordArray.create([0, 0, 0, 0], 16),
        ...paddingOption
      };
      break;
    default: // ECB
      modeOption = {
        mode: CryptoJS.mode.ECB,
        ...paddingOption
      };
      break;
  }
  
  const encrypted = CryptoJS.AES.encrypt(plaintext, keyWordArray, modeOption);
  
  // Get all output formats
  const base64Output = encrypted.toString();
  const cipherParams = CryptoJS.lib.CipherParams.create({
    ciphertext: CryptoJS.enc.Base64.parse(base64Output)
  });
  const hexOutput = CryptoJS.format.Hex.stringify(cipherParams);
  
  // For binary, we need to convert the hex to binary
  const hexBytes = hexOutput.match(/.{2}/g)!.map(hex => parseInt(hex, 16));
  const binaryOutput = bytesToBinary(hexBytes, '');
  
  // Select the requested format for primary output
  let primaryOutput: string;
  switch (outputFormat) {
    case OutputFormat.HEX:
      primaryOutput = hexOutput;
      break;
    case OutputFormat.BINARY:
      primaryOutput = binaryOutput;
      break;
    default: // BASE64
      primaryOutput = base64Output;
      break;
  }
  
  return { 
    ciphertext: primaryOutput,
    iv: iv ? CryptoJS.enc.Hex.stringify(iv) : undefined,
    formats: {
      base64: base64Output,
      hex: hexOutput,
      binary: binaryOutput
    }
  };
};

// Test specific case for "Hello, AES!" with key "7b0dd452e211631d"
export const testSpecificCase = (): string => {
  const plaintext = "Hello, AES!";
  const key = "7b0dd452e211631d";
  
  // Create key and input as byte arrays
  const keyBytes = [];
  for (let i = 0; i < key.length; i += 2) {
    keyBytes.push(parseInt(key.substr(i, 2), 16));
  }
  
  // Use our implementation
  const { finalCiphertext } = getAesSteps(plaintext, keyBytes, AesMode.ECB, PaddingType.PKCS7);
  
  // Use CryptoJS implementation
  const cryptoResult = realAesEncrypt(plaintext, key, AesMode.ECB, PaddingType.PKCS7, OutputFormat.HEX);
  
  return `
    Our implementation (HEX): ${finalCiphertext.hex}
    CryptoJS implementation (HEX): ${cryptoResult.formats.hex}
    Expected result: 30484B8F8C6BB09CA3F94C6F84F0305E
  `;
};