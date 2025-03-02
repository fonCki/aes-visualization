import React from 'react';
import { SBOX, bytesToHex } from '@/utils/aes';

interface DetailedExplanationProps {
  operationType: string;
  inputState: number[];
  outputState: number[];
  roundKey?: number[];
}

const DetailedExplanation: React.FC<DetailedExplanationProps> = ({
  operationType,
  inputState,
  outputState,
  roundKey
}) => {
  // Format a byte as hex string
  const formatByte = (byte: number) => {
    return byte.toString(16).padStart(2, '0');
  };

  const renderSubBytesExplanation = () => {
    return (
      <div>
        <h3 className="font-bold mb-2">SubBytes Operation</h3>
        <p className="mb-4">
          Each byte in the state matrix is replaced with its corresponding value in the S-box.
          The S-box is a substitution table that provides non-linearity to the cipher.
        </p>
        <div className="grid grid-cols-2 gap-4">
          {inputState.slice(0, 4).map((byte, index) => (
            <div key={index} className="border p-2 rounded">
              <div className="font-mono">
                Input byte: 0x{formatByte(byte)}
              </div>
              <div className="font-mono">
                S-box lookup: S[0x{formatByte(byte)}] = 0x{formatByte(SBOX[byte])}
              </div>
              <div className="font-mono bg-gray-100 p-1 mt-1">
                Output byte: 0x{formatByte(outputState[index])}
              </div>
            </div>
          ))}
        </div>
        <p className="mt-4 italic">
          Note: Only showing the first row for clarity. The same process is applied to all 16 bytes.
        </p>
      </div>
    );
  };

  const renderShiftRowsExplanation = () => {
    return (
      <div>
        <h3 className="font-bold mb-2">ShiftRows Operation</h3>
        <p className="mb-4">
          The rows of the state matrix are shifted cyclically to the left by different offsets:
          <ul className="list-disc pl-6 my-2">
            <li>Row 0: No shift</li>
            <li>Row 1: Shifted 1 position left</li>
            <li>Row 2: Shifted 2 positions left</li>
            <li>Row 3: Shifted 3 positions left</li>
          </ul>
        </p>
        
        <div className="grid grid-cols-2 gap-8 mt-4">
          <div>
            <h4 className="font-semibold mb-2">Before ShiftRows:</h4>
            <div className="font-mono">
              Row 0: {inputState.slice(0, 4).map(formatByte).join(' ')}
              <br />
              Row 1: {inputState.slice(4, 8).map(formatByte).join(' ')}
              <br />
              Row 2: {inputState.slice(8, 12).map(formatByte).join(' ')}
              <br />
              Row 3: {inputState.slice(12, 16).map(formatByte).join(' ')}
            </div>
          </div>
          
          <div>
            <h4 className="font-semibold mb-2">After ShiftRows:</h4>
            <div className="font-mono">
              Row 0: {outputState.slice(0, 4).map(formatByte).join(' ')}
              <br />
              Row 1: {outputState.slice(4, 8).map(formatByte).join(' ')}
              <br />
              Row 2: {outputState.slice(8, 12).map(formatByte).join(' ')}
              <br />
              Row 3: {outputState.slice(12, 16).map(formatByte).join(' ')}
            </div>
          </div>
        </div>
        
        <div className="mt-4">
          <p className="font-semibold">Transformation:</p>
          <div className="font-mono mt-2">
            Row 1: [{inputState.slice(4, 8).map(formatByte).join(' ')}] → [{outputState.slice(4, 8).map(formatByte).join(' ')}]
            <br />
            Row 2: [{inputState.slice(8, 12).map(formatByte).join(' ')}] → [{outputState.slice(8, 12).map(formatByte).join(' ')}]
            <br />
            Row 3: [{inputState.slice(12, 16).map(formatByte).join(' ')}] → [{outputState.slice(12, 16).map(formatByte).join(' ')}]
          </div>
        </div>
      </div>
    );
  };

  const renderMixColumnsExplanation = () => {
    return (
      <div>
        <h3 className="font-bold mb-2">MixColumns Operation</h3>
        <p className="mb-4">
          Each column of the state matrix is treated as a polynomial over GF(2^8) and is multiplied by 
          a fixed polynomial a(x) = {'{03}'} x^3 + {'{01}'} x^2 + {'{01}'} x + {'{02}'}.
          This operation provides diffusion in the cipher.
        </p>
        
        <div className="grid grid-cols-2 gap-8 mt-4">
          <div>
            <h4 className="font-semibold mb-2">Before MixColumns:</h4>
            <div className="font-mono">
              Col 0: {[inputState[0], inputState[4], inputState[8], inputState[12]].map(formatByte).join(' ')}
              <br />
              Col 1: {[inputState[1], inputState[5], inputState[9], inputState[13]].map(formatByte).join(' ')}
              <br />
              Col 2: {[inputState[2], inputState[6], inputState[10], inputState[14]].map(formatByte).join(' ')}
              <br />
              Col 3: {[inputState[3], inputState[7], inputState[11], inputState[15]].map(formatByte).join(' ')}
            </div>
          </div>
          
          <div>
            <h4 className="font-semibold mb-2">After MixColumns:</h4>
            <div className="font-mono">
              Col 0: {[outputState[0], outputState[4], outputState[8], outputState[12]].map(formatByte).join(' ')}
              <br />
              Col 1: {[outputState[1], outputState[5], outputState[9], outputState[13]].map(formatByte).join(' ')}
              <br />
              Col 2: {[outputState[2], outputState[6], outputState[10], outputState[14]].map(formatByte).join(' ')}
              <br />
              Col 3: {[outputState[3], outputState[7], outputState[11], outputState[15]].map(formatByte).join(' ')}
            </div>
          </div>
        </div>
        
        <div className="mt-4 p-3 bg-gray-100 rounded">
          <p className="font-semibold mb-2">Matrix Multiplication:</p>
          <p className="font-mono">
            For each column [a, b, c, d], the transformation is:
            <br />
            a' = (2 × a) ⊕ (3 × b) ⊕ c ⊕ d
            <br />
            b' = a ⊕ (2 × b) ⊕ (3 × c) ⊕ d
            <br />
            c' = a ⊕ b ⊕ (2 × c) ⊕ (3 × d)
            <br />
            d' = (3 × a) ⊕ b ⊕ c ⊕ (2 × d)
          </p>
          <p className="mt-2 text-sm">
            Note: Multiplication is performed in GF(2^8) with the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
          </p>
        </div>
      </div>
    );
  };

  const renderAddRoundKeyExplanation = () => {
    if (!roundKey) return null;
    
    return (
      <div>
        <h3 className="font-bold mb-2">AddRoundKey Operation</h3>
        <p className="mb-4">
          Each byte in the state matrix is XORed with the corresponding byte in the round key.
          This is the only step that directly uses the key.
        </p>
        
        <div className="overflow-x-auto">
          <table className="min-w-full border border-gray-300">
            <thead>
              <tr className="bg-gray-100">
                <th className="border p-2">Position</th>
                <th className="border p-2">State Byte</th>
                <th className="border p-2">Key Byte</th>
                <th className="border p-2">XOR Result</th>
                <th className="border p-2">Binary Operation</th>
              </tr>
            </thead>
            <tbody>
              {inputState.slice(0, 8).map((byte, index) => (
                <tr key={index}>
                  <td className="border p-2 text-center">({Math.floor(index / 4)}, {index % 4})</td>
                  <td className="border p-2 font-mono text-center">0x{formatByte(byte)}</td>
                  <td className="border p-2 font-mono text-center">0x{formatByte(roundKey[index])}</td>
                  <td className="border p-2 font-mono text-center">0x{formatByte(outputState[index])}</td>
                  <td className="border p-2 font-mono text-center">
                    {byte.toString(2).padStart(8, '0')} ⊕ {roundKey[index].toString(2).padStart(8, '0')} = {outputState[index].toString(2).padStart(8, '0')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        <p className="mt-4 italic">
          Note: Only showing the first 8 bytes for clarity. The same process is applied to all 16 bytes.
        </p>
      </div>
    );
  };

  const renderExplanation = () => {
    switch (operationType) {
      case 'SubBytes':
        return renderSubBytesExplanation();
      case 'ShiftRows':
        return renderShiftRowsExplanation();
      case 'MixColumns':
        return renderMixColumnsExplanation();
      case 'AddRoundKey':
        return renderAddRoundKeyExplanation();
      default:
        return (
          <div>
            <h3 className="font-bold mb-2">Operation: {operationType}</h3>
            <p>Detailed explanation not available for this operation.</p>
          </div>
        );
    }
  };

  return (
    <div className="bg-white p-4 rounded shadow mt-4">
      {renderExplanation()}
    </div>
  );
};

export default DetailedExplanation;