import { useState, useEffect } from 'react';
import { 
  keyToBytes, 
  generateRandomKey, 
  bytesToHex, 
  getAesSteps,
  getKeyExpansionSteps,
  AesStep,
  AesMode,
  PaddingType,
  OutputFormat,
  KeyLength,
  realAesEncrypt,
  testSpecificCase
} from '@/utils/aes';
import MatrixVisualizer from '@/components/MatrixVisualizer';
import DetailedExplanation from '@/components/DetailedExplanation';

export default function Home() {
  const [input, setInput] = useState('Hello, AES!');
  const [key, setKey] = useState('7b0dd452e211631d'); // Default to the test key
  const [keyBytes, setKeyBytes] = useState<number[]>([]);
  const [steps, setSteps] = useState<AesStep[]>([]);
  const [currentStep, setCurrentStep] = useState(0);
  const [showKeyExpansion, setShowKeyExpansion] = useState(false);
  const [keySteps, setKeySteps] = useState<{ description: string, key: number[], explanation?: string, highlightedCells?: number[] }[]>([]);
  const [keyStep, setKeyStep] = useState(0);
  const [aesMode, setAesMode] = useState<AesMode>(AesMode.ECB);
  const [paddingType, setPaddingType] = useState<PaddingType>(PaddingType.PKCS7);
  const [keyLength, setKeyLength] = useState<KeyLength>(KeyLength.AES_128);
  const [outputFormat, setOutputFormat] = useState<OutputFormat>(OutputFormat.BASE64);
  const [finalCiphertext, setFinalCiphertext] = useState<{
    base64: string;
    hex: string;
    binary: string;
  } | null>(null);
  const [iv, setIv] = useState<number[] | undefined>(undefined);
  const [realCiphertext, setRealCiphertext] = useState<{
    base64: string;
    hex: string;
    binary: string;
  } | null>(null);
  const [showFinalResult, setShowFinalResult] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<string>('');

  // Initialize key on first render
  useEffect(() => {
    // Set the initial key bytes from the preset key
    try {
      const initialKeyBytes = keyToBytes(key);
      setKeyBytes(initialKeyBytes);
      
      // Run the test case to validate our implementation
      setTestResult(testSpecificCase());
    } catch (error) {
      console.error('Invalid initial key format');
    }
  }, []);

  // Handle random key generation
  const handleRandomKey = () => {
    const randomKeyBytes = generateRandomKey(keyLength);
    setKeyBytes(randomKeyBytes);
    setKey(bytesToHex(randomKeyBytes));
  };
  
  // Handle key length change
  const handleKeyLengthChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newKeyLength = parseInt(e.target.value) as KeyLength;
    setKeyLength(newKeyLength);
    
    // Regenerate key with new length if requested
    if (window.confirm('Do you want to generate a new key with this length?')) {
      const newKeyBytes = generateRandomKey(newKeyLength);
      setKeyBytes(newKeyBytes);
      setKey(bytesToHex(newKeyBytes));
    }
  };
  
  // Handle output format change
  const handleOutputFormatChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setOutputFormat(e.target.value as OutputFormat);
  };

  // Handle custom key input
  const handleKeyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newKey = e.target.value;
    setKey(newKey);
    try {
      const newKeyBytes = keyToBytes(newKey);
      setKeyBytes(newKeyBytes);
    } catch (error) {
      console.error('Invalid key format');
    }
  };

  // Handle input text change
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInput(e.target.value);
  };

  // Handle AES mode change
  const handleModeChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setAesMode(e.target.value as AesMode);
  };

  // Handle padding type change
  const handlePaddingChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setPaddingType(e.target.value as PaddingType);
  };

  // Start AES encryption visualization
  const handleEncrypt = () => {
    setShowKeyExpansion(false);
    setShowFinalResult(false);
    
    const { steps: aesSteps, finalCiphertext, iv: newIv } = getAesSteps(input, keyBytes, aesMode, paddingType);
    setSteps(aesSteps);
    setFinalCiphertext(finalCiphertext);
    setIv(newIv);
    setCurrentStep(0);
    
    // Also generate the real ciphertext using CryptoJS for verification
    const ivHex = newIv ? bytesToHex(newIv, '') : undefined;
    const keyHex = bytesToHex(keyBytes, '');
    const result = realAesEncrypt(input, keyHex, aesMode, paddingType, outputFormat, keyLength, ivHex);
    setRealCiphertext(result.formats);
    
    // Run test case with the specific test input
    if (input === 'Hello, AES!' && keyHex === '7b0dd452e211631d' && aesMode === AesMode.ECB) {
      setTestResult(testSpecificCase());
    }
  };

  // Show key expansion visualization
  const handleShowKeyExpansion = () => {
    setShowKeyExpansion(true);
    setShowFinalResult(false);
    const expansionSteps = getKeyExpansionSteps(keyBytes);
    setKeySteps(expansionSteps);
    setKeyStep(0);
  };
  
  // Show final encryption result
  const handleShowFinalResult = () => {
    setShowFinalResult(true);
    setShowKeyExpansion(false);
  };

  // Move to next step in the encryption process
  const nextStep = () => {
    if (showKeyExpansion) {
      if (keyStep < keySteps.length - 1) {
        setKeyStep(keyStep + 1);
      }
    } else {
      if (currentStep < steps.length - 1) {
        setCurrentStep(currentStep + 1);
      }
    }
  };

  // Move to previous step in the encryption process
  const prevStep = () => {
    if (showKeyExpansion) {
      if (keyStep > 0) {
        setKeyStep(keyStep - 1);
      }
    } else {
      if (currentStep > 0) {
        setCurrentStep(currentStep - 1);
      }
    }
  };

  const [showDetailedExplanation, setShowDetailedExplanation] = useState(false);
  const [previousStepState, setPreviousStepState] = useState<number[]>([]);
  
  // Format a byte as hex string
  const formatByte = (byte: number) => {
    return byte.toString(16).padStart(2, '0');
  };

  // Reset to the beginning of the visualization
  const resetVisualization = () => {
    setCurrentStep(0);
    setKeyStep(0);
    setShowDetailedExplanation(false);
  };

  // Get previous step state for comparison
  const getPreviousStepState = (currentStep: number) => {
    if (currentStep === 0) return steps[0].state;
    return steps[currentStep - 1].state;
  };
  
  // Get operation type from step description
  const getOperationType = (description: string) => {
    if (description.includes('SubBytes')) return 'SubBytes';
    if (description.includes('ShiftRows')) return 'ShiftRows';
    if (description.includes('MixColumns')) return 'MixColumns';
    if (description.includes('AddRoundKey')) return 'AddRoundKey';
    return '';
  };
  
  // Handle showing detailed explanation
  const handleShowDetailedExplanation = () => {
    setPreviousStepState(getPreviousStepState(currentStep));
    setShowDetailedExplanation(!showDetailedExplanation);
  };

  // Render the state matrix (4x4)
  const renderStateMatrix = () => {
    if (steps.length === 0) return null;
    
    const currentState = steps[currentStep].state;
    const activeIndices = steps[currentStep].activeIndices || [];
    
    return (
      <div className="flex flex-col items-center">
        <h3 className="font-bold mb-2">{steps[currentStep].description}</h3>
        <MatrixVisualizer 
          matrix={currentState}
          activeIndices={activeIndices}
        />
        {currentStep > 0 && (
          <button 
            onClick={handleShowDetailedExplanation}
            className="mt-4 bg-blue-500 text-white px-4 py-2 rounded"
          >
            {showDetailedExplanation ? 'Hide Detailed Explanation' : 'Show Detailed Explanation'}
          </button>
        )}
      </div>
    );
  };

  // Render the key matrix (4x4) for key expansion
  const renderKeyMatrix = () => {
    if (keySteps.length === 0) return null;
    
    const currentKeyStep = keySteps[keyStep];
    
    return (
      <div className="flex flex-col items-center">
        <h3 className="font-bold mb-2">{currentKeyStep.description}</h3>
        <MatrixVisualizer
          matrix={currentKeyStep.key}
          isKey={true}
          highlightedCells={currentKeyStep.highlightedCells || []}
        />
        
        {currentKeyStep.explanation && (
          <div className="mt-4 p-3 bg-blue-50 rounded-md max-w-2xl">
            <p className="whitespace-pre-line">{currentKeyStep.explanation}</p>
          </div>
        )}
      </div>
    );
  };
  
  // Render the final encryption result
  const renderFinalResult = () => {
    if (!finalCiphertext || !realCiphertext) return null;
    
    return (
      <div className="flex flex-col items-center">
        <h3 className="font-bold mb-4">Final Encryption Result</h3>
        
        <div className="bg-gray-100 p-4 rounded-md w-full max-w-2xl mb-4">
          <div className="mb-4">
            <h4 className="font-semibold mb-1">Original Text:</h4>
            <div className="p-2 bg-white rounded border">{input}</div>
          </div>
          
          <div className="mb-4">
            <h4 className="font-semibold mb-1">Encryption Key:</h4>
            <div className="p-2 bg-white rounded border">
              <div className="font-mono">Hex: {bytesToHex(keyBytes, '')}</div>
              <div className="text-sm text-gray-600 mt-1">Key Length: {keyLength} bits ({keyLength/8} bytes)</div>
            </div>
          </div>
          
          {iv && (
            <div className="mb-4">
              <h4 className="font-semibold mb-1">
                {aesMode === AesMode.CBC ? 'Initialization Vector (IV)' : 'Counter (Nonce)'}:
              </h4>
              <div className="p-2 bg-white rounded border font-mono">{bytesToHex(iv)}</div>
            </div>
          )}
          
          <div className="mb-4">
            <h4 className="font-semibold mb-1">Settings:</h4>
            <div className="p-2 bg-white rounded border">
              <div>Mode: <span className="font-semibold">{aesMode}</span></div>
              <div>Padding: <span className="font-semibold">{paddingType}</span></div>
              <div>Output Format: <span className="font-semibold">{outputFormat}</span></div>
            </div>
          </div>
          
          <div className="mb-4">
            <h4 className="font-semibold mb-1">Our Implementation:</h4>
            <div className="border rounded bg-white">
              <div className="p-2 border-b">
                <span className="inline-block w-24 font-semibold">Base64:</span>
                <span className="font-mono break-all">{finalCiphertext.base64}</span>
              </div>
              <div className="p-2 border-b">
                <span className="inline-block w-24 font-semibold">Hex:</span>
                <span className="font-mono break-all">{finalCiphertext.hex}</span>
              </div>
              <div className="p-2">
                <span className="inline-block w-24 font-semibold">Binary:</span>
                <span className="font-mono break-all text-xs">{finalCiphertext.binary.length > 100 ? finalCiphertext.binary.substring(0, 100) + '...' : finalCiphertext.binary}</span>
              </div>
            </div>
          </div>
          
          <div className="mb-4">
            <h4 className="font-semibold mb-1">CryptoJS Verification:</h4>
            <div className="border rounded bg-white">
              <div className="p-2 border-b">
                <span className="inline-block w-24 font-semibold">Base64:</span>
                <span className="font-mono break-all">{realCiphertext.base64}</span>
              </div>
              <div className="p-2 border-b">
                <span className="inline-block w-24 font-semibold">Hex:</span>
                <span className="font-mono break-all">{realCiphertext.hex}</span>
              </div>
              <div className="p-2">
                <span className="inline-block w-24 font-semibold">Binary:</span>
                <span className="font-mono break-all text-xs">{realCiphertext.binary.length > 100 ? realCiphertext.binary.substring(0, 100) + '...' : realCiphertext.binary}</span>
              </div>
            </div>
          </div>
          
          {input === 'Hello, AES!' && bytesToHex(keyBytes, '') === '7b0dd452e211631d' && aesMode === AesMode.ECB && (
            <div className="mt-4 p-3 bg-yellow-100 rounded border border-yellow-300">
              <h4 className="font-semibold mb-1">Test Case Verification:</h4>
              <pre className="text-xs font-mono whitespace-pre-wrap">{testResult}</pre>
            </div>
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="container mx-auto p-6 max-w-4xl">
      <h1 className="text-3xl font-bold mb-6">AES Encryption Visualization</h1>
      
      {/* Input and Key Section */}
      <div className="bg-white p-4 rounded shadow mb-6">
        <div className="mb-4">
          <label className="block mb-2">Input Text:</label>
          <input
            type="text"
            value={input}
            onChange={handleInputChange}
            className="w-full border p-2 rounded"
            placeholder="Enter text to encrypt"
          />
          <p className="text-sm text-gray-500 mt-1">
            Text will be converted to bytes and padded according to selected padding mode.
          </p>
        </div>
        
        <div className="mb-4">
          <label className="block mb-2">Key (hex):</label>
          <div className="flex">
            <input
              type="text"
              value={key}
              onChange={handleKeyChange}
              className="flex-grow border p-2 rounded mr-2"
              placeholder="Enter 128-bit key as hex or text"
            />
            <button 
              onClick={handleRandomKey}
              className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
            >
              Random
            </button>
          </div>
          <p className="text-sm text-gray-500 mt-1">
            Key will be padded/truncated to 16 bytes (128 bits).
          </p>
        </div>
        
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block mb-2">Encryption Mode:</label>
            <select
              value={aesMode}
              onChange={handleModeChange}
              className="w-full border p-2 rounded"
            >
              <option value={AesMode.ECB}>ECB (Electronic Codebook)</option>
              <option value={AesMode.CBC}>CBC (Cipher Block Chaining)</option>
              <option value={AesMode.CTR}>CTR (Counter)</option>
            </select>
            <p className="text-sm text-gray-500 mt-1">
              {aesMode === AesMode.ECB && 'Basic mode, each block is encrypted independently (not recommended for security).'}
              {aesMode === AesMode.CBC && 'Chains blocks together using an IV for better security.'}
              {aesMode === AesMode.CTR && 'Encrypts a counter instead of the plaintext for better parallelization.'}
            </p>
          </div>
          
          <div>
            <label className="block mb-2">Padding:</label>
            <select
              value={paddingType}
              onChange={handlePaddingChange}
              className="w-full border p-2 rounded"
            >
              <option value={PaddingType.PKCS7}>PKCS#7 (Default)</option>
              <option value={PaddingType.ANSI_X923}>ANSI X.923</option>
              <option value={PaddingType.NONE}>None (No Padding)</option>
            </select>
            <p className="text-sm text-gray-500 mt-1">
              {paddingType === PaddingType.PKCS7 && 'Pads with the byte value of the padding length.'}
              {paddingType === PaddingType.ANSI_X923 && 'Pads with zeros, with the last byte being the padding length.'}
              {paddingType === PaddingType.NONE && 'No padding (input must be exactly 16 bytes).'}
            </p>
          </div>
        </div>
        
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block mb-2">Key Length:</label>
            <select
              value={keyLength}
              onChange={handleKeyLengthChange}
              className="w-full border p-2 rounded"
            >
              <option value={KeyLength.AES_128}>AES-128 (16 bytes)</option>
              <option value={KeyLength.AES_192}>AES-192 (24 bytes)</option>
              <option value={KeyLength.AES_256}>AES-256 (32 bytes)</option>
            </select>
            <p className="text-sm text-gray-500 mt-1">
              {keyLength === KeyLength.AES_128 && 'Standard 128-bit key length.'}
              {keyLength === KeyLength.AES_192 && 'Extended 192-bit key length for more security.'}
              {keyLength === KeyLength.AES_256 && 'Maximum 256-bit key length for highest security.'}
            </p>
          </div>
          
          <div>
            <label className="block mb-2">Output Format:</label>
            <select
              value={outputFormat}
              onChange={handleOutputFormatChange}
              className="w-full border p-2 rounded"
            >
              <option value={OutputFormat.BASE64}>Base64</option>
              <option value={OutputFormat.HEX}>Hexadecimal</option>
              <option value={OutputFormat.BINARY}>Binary</option>
            </select>
            <p className="text-sm text-gray-500 mt-1">
              {outputFormat === OutputFormat.BASE64 && 'Standard Base64 encoding for web applications.'}
              {outputFormat === OutputFormat.HEX && 'Hexadecimal representation for human readability.'}
              {outputFormat === OutputFormat.BINARY && 'Raw binary format for educational purposes.'}
            </p>
          </div>
        </div>
        
        <div className="flex flex-wrap justify-between gap-2">
          <button 
            onClick={handleEncrypt}
            className="bg-green-500 text-white px-6 py-2 rounded hover:bg-green-600"
          >
            Encrypt
          </button>
          <button 
            onClick={handleShowKeyExpansion}
            className="bg-purple-500 text-white px-6 py-2 rounded hover:bg-purple-600"
          >
            Key Expansion
          </button>
          {finalCiphertext && (
            <button 
              onClick={handleShowFinalResult}
              className="bg-blue-500 text-white px-6 py-2 rounded hover:bg-blue-600"
            >
              Show Result
            </button>
          )}
        </div>
      </div>
      
      {/* Visualization Section */}
      <div className="bg-white p-4 rounded shadow mb-6">
        <h2 className="text-xl font-bold mb-4">
          {showFinalResult 
            ? 'Final Encryption Result' 
            : showKeyExpansion 
              ? 'Key Expansion Visualization' 
              : 'Encryption Process Visualization'
          }
        </h2>
        
        <div className="flex justify-center mb-6">
          {showFinalResult 
            ? renderFinalResult()
            : showKeyExpansion 
              ? renderKeyMatrix() 
              : renderStateMatrix()
          }
        </div>
        
        {/* Detailed Explanation Section */}
        {showDetailedExplanation && !showKeyExpansion && !showFinalResult && steps.length > 0 && (
          <DetailedExplanation
            operationType={getOperationType(steps[currentStep].description)}
            inputState={previousStepState}
            outputState={steps[currentStep].state}
            roundKey={steps[currentStep].roundKey}
          />
        )}
        
        {/* Step Navigation */}
        {!showFinalResult && (steps.length > 0 || keySteps.length > 0) && (
          <div className="flex justify-between items-center mt-6">
            <button 
              onClick={prevStep}
              disabled={showKeyExpansion ? keyStep === 0 : currentStep === 0}
              className={`px-4 py-2 rounded ${
                showKeyExpansion 
                  ? keyStep === 0 ? 'bg-gray-300 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600 text-white'
                  : currentStep === 0 ? 'bg-gray-300 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600 text-white'
              }`}
            >
              Previous Step
            </button>
            
            <div className="text-center">
              Step {showKeyExpansion ? keyStep + 1 : currentStep + 1} of {showKeyExpansion ? keySteps.length : steps.length}
              <button 
                onClick={resetVisualization}
                className="ml-4 text-blue-500 hover:underline"
              >
                Reset
              </button>
            </div>
            
            <button 
              onClick={nextStep}
              disabled={showKeyExpansion ? keyStep === keySteps.length - 1 : currentStep === steps.length - 1}
              className={`px-4 py-2 rounded ${
                showKeyExpansion 
                  ? keyStep === keySteps.length - 1 ? 'bg-gray-300 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600 text-white'
                  : currentStep === steps.length - 1 ? 'bg-gray-300 cursor-not-allowed' : 'bg-blue-500 hover:bg-blue-600 text-white'
              }`}
            >
              Next Step
            </button>
          </div>
        )}
      </div>
      
      {/* Explanation Section */}
      <div className="bg-white p-4 rounded shadow">
        <h2 className="text-xl font-bold mb-4">AES Process Explanation</h2>
        
        {showFinalResult ? (
          <div>
            <h3 className="font-bold mb-2">AES Encryption Modes</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div className="border p-3 rounded">
                <h4 className="font-semibold mb-2">ECB Mode</h4>
                <p className="text-sm">
                  Electronic Codebook mode encrypts each block independently. 
                  It's simple but not secure for most uses as patterns in the plaintext 
                  remain visible in the ciphertext.
                </p>
              </div>
              <div className="border p-3 rounded">
                <h4 className="font-semibold mb-2">CBC Mode</h4>
                <p className="text-sm">
                  Cipher Block Chaining XORs each plaintext block with the previous 
                  ciphertext block before encryption. This hides patterns and requires 
                  an Initialization Vector (IV).
                </p>
              </div>
              <div className="border p-3 rounded">
                <h4 className="font-semibold mb-2">CTR Mode</h4>
                <p className="text-sm">
                  Counter mode encrypts a sequence of counters and XORs the result 
                  with the plaintext. This allows parallel encryption/decryption and 
                  turns the block cipher into a stream cipher.
                </p>
              </div>
            </div>
            
            <h3 className="font-bold mb-2">Padding Methods</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="border p-3 rounded">
                <h4 className="font-semibold mb-2">PKCS#7 Padding</h4>
                <p className="text-sm">
                  Pads the plaintext with bytes equal to the padding length. 
                  For example, if 4 bytes of padding are needed, pad with 
                  [04, 04, 04, 04].
                </p>
              </div>
              <div className="border p-3 rounded">
                <h4 className="font-semibold mb-2">ANSI X.923 Padding</h4>
                <p className="text-sm">
                  Pads the plaintext with zeros, and the last byte is the padding length. 
                  For example, if 4 bytes of padding are needed, pad with 
                  [00, 00, 00, 04].
                </p>
              </div>
            </div>
          </div>
        ) : showKeyExpansion ? (
          <div>
            <h3 className="font-bold mb-2">Key Expansion Process</h3>
            <p className="mb-4">
              The AES algorithm takes the original key and expands it to create different round keys for each round of encryption.
              For AES-128, we have 11 round keys (including the original key) each of 128 bits.
            </p>
            
            <div className="bg-gray-100 p-4 rounded">
              <h4 className="font-semibold mb-2">Key Expansion Algorithm:</h4>
              <ol className="list-decimal pl-6 mb-4">
                <li>The first round key is the original key</li>
                <li>For each subsequent round (1-10):
                  <ul className="list-disc pl-6 mt-1">
                    <li>Take the last 4 bytes (word) of the previous round key</li>
                    <li>Apply the key schedule core:
                      <ul className="list-circle pl-6 mt-1">
                        <li>Rotate the word one byte to the left (RotWord)</li>
                        <li>Apply S-box substitution to each byte (SubWord)</li>
                        <li>XOR the first byte with the round constant (Rcon)</li>
                      </ul>
                    </li>
                    <li>XOR this transformed word with the first 4 bytes of the previous round key</li>
                    <li>Generate the remaining 12 bytes by XORing each word with the corresponding word from the previous round key</li>
                  </ul>
                </li>
              </ol>
            </div>
            
            <p className="mt-4">
              The key expansion provides resistance against various attacks by ensuring each round 
              uses a different but related key. This is crucial for the security of AES.
            </p>
          </div>
        ) : (
          <>
            {currentStep < steps.length && (
              <div>
                <h3 className="font-bold mb-2">{steps[currentStep]?.description}</h3>
                <p className="mb-4">{steps[currentStep]?.explanation}</p>
                
                {steps[currentStep]?.description.includes('SubBytes') && (
                  <div className="bg-gray-100 p-3 rounded">
                    <p>The S-box substitution is a non-linear transformation that provides confusion in the cipher.
                    This is the only non-linear operation in AES and is critical for its security.</p>
                  </div>
                )}
                
                {steps[currentStep]?.description.includes('ShiftRows') && (
                  <div className="bg-gray-100 p-3 rounded">
                    <p>ShiftRows provides diffusion by ensuring that bytes from each column are spread out in the next round.
                    This helps to dissipate patterns in the plaintext.</p>
                  </div>
                )}
                
                {steps[currentStep]?.description.includes('MixColumns') && (
                  <div className="bg-gray-100 p-3 rounded">
                    <p>MixColumns is the main diffusion element of AES.
                    It ensures that each byte of output depends on all input bytes of the same column.
                    This matrix multiplication has the property that if you change one byte, all bytes in that column will change.</p>
                  </div>
                )}
                
                {steps[currentStep]?.description.includes('AddRoundKey') && (
                  <div className="bg-gray-100 p-3 rounded">
                    <p>AddRoundKey is the only step that directly involves the key.
                    Without the correct key, the ciphertext cannot be decrypted properly.
                    This simple XOR operation is what makes AES secure when combined with the other steps.</p>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}