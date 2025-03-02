import React from 'react';

interface MatrixVisualizerProps {
  matrix: number[];
  activeIndices?: number[];
  isKey?: boolean;
  highlightedCells?: number[];
}

const MatrixVisualizer: React.FC<MatrixVisualizerProps> = ({ 
  matrix, 
  activeIndices = [], 
  isKey = false,
  highlightedCells = []
}) => {
  // Format a byte as hex string
  const formatByte = (byte: number) => {
    return byte.toString(16).padStart(2, '0');
  };

  return (
    <div className="flex flex-col items-center">
      <div className="grid grid-cols-4 gap-1">
        {Array.from({ length: 16 }).map((_, i) => (
          <div 
            key={i} 
            className={`
              ${isKey ? 'key-matrix-cell' : 'matrix-cell'} 
              ${activeIndices.includes(i) ? 'active-cell' : ''}
              ${highlightedCells.includes(i) ? 'bg-blue-200' : ''}
            `}
          >
            {formatByte(matrix[i])}
          </div>
        ))}
      </div>
      
      {/* Row and column labels */}
      <div className="flex justify-center mt-2">
        <div className="flex">
          <div className="mr-8">
            <div className="text-sm text-gray-600">Row View:</div>
            <div>Row 0: {matrix.slice(0, 4).map(formatByte).join(' ')}</div>
            <div>Row 1: {matrix.slice(4, 8).map(formatByte).join(' ')}</div>
            <div>Row 2: {matrix.slice(8, 12).map(formatByte).join(' ')}</div>
            <div>Row 3: {matrix.slice(12, 16).map(formatByte).join(' ')}</div>
          </div>
          
          <div>
            <div className="text-sm text-gray-600">Column View:</div>
            <div>Col 0: {[matrix[0], matrix[4], matrix[8], matrix[12]].map(formatByte).join(' ')}</div>
            <div>Col 1: {[matrix[1], matrix[5], matrix[9], matrix[13]].map(formatByte).join(' ')}</div>
            <div>Col 2: {[matrix[2], matrix[6], matrix[10], matrix[14]].map(formatByte).join(' ')}</div>
            <div>Col 3: {[matrix[3], matrix[7], matrix[11], matrix[15]].map(formatByte).join(' ')}</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MatrixVisualizer;