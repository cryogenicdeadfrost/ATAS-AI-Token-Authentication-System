import React from 'react';
import IpAddress from './IpAddress';

const ApiKeyGenerator = ({ selectedModel, tokenValue, onGenerate }) => {
  // Function to generate random access status
  const generateRandomAccess = () => {
    return Math.random() < 0.5 ? 'yes ✅ ' : 'no 🚫';
  };

  // Function to generate random time
  const generateRandomTime = () => {
    const min = 30; // 30 minutes
    const max = 90; // 1.5 hours
    return Math.floor(Math.random() * (max - min + 1)) + min;
  };

  const handleGenerate = () => {
    // Note: The actual API key will be generated on the backend
    // We're just creating a placeholder object here
    const newKey = {
      model: selectedModel,
      token: tokenValue,
      access: generateRandomAccess(),
      time: generateRandomTime()
    };
    onGenerate(newKey);
  };

  return (
    <button className="generate-button" onClick={handleGenerate}>
      Generate API key
    </button>
  );
};

export default ApiKeyGenerator;