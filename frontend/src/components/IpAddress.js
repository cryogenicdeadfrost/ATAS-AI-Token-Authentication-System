import React from 'react';

const IpAddress = () => {
  const generateRandomIp = () => {
    return Array(4)
      .fill(0)
      .map(() => Math.floor(Math.random() * 256))
      .join('.');
  };

  return <span>{generateRandomIp()}</span>;
};

export default IpAddress; 