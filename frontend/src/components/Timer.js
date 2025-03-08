import React, { useState, useEffect } from 'react';

const Timer = ({ initialMinutes, isRevoked }) => {
  const [timeLeft, setTimeLeft] = useState(initialMinutes * 60); // Convert to seconds
  
  useEffect(() => {
    // Update timeLeft when initialMinutes changes
    setTimeLeft(initialMinutes * 60);
  }, [initialMinutes]);
  
  useEffect(() => {
    // Don't start the timer if initialMinutes is 0 (access denied) or if access is revoked
    if (initialMinutes <= 0 || isRevoked) {
      return;
    }
    
    const timer = setInterval(() => {
      setTimeLeft(prevTime => {
        if (prevTime <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prevTime - 1;
      });
    }, 1000);
    
    return () => clearInterval(timer);
  }, [initialMinutes, isRevoked]);
  
  // Format time
  const formatTime = (seconds) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
      return `${hours}:${minutes < 10 ? '0' : ''}${minutes}:${secs < 10 ? '0' : ''}${secs}`;
    } else {
      return `${minutes}:${secs < 10 ? '0' : ''}${secs}`;
    }
  };
  
  // If initialMinutes is 0 or access is revoked, display a message instead of a timer
  if (initialMinutes <= 0 || isRevoked) {
    return <span className="no-access">No Access</span>;
  }
  
  return <span className="timer">{formatTime(timeLeft)}</span>;
};

export default Timer;