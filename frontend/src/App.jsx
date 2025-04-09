import React, { useState, useEffect } from "react";
import "./App.css";
import Loader from "./components/Loader";
import Timer from "./components/Timer";

const App = () => {
  const [ip, setIp] = useState("");
  const [selectedModel, setSelectedModel] = useState("model3");
  const [tokenValue, setTokenValue] = useState("20000");
  const [purposeOfUse, setPurposeOfUse] = useState("Research");
  const [loading, setLoading] = useState(false);
  const [apiKeys, setApiKeys] = useState([]);
  const [generatedTokens, setGeneratedTokens] = useState([]);
  const [verificationKey, setVerificationKey] = useState("");
  const [verificationResult, setVerificationResult] = useState(null);
  const [revokedIPs, setRevokedIPs] = useState([]);
  
  // Define fixed column widths without the adjustment functionality
  const columnWidths = {
    model: 150,
    token: 100,
    apiKey: 250,
    access: 120,
    time: 150,
    ip: 150,
    purpose: 120,
    reason: 200 // Added column for denial reason
  };

  useEffect(() => {
    // Only fetch IP on load, don't restore any saved data
    const fetchIP = async () => {
      try {
        const response = await fetch('https://api.ipify.org?format=json');
        const data = await response.json();
        setIp(data.ip);
      } catch (error) {
        console.error("Error fetching IP:", error);
      }
    };

    // Clear any potentially stored data
    localStorage.removeItem("apiKeys");
    localStorage.removeItem("generatedTokens");
    
    fetchIP(); 
    // Start polling for revoked IPs
    checkRevokedIPs();
    const interval = setInterval(checkRevokedIPs, 10000); // Check every 10 seconds
    
    return () => clearInterval(interval);
  }, []);
  
  // Function to check for revoked IPs and update the UI accordingly
  const checkRevokedIPs = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/revoked-ips');
      if (response.ok) {
        const data = await response.json();
        const newRevokedIPs = data.revoked_ips || [];
        
        // If we have new revoked IPs, update the UI
        if (JSON.stringify(newRevokedIPs) !== JSON.stringify(revokedIPs)) {
          setRevokedIPs(newRevokedIPs);
          
          // Update all apiKeys where IP has been revoked
          setApiKeys(prevKeys => 
            prevKeys.map(key => {
              if (newRevokedIPs.includes(key.ip)) {
                return {
                  ...key,
                  access: 'no 🚫',
                  time: 0, // Stop the timer
                  revoked: true,
                  denialReason: "IP address has been revoked"
                };
              }
              return key;
            })
          );
          
          // If current IP is revoked, show notification
          if (newRevokedIPs.includes(ip) && !revokedIPs.includes(ip)) {
            alert("Access from your IP address has been revoked by the administrator.");
          }
        }
      }
    } catch (error) {
      console.error("Error checking revoked IPs:", error);
    }
  };

  // Fixed allocation time of 60 minutes
  const getFixedTimeAllocation = () => {
    return 60; // Always return 60 minutes
  };

  const generateRandomAccess = () => {
    return Math.random() < 0.7 ? 'yes ✅' : 'no 🚫';
  };

  const handleGenerate = async () => {
    // Check if the current IP is already revoked
    if (revokedIPs.includes(ip)) {
      // Display revoked status in the table
      const updatedKeys = [...apiKeys, { 
        model: selectedModel,
        token: tokenValue,
        apiKey: "REVOKED",
        access: 'no 🚫',
        time: 0,
        ip: ip,
        purposeOfUse: purposeOfUse,
        jwt_token: "REVOKED",
        revoked: true,
        denialReason: "IP address has been revoked"
      }];
      setApiKeys(updatedKeys);
      
      // Show a notification to the user
      alert("Access from your IP address has been revoked by the administrator.");
      return;
    }
    
    setLoading(true);

    try {
      // Send data to backend instead of generating locally
      const response = await fetch('http://localhost:5000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          ip: ip,
          selectedModel: selectedModel,
          tokenValue: tokenValue,
          purposeOfUse: purposeOfUse,
          params: {} // Additional params if needed
        }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      
      setTimeout(() => {
        setLoading(false);
        
        // Check if the IP has been revoked
        if (data.revoked) {
          // Display revoked status in the table
          const updatedKeys = [...apiKeys, { 
            model: selectedModel,
            token: tokenValue,
            apiKey: "REVOKED",
            access: 'no 🚫',
            time: 0,
            ip: ip,
            purposeOfUse: purposeOfUse,
            jwt_token: "REVOKED",
            revoked: true,
            denialReason: "IP address has been revoked"
          }];
          setApiKeys(updatedKeys);
          
          // Show a notification to the user
          alert("Access from your IP address has been revoked by the administrator.");
          return;
        }
        
        // Check if access was granted based on the backend response
        const accessGiven = data.access_given !== undefined ? data.access_given : generateRandomAccess();
        
        // Always use 60 minutes if access is given, regardless of backend value
        // But keep the 0 value for when access is denied
        const timeAllocated = accessGiven ? getFixedTimeAllocation() : 0;
        
        // Use the access status from backend or fallback
        const accessStatus = accessGiven ? 'yes ✅' : 'no 🚫';
        
        // Get denial reason if access was denied
        const denialReason = !accessGiven ? (data.denial_reason || "Access denied by security system") : null;
        
        // If anomaly was detected, extract info
        const anomalyCheck = data.anomaly_check || {};
        const isAnomalous = anomalyCheck.is_anomalous || false;
        const anomalyResult = anomalyCheck.result || "";
        const anomalyPercentage = anomalyCheck.anomaly_percentage || "0%";
        
        // Update API keys with the data from backend
        const updatedKeys = [...apiKeys, { 
          model: selectedModel,
          token: tokenValue,
          apiKey: data.api_key,
          access: accessStatus,
          time: timeAllocated, // Using fixed time or 0 if access denied
          ip: ip,
          purposeOfUse: purposeOfUse,
          jwt_token: data.jwt_token,
          denialReason: denialReason,
          isAnomalous: isAnomalous,
          anomalyResult: anomalyResult,
          anomalyPercentage: anomalyPercentage
        }];
        setApiKeys(updatedKeys);
        
        // Only store valid tokens in state
        if (accessGiven) {
          const newToken = { apiKey: data.api_key, jwtToken: data.jwt_token };
          setGeneratedTokens(prev => [...prev, newToken]);
          
          // Auto-set the verification field with the new API key
          setVerificationKey(data.api_key);
        } else if (isAnomalous) {
          // Alert user if request was flagged as anomalous
          alert("Access denied: Your request pattern was flagged as anomalous by our security system.");
        }
      }, 1000);
    } catch (error) {
      console.error("Error generating key:", error);
      setLoading(false);
      
      // Fallback to mock data if backend is unavailable
      const apiKeyChars = "abcdefghijklmnopqrstuvwxyz0123456789";
      let apiKey = "atk_";
      for (let i = 0; i < 16; i++) {
        apiKey += apiKeyChars.charAt(Math.floor(Math.random() * apiKeyChars.length));
      }

      // Generate a mock JWT token
      const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + 
                      btoa(JSON.stringify({
                        model: selectedModel,
                        tokens: tokenValue,
                        purpose: purposeOfUse,
                        ip: ip,
                        exp: Date.now() + 3600000
                      })) + 
                      ".mockSignature";
      
      // Generate mock access (more likely to be denied in fallback)
      const accessGiven = Math.random() < 0.5;
      const accessStatus = accessGiven ? 'yes ✅' : 'no 🚫';
      
      setTimeout(() => {
        setLoading(false);
        
        // Update with mock data
        const updatedKeys = [...apiKeys, { 
          model: selectedModel,
          token: tokenValue,
          apiKey: accessGiven ? apiKey : "access_denied",
          access: accessStatus,
          time: accessGiven ? getFixedTimeAllocation() : 0, // Using fixed time
          ip: ip,
          purposeOfUse: purposeOfUse,
          jwt_token: accessGiven ? jwtToken : "access_denied",
          denialReason: accessGiven ? null : "Access denied (offline mode)"
        }];
        setApiKeys(updatedKeys);
        
        if (accessGiven) {
          const newToken = { apiKey, jwtToken };
          setGeneratedTokens(prev => [...prev, newToken]);
          
          setVerificationKey(apiKey);
        }
      }, 1000);
    }
  };

  const handleVerify = async () => {
    setLoading(true);
    
    try {
      // Send verification request to backend
      const response = await fetch('http://localhost:5000/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          apiKey: verificationKey
        }),
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      
      setTimeout(() => {
        if (data.verified) {
          // Handle successful verification
          setVerificationResult({
            success: true,
            message: "Verification Successful",
            details: `Token is valid and active. Access granted.`,
            expiresIn: "60 minutes", // Always show 60 minutes
          });
        } else {
          // Check if the failure is due to revocation
          const isRevoked = data.message && data.message.toLowerCase().includes('revoked');
          
          // Handle failed verification
          setVerificationResult({
            success: false,
            message: isRevoked ? "Access Revoked" : "Verification Failed",
            details: data.message || "Invalid or expired token. Please check and try again."
          });
        }
        
        setLoading(false);
      }, 800);
    } catch (error) {
      console.error("Error verifying key:", error);
      
      // Fallback to local verification if backend is unavailable
      setTimeout(() => {
        // Check if key indicates revoked access
        if (verificationKey === "REVOKED" || verificationKey === "access_revoked") {
          setVerificationResult({
            success: false,
            message: "Access Revoked",
            details: "Access from your IP address has been revoked by the administrator."
          });
          setLoading(false);
          return;
        }
        
        // Check if the key is from a revoked IP
        const keyFromRevokedIP = apiKeys.find(key => 
          (key.apiKey === verificationKey || key.jwt_token === verificationKey) && 
          revokedIPs.includes(key.ip)
        );
        
        if (keyFromRevokedIP) {
          setVerificationResult({
            success: false,
            message: "Access Revoked",
            details: `Access from IP ${keyFromRevokedIP.ip} has been revoked by the administrator.`
          });
          setLoading(false);
          return;
        }
        
        // Check if token is from an anomalous request
        const anomalousKey = apiKeys.find(key => 
          (key.apiKey === verificationKey || key.jwt_token === verificationKey) && 
          key.isAnomalous
        );
        
        if (anomalousKey) {
          setVerificationResult({
            success: false,
            message: "Security Alert",
            details: "This token was denied due to anomalous request patterns detected by our security system."
          });
          setLoading(false);
          return;
        }
        
        // Improved local verification logic:
        // First check if it's one of our keys
        const token = generatedTokens.find(t => 
          t.apiKey === verificationKey || 
          t.jwtToken === verificationKey
        );
        
        // Second, check that it's not an "access_denied" key
        const isValidKey = token && 
                          token.apiKey !== "access_denied" && 
                          token.jwtToken !== "access_denied";
        
        if (isValidKey) {
          setVerificationResult({
            success: true,
            message: "Verification Successful (Local)",
            details: "Token is valid and active. Access granted.",
            expiresIn: "60 minute", // Always show 60 minutes
            usageLimit: "<tokenValue>"
          });
        } else {
          // Check denial reason from apiKeys
          const deniedKey = apiKeys.find(key => 
            key.apiKey === verificationKey || 
            key.jwt_token === verificationKey
          );
          
          let denialDetails = "Invalid or expired token. Please check and try again.";
          
          // If key contains "access_denied", give appropriate message
          if (verificationKey === "access_denied") {
            denialDetails = "Access was denied due to security checks.";
            
            // If we have a specific denial reason, use it
            if (deniedKey && deniedKey.denialReason) {
              denialDetails = deniedKey.denialReason;
            }
          }
          
          setVerificationResult({
            success: false,
            message: "Verification Failed",
            details: denialDetails
          });
        }
        
        setLoading(false);
      }, 800);
    }
  };

  const handleUseLatest = () => {
    if (generatedTokens.length > 0) {
      const latestToken = generatedTokens[generatedTokens.length - 1];
      setVerificationKey(latestToken.apiKey);
    }
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <div className="logo-container">
          <h1 className="logo">ATAS</h1>
        </div>
        <div className="title-container">
          <h2 className="title">
            AI-powered adaptive token auth to    
            <span className="typing-text">  block scrapers, secure keys, and stop abuse.</span>
          </h2>
        </div>
      </header>

      <main className="app-main">
        <section className="control-panel">
          <div className="input-row">
            <div className="input-group">
              <label htmlFor="model-select">Select Model:</label>
              <select
                id="model-select"
                className="input-control model-select"
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
              >
                <option value="model1">Model 1 (1.5B)</option>
                <option value="model2">Model 2 (175B)</option>
                <option value="model3">Model 3 (500B)</option>
                <option value="model4">Model 4 (1T)</option>
              </select>
            </div>

            <div className="input-group">
              <label htmlFor="token-input">Token Required:</label>
              <input
                id="token-input"
                type="text"
                value={tokenValue}
                onChange={(e) => setTokenValue(e.target.value)}
                className="input-control token-input"
              />
            </div>

            <div className="input-group">
              <label htmlFor="purpose-select">Purpose of Use:</label>
              <select
                id="purpose-select"
                className="input-control purpose-select"
                value={purposeOfUse}
                onChange={(e) => setPurposeOfUse(e.target.value)}
              >
                <option value="Personal">Personal</option>
                <option value="Research">Research</option>
                <option value="Commercial">Commercial</option>
                <option value="Educational">Educational</option>
              </select>
            </div>

            <button 
              className="generate-button"
              onClick={handleGenerate}
              disabled={loading}
            >
              Generate API Key
            </button>
          </div>
          
          {loading && <Loader />}
        </section>

        <section className="data-table-container">
          <div className="table-wrapper">
            <table className="data-table">
              <colgroup>
                <col style={{ width: `${columnWidths.model}px` }} />
                <col style={{ width: `${columnWidths.token}px` }} />
                <col style={{ width: `${columnWidths.apiKey}px` }} />
                <col style={{ width: `${columnWidths.access}px` }} />
                <col style={{ width: `${columnWidths.time}px` }} />
                <col style={{ width: `${columnWidths.ip}px` }} />
                <col style={{ width: `${columnWidths.purpose}px` }} />
                <col style={{ width: `${columnWidths.reason}px` }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Token</th>
                  <th>API Key</th>
                  <th>Access Given</th>
                  <th>Time Allocated (min)</th>
                  <th>IP Address</th>
                  <th>Purpose</th>
                  <th>Status/Reason</th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.length === 0 ? (
                  <tr>
                    <td colSpan="8" className="no-data">No API keys generated yet. Use the form above to create one.</td>
                  </tr>
                ) : (
                  apiKeys.map((key, index) => {
                    // Check if this IP is now revoked
                    const isRevoked = key.revoked || revokedIPs.includes(key.ip);
                    const isAnomalous = key.isAnomalous;
                    
                    return (
                      <tr key={index} className={isRevoked ? "revoked-row" : (isAnomalous ? "anomalous-row" : "")}>
                        <td>{key.model}</td>
                        <td>{key.token}</td>
                        <td className="api-key-cell" title={key.apiKey}>
                          {isRevoked ? "REVOKED" : key.apiKey}
                        </td>
                        <td>{isRevoked ? 'no 🚫' : key.access}</td>
                        <td>
                          <Timer initialMinutes={isRevoked ? 0 : key.time} isRevoked={isRevoked} />
                        </td>
                        <td>{key.ip}</td>
                        <td>{key.purposeOfUse}</td>
                        <td>
                          {isRevoked 
                            ? "IP Revoked" 
                            : (key.denialReason 
                                ? key.denialReason 
                                : key.access === 'yes ✅' 
                                  ? "Active" 
                                  : "Denied")}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="verification-panel">
          <h2>Verify API Key or JWT Token</h2>
          
          <div className="verification-controls">
            <input
              type="text"
              className="verification-input"
              placeholder="Enter API Key or JWT Token to verify"
              value={verificationKey}
              onChange={(e) => setVerificationKey(e.target.value)}
            />
            
            <div className="verification-buttons">
              <button 
                className="verify-button"
                onClick={handleVerify}
                disabled={!verificationKey || loading}
              >
                Verify
              </button>
              
              <button 
                className="latest-button"
                onClick={handleUseLatest}
                disabled={generatedTokens.length === 0}
              >
                Use Latest
              </button>
            </div>
          </div>
          
          {verificationResult && (
            <div className={`verification-result ${verificationResult.success ? 'success' : 'error'}`}>
              <h3>{verificationResult.message}</h3>
              <p>{verificationResult.details}</p>
              
              {verificationResult.success && (
                <div className="token-details">
                  <p><strong>Expires in:  60 minutes</strong> {}</p>
                  <p><strong>Usage limit:</strong> {tokenValue}</p>
                </div>
              )}
            </div>
          )}
        </section>
      </main>

      <style jsx>{`
        .anomalous-row {
          background-color: rgba(255, 193, 7, 0.15);
        }
        .revoked-row {
          background-color: #ffebee;
        }
      `}</style>
    </div>
  );
};

export default App;
