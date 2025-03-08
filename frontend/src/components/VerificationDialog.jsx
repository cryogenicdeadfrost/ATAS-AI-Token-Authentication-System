import React, { useState } from "react";
import "./VerificationDialog.css";

const VerificationDialog = ({ generatedTokens }) => {
  const [apiKey, setApiKey] = useState("");
  const [isVerified, setIsVerified] = useState(null);
  const [verificationDetails, setVerificationDetails] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleVerify = async () => {
    if (!apiKey) {
      alert("Please enter an API key or JWT token.");
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch("http://127.0.0.1:5000/verify", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ apiKey }),
      });

      const data = await response.json();
      console.log("Verification response:", data);
      setIsVerified(data.verified);
      setVerificationDetails(data);
    } catch (error) {
      console.error("Verification failed:", error);
      setIsVerified(false);
      setVerificationDetails({ error: "Connection error" });
    } finally {
      setIsLoading(false);
    }
  };

  // Add buttons to quickly fill in generated API keys
  const fillInLatestAPIKey = () => {
    if (generatedTokens && generatedTokens.length > 0) {
      const latest = generatedTokens[generatedTokens.length - 1];
      if (latest.apiKey) {
        setApiKey(latest.apiKey);
      } else if (typeof latest === 'string') {
        // Handle old format if needed
        setApiKey(latest);
      }
    }
  };

  return (
    <div className="verification-dialog">
      <h3>Verify API Key or JWT Token</h3>
      <div className="dialog-box">
        <input
          type="text"
          className="api-input"
          placeholder="Enter API key or JWT token"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
        />
        <button 
          className="verify-button" 
          onClick={handleVerify}
          disabled={isLoading}
        >
          {isLoading ? "Verifying..." : "Verify"}
        </button>
        {generatedTokens && generatedTokens.length > 0 && (
          <button 
            className="fill-button" 
            onClick={fillInLatestAPIKey}
          >
            Use Latest API Key
          </button>
        )}
      </div>
      
      {isVerified === null ? (
        ""
      ) : isVerified ? (
        <div className="verification-result success">
          <h2>✅ Verification Successful</h2>
          {verificationDetails?.type === "jwt" && (
            <div className="token-details">
              <p><strong>Type:</strong> JWT Token</p>
              <p><strong>API Key:</strong> {verificationDetails.payload.api_key}</p>
              <p><strong>Model:</strong> {verificationDetails.payload.model}</p>
              <p><strong>Tokens:</strong> {verificationDetails.payload.token_value}</p>
              <p><strong>IP:</strong> {verificationDetails.payload.ip_address}</p>
              <p><strong>Purpose:</strong> {verificationDetails.payload.purpose}</p>
              <p><strong>Expires:</strong> {new Date(verificationDetails.payload.exp * 1000).toLocaleString()}</p>
            </div>
          )}
          {verificationDetails?.type === "api_key" && (
            <div className="token-details">
              <p><strong>Type:</strong> API Key</p>
              <p><strong>Expires:</strong> {new Date(verificationDetails.expires_at * 1000).toLocaleString()}</p>
            </div>
          )}
        </div>
      ) : (
        <div className="verification-result error">
          <h2>❌ Verification Failed</h2>
          <p>{verificationDetails?.message || verificationDetails?.error || "Invalid or expired token"}</p>
        </div>
      )}
    </div>
  );
};

export default VerificationDialog;