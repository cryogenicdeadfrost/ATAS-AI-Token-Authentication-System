# ATAS (AI Adaptive Token Authentication System)

ATAS is an AI-powered authentication system that dynamically adjusts token expiration to prevent **unauthorized API access, data scraping, compromised key usage, and illegal AI wrappers**. Using **FastAPI, JWT, Isolation Forest, and IPQS**, ATAS enhances API security through real-time anomaly detection and risk-based token validation.

## 🚀 Features
- **AI-Driven Token Expiry** – Adjusts token lifetime based on anomaly detection and IP risk scoring.
- **Anomaly Detection** – Uses **Isolation Forest** to detect unusual API activity.
- **IP & Proxy Check** – Integrates **IPQS** to flag VPNs, proxies, and suspicious IPs.
- **Context-Based Filtering** – Evaluates request metadata (geolocation, frequency, and behavior patterns).
- **Unauthorized AI Wrapper Prevention** – Blocks third-party applications repackaging API services.
- **Compromised API Key Detection** – Automatically invalidates suspicious keys.

## 🛠️ Tech Stack
- **Backend**: FastAPI, Python
- **Security**: JWT, IPQS Proxy Detection
- **Machine Learning**: Isolation Forest (Scikit-learn)
- **Database**: MongoDB / PostgreSQL (configurable)

## ⚡ Roadmap
- 🔜 Web dashboard for monitoring API requests & risk analysis.
- 🔜 Multi-factor authentication (MFA) support.
- 🔜 Advanced ML-based fraud detection.

## 🤝 Contributing
Feel free to fork and contribute! Open issues and PRs are welcome.

## 📜 License
MIT License - [View License](LICENSE)
