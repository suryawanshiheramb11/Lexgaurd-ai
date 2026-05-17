# LexGuard AI 🛡️

**LexGuard AI** is an enterprise-grade Legal Intelligence & Governance platform built to automate document analysis, mitigate legal risks, and protect AI integrations against adversarial threats. 

With a premium glassmorphism user interface and cutting-edge Google Gemini 2.5 Flash integration, LexGuard serves as a comprehensive "Chief Legal Officer" right in your browser.

---

## 🌟 Key Features

### 1. Document Auditor & Risk Analysis
Upload contracts, NDAs, and compliance documents (PDF/DOCX/TXT) for instant, multi-framework analysis:
- **Contract Audit**: Evaluates financial exposure, termination symmetry, non-competes, and jurisdiction clauses.
- **Risk Assessment**: Detects force majeure gaps, unconstrained warranties, and missing insurance requirements.
- **Regulatory Compliance**: Audits data protection requirements (GDPR, CCPA), SOC2/ISO compliance, and export control logic.
- **KYC & AML**: Validates beneficial ownership declarations, sanctions screening, and PEP attestations for transactional agreements.

### 2. Threat Intelligence (Prompt Shield)
A dedicated environment to test and harden your LLM prompts against prompt injection attacks, jailbreak attempts, PII leakage, and toxicity before deploying to production.

### 3. AI Legal Advocate
A fully integrated, conversational AI compliance agent. If you upload a document in the Auditor, the AI Advocate actively reads the context and can answer specific questions, explain complex clauses, and offer actionable legal recommendations interactively.

### 4. Enterprise-Grade Security
- **Google Authentication**: Secure access using `@react-oauth/google` with dynamic user profile mapping.
- **Server-Side Hardening**: Enforced CSP, strict CORS policies, and advanced document sanitization.
- **Mock Fallbacks**: Complete operational fallback generators ensure zero downtime even if the primary AI API connection drops.

---

## 🛠️ Technology Stack

**Frontend:**
- React 18 + Vite
- Vanilla CSS (Premium Glassmorphism & Dark Mode)
- Google OAuth 2.0 Integration (`@react-oauth/google`)
- React Markdown (Rich text rendering)
- Axios & Lucide React (Icons)

**Backend:**
- FastAPI (Python)
- Google Generative AI SDK (Gemini 2.5 Flash)
- PyMuPDF (`fitz`) & `python-docx` (Document Parsing)
- Uvicorn (ASGI Web Server)

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v18+)
- Python (3.10+)
- A Google Cloud Platform (GCP) account (for Gemini and OAuth credentials)

### 1. Backend Setup (FastAPI)

1. Open a terminal and navigate to the `backend` directory:
   ```bash
   cd lexguard/backend
   ```
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Set up your environment variables by creating a `.env` file in the `backend` folder:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   CORS_ORIGINS=http://localhost:5173,http://localhost:8080
   ENVIRONMENT=development
   ```
4. Start the backend server:
   ```bash
   python main.py
   # Or using uvicorn directly:
   # uvicorn main:app --host 0.0.0.0 --port 8080 --reload
   ```

### 2. Frontend Setup (React)

1. Open a new terminal and navigate to the `frontend` directory:
   ```bash
   cd lexguard/frontend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. (Optional) Set up your Google OAuth Client ID by creating a `.env` file:
   ```env
   VITE_GOOGLE_CLIENT_ID=your_google_oauth_client_id.apps.googleusercontent.com
   ```
4. Start the Vite development server:
   ```bash
   npm run dev
   ```
   *The frontend will typically run on `http://localhost:5173`.*

---

## 🛡️ Architecture & Security Notes

- **Separation of Concerns**: The AI engine is restricted to the *AI Advocate* tab to prevent over-reliance on generative AI for structural legal auditing. Document scanning heavily relies on rule-based validation combined with intelligent semantic analysis.
- **PII Protection**: Files are parsed strictly in-memory using `BytesIO` where possible. Temp files are deterministically cleaned up using `try/finally` blocks.
- **Authentication Bypass**: For local development without authorized OAuth origins, a "Developer Mode Bypass" is included on the login screen.

---

## 📜 License

This project is licensed under the MIT License.
