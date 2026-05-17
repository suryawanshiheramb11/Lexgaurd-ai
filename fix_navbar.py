import re

with open("frontend/src/App.jsx", "r") as f:
    app_jsx = f.read()

# 1. Remove the entire <aside className="sidebar"> ... </aside>
sidebar_pattern = re.compile(r'<aside className="sidebar">.*?</aside>', re.DOTALL)
app_jsx = sidebar_pattern.sub('', app_jsx)

# 2. Replace the left part of the header with logo + nav
header_left_old = r"""          <div className="header-left">
            <h2 className="page-title">
              {activeTab === 'dashboard' && 'Dashboard'}
              {activeTab === 'auditor' && 'Document Library & Auditor'}
              {activeTab === 'prompt-shield' && 'Threat Intelligence'}
              {activeTab === 'advocate' && 'AI Advocate Chat'}
            </h2>
          </div>"""

header_left_new = """          <div className="header-left" style={{display: 'flex', alignItems: 'center'}}>
            <div className="logo-icon-wrapper" style={{marginRight: '12px'}}>
              <Shield className="logo-icon" size={20} />
            </div>
            <span className="logo-text" style={{marginRight: '30px', fontSize: '1.2rem'}}>LexGuard<span className="logo-accent">AI</span></span>
            
            <nav className="top-nav">
              <button className={`top-nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
                <BarChart3 size={16} /> Dashboard
              </button>
              <button className={`top-nav-btn ${activeTab === 'auditor' ? 'active' : ''}`} onClick={() => setActiveTab('auditor')}>
                <FileSearch size={16} /> Document Library
              </button>
              <button className={`top-nav-btn ${activeTab === 'prompt-shield' ? 'active' : ''}`} onClick={() => setActiveTab('prompt-shield')}>
                <Terminal size={16} /> Threat Intelligence
              </button>
              <button className={`top-nav-btn ${activeTab === 'advocate' ? 'active' : ''}`} onClick={() => setActiveTab('advocate')}>
                <MessageSquare size={16} /> AI Advocate
              </button>
            </nav>
          </div>"""

app_jsx = app_jsx.replace(header_left_old, header_left_new)

with open("frontend/src/App.jsx", "w") as f:
    f.write(app_jsx)

with open("frontend/src/App.css", "r") as f:
    app_css = f.read()

# Modify .chat-bubble to remove box design
app_css = app_css.replace(
""".chat-bubble {
  padding: 1.2rem 1.5rem;
  border-radius: var(--radius-md);
  max-width: 85%;
  line-height: 1.6;
  font-size: 0.95rem;
  box-shadow: 0 4px 20px rgba(0,0,0,0.15);
}""",
""".chat-bubble {
  padding: 0.5rem 1rem;
  max-width: 90%;
  line-height: 1.6;
  font-size: 0.95rem;
  background: transparent !important;
  border: none !important;
  box-shadow: none !important;
}"""
)

# Also ensure specific bubble backgrounds are removed
app_css = app_css.replace(
""".chat-message-row.user .chat-bubble {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid var(--border-light);
  color: var(--text-primary);
}""",
""".chat-message-row.user .chat-bubble {
  color: var(--text-primary);
}"""
)

app_css = app_css.replace(
""".chat-message-row.assistant .chat-bubble {
  background: rgba(14, 165, 233, 0.05);
  border: 1px solid rgba(14, 165, 233, 0.2);
  color: #E0F2FE;
}""",
""".chat-message-row.assistant .chat-bubble {
  color: #E0F2FE;
}"""
)

# Add Top Nav CSS
top_nav_css = """

/* === TOP NAV === */
.top-nav {
  display: flex;
  gap: 1rem;
  align-items: center;
}

.top-nav-btn {
  background: transparent;
  border: none;
  color: var(--text-secondary);
  font-family: 'Inter', sans-serif;
  font-size: 0.9rem;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.8rem;
  border-radius: var(--radius-sm);
  cursor: pointer;
  transition: all 0.2s ease;
}

.top-nav-btn:hover {
  color: var(--text-primary);
  background: rgba(255, 255, 255, 0.05);
}

.top-nav-btn.active {
  color: var(--neon-cyan);
  background: rgba(0, 240, 255, 0.1);
}
"""
app_css += top_nav_css

with open("frontend/src/App.css", "w") as f:
    f.write(app_css)

