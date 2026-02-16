import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { api, Header, Countdown, Modal } from './Components';
import { Plus, Trash2, Calendar, FileText, Upload } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

/**
 * ESG Idea Competition - Main App & Pages
 * Consolidates all pages into one file to follow "1-page-rule" for frontend service.
 */

// --- PAGES ---

const LoginPage = () => {
  const [employeeId, setEmployeeId] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await api.post('/auth/login', { employeeId, password });
      localStorage.setItem('esg_token', res.data.token);
      localStorage.setItem('esg_role', res.data.role);
      localStorage.setItem('esg_user_name', res.data.name);
      localStorage.setItem('esg_employee_id', res.data.employeeId);

      if (res.data.needsPasswordReset) {
        navigate('/reset-password');
      } else {
        navigate(res.data.role === 'ADMIN' ? '/admin' : '/dashboard');
      }
    } catch (err: any) {
      setError(err.response?.data || '登入失敗');
    }
  };

  return (
    <div className="flex" style={{ height: '100vh', justifyContent: 'center' }}>
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="card glass" style={{ width: '400px' }}>
        <h1 style={{ textAlign: 'center', marginBottom: '10px' }}>歡迎登入</h1>
        <p style={{ textAlign: 'center', color: 'var(--text-muted)', marginBottom: '30px' }}>ESG 點子競賽提案系統</p>

        {error && <div style={{ color: 'var(--danger)', marginBottom: '20px', textAlign: 'center' }}>{error}</div>}

        <form onSubmit={handleLogin}>
          <div className="form-group">
            <label>工號 (Employee ID)</label>
            <input className="form-input" required value={employeeId} onChange={e => setEmployeeId(e.target.value)} placeholder="Enter ID" />
          </div>
          <div className="form-group">
            <label>密碼</label>
            <input className="form-input" type="password" required value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" />
          </div>
          <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', marginTop: '10px' }}>登入</button>
        </form>

        <div style={{ marginTop: '30px', textAlign: 'center', fontSize: '0.875rem' }}>
          <span style={{ color: 'var(--text-muted)' }}>初次登入？</span>
          <button onClick={() => navigate('/register')} style={{ background: 'none', border: 'none', color: 'var(--primary)', cursor: 'pointer', marginLeft: '5px' }}>設定帳號</button>
        </div>
      </motion.div>
    </div>
  );
};

const ResetPasswordPage = () => {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const navigate = useNavigate();

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (password !== confirm) return alert('密碼不一致');
    try {
      await api.post('/auth/reset-password', { password });
      alert('密碼重設成功，請重新登入');
      localStorage.clear();
      navigate('/login');
    } catch (e) { alert('重設失敗'); }
  };

  return (
    <div className="flex" style={{ height: '100vh', justifyContent: 'center' }}>
      <div className="card glass" style={{ width: '400px' }}>
        <h2 style={{ textAlign: 'center', marginBottom: '20px' }}>安全性要求：請更換密碼</h2>
        <p style={{ color: 'var(--text-muted)', marginBottom: '30px', textAlign: 'center' }}>您的帳號為初始密碼，請設定新密碼以利繼續使用。</p>
        <form onSubmit={handleReset}>
          <div className="form-group">
            <label>新密碼</label>
            <input className="form-input" type="password" required value={password} onChange={e => setPassword(e.target.value)} />
          </div>
          <div className="form-group">
            <label>確認新密碼</label>
            <input className="form-input" type="password" required value={confirm} onChange={e => setConfirm(e.target.value)} />
          </div>
          <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>更新密碼並重新登入</button>
        </form>
      </div>
    </div>
  );
};

const RegisterPage = () => {
  const [formData, setFormData] = useState({ name: '', employeeId: '', department: 'AAID', password: '' });
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const depts = ['AAID', 'BSID', 'ICSD', 'TSID', 'PLED', 'PEID'];

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.post('/auth/register', formData);
      alert('註冊成功！請使用新密碼登入');
      navigate('/login');
    } catch (err: any) {
      setError(err.response?.data || '註冊失敗');
    }
  };

  return (
    <div className="flex" style={{ height: '100vh', justifyContent: 'center' }}>
      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="card glass" style={{ width: '450px' }}>
        <h2 style={{ textAlign: 'center', marginBottom: '30px' }}>初次登入帳號設定</h2>
        {error && <div style={{ color: 'var(--danger)', marginBottom: '20px', textAlign: 'center' }}>{error}</div>}
        <form onSubmit={handleRegister}>
          <div className="form-group">
            <label>姓名</label>
            <input className="form-input" required value={formData.name} onChange={e => setFormData({ ...formData, name: e.target.value })} />
          </div>
          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group">
              <label>工號</label>
              <input className="form-input" required value={formData.employeeId} onChange={e => setFormData({ ...formData, employeeId: e.target.value })} />
            </div>
            <div className="form-group">
              <label>部門</label>
              <select className="form-input" value={formData.department} onChange={e => setFormData({ ...formData, department: e.target.value })}>
                {depts.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
          </div>
          <div className="form-group">
            <label>密碼 (設定新密碼)</label>
            <input className="form-input" type="password" required value={formData.password} onChange={e => setFormData({ ...formData, password: e.target.value })} />
          </div>
          <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>創立帳號</button>
        </form>
        <div style={{ marginTop: '20px', textAlign: 'center' }}>
          <button onClick={() => navigate('/login')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>返回登入</button>
        </div>
      </motion.div>
    </div>
  );
};

const DashboardPage = () => {
  const [proposals, setProposals] = useState<any[]>([]);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const navigate = useNavigate();

  const fetchProposals = async () => {
    try {
      const res = await api.get('/proposals');
      setProposals(res.data);
    } catch (e) { console.error(e); }
  };

  useEffect(() => { fetchProposals(); }, []);

  const handleDelete = async () => {
    if (!deleteId) return;
    try {
      await api.delete(`/proposals/${deleteId}`);
      setProposals(proposals.filter(p => p.id !== deleteId));
      setDeleteId(null);
    } catch (e) { alert('刪除失敗'); }
  };

  return (
    <div className="container">
      <Header />
      <Countdown />

      <div className="flex justify-between" style={{ marginBottom: '30px' }}>
        <h1>我的提案 <span style={{ color: 'var(--text-muted)', fontSize: '1rem' }}>({proposals.length})</span></h1>
        <button className="btn btn-primary" onClick={() => navigate('/propose')}>
          <Plus size={18} /> 新增提案
        </button>
      </div>

      <div className="grid">
        {proposals.map(p => (
          <motion.div layout key={p.id} className="card glass flex justify-between" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
            <div style={{ width: '100%', marginBottom: '20px' }}>
              <div className="flex" style={{ gap: '8px', marginBottom: '10px' }}>
                <span style={{ fontSize: '0.7rem', padding: '2px 8px', borderRadius: '4px', background: p.category === 'I' ? '#3b82f6' : '#a855f7' }}>
                  {p.category === 'I' ? '酷炫點子' : '卓越影響'}
                </span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{new Date(p.createdAt).toLocaleDateString()}</span>
              </div>
              <h3 style={{ marginBottom: '10px' }}>{p.title}</h3>
              <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', display: '-webkit-box', WebkitLineClamp: 3, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{p.summary}</p>
            </div>
            <div className="flex justify-between" style={{ width: '100%', borderTop: '1px solid var(--border)', paddingTop: '15px' }}>
              <div className="flex" style={{ gap: '5px', color: 'var(--primary)', fontSize: '0.8rem' }}>
                <FileText size={14} /> 附件已上傳
              </div>
              <button className="btn btn-danger" onClick={() => setDeleteId(p.id)} style={{ padding: '5px' }}>
                <Trash2 size={16} />
              </button>
            </div>
          </motion.div>
        ))}
      </div>

      <Modal isOpen={!!deleteId} onClose={() => setDeleteId(null)} onConfirm={handleDelete} title="確認刪除提案？" danger confirmText="確認刪除">
        刪除後將無法恢復此提案，確定要繼續嗎？
      </Modal>
    </div>
  );
};

const ProposePage = () => {
  const [formData, setFormData] = useState({ title: '', category: 'I', direction: '綠色製造', summary: '' });
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const directions = ['綠色製造', '建立責任供應鏈', '打造健康共榮職場', '培育人才', '關懷弱勢'];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return alert('請上傳點子報告');
    if (file.size > 5 * 1024 * 1024) return alert('檔案大小不得超過 5MB');

    setLoading(true);
    const data = new FormData();
    data.append('title', formData.title);
    data.append('category', formData.category);
    data.append('direction', formData.direction);
    data.append('summary', formData.summary);
    data.append('file', file);

    try {
      await api.post('/proposals', data);
      alert('上傳成功！');
      navigate('/dashboard');
    } catch (err: any) {
      alert(err.response?.data || '上傳失敗');
    } finally { setLoading(false); }
  };

  return (
    <div className="container" style={{ maxWidth: '800px' }}>
      <Header />
      <div className="card glass">
        <h1 style={{ marginBottom: '30px' }}>提交點子提案</h1>
        <form onSubmit={handleSubmit}>
          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="form-group">
              <label>點子類別</label>
              <select className="form-input" value={formData.category} onChange={e => setFormData({ ...formData, category: e.target.value })}>
                <option value="I">酷炫點子獎</option>
                <option value="O">卓越影響獎</option>
              </select>
            </div>
            <div className="form-group">
              <label>五大方向</label>
              <select className="form-input" value={formData.direction} onChange={e => setFormData({ ...formData, direction: e.target.value })}>
                {directions.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
          </div>
          <div className="form-group">
            <label>點子名稱 (≤50字)</label>
            <input className="form-input" maxLength={50} required value={formData.title} onChange={e => setFormData({ ...formData, title: e.target.value })} />
          </div>
          <div className="form-group">
            <label>點子摘要 (≤300字)</label>
            <textarea className="form-input" maxLength={300} required rows={4} value={formData.summary} onChange={e => setFormData({ ...formData, summary: e.target.value })} />
          </div>
          <div className="form-group">
            <label>點子報告 (PDF/PPT, ≤5MB)</label>
            <div style={{ position: 'relative' }}>
              <input type="file" accept=".pdf,.ppt,.pptx" required onChange={e => setFile(e.target.files?.[0] || null)} style={{ opacity: 0, position: 'absolute', inset: 0, cursor: 'pointer' }} />
              <div className="form-input flex" style={{ justifyContent: 'center', gap: '10px', color: file ? 'var(--primary)' : 'var(--text-muted)' }}>
                <Upload size={20} />
                {file ? file.name : '點擊或拖曳檔案上傳'}
              </div>
            </div>
          </div>
          <div style={{ marginTop: '30px', display: 'flex', gap: '15px' }}>
            <button type="button" onClick={() => navigate('/dashboard')} className="btn" style={{ background: 'var(--border)' }}>取消</button>
            <button type="submit" className="btn btn-primary" disabled={loading} style={{ flex: 1, justifyContent: 'center' }}>
              {loading ? '上傳中...' : '正式提交'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

const AdminPage = () => {
  const [proposals, setProposals] = useState<any[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [deadline, setDeadline] = useState('');
  const [tab, setTab] = useState('proposals');

  const fetchData = async () => {
    try {
      const [p, u, a, d] = await Promise.all([
        api.get('/proposals'),
        api.get('/admin/users'),
        api.get('/admin/audit-logs'),
        api.get('/deadline')
      ]);
      setProposals(p.data);
      setUsers(u.data);
      setAuditLogs(a.data);
      if (d.data.value) setDeadline(d.data.value);
    } catch (e) { console.error(e); }
  };

  useEffect(() => { fetchData(); }, []);

  const handleUpdateDeadline = async () => {
    try {
      await api.post('/admin/deadline', { deadline });
      alert('截止時間已更換');
    } catch (e) { alert('更新失敗'); }
  };

  const deleteUser = async (id: string) => {
    if (!confirm('確認刪除此人員？')) return;
    await api.delete(`/admin/users/${id}`);
    setUsers(users.filter(u => u.id !== id));
  };

  const deleteProposal = async (id: string) => {
    if (!confirm('確認刪除此提案？')) return;
    await api.delete(`/proposals/${id}`);
    setProposals(proposals.filter(p => p.id !== id));
  };

  return (
    <div className="container">
      <Header />
      <div className="flex justify-between" style={{ marginBottom: '30px' }}>
        <div className="flex" style={{ gap: '10px' }}>
          <button className={`btn ${tab === 'proposals' ? 'btn-primary' : ''}`} onClick={() => setTab('proposals')}>提案管理</button>
          <button className={`btn ${tab === 'users' ? 'btn-primary' : ''}`} onClick={() => setTab('users')}>人員管理</button>
          <button className={`btn ${tab === 'audit' ? 'btn-primary' : ''}`} onClick={() => setTab('audit')}>稽核紀錄</button>
        </div>
        <div className="flex glass" style={{ padding: '8px 15px', gap: '15px' }}>
          <div className="flex" style={{ gap: '8px', fontSize: '0.85rem' }}>
            <Calendar size={16} color="var(--primary)" />
            截止時間：
          </div>
          <input type="datetime-local" className="form-input" style={{ width: '200px', padding: '5px' }} value={deadline} onChange={e => setDeadline(e.target.value)} />
          <button className="btn btn-primary" onClick={handleUpdateDeadline} style={{ padding: '5px 12px' }}>設定</button>
        </div>
      </div>

      {tab === 'proposals' && (
        <div className="card glass">
          <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 10px' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                <th style={{ padding: '10px' }}>類別</th>
                <th style={{ padding: '10px' }}>提案名稱</th>
                <th style={{ padding: '10px' }}>提案人</th>
                <th style={{ padding: '10px' }}>建立時間</th>
                <th style={{ padding: '10px' }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {proposals.map(p => (
                <tr key={p.id} className="glass" style={{ background: 'rgba(255,255,255,0.02)' }}>
                  <td style={{ padding: '15px', borderRadius: '8px 0 0 8px' }}>{p.category}</td>
                  <td style={{ padding: '15px' }}>{p.title}</td>
                  <td style={{ padding: '15px' }}>{p.creatorName} ({p.creatorId})</td>
                  <td style={{ padding: '15px' }}>{new Date(p.createdAt).toLocaleString()}</td>
                  <td style={{ padding: '15px', borderRadius: '0 8px 8px 0' }}>
                    <button className="btn btn-danger" onClick={() => deleteProposal(p.id)} style={{ padding: '5px' }}><Trash2 size={16} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'users' && (
        <div className="card glass">
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', color: 'var(--text-muted)' }}>
                <th style={{ padding: '15px' }}>姓名</th>
                <th style={{ padding: '15px' }}>工號</th>
                <th style={{ padding: '15px' }}>部門</th>
                <th style={{ padding: '15px' }}>角色</th>
                <th style={{ padding: '15px' }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td style={{ padding: '15px' }}>{u.name}</td>
                  <td style={{ padding: '15px' }}>{u.employeeId}</td>
                  <td style={{ padding: '15px' }}>{u.department}</td>
                  <td style={{ padding: '15px' }}>{u.role}</td>
                  <td style={{ padding: '15px' }}>
                    {u.employeeId !== 'admin' && <button className="btn btn-danger" onClick={() => deleteUser(u.id)} style={{ padding: '5px' }}><Trash2 size={16} /></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'audit' && (
        <div className="card glass">
          <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
            {auditLogs.map(log => (
              <div key={log.id} style={{ padding: '10px', borderBottom: '1px solid var(--border)', fontSize: '0.85rem' }}>
                <span style={{ color: 'var(--primary)' }}>[{new Date(log.timestamp).toLocaleString()}]</span>
                <b style={{ margin: '0 10px' }}>{log.performedBy}</b>
                <span style={{ color: 'var(--text-muted)' }}>{log.action}: {log.details}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

// --- APP CORE ---

const App = () => {
  return (
    <BrowserRouter>
      <AnimatePresence mode="wait">
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/reset-password" element={<ResetPasswordPage />} />
          <Route path="/dashboard" element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
          <Route path="/propose" element={<ProtectedRoute><ProposePage /></ProtectedRoute>} />
          <Route path="/admin" element={<AdminRoute><AdminPage /></AdminRoute>} />
          <Route path="*" element={<Navigate to="/login" />} />
        </Routes>
      </AnimatePresence>
    </BrowserRouter>
  );
};

const ProtectedRoute = ({ children }: any) => {
  const token = localStorage.getItem('esg_token');
  if (!token) return <Navigate to="/login" />;
  return children;
};

const AdminRoute = ({ children }: any) => {
  const token = localStorage.getItem('esg_token');
  const role = localStorage.getItem('esg_role');
  if (!token || role !== 'ADMIN') return <Navigate to="/login" />;
  return children;
};

export default App;
