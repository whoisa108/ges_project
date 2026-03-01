import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import api from '../../services/api';

export const LoginPage = () => {
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

export const RegisterPage = () => {
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

export const ResetPasswordPage = () => {
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
