import React, { useState, useEffect } from 'react';
import { Calendar, Download, Trash2, Edit } from 'lucide-react';
import api, { downloadFile } from '../../services/api';
import { Header, Modal } from '../../Components';

export const AdminPage = () => {
    const [proposals, setProposals] = useState<any[]>([]);
    const [users, setUsers] = useState<any[]>([]);
    const [auditLogs, setAuditLogs] = useState<any[]>([]);
    const [deadline, setDeadline] = useState('');
    const [tab, setTab] = useState('proposals');
    const [editingUser, setEditingUser] = useState<any>(null);
    const [editForm, setEditForm] = useState({ department: 'AAID', role: 'PROPOSER' });
    const depts = ['AAID', 'BSID', 'ICSD', 'TSID', 'PLED', 'PEID'];

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
        try {
            await api.delete(`/admin/users/${id}`);
            setUsers(users.filter(u => u.id !== id));
        } catch (e) { alert('刪除失敗'); }
    };

    const handleEditUser = (user: any) => {
        setEditingUser(user);
        setEditForm({ department: user.department, role: user.role });
    };

    const saveUserEdit = async () => {
        try {
            await api.put(`/admin/users/${editingUser.id}`, editForm);
            setUsers(users.map(u => u.id === editingUser.id ? { ...u, ...editForm } : u));
            setEditingUser(null);
            alert('人員資料已更新');
        } catch (e) { alert('更新失敗'); }
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
                                        <div className="flex" style={{ gap: '10px' }}>
                                            <button className="btn" onClick={() => downloadFile(p.id, p.fileName)} style={{ padding: '5px', background: 'rgba(255,255,255,0.05)' }} title="下載檔案"><Download size={16} /></button>
                                            <button className="btn btn-danger" onClick={() => deleteProposal(p.id)} style={{ padding: '5px' }}><Trash2 size={16} /></button>
                                        </div>
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
                                        <div className="flex" style={{ gap: '10px' }}>
                                            <button className="btn" onClick={() => handleEditUser(u)} style={{ padding: '5px', background: 'rgba(255,255,255,0.05)' }} title="編輯人員"><Edit size={16} /></button>
                                            {u.employeeId !== 'admin' && <button className="btn btn-danger" onClick={() => deleteUser(u.id)} style={{ padding: '5px' }}><Trash2 size={16} /></button>}
                                        </div>
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

            <Modal isOpen={!!editingUser} onClose={() => setEditingUser(null)} onConfirm={saveUserEdit} title="編輯人員資料" confirmText="儲存變更">
                {editingUser && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
                        <div className="form-group">
                            <label>姓名 (不可編輯)</label>
                            <input className="form-input" value={editingUser.name} disabled style={{ opacity: 0.6 }} />
                        </div>
                        <div className="form-group">
                            <label>工號 (不可編輯)</label>
                            <input className="form-input" value={editingUser.employeeId} disabled style={{ opacity: 0.6 }} />
                        </div>
                        <div className="form-group">
                            <label>部門</label>
                            <select className="form-input" value={editForm.department} onChange={e => setEditForm({ ...editForm, department: e.target.value })}>
                                {depts.map(d => <option key={d} value={d}>{d}</option>)}
                            </select>
                        </div>
                        <div className="form-group">
                            <label>角色</label>
                            <select className="form-input" value={editForm.role} onChange={e => setEditForm({ ...editForm, role: e.target.value })}>
                                <option value="PROPOSER">提案人 (PROPOSER)</option>
                                <option value="ADMIN">管理員 (ADMIN)</option>
                            </select>
                        </div>
                    </div>
                )}
            </Modal>
        </div>
    );
};
