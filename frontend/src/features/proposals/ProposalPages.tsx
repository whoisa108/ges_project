import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Plus, Trash2, Edit, Download, Upload } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import api, { downloadFile } from '../../services/api';
import { Header, Countdown, Modal } from '../../Components';

export const DashboardPage = () => {
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
                            <div className="flex" style={{ gap: '10px' }}>
                                <button className="btn" onClick={() => downloadFile(p.id, p.fileName)} style={{ padding: '5px', background: 'rgba(255,255,255,0.05)' }} title="下載檔案">
                                    <Download size={16} />
                                </button>
                                <button className="btn" onClick={() => navigate(`/propose/${p.id}`)} style={{ padding: '5px', background: 'rgba(255,255,255,0.05)' }} title="編輯提案">
                                    <Edit size={16} />
                                </button>
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

export const ProposePage = () => {
    const [formData, setFormData] = useState({ title: '', category: 'I', direction: '綠色製造', summary: '' });
    const [teamMembers, setTeamMembers] = useState<{ name: string, employeeId: string }[]>([]);
    const [file, setFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();
    const { id } = useParams();
    const isEdit = !!id;

    const directions = ['綠色製造', '建立責任供應鏈', '打造健康共榮職場', '培育人才', '關懷弱勢'];

    useEffect(() => {
        if (isEdit) {
            const fetchProposal = async () => {
                try {
                    const res = await api.get('/proposals');
                    const p = res.data.find((item: any) => item.id === id);
                    if (p) {
                        setFormData({ title: p.title, category: p.category, direction: p.direction, summary: p.summary });
                        setTeamMembers(p.teamMembers || []);
                    }
                } catch (e) { console.error(e); }
            };
            fetchProposal();
        }
    }, [id, isEdit]);

    const addMember = () => {
        if (teamMembers.length < 4) {
            setTeamMembers([...teamMembers, { name: '', employeeId: '' }]);
        }
    };

    const removeMember = (index: number) => {
        setTeamMembers(teamMembers.filter((_, i) => i !== index));
    };

    const updateMember = (index: number, field: string, value: string) => {
        const newMembers = [...teamMembers];
        (newMembers[index] as any)[field] = value;
        setTeamMembers(newMembers);
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!isEdit && !file) return alert('請上傳點子報告');
        if (file && file.size > 5 * 1024 * 1024) return alert('檔案大小不得超過 5MB');

        setLoading(true);
        const data = new FormData();
        data.append('title', formData.title);
        data.append('category', formData.category);
        data.append('direction', formData.direction);
        data.append('summary', formData.summary);
        data.append('teamMembers', JSON.stringify(teamMembers.filter(m => m.name && m.employeeId)));
        if (file) data.append('file', file);

        try {
            if (isEdit) {
                await api.post(`/proposals/${id}`, data, { headers: { 'Content-Type': 'multipart/form-data' } });
            } else {
                await api.post('/proposals', data, { headers: { 'Content-Type': 'multipart/form-data' } });
            }
            alert(isEdit ? '更新成功！' : '上傳成功！');
            navigate('/dashboard');
        } catch (err: any) {
            alert(err.response?.data || '操作失敗');
        } finally { setLoading(false); }
    };

    return (
        <div className="container" style={{ maxWidth: '800px' }}>
            <Header />
            <div className="card glass">
                <h1 style={{ marginBottom: '30px' }}>{isEdit ? '編輯點子提案' : '提交點子提案'}</h1>
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
                        <div className="flex justify-between" style={{ marginBottom: '10px', alignItems: 'center' }}>
                            <label style={{ marginBottom: 0 }}>隊友 (0-4人)</label>
                            {teamMembers.length < 4 && (
                                <button type="button" onClick={addMember} className="btn" style={{ padding: '4px 10px', fontSize: '0.8rem', background: 'rgba(255,255,255,0.1)' }}>
                                    <Plus size={14} style={{ marginRight: '5px' }} /> 新增隊友
                                </button>
                            )}
                        </div>
                        <AnimatePresence>
                            {teamMembers.map((member, index) => (
                                <motion.div
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    exit={{ opacity: 0, x: 10 }}
                                    key={index}
                                    className="grid"
                                    style={{ gridTemplateColumns: '1fr 1fr auto', gap: '10px', marginBottom: '10px' }}
                                >
                                    <input className="form-input" placeholder="隊友姓名" value={member.name} onChange={e => updateMember(index, 'name', e.target.value)} />
                                    <input className="form-input" placeholder="隊友工號" value={member.employeeId} onChange={e => updateMember(index, 'employeeId', e.target.value)} />
                                    <button type="button" onClick={() => removeMember(index)} className="btn btn-danger" style={{ padding: '8px' }}>
                                        <Trash2 size={16} />
                                    </button>
                                </motion.div>
                            ))}
                        </AnimatePresence>
                    </div>
                    <div className="form-group">
                        <label>點子報告 (PDF/PPT, ≤5MB) {isEdit && '(若不更新則不需上傳)'}</label>
                        <div style={{ position: 'relative' }}>
                            <input type="file" accept=".pdf,.ppt,.pptx" required={!isEdit} onChange={e => setFile(e.target.files?.[0] || null)} style={{ opacity: 0, position: 'absolute', inset: 0, cursor: 'pointer' }} />
                            <div className="form-input flex" style={{ justifyContent: 'center', gap: '10px', color: file ? 'var(--primary)' : 'var(--text-muted)' }}>
                                <Upload size={20} />
                                {file ? file.name : '點擊或拖曳檔案上傳'}
                            </div>
                        </div>
                    </div>
                    <div style={{ marginTop: '30px', display: 'flex', gap: '15px' }}>
                        <button type="button" onClick={() => navigate('/dashboard')} className="btn" style={{ background: 'var(--border)' }}>取消</button>
                        <button type="submit" className="btn btn-primary" disabled={loading} style={{ flex: 1, justifyContent: 'center' }}>
                            {loading ? '處理中...' : (isEdit ? '更新提案' : '正式提交')}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};
