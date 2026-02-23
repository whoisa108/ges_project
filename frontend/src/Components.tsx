import { useState, useEffect } from 'react';
import axios, { type InternalAxiosRequestConfig } from 'axios';
import { useNavigate } from 'react-router-dom';
import { Clock, CheckCircle, LogOut, User } from 'lucide-react';

/**
 * Shared Components for ESG Project
 * Following "1-page-rule" - keeping common UI here.
 */

export const api = axios.create({
    baseURL: '/api'
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    const token = localStorage.getItem('esg_token');
    if (token && config.headers) config.headers.Authorization = `Bearer ${token}`;
    return config;
});

export const Header = () => {
    const navigate = useNavigate();
    const name = localStorage.getItem('esg_user_name');
    const role = localStorage.getItem('esg_role');

    const logout = () => {
        localStorage.clear();
        navigate('/login');
    };

    return (
        <nav className="glass" style={{ margin: '20px', padding: '15px 30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div className="flex" style={{ gap: '12px', cursor: 'pointer' }} onClick={() => navigate('/dashboard')}>
                <div style={{ background: 'var(--primary)', padding: '8px', borderRadius: '10px' }}>
                    <CheckCircle size={24} color="white" />
                </div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>ESG <span style={{ color: 'var(--primary)' }}>IDEAS</span></h2>
            </div>

            <div className="flex" style={{ gap: '20px' }}>
                <div className="flex" style={{ gap: '10px' }}>
                    <User size={18} color="var(--text-muted)" />
                    <span style={{ fontWeight: 500 }}>{name} ({role})</span>
                </div>
                <button className="btn btn-danger" onClick={logout} style={{ padding: '8px 12px' }}>
                    <LogOut size={16} />
                </button>
            </div>
        </nav>
    );
};

export const Countdown = () => {
    const [timeLeft, setTimeLeft] = useState<{ d: number, h: number, m: number, s: number } | null>(null);

    useEffect(() => {
        const fetchDeadline = async () => {
            try {
                const res = await api.get('/deadline');
                if (res.data.value && res.data.value !== "Not Set") {
                    const deadline = new Date(res.data.value).getTime();
                    const timer = setInterval(() => {
                        const now = new Date().getTime();
                        const diff = deadline - now;
                        if (diff <= 0) {
                            clearInterval(timer);
                            setTimeLeft({ d: 0, h: 0, m: 0, s: 0 });
                        } else {
                            setTimeLeft({
                                d: Math.floor(diff / (1000 * 60 * 60 * 24)),
                                h: Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)),
                                m: Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60)),
                                s: Math.floor((diff % (1000 * 60)) / 1000)
                            });
                        }
                    }, 1000);
                    return () => clearInterval(timer);
                }
            } catch (e) { console.error("Deadline error", e); }
        };
        fetchDeadline();
    }, []);

    if (!timeLeft) return null;

    return (
        <div className="glass flex" style={{ padding: '15px 25px', gap: '20px', marginBottom: '30px' }}>
            <div className="flex" style={{ gap: '10px', color: 'var(--primary)' }}>
                <Clock size={20} />
                <span style={{ fontWeight: 600 }}>提案截止剩餘時間：</span>
            </div>
            <div className="flex" style={{ gap: '15px' }}>
                {Object.entries(timeLeft).map(([unit, val]) => (
                    <div key={unit} style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: '1.5rem', fontWeight: 700 }}>{val.toString().padStart(2, '0')}</div>
                        <div style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                            {unit === 'd' ? '天' : unit === 'h' ? '時' : unit === 'm' ? '分' : '秒'}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export const Modal = ({ isOpen, onClose, title, children, onConfirm, confirmText = "確認", danger = false }: any) => {
    if (!isOpen) return null;
    return (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.8)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
            <div className="card glass animate-fade" style={{ width: '400px', maxWidth: '90%' }}>
                <h3 style={{ marginBottom: '20px' }}>{title}</h3>
                <div style={{ marginBottom: '30px', color: 'var(--text-muted)' }}>{children}</div>
                <div className="flex justify-between" style={{ gap: '10px' }}>
                    <button className="btn" onClick={onClose} style={{ flex: 1, background: 'var(--border)' }}>取消</button>
                    <button className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`} onClick={onConfirm} style={{ flex: 1 }}>{confirmText}</button>
                </div>
            </div>
        </div>
    );
};

export const downloadFile = async (id: string, fileName: string) => {
    try {
        const res = await api.get(`/proposals/${id}/download`, { responseType: 'blob' });
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', fileName);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
    } catch (e) {
        alert('下載失敗');
        console.error(e);
    }
};
