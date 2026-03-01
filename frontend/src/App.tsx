import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AnimatePresence } from 'framer-motion';
import { LoginPage, RegisterPage, ResetPasswordPage } from './features/auth/AuthPages';
import { DashboardPage, ProposePage } from './features/proposals/ProposalPages';
import { AdminPage } from './features/admin/AdminPage';

/**
 * ESG Idea Competition - Main App & Routing
 * Refactored to follow maintainable feature-based structure.
 */

const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('esg_token');
  if (!token) return <Navigate to="/login" />;
  return <>{children}</>;
};

const AdminRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('esg_token');
  const role = localStorage.getItem('esg_role');
  if (!token || role !== 'ADMIN') return <Navigate to="/login" />;
  return <>{children}</>;
};

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
          <Route path="/propose/:id" element={<ProtectedRoute><ProposePage /></ProtectedRoute>} />

          <Route path="/admin" element={<AdminRoute><AdminPage /></AdminRoute>} />

          <Route path="*" element={<Navigate to="/login" />} />
        </Routes>
      </AnimatePresence>
    </BrowserRouter>
  );
};

export default App;
