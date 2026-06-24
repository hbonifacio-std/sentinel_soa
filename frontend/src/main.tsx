import { Suspense, lazy } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { LoadingScreen } from '@/components/LoadingScreen';
import { AuthBootstrap } from '@/components/AuthBootstrap';
import { RequireAuth } from '@/components/RequireAuth';
import { RequireRole } from '@/components/RequireRole';
import App from '@/App';
import { configureApiClient } from '@/lib/apiClient';
import { useAuthStore } from '@/store/authStore';
import '@/index.css';

const DashboardPage = lazy(() => import('@/features/dashboard/DashboardPage'));
const AlertsPage = lazy(() => import('@/features/alerts/AlertsPage'));
const LogsPage = lazy(() => import('@/features/logs/LogsPage'));
const RulesPage = lazy(() => import('@/features/rules/RulesPage'));
const LoginPage = lazy(() => import('@/features/auth/LoginPage'));

configureApiClient({
  getAccessToken: () => useAuthStore.getState().accessToken,
  onUnauthorized: () => {
    useAuthStore.getState().setAuthError('Tu sesion expiro. Inicia sesion nuevamente.');
    useAuthStore.getState().clearSession();
  },
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <ErrorBoundary>
    <BrowserRouter>
      <AuthBootstrap>
        <Suspense fallback={<LoadingScreen />}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />

            <Route element={<RequireAuth />}>
              <Route element={<RequireRole allowedRoles={['admin', 'analyst']} />}>
                <Route path="/" element={<App />}>
                  <Route index element={<DashboardPage />} />
                  <Route path="alerts" element={<AlertsPage />} />
                  <Route path="logs" element={<LogsPage />} />
                  <Route path="rules" element={<RulesPage />} />
                </Route>
              </Route>
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </AuthBootstrap>
    </BrowserRouter>
  </ErrorBoundary>,
);
