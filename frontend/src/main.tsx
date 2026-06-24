import { Suspense, lazy } from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { LoadingScreen } from '@/components/LoadingScreen';
import App from '@/App';
import '@/index.css';

const DashboardPage = lazy(() => import('@/features/dashboard/DashboardPage'));
const AlertsPage = lazy(() => import('@/features/alerts/AlertsPage'));
const LogsPage = lazy(() => import('@/features/logs/LogsPage'));
const RulesPage = lazy(() => import('@/features/rules/RulesPage'));

ReactDOM.createRoot(document.getElementById('root')!).render(
  <ErrorBoundary>
    <BrowserRouter>
      <Suspense fallback={<LoadingScreen />}>
        <Routes>
          <Route path="/" element={<App />}>
            <Route index element={<DashboardPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="logs" element={<LogsPage />} />
            <Route path="rules" element={<RulesPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  </ErrorBoundary>,
);

