import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router'
import './index.css'
import { Shell } from './pages/Shell'
import { Login } from './pages/Login'
import { InviteAccept } from './pages/InviteAccept'
import { OrgHome } from './pages/OrgHome'
import { NetworkDetail } from './pages/NetworkDetail'
import { Settings } from './pages/Settings'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 5_000 } },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/invite" element={<InviteAccept />} />
          <Route path="/" element={<Shell />}>
            <Route index element={<Navigate to="pick" replace />} />
            <Route path="pick" element={<OrgHome pick />} />
            <Route path="o/:slug" element={<OrgHome />} />
            <Route path="o/:slug/networks/:name" element={<NetworkDetail />} />
            <Route path="o/:slug/settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
