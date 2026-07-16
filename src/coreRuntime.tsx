import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/core';

export type CoreStatus = {
  installed: boolean;
  running: boolean;
  managed: boolean;
  processId: number | null;
  currentVersion: string | null;
  installDir: string;
  binaryPath: string | null;
  message: string;
};

type CoreRuntimeContextValue = {
  status: CoreStatus | null;
  statusError: string;
  publishStatus: (status: CoreStatus | null) => void;
};

const CoreRuntimeContext = createContext<CoreRuntimeContextValue | null>(null);

export function CoreRuntimeProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<CoreStatus | null>(null);
  const [statusError, setStatusError] = useState('');

  const refreshStatus = useCallback(async () => {
    try {
      const nextStatus = await invoke<CoreStatus>('get_core_status');
      setStatus(nextStatus);
      setStatusError('');
    } catch (error) {
      setStatus(null);
      setStatusError(String(error));
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
    const timer = window.setInterval(() => {
      void refreshStatus();
    }, 1500);

    return () => window.clearInterval(timer);
  }, [refreshStatus]);

  const value = useMemo(
    () => ({ status, statusError, publishStatus: setStatus }),
    [status, statusError],
  );

  return <CoreRuntimeContext.Provider value={value}>{children}</CoreRuntimeContext.Provider>;
}

export function useCoreRuntime() {
  const context = useContext(CoreRuntimeContext);
  if (!context) {
    throw new Error('useCoreRuntime 必须在 CoreRuntimeProvider 内使用');
  }
  return context;
}
