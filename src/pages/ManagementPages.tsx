import { useCallback, useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Check,
  Copy,
  ExternalLink,
  LoaderCircle,
  LogIn,
} from 'lucide-react';
import antigravityIcon from '../assets/icons/antigravity.svg';
import claudeIcon from '../assets/icons/claude.svg';
import codexIcon from '../assets/icons/codex.svg';
import grokIcon from '../assets/icons/grok.svg';
import kimiIcon from '../assets/icons/kimi-light.svg';

type OAuthProviderId = 'codex' | 'claude' | 'antigravity' | 'kimi' | 'xai';
type OAuthFlowStatus = 'idle' | 'waiting' | 'success' | 'error';

type OAuthProviderState = {
  url?: string;
  state?: string;
  status: OAuthFlowStatus;
  error?: string;
  polling?: boolean;
  callbackUrl?: string;
  callbackSubmitting?: boolean;
  callbackStatus?: 'success' | 'error';
  callbackError?: string;
};

type OAuthStartResult = {
  url: string;
  state?: string | null;
  opened: boolean;
  openError?: string | null;
};

type OAuthStatusResult = {
  status: string;
  error?: string | null;
};

const oauthProviders = [
  { id: 'codex' as const, name: 'Codex OAuth', icon: codexIcon },
  { id: 'claude' as const, name: 'Claude OAuth', icon: claudeIcon },
  { id: 'antigravity' as const, name: 'Antigravity OAuth', icon: antigravityIcon },
  { id: 'kimi' as const, name: 'Kimi OAuth', icon: kimiIcon },
  { id: 'xai' as const, name: 'xAI OAuth', icon: grokIcon },
];

const OAUTH_CALLBACK_SUPPORTED = new Set<OAuthProviderId>([
  'codex',
  'claude',
  'antigravity',
  'xai',
]);
const XAI_CALLBACK_URL = 'http://127.0.0.1:56121/callback';
const OAUTH_SUCCESS_RESET_MS = 5000;
const OAUTH_POLL_INTERVAL_MS = 3000;

export function OAuthLoginPage() {
  const [states, setStates] = useState<Partial<Record<OAuthProviderId, OAuthProviderState>>>({});
  const [notice, setNotice] = useState<{
    message: string;
    tone: 'success' | 'error' | 'info';
  } | null>(null);
  const pollingTimers = useRef<Partial<Record<OAuthProviderId, number>>>({});
  const pollingRequests = useRef<Partial<Record<OAuthProviderId, boolean>>>({});
  const successResetTimers = useRef<Partial<Record<OAuthProviderId, number>>>({});
  const noticeTimerRef = useRef<number | null>(null);

  const showNotice = useCallback((message: string, tone: 'success' | 'error' | 'info') => {
    if (noticeTimerRef.current !== null) window.clearTimeout(noticeTimerRef.current);
    setNotice({ message, tone });
    noticeTimerRef.current = window.setTimeout(() => {
      setNotice(null);
      noticeTimerRef.current = null;
    }, 3600);
  }, []);

  const updateProviderState = useCallback(
    (provider: OAuthProviderId, next: Partial<OAuthProviderState>) => {
      setStates((current) => ({
        ...current,
        [provider]: {
          status: 'idle',
          ...(current[provider] ?? {}),
          ...next,
        },
      }));
    },
    [],
  );

  const clearPollingTimer = useCallback((provider: OAuthProviderId) => {
    const timer = pollingTimers.current[provider];
    if (timer !== undefined) window.clearInterval(timer);
    delete pollingTimers.current[provider];
    delete pollingRequests.current[provider];
  }, []);

  const clearSuccessResetTimer = useCallback((provider: OAuthProviderId) => {
    const timer = successResetTimers.current[provider];
    if (timer !== undefined) window.clearTimeout(timer);
    delete successResetTimers.current[provider];
  }, []);

  const clearProviderTimers = useCallback(
    (provider: OAuthProviderId) => {
      clearPollingTimer(provider);
      clearSuccessResetTimer(provider);
    },
    [clearPollingTimer, clearSuccessResetTimer],
  );

  const resetProviderAttempt = useCallback(
    (provider: OAuthProviderId) => {
      clearProviderTimers(provider);
      setStates((current) => ({ ...current, [provider]: { status: 'idle' } }));
    },
    [clearProviderTimers],
  );

  const completeProviderAuth = useCallback(
    (provider: OAuthProviderId) => {
      clearProviderTimers(provider);
      updateProviderState(provider, {
        url: undefined,
        state: undefined,
        status: 'success',
        error: undefined,
        polling: false,
        callbackUrl: '',
        callbackSubmitting: false,
        callbackStatus: undefined,
        callbackError: undefined,
      });
      successResetTimers.current[provider] = window.setTimeout(() => {
        resetProviderAttempt(provider);
      }, OAUTH_SUCCESS_RESET_MS);
    },
    [clearProviderTimers, resetProviderAttempt, updateProviderState],
  );

  const startPolling = useCallback(
    (provider: OAuthProviderId, state: string) => {
      clearPollingTimer(provider);
      const checkStatus = async () => {
        if (pollingRequests.current[provider]) return;
        pollingRequests.current[provider] = true;
        try {
          const result = await invoke<OAuthStatusResult>('get_oauth_status', { state });
          const status = (result.status || '').toLowerCase();
          if (status === 'ok') {
            completeProviderAuth(provider);
            showNotice(`${providerLabel(provider)} 登录成功`, 'success');
          } else if (status === 'error') {
            updateProviderState(provider, {
              status: 'error',
              error: result.error || '认证失败',
              polling: false,
            });
            clearPollingTimer(provider);
            showNotice(
              `${providerLabel(provider)} 登录失败${result.error ? `：${result.error}` : ''}`,
              'error',
            );
          }
        } catch (error) {
          updateProviderState(provider, {
            status: 'error',
            error: String(error),
            polling: false,
          });
          clearPollingTimer(provider);
          showNotice(String(error), 'error');
        } finally {
          delete pollingRequests.current[provider];
        }
      };
      pollingTimers.current[provider] = window.setInterval(
        () => void checkStatus(),
        OAUTH_POLL_INTERVAL_MS,
      );
    },
    [clearPollingTimer, completeProviderAuth, showNotice, updateProviderState],
  );

  useEffect(() => {
    return () => {
      Object.values(pollingTimers.current).forEach((timer) => {
        if (timer !== undefined) window.clearInterval(timer);
      });
      Object.values(successResetTimers.current).forEach((timer) => {
        if (timer !== undefined) window.clearTimeout(timer);
      });
      if (noticeTimerRef.current !== null) window.clearTimeout(noticeTimerRef.current);
    };
  }, []);

  const startLogin = async (provider: OAuthProviderId) => {
    clearProviderTimers(provider);
    updateProviderState(provider, {
      url: undefined,
      state: undefined,
      status: 'waiting',
      polling: true,
      error: undefined,
      callbackUrl: '',
      callbackStatus: undefined,
      callbackError: undefined,
    });

    try {
      const result = await invoke<OAuthStartResult>('start_oauth_login', { provider });
      if (!result.state) {
        updateProviderState(provider, {
          url: result.url,
          state: undefined,
          status: 'error',
          error: '内核未返回 OAuth state',
          polling: false,
        });
        showNotice('内核未返回 OAuth state，无法轮询登录状态', 'error');
        return;
      }

      updateProviderState(provider, {
        url: result.url,
        state: result.state,
        status: 'waiting',
        polling: true,
      });
      startPolling(provider, result.state);

      if (!result.opened) {
        showNotice(
          result.openError
            ? `已获取登录链接，但自动打开浏览器失败：${result.openError}`
            : '已获取登录链接，但自动打开浏览器失败，请手动打开',
          'info',
        );
      }
    } catch (error) {
      updateProviderState(provider, {
        status: 'error',
        error: String(error),
        polling: false,
      });
      showNotice(String(error), 'error');
    }
  };

  const openAuthUrl = async (url?: string) => {
    if (!url) return;
    try {
      await invoke('open_external_url', { url });
    } catch (error) {
      showNotice(String(error), 'error');
    }
  };

  const copyAuthUrl = async (url?: string) => {
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      showNotice('登录链接已复制', 'success');
    } catch {
      showNotice('复制登录链接失败', 'error');
    }
  };

  const submitCallback = async (provider: OAuthProviderId) => {
    const current = states[provider];
    const callbackInput = (current?.callbackUrl || '').trim();
    if (!callbackInput) {
      showNotice(
        provider === 'xai' ? '请粘贴 xAI 返回的 code 或回调 URL' : '请粘贴回调 URL',
        'error',
      );
      return;
    }

    const redirectUrl = resolveCallbackUrl(provider, callbackInput, current?.state);
    if (!redirectUrl) {
      showNotice(
        provider === 'xai'
          ? '无法从输入内容构造 xAI 回调，请检查 code 与 state'
          : '回调内容无效',
        'error',
      );
      return;
    }

    updateProviderState(provider, {
      callbackSubmitting: true,
      callbackStatus: undefined,
      callbackError: undefined,
    });
    try {
      await invoke('submit_oauth_callback', { provider, redirectUrl });
      updateProviderState(provider, {
        callbackSubmitting: false,
        callbackStatus: 'success',
      });
      showNotice('回调已提交，正在等待认证完成', 'success');
    } catch (error) {
      updateProviderState(provider, {
        callbackSubmitting: false,
        callbackStatus: 'error',
        callbackError: String(error),
      });
      showNotice(String(error), 'error');
    }
  };

  return (
    <section className="page management-page">
      <header className="management-header">
        <div><span>OAuth</span><h1>OAuth 登录</h1></div>
      </header>

      {notice ? (
        <div className={`inline-notice ${notice.tone === 'error' ? 'error' : notice.tone === 'success' ? 'success' : ''}`}>
          {notice.message}
        </div>
      ) : null}

      <div className="oauth-grid">
        {oauthProviders.map((provider) => {
          const state = states[provider.id] ?? { status: 'idle' as const };
          const canSubmitCallback = OAUTH_CALLBACK_SUPPORTED.has(provider.id) && Boolean(state.url);
          const loginLabel = state.status === 'success'
            ? '登录另一个账号'
            : state.polling
              ? '登录中…'
              : '开始登录';

          return (
            <section className="panel oauth-card" key={provider.id}>
              <div className="provider-title-row">
                <img src={provider.icon} alt="" className="provider-logo" />
                <div>
                  <h2>{provider.name}</h2>
                  <span className={`state-pill ${state.status === 'success' ? 'success' : state.status === 'error' ? 'error' : ''}`}>
                    {oauthStatusLabel(state)}
                  </span>
                </div>
              </div>

              <div className="oauth-card-body">
                <p className="oauth-hint">点击开始登录后，将自动打开浏览器完成授权；如未自动跳转，可手动打开链接</p>
                {state.url ? (
                  <div className="oauth-auth-url-box">
                    <div className="oauth-auth-url-label">授权链接</div>
                    <div className="oauth-auth-url-value" title={state.url}>{state.url}</div>
                    <div className="oauth-auth-url-actions">
                      <button type="button" className="secondary-button compact-button" onClick={() => void copyAuthUrl(state.url)}>
                        <Copy size={15} aria-hidden="true" />复制链接
                      </button>
                      <button type="button" className="secondary-button compact-button" onClick={() => void openAuthUrl(state.url)}>
                        <ExternalLink size={15} aria-hidden="true" />打开链接
                      </button>
                    </div>
                  </div>
                ) : null}

                {canSubmitCallback ? (
                  <div className="oauth-callback-block">
                    <div className="oauth-callback-row">
                      <input
                        value={state.callbackUrl ?? ''}
                        onChange={(event) => {
                          const value = event.currentTarget.value;
                          updateProviderState(provider.id, {
                            callbackUrl: value,
                            callbackStatus: undefined,
                            callbackError: undefined,
                          });
                        }}
                        placeholder={provider.id === 'xai' ? '粘贴 code 或完整回调 URL' : '粘贴完整回调 URL'}
                      />
                      <button type="button" className="secondary-button" disabled={state.callbackSubmitting} onClick={() => void submitCallback(provider.id)}>
                        {state.callbackSubmitting ? <LoaderCircle size={16} className="spin" aria-hidden="true" /> : <Check size={16} aria-hidden="true" />}
                        提交回调
                      </button>
                    </div>
                    {state.callbackStatus === 'success' && state.status === 'waiting' ? (
                      <div className="oauth-inline-status success">回调已提交，等待认证完成</div>
                    ) : null}
                    {state.callbackStatus === 'error' ? (
                      <div className="oauth-inline-status error">回调提交失败{state.callbackError ? `：${state.callbackError}` : ''}</div>
                    ) : null}
                  </div>
                ) : null}

                {state.status === 'error' && state.error ? (
                  <div className="oauth-inline-status error">{state.error}</div>
                ) : null}
              </div>

              <div className="button-row management-card-actions">
                <button type="button" className="primary-button" disabled={Boolean(state.polling)} onClick={() => void startLogin(provider.id)}>
                  {state.polling ? <LoaderCircle size={16} className="spin" aria-hidden="true" /> : <LogIn size={16} aria-hidden="true" />}
                  {loginLabel}
                </button>
                {state.url ? (
                  <button type="button" className="secondary-button" onClick={() => void openAuthUrl(state.url)}>
                    <ExternalLink size={16} aria-hidden="true" />打开浏览器
                  </button>
                ) : null}
              </div>
            </section>
          );
        })}
      </div>
    </section>
  );
}

function oauthStatusLabel(state: OAuthProviderState) {
  if (state.status === 'success') return '已完成';
  if (state.status === 'error') return '失败';
  if (state.status === 'waiting' || state.polling) return '等待回调';
  return '未登录';
}

function providerLabel(provider: OAuthProviderId) {
  return oauthProviders.find((item) => item.id === provider)?.name ?? provider;
}

function isAbsoluteUrl(value: string) {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function readQueryLikeCallbackInput(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const queryStart = trimmed.indexOf('?');
  const hashStart = trimmed.indexOf('#');
  const rawParams = queryStart >= 0
    ? trimmed.slice(queryStart + 1)
    : hashStart >= 0
      ? trimmed.slice(hashStart + 1)
      : trimmed;
  if (!/(^|[&#?])(code|state|error)=/i.test(rawParams)) return null;
  return new URLSearchParams(rawParams.replace(/^[?#]/, ''));
}

function buildXaiCallbackUrl(input: string, state?: string) {
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (isAbsoluteUrl(trimmed)) return trimmed;
  const params = readQueryLikeCallbackInput(trimmed);
  if (params) {
    const callbackState = params.get('state')?.trim() || state?.trim();
    if (!callbackState) return null;
    const callbackUrl = new URL(XAI_CALLBACK_URL);
    callbackUrl.searchParams.set('state', callbackState);
    for (const key of ['code', 'error', 'error_description']) {
      const value = params.get(key)?.trim();
      if (value) callbackUrl.searchParams.set(key, value);
    }
    return callbackUrl.toString();
  }
  const code = (trimmed.match(/\bcode\s*[:=]\s*([^\s&]+)/i)?.[1] ?? trimmed).trim();
  const callbackState = state?.trim();
  if (!code || !callbackState) return null;
  const callbackUrl = new URL(XAI_CALLBACK_URL);
  callbackUrl.searchParams.set('code', code);
  callbackUrl.searchParams.set('state', callbackState);
  return callbackUrl.toString();
}

function resolveCallbackUrl(provider: OAuthProviderId, input: string, state?: string) {
  return provider === 'xai' ? buildXaiCallbackUrl(input, state) : input.trim();
}
