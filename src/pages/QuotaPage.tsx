import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertCircle, LoaderCircle, RefreshCw } from 'lucide-react';
import antigravityIcon from '../assets/icons/antigravity.svg';
import claudeIcon from '../assets/icons/claude.svg';
import codexIcon from '../assets/icons/codex.svg';
import grokIcon from '../assets/icons/grok.svg';
import kimiIcon from '../assets/icons/kimi-light.svg';
import { managementApi, readBoolean, responseList } from '../services/managementApi';
import {
  consumeCodexResetCredit,
  fileName,
  formatQuotaTimestamp,
  idleQuota,
  loadQuota,
  providerForFile,
  quotaKey,
  type AuthFile,
  type QuotaProvider,
  type QuotaState,
} from '../services/quotaService';
import {
  captureQuotaCacheGeneration,
  commitQuotaCacheIfCurrent,
  pruneQuotaCache,
  updateQuotaCache,
  useQuotaCache,
} from '../services/quotaCache';
import { dedupeAuthFiles } from '../services/authFiles';

const providerMeta: Record<QuotaProvider, { label: string; icon: string }> = {
  claude: { label: 'Claude', icon: claudeIcon },
  codex: { label: 'Codex', icon: codexIcon },
  kimi: { label: 'Kimi', icon: kimiIcon },
  xai: { label: 'xAI', icon: grokIcon },
  antigravity: { label: 'Antigravity', icon: antigravityIcon },
};

const providerOrder: QuotaProvider[] = ['claude', 'antigravity', 'codex', 'xai', 'kimi'];
const REFRESH_CONCURRENCY = 4;

export function QuotaPage() {
  const [files, setFiles] = useState<AuthFile[]>([]);
  const quotas = useQuotaCache();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');

  const loadFiles = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const payload = await managementApi.get('/auth-files');
      const nextFiles = dedupeAuthFiles(responseList(payload, 'files')).filter(
        (file) => !readBoolean(file, 'disabled') && providerForFile(file),
      );
      setFiles(nextFiles);
      const validQuotaKeys = new Set(nextFiles.map(quotaKey));
      pruneQuotaCache(validQuotaKeys);
      updateQuotaCache((current) => {
        const next = { ...current };
        nextFiles.forEach((file) => {
          const key = quotaKey(file);
          if (!next[key]) next[key] = idleQuota();
        });
        return next;
      });
    } catch (requestError) {
      setError(String(requestError));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadFiles();
  }, [loadFiles]);

  const refreshOne = useCallback(async (file: AuthFile) => {
    const key = quotaKey(file);
    const cacheGeneration = captureQuotaCacheGeneration();
    updateQuotaCache((current) => ({ ...current, [key]: { status: 'loading', rows: [] } }));
    const result = await loadQuota(file);
    commitQuotaCacheIfCurrent(cacheGeneration, () => {
      updateQuotaCache((current) => ({ ...current, [key]: result }));
    });
  }, []);

  const resetCodexQuota = useCallback(async (file: AuthFile, quota: QuotaState) => {
    const confirmed = window.confirm([
      `确认重置「${fileName(file)}」的 Codex 额度吗？`,
      '',
      '本操作将消耗 1 次主动重置机会。',
      `当前可用：${quota.resetCredits ?? '未记录'} 次`,
      `最早过期：${formatQuotaTimestamp(quota.resetCreditsEarliestExpiry)}`,
      '',
      '只有点击“确定”后才会执行；点击“取消”不会消耗重置机会。',
    ].join('\n'));
    if (!confirmed) return;
    const key = quotaKey(file);
    const cacheGeneration = captureQuotaCacheGeneration();
    updateQuotaCache((current) => ({ ...current, [key]: { ...current[key], status: 'loading', rows: [] } }));
    try {
      const result = await consumeCodexResetCredit(file);
      commitQuotaCacheIfCurrent(cacheGeneration, () => {
        updateQuotaCache((current) => ({ ...current, [key]: result }));
      });
    } catch (requestError) {
      commitQuotaCacheIfCurrent(cacheGeneration, () => {
        updateQuotaCache((current) => ({
          ...current,
          [key]: {
            status: 'error',
            rows: [],
            error: requestError instanceof Error ? requestError.message : String(requestError),
          },
        }));
      });
    }
  }, []);

  const refreshAll = useCallback(async () => {
    setRefreshing(true);
    setError('');
    const cacheGeneration = captureQuotaCacheGeneration();
    updateQuotaCache((current) => Object.fromEntries(files.map((file) => [quotaKey(file), { ...current[quotaKey(file)], status: 'loading', rows: [] }])));
    try {
      for (let index = 0; index < files.length; index += REFRESH_CONCURRENCY) {
        const batch = files.slice(index, index + REFRESH_CONCURRENCY);
        await Promise.all(batch.map(async (file) => {
          const result = await loadQuota(file);
          commitQuotaCacheIfCurrent(cacheGeneration, () => {
            updateQuotaCache((current) => ({ ...current, [quotaKey(file)]: result }));
          });
        }));
      }
    } finally {
      setRefreshing(false);
    }
  }, [files]);

  const grouped = useMemo(() => {
    const groups = new Map<QuotaProvider, { file: AuthFile; quota: QuotaState }[]>();
    files.forEach((file) => {
      const provider = providerForFile(file);
      if (!provider) return;
      const items = groups.get(provider) ?? [];
      items.push({ file, quota: quotas[quotaKey(file)] ?? idleQuota() });
      groups.set(provider, items);
    });
    return providerOrder.flatMap((provider) => {
      const items = groups.get(provider);
      return items ? [[provider, items] as const] : [];
    });
  }, [files, quotas]);

  return (
    <section className="page management-page quota-page">
      <header className="management-header">
        <div><span>Quota</span><h1>配额</h1></div>
        <div className="management-heading-actions">
          <span className="muted-summary">{files.length} 个可查询凭据</span>
          <button type="button" className="secondary-button compact-button" onClick={() => void loadFiles()} disabled={loading || refreshing}>
            <RefreshCw size={16} />读取列表
          </button>
          <button type="button" className="secondary-button compact-button" onClick={() => void refreshAll()} disabled={refreshing || loading || files.length === 0}>
            <RefreshCw size={16} className={refreshing ? 'spin' : ''} />刷新全部
          </button>
        </div>
      </header>
      {error ? <div className="management-alert error">{error}</div> : null}
      {loading ? (
        <div className="management-loading"><LoaderCircle size={20} className="spin" />读取认证文件中</div>
      ) : grouped.length === 0 ? (
        <div className="management-empty"><AlertCircle size={24} /><strong>暂无可查询配额</strong><span>先在认证文件中添加支持配额查询的凭据。</span></div>
      ) : (
        <div className="quota-group-list">
          {grouped.map(([provider, items]) => (
            <section className="quota-provider-group" key={provider}>
              <div className="quota-group-heading"><div><img src={providerMeta[provider].icon} alt="" className="provider-logo" /><h2>{providerMeta[provider].label}</h2></div><span>{items.length} 个凭据</span></div>
              <div className="real-quota-grid">{items.map(({ file, quota }) => <QuotaCard key={quotaKey(file)} file={file} quota={quota} onRefresh={() => void refreshOne(file)} onReset={provider === 'codex' ? () => void resetCodexQuota(file, quota) : undefined} />)}</div>
            </section>
          ))}
        </div>
      )}
    </section>
  );
}

export function QuotaCard({ file, quota, onRefresh, onReset }: { file: AuthFile; quota: QuotaState; onRefresh: () => void; onReset?: () => void }) {
  const provider = providerForFile(file);
  const name = fileName(file);
  const disabled = readBoolean(file, 'disabled');
  return (
    <article className="panel real-quota-card">
      <div className="real-quota-card-header"><div><strong title={name}>{name}</strong><span>{provider ? providerMeta[provider].label : '未知'}{quota.plan ? ` · ${quota.plan}` : ''}</span></div><div className="quota-card-actions">{onReset && (quota.resetCredits ?? 0) > 0 ? <button type="button" className="secondary-button compact-button" onClick={onReset} disabled={disabled || quota.status === 'loading'}>重置额度</button> : null}<button type="button" className="icon-button quiet" onClick={onRefresh} disabled={disabled || quota.status === 'loading'} title={disabled ? '认证文件已停用' : '获取/刷新额度'}><RefreshCw size={16} className={quota.status === 'loading' ? 'spin' : ''} /></button></div></div>
      {quota.status === 'idle' ? <div className="quota-card-message"><span>{disabled ? '认证文件已停用' : '尚未获取额度'}</span><button type="button" className="secondary-button compact-button" onClick={onRefresh} disabled={disabled}>{disabled ? '已停用' : '获取额度'}</button></div> : null}
      {quota.status === 'loading' ? <div className="quota-card-message"><LoaderCircle size={18} className="spin" />查询中</div> : null}
      {quota.status === 'error' ? <div className="quota-card-error"><AlertCircle size={18} />{quota.error}</div> : null}
      {quota.status === 'success' && provider === 'codex' ? <div className="quota-reset-credit-summary"><span>主动重置次数 <strong>{quota.resetCredits ?? '未记录'}</strong></span><span>最早过期 <strong>{formatQuotaTimestamp(quota.resetCreditsEarliestExpiry)}</strong></span></div> : null}
      {quota.status === 'success' ? <div className="quota-row-list">{quota.rows.map((row, index) => <div className="real-quota-row" key={`${row.label}-${index}`}><div><span>{row.label}</span><strong>{row.remainingPercent === null ? '—' : `剩余 ${Math.round(row.remainingPercent)}%`}</strong></div><div className="real-quota-track"><span style={{ width: `${Math.max(0, Math.min(100, row.remainingPercent ?? 0))}%` }} /></div><small>{row.detail ?? ''}{row.reset ? `${row.detail ? ' · ' : ''}${row.reset}` : ''}</small></div>)}</div> : null}
    </article>
  );
}
