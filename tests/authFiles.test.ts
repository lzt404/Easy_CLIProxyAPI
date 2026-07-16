import { describe, expect, it } from 'bun:test';
import { dedupeAuthFiles } from '../src/services/authFiles';

describe('认证文件列表规范化', () => {
  it('合并同名的磁盘和运行时记录并优先保留磁盘状态', () => {
    const files = dedupeAuthFiles([
      {
        name: 'codex-user.json',
        provider: 'codex',
        runtime_only: true,
        auth_index: 'runtime-index',
        email: 'user@example.com',
      },
      {
        name: 'codex-user.json',
        provider: 'codex',
        source: 'file',
        path: '/tmp/codex-user.json',
        disabled: false,
        modtime: 100,
      },
    ]);

    expect(files).toHaveLength(1);
    expect(files[0].source).toBe('file');
    expect(files[0].path).toBe('/tmp/codex-user.json');
    expect(files[0].email).toBe('user@example.com');
    expect(files[0].auth_index).toBe('runtime-index');
  });
});
