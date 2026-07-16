#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use flate2::read::GzDecoder;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::File,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tar::Archive;
use tauri::{Emitter, Manager};
use tokio_util::sync::CancellationToken;
use zip::ZipArchive;

const RELEASE_API_URL: &str =
    "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest";
const RELEASE_PAGE_URL: &str = "https://github.com/router-for-me/CLIProxyAPI/releases/latest";
const RELEASE_TAG_PAGE_PREFIX: &str = "https://github.com/router-for-me/CLIProxyAPI/releases/tag/";
const RELEASE_ASSETS_PAGE_PREFIX: &str =
    "https://github.com/router-for-me/CLIProxyAPI/releases/expanded_assets/";
const CORE_INSTALL_PROGRESS_EVENT: &str = "core-install-progress";
const CORE_METADATA_FILE: &str = "cpa-gui-meta.json";
const CORE_CONFIG_FILE: &str = "config.yaml";
const CORE_EXAMPLE_CONFIG_FILE: &str = "config.example.yaml";
const GUI_CONFIG_FILE: &str = "config.toml";
const LEGACY_GUI_CONFIG_FILE: &str = "cpa-gui.yaml";
const OAUTH_DIR_NAME: &str = "oauth";
const DEFAULT_API_KEY: &str = "123456";
const DEFAULT_API_KEY_REMARK: &str = "内置密钥";
const DEFAULT_MANAGEMENT_SECRET_KEY: &str = "123456";
const USER_AGENT: &str = "CPA-GUI/0.1.0 (+https://github.com/router-for-me/CLIProxyAPI)";
const GITHUB_API_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_API_VERSION: &str = "2022-11-28";
static CORE_CONFIG_FILE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct CoreDownloadState {
    inner: Mutex<CoreDownloadInner>,
}

#[derive(Default)]
struct CoreDownloadInner {
    running: bool,
    token: Option<CancellationToken>,
    task: CoreInstallTask,
}

#[derive(Default)]
struct CoreProcessState {
    child: Mutex<Option<Child>>,
    #[cfg(windows)]
    job: Mutex<Option<isize>>,
}

struct GuiConfigState {
    inner: Mutex<GuiConfigFile>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CorePlatform {
    os: String,
    arch: String,
    asset_os: String,
    asset_arch: String,
    archive_kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreStatus {
    installed: bool,
    running: bool,
    managed: bool,
    process_id: Option<u32>,
    current_version: Option<String>,
    install_dir: String,
    binary_path: Option<String>,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreLatest {
    version: String,
    asset_name: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreInstallResult {
    version: String,
    asset_name: String,
    install_dir: String,
    binary_path: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreInstallTask {
    running: bool,
    cancellable: bool,
    phase: String,
    downloaded: u64,
    total: Option<u64>,
    percent: Option<f64>,
    message: Option<String>,
    result: Option<CoreInstallResult>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct GuiConfigFile {
    port: u16,
    allow_lan: bool,
    run_on_startup: bool,
    auth_dir: String,
    #[serde(deserialize_with = "deserialize_gui_api_keys")]
    api_keys: Vec<GuiApiKeyEntry>,
    management_secret_key: String,
    plugins_enabled: bool,
    routing_strategy: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GuiApiKeyEntry {
    key: String,
    #[serde(default)]
    remark: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GuiApiKeyInput {
    Legacy(String),
    Entry(GuiApiKeyEntry),
}

fn deserialize_gui_api_keys<'de, D>(deserializer: D) -> Result<Vec<GuiApiKeyEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let entries = Vec::<GuiApiKeyInput>::deserialize(deserializer)?;
    Ok(entries
        .into_iter()
        .map(|entry| match entry {
            GuiApiKeyInput::Legacy(key) => GuiApiKeyEntry {
                remark: String::new(),
                key,
            },
            GuiApiKeyInput::Entry(entry) => entry,
        })
        .collect())
}

impl Default for GuiConfigFile {
    fn default() -> Self {
        Self {
            port: 8317,
            allow_lan: false,
            run_on_startup: false,
            auth_dir: env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.join(OAUTH_DIR_NAME)))
                .map(|path| path_to_string(&path))
                .unwrap_or_else(|| OAUTH_DIR_NAME.to_string()),
            api_keys: vec![built_in_api_key_entry()],
            // Keep plaintext here for management API auth. Core hashes the
            // value written into config.yaml on startup.
            management_secret_key: DEFAULT_MANAGEMENT_SECRET_KEY.to_string(),
            plugins_enabled: false,
            routing_strategy: "round-robin".to_string(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "kebab-case")]
struct GuiConfigPresence {
    auth_dir: Option<String>,
    api_keys: Option<Vec<GuiApiKeyInput>>,
    management_secret_key: Option<String>,
    plugins_enabled: Option<bool>,
    routing_strategy: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuiSettings {
    port: u16,
    allow_lan: bool,
    run_on_startup: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GuiNetworkSettings {
    port: u16,
    allow_lan: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreConfigSettings {
    api_keys: Vec<String>,
    management_secret_configured: bool,
    plugins_enabled: bool,
    routing_strategy: String,
    // Kept for internal config migration/tests; never exposed to the WebView.
    #[allow(dead_code)]
    #[serde(skip_serializing)]
    management_secret_key: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreApiKeyView {
    api_key: String,
    remark: String,
    built_in: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreConfigView {
    api_keys: Vec<CoreApiKeyView>,
    management_secret_configured: bool,
    plugins_enabled: bool,
    routing_strategy: String,
}

impl Default for CoreInstallTask {
    fn default() -> Self {
        Self {
            running: false,
            cancellable: false,
            phase: "空闲".to_string(),
            downloaded: 0,
            total: None,
            percent: None,
            message: None,
            result: None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CoreMetadata {
    version: String,
    asset_name: String,
    installed_at_unix: u64,
}

struct DownloadedArchive {
    size: u64,
    sha256: String,
}

impl CoreDownloadState {
    fn start(&self, token: CancellationToken, version: Option<String>) -> Result<(), String> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| "内核安装状态锁已损坏".to_string())?;

        if inner.running {
            return Err("已有内核安装任务正在运行".to_string());
        }

        inner.running = true;
        inner.token = Some(token);
        inner.task = CoreInstallTask {
            running: true,
            cancellable: true,
            phase: version
                .map(|version| format!("准备安装 {version}"))
                .unwrap_or_else(|| "准备安装最新版".to_string()),
            downloaded: 0,
            total: None,
            percent: None,
            message: None,
            result: None,
        };

        Ok(())
    }

    fn cancel(&self) {
        if let Ok(inner) = self.inner.lock() {
            if let Some(token) = &inner.token {
                token.cancel();
            }
        }
    }

    fn snapshot(&self) -> CoreInstallTask {
        self.inner
            .lock()
            .map(|inner| inner.task.clone())
            .unwrap_or_default()
    }

    fn progress(
        &self,
        window: &tauri::Window,
        phase: &str,
        downloaded: u64,
        total: Option<u64>,
        cancellable: bool,
    ) {
        let percent = total
            .filter(|total| *total > 0)
            .map(|total| downloaded as f64 * 100.0 / total as f64);

        let task = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };

            inner.task.running = inner.running;
            inner.task.cancellable = cancellable;
            inner.task.phase = phase.to_string();
            inner.task.downloaded = downloaded;
            inner.task.total = total;
            inner.task.percent = percent;
            inner.task.clone()
        };

        let _ = window.emit(CORE_INSTALL_PROGRESS_EVENT, task);
    }

    fn finish(&self, window: &tauri::Window, result: Result<CoreInstallResult, String>) {
        let task = {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };

            inner.running = false;
            inner.token = None;
            inner.task.running = false;
            inner.task.cancellable = false;

            match result {
                Ok(result) => {
                    inner.task.phase = "安装完成".to_string();
                    inner.task.downloaded = 1;
                    inner.task.total = Some(1);
                    inner.task.percent = Some(100.0);
                    inner.task.message = Some(format!("{} 安装完成", result.version));
                    inner.task.result = Some(result);
                }
                Err(error) => {
                    inner.task.phase = if error.contains("取消") {
                        "已取消".to_string()
                    } else {
                        "安装失败".to_string()
                    };
                    inner.task.message = Some(error);
                    inner.task.result = None;
                }
            }

            inner.task.clone()
        };

        let _ = window.emit(CORE_INSTALL_PROGRESS_EVENT, task);
    }
}

impl CoreProcessState {
    fn managed_pid(&self) -> Option<u32> {
        let Ok(mut child) = self.child.lock() else {
            return None;
        };

        let process = child.as_mut()?;

        if let Ok(None) = process.try_wait() {
            return Some(process.id());
        }

        *child = None;
        drop(child);
        self.clear_lifetime_guard();

        None
    }

    fn clear_lifetime_guard(&self) {
        #[cfg(windows)]
        if let Ok(mut job) = self.job.lock() {
            if let Some(handle) = job.take() {
                close_windows_handle(handle);
            }
        }
    }

    fn take_child(&self) -> Option<Child> {
        self.child.lock().ok().and_then(|mut child| child.take())
    }

    fn store_child(&self, child: Child) -> Result<u32, String> {
        let pid = child.id();

        #[cfg(windows)]
        {
            let job = attach_child_to_windows_job(&child)?;
            let Ok(mut managed_child) = self.child.lock() else {
                close_windows_handle(job);
                return Err("内核进程状态锁已损坏".to_string());
            };
            let Ok(mut managed_job) = self.job.lock() else {
                close_windows_handle(job);
                return Err("内核进程作业状态锁已损坏".to_string());
            };
            *managed_child = Some(child);
            *managed_job = Some(job);
        }

        #[cfg(not(windows))]
        {
            let mut managed_child = self
                .child
                .lock()
                .map_err(|_| "内核进程状态锁已损坏".to_string())?;
            *managed_child = Some(child);
        }

        Ok(pid)
    }
}

impl GuiConfigState {
    fn new(config: GuiConfigFile) -> Self {
        Self {
            inner: Mutex::new(config),
        }
    }

    fn snapshot(&self) -> Result<GuiConfigFile, String> {
        self.inner
            .lock()
            .map(|config| config.clone())
            .map_err(|_| "GUI 配置状态锁已损坏".to_string())
    }

    fn update_network(&self, port: u16, allow_lan: bool) -> Result<GuiConfigFile, String> {
        self.update(|config| {
            config.port = port;
            config.allow_lan = allow_lan;
            Ok(())
        })
    }

    fn set_run_on_startup(&self, run_on_startup: bool) -> Result<GuiConfigFile, String> {
        self.update(|config| {
            config.run_on_startup = run_on_startup;
            Ok(())
        })
    }

    fn set_management_secret_key(&self, secret_key: String) -> Result<GuiConfigFile, String> {
        self.update(|config| {
            config.management_secret_key = secret_key;
            Ok(())
        })
    }

    fn sync_core_settings(&self, settings: &CoreConfigSettings) -> Result<GuiConfigFile, String> {
        self.sync_core_settings_with_api_key(settings, None)
    }

    fn sync_core_settings_with_api_key(
        &self,
        settings: &CoreConfigSettings,
        added_api_key: Option<GuiApiKeyEntry>,
    ) -> Result<GuiConfigFile, String> {
        self.update(|config| {
            config.api_keys = merge_core_api_keys_with_gui_metadata(
                &config.api_keys,
                &settings.api_keys,
                added_api_key.as_ref(),
            );
            config.plugins_enabled = settings.plugins_enabled;
            config.routing_strategy = settings.routing_strategy.clone();
            Ok(())
        })
    }

    fn update<F>(&self, update: F) -> Result<GuiConfigFile, String>
    where
        F: FnOnce(&mut GuiConfigFile) -> Result<(), String>,
    {
        let mut current = self
            .inner
            .lock()
            .map_err(|_| "GUI 配置状态锁已损坏".to_string())?;
        let mut config = current.clone();
        update(&mut config)?;
        write_gui_config(&config)?;
        *current = config.clone();
        Ok(config)
    }
}

impl From<&GuiConfigFile> for GuiSettings {
    fn from(config: &GuiConfigFile) -> Self {
        Self {
            port: config.port,
            allow_lan: config.allow_lan,
            run_on_startup: config.run_on_startup,
        }
    }
}

impl From<&GuiConfigFile> for CoreConfigSettings {
    fn from(config: &GuiConfigFile) -> Self {
        Self {
            api_keys: gui_api_key_values(&config.api_keys),
            management_secret_configured: !config.management_secret_key.is_empty(),
            plugins_enabled: config.plugins_enabled,
            routing_strategy: config.routing_strategy.clone(),
            management_secret_key: Some(config.management_secret_key.clone()),
        }
    }
}

impl From<&GuiConfigFile> for CoreConfigView {
    fn from(config: &GuiConfigFile) -> Self {
        Self {
            api_keys: config
                .api_keys
                .iter()
                .map(|entry| CoreApiKeyView {
                    api_key: entry.key.clone(),
                    remark: entry.remark.clone(),
                    built_in: entry.key == DEFAULT_API_KEY,
                })
                .collect(),
            management_secret_configured: !config.management_secret_key.is_empty(),
            plugins_enabled: config.plugins_enabled,
            routing_strategy: config.routing_strategy.clone(),
        }
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: Option<u64>,
    digest: Option<String>,
}

#[tauri::command]
fn health_check() -> &'static str {
    "CPA GUI Rust backend is ready"
}

#[tauri::command]
fn detect_core_platform() -> Result<CorePlatform, String> {
    current_core_platform()
}

#[tauri::command]
fn get_core_status(
    process_state: tauri::State<'_, CoreProcessState>,
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreStatus, String> {
    let config = gui_config_state.snapshot()?;
    current_core_status(Some(process_state.inner()), Some(config.port))
}

#[tauri::command]
fn get_gui_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<GuiSettings, String> {
    let config = gui_config_state.snapshot()?;
    Ok(GuiSettings::from(&config))
}

#[tauri::command]
fn get_lan_ipv4() -> Option<String> {
    detect_lan_ipv4().map(|address| address.to_string())
}

fn detect_lan_ipv4() -> Option<Ipv4Addr> {
    for target in ["192.0.2.1:80", "8.8.8.8:80"] {
        let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) else {
            continue;
        };
        if socket.connect(target).is_err() {
            continue;
        }
        let Ok(local_address) = socket.local_addr() else {
            continue;
        };
        let IpAddr::V4(address) = local_address.ip() else {
            continue;
        };
        if !address.is_unspecified() && !address.is_loopback() {
            return Some(address);
        }
    }
    None
}

#[tauri::command]
fn save_gui_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    settings: GuiNetworkSettings,
) -> Result<GuiSettings, String> {
    if settings.port == 0 {
        return Err("端口必须在 1 到 65535 之间".to_string());
    }

    let previous = gui_config_state.snapshot()?;
    let mut next = previous.clone();
    next.port = settings.port;
    next.allow_lan = settings.allow_lan;
    patch_core_network_settings(&next)?;
    let config = match gui_config_state.update_network(settings.port, settings.allow_lan) {
        Ok(config) => config,
        Err(error) => {
            let rollback_error = patch_core_network_settings(&previous).err();
            return Err(match rollback_error {
                Some(rollback_error) => {
                    format!("{error}；回滚内核网络配置也失败: {rollback_error}")
                }
                None => error,
            });
        }
    };

    Ok(GuiSettings::from(&config))
}

#[tauri::command]
fn get_core_config_settings(
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreConfigView, String> {
    let settings = current_core_config_settings(gui_config_state.inner())?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    let api_keys = gui_api_key_values(&config.api_keys);
    if api_keys != settings.api_keys {
        patch_core_api_keys(&api_keys)?;
    }
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
fn add_core_api_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    api_key: String,
    remark: String,
) -> Result<CoreConfigView, String> {
    let api_key = api_key.trim().to_string();
    let remark = remark.trim().to_string();
    validate_core_api_key(&api_key)?;
    validate_api_key_remark(&remark)?;
    let mut settings = current_core_config_settings(gui_config_state.inner())?;
    if api_key == DEFAULT_API_KEY
        || settings
            .api_keys
            .iter()
            .any(|existing| existing == &api_key)
    {
        return Err("该鉴权密钥已经存在".to_string());
    }
    if !settings.api_keys.iter().any(|key| key == DEFAULT_API_KEY) {
        settings.api_keys.insert(0, DEFAULT_API_KEY.to_string());
    }
    settings.api_keys.push(api_key);
    patch_core_api_keys(&settings.api_keys)?;
    let added_api_key = settings.api_keys.last().map(|key| GuiApiKeyEntry {
        key: key.clone(),
        remark,
    });
    let config = gui_config_state.sync_core_settings_with_api_key(&settings, added_api_key)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
fn delete_core_api_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    api_key: String,
) -> Result<CoreConfigView, String> {
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err("要删除的鉴权密钥不能为空".to_string());
    }
    if api_key == DEFAULT_API_KEY {
        return Err("内置密钥不能删除".to_string());
    }
    let mut settings = current_core_config_settings(gui_config_state.inner())?;
    let index = settings
        .api_keys
        .iter()
        .position(|existing| existing == api_key)
        .ok_or_else(|| "要删除的鉴权密钥不存在，请刷新后重试".to_string())?;
    settings.api_keys.remove(index);
    patch_core_api_keys(&settings.api_keys)?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
fn set_core_management_secret_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    secret_key: String,
) -> Result<CoreConfigView, String> {
    let secret_key = secret_key.trim().to_string();
    if secret_key != DEFAULT_MANAGEMENT_SECRET_KEY {
        return Err("管理密钥统一固定为 123456".to_string());
    }
    let config =
        gui_config_state.set_management_secret_key(DEFAULT_MANAGEMENT_SECRET_KEY.to_string())?;
    patch_core_management_secret_key(&config.management_secret_key)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
fn clear_core_management_secret_key(
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreConfigView, String> {
    let config =
        gui_config_state.set_management_secret_key(DEFAULT_MANAGEMENT_SECRET_KEY.to_string())?;
    patch_core_management_secret_key(&config.management_secret_key)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
fn set_core_plugins_enabled(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    enabled: bool,
) -> Result<CoreConfigView, String> {
    let mut settings = current_core_config_settings(gui_config_state.inner())?;
    settings.plugins_enabled = enabled;
    patch_core_plugins_enabled(settings.plugins_enabled)?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    Ok(CoreConfigView::from(&config))
}

#[tauri::command]
fn set_core_routing_strategy(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    strategy: String,
) -> Result<CoreConfigView, String> {
    validate_routing_strategy(&strategy)?;
    let mut settings = current_core_config_settings(gui_config_state.inner())?;
    settings.routing_strategy = strategy;
    patch_core_routing_strategy(&settings.routing_strategy)?;
    let config = gui_config_state.sync_core_settings(&settings)?;
    Ok(CoreConfigView::from(&config))
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OAuthStartResult {
    url: String,
    state: Option<String>,
    opened: bool,
    open_error: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OAuthStatusResult {
    status: String,
    error: Option<String>,
}

#[derive(Deserialize)]
struct OAuthStartApiResponse {
    url: Option<String>,
    state: Option<String>,
    #[allow(dead_code)]
    status: Option<String>,
    error: Option<String>,
    #[serde(rename = "error_message")]
    error_message: Option<String>,
}

#[derive(Deserialize)]
struct OAuthStatusApiResponse {
    status: Option<String>,
    error: Option<String>,
    #[serde(rename = "error_message")]
    error_message: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagementRequest {
    method: String,
    path: String,
    query: Option<std::collections::HashMap<String, String>>,
    body: Option<serde_json::Value>,
}

#[tauri::command]
async fn management_request(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    request: ManagementRequest,
) -> Result<serde_json::Value, String> {
    let config = gui_config_state.snapshot()?;
    let method = match request.method.trim().to_ascii_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "PATCH" => reqwest::Method::PATCH,
        "DELETE" => reqwest::Method::DELETE,
        _ => return Err("不支持的管理 API 请求方法".to_string()),
    };
    let path = request.path.trim();
    if path.is_empty() || path.contains("://") || path.contains("..") {
        return Err("无效的管理 API 路径".to_string());
    }

    let client = management_http_client()?;
    let mut builder = client
        .request(method, management_endpoint(&config, path)?)
        .header("Authorization", management_authorization(&config)?);
    if let Some(query) = request.query {
        builder = builder.query(&query);
    }
    if let Some(body) = request.body {
        builder = builder.json(&body);
    }

    let response = builder
        .send()
        .await
        .map_err(|err| format!("请求管理 API 失败: {err}"))?;
    read_management_value(response).await
}

#[tauri::command]
async fn upload_auth_file(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    name: String,
    data: Vec<u8>,
) -> Result<serde_json::Value, String> {
    let name = name.trim().to_string();
    if name.is_empty() || !name.to_ascii_lowercase().ends_with(".json") {
        return Err("认证文件名必须以 .json 结尾".to_string());
    }

    let config = gui_config_state.snapshot()?;
    let client = management_http_client()?;
    let mut query = std::collections::HashMap::new();
    query.insert("name".to_string(), name);
    let response = client
        .post(management_endpoint(&config, "auth-files")?)
        .header("Authorization", management_authorization(&config)?)
        .query(&query)
        .header("Content-Type", "application/json")
        .body(data)
        .send()
        .await
        .map_err(|err| format!("上传认证文件失败: {err}"))?;
    read_management_value(response).await
}

#[tauri::command]
async fn download_auth_file(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    name: String,
) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("认证文件名不能为空".to_string());
    }

    let config = gui_config_state.snapshot()?;
    let client = management_http_client()?;
    let mut query = std::collections::HashMap::new();
    query.insert("name".to_string(), name.to_string());
    let response = client
        .get(management_endpoint(&config, "auth-files/download")?)
        .header("Authorization", management_authorization(&config)?)
        .query(&query)
        .send()
        .await
        .map_err(|err| format!("下载认证文件失败: {err}"))?;
    read_management_text(response).await
}

#[tauri::command]
async fn start_oauth_login(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    provider: String,
) -> Result<OAuthStartResult, String> {
    let config = gui_config_state.snapshot()?;
    let provider_key = normalize_management_oauth_provider(&provider)?;
    let client = management_http_client()?;
    let mut request = client
        .get(management_endpoint(
            &config,
            &format!("{provider_key}-auth-url"),
        )?)
        .header("Authorization", management_authorization(&config)?);
    if management_oauth_uses_webui_callback(&provider_key) {
        request = request.query(&[("is_webui", "true")]);
    }
    let response = request
        .send()
        .await
        .map_err(|err| format!("请求 OAuth 登录链接失败: {err}"))?;
    let payload = read_management_json::<OAuthStartApiResponse>(response).await?;
    if let Some(error) = payload
        .error
        .or(payload.error_message)
        .filter(|value| !value.trim().is_empty())
    {
        return Err(error);
    }
    let url = payload
        .url
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "内核未返回 OAuth 登录链接".to_string())?;
    let state = payload
        .state
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let (opened, open_error) = match open_external_url_inner(&url) {
        Ok(()) => (true, None),
        Err(error) => (false, Some(error)),
    };

    Ok(OAuthStartResult {
        url,
        state,
        opened,
        open_error,
    })
}

#[tauri::command]
async fn get_oauth_status(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    state: String,
) -> Result<OAuthStatusResult, String> {
    let state = state.trim().to_string();
    if state.is_empty() {
        return Err("OAuth state 不能为空".to_string());
    }
    let config = gui_config_state.snapshot()?;
    let client = management_http_client()?;
    let response = client
        .get(management_endpoint(&config, "get-auth-status")?)
        .header("Authorization", management_authorization(&config)?)
        .query(&[("state", state)])
        .send()
        .await
        .map_err(|err| format!("查询 OAuth 状态失败: {err}"))?;
    let payload = read_management_json::<OAuthStatusApiResponse>(response).await?;
    let status = payload
        .status
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "wait".to_string());
    Ok(OAuthStatusResult {
        status,
        error: payload
            .error
            .or(payload.error_message)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    })
}

#[tauri::command]
async fn submit_oauth_callback(
    gui_config_state: tauri::State<'_, GuiConfigState>,
    provider: String,
    redirect_url: String,
) -> Result<(), String> {
    let redirect_url = redirect_url.trim().to_string();
    if redirect_url.is_empty() {
        return Err("回调链接不能为空".to_string());
    }
    let config = gui_config_state.snapshot()?;
    let provider_key = normalize_management_oauth_provider(&provider)?;
    let client = management_http_client()?;
    let body = serde_json::json!({
        "provider": provider_key,
        "redirect_url": redirect_url,
    });
    let response = client
        .post(management_endpoint(&config, "oauth-callback")?)
        .header("Authorization", management_authorization(&config)?)
        .json(&body)
        .send()
        .await
        .map_err(|err| format!("提交 OAuth 回调失败: {err}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| format!("读取 OAuth 回调响应失败: {err}"))?;
    if !status.is_success() {
        return Err(format_management_error(status.as_u16(), &text));
    }
    Ok(())
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    open_external_url_inner(&url)
}

#[tauri::command]
async fn check_latest_core() -> Result<CoreLatest, String> {
    let platform = current_core_platform()?;
    let client = http_client()?;
    let release = fetch_release(&client, None).await?;
    let asset = select_release_asset(&release, &platform)?;

    Ok(CoreLatest {
        version: normalize_version(&release.tag_name),
        asset_name: asset.name.clone(),
    })
}

#[tauri::command]
fn cancel_core_install(state: tauri::State<'_, CoreDownloadState>) {
    state.cancel();
}

#[tauri::command]
fn get_core_install_task(state: tauri::State<'_, CoreDownloadState>) -> CoreInstallTask {
    state.snapshot()
}

#[tauri::command]
async fn install_core_version(
    window: tauri::Window,
    state: tauri::State<'_, CoreDownloadState>,
    version: Option<String>,
) -> Result<CoreInstallResult, String> {
    let token = CancellationToken::new();
    state.start(token.clone(), version.clone())?;
    let result = install_core_version_inner(&window, state.inner(), token, version).await;
    if result.is_err() {
        let _ = cleanup_core_work_dirs();
    }
    state.finish(&window, result.clone());

    result
}

#[tauri::command]
fn start_core_process(
    process_state: tauri::State<'_, CoreProcessState>,
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreStatus, String> {
    let config = gui_config_state.snapshot()?;
    start_core_process_inner(process_state.inner(), &config)?;
    if let Err(error) = gui_config_state.set_run_on_startup(true) {
        let _ = stop_core_process_inner(process_state.inner());
        return Err(error);
    }
    current_core_status(Some(process_state.inner()), Some(config.port))
}

#[tauri::command]
fn stop_core_process(
    process_state: tauri::State<'_, CoreProcessState>,
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreStatus, String> {
    stop_core_process_inner(process_state.inner())?;
    let config = gui_config_state.set_run_on_startup(false)?;
    current_core_status(Some(process_state.inner()), Some(config.port))
}

#[tauri::command]
fn restart_core_process(
    process_state: tauri::State<'_, CoreProcessState>,
    gui_config_state: tauri::State<'_, GuiConfigState>,
) -> Result<CoreStatus, String> {
    let config = gui_config_state.snapshot()?;
    let _ = stop_core_process_inner(process_state.inner());
    start_core_process_inner(process_state.inner(), &config)?;
    if let Err(error) = gui_config_state.set_run_on_startup(true) {
        let _ = stop_core_process_inner(process_state.inner());
        return Err(error);
    }
    current_core_status(Some(process_state.inner()), Some(config.port))
}

async fn install_core_version_inner(
    window: &tauri::Window,
    state: &CoreDownloadState,
    token: CancellationToken,
    version: Option<String>,
) -> Result<CoreInstallResult, String> {
    let platform = current_core_platform()?;
    let client = http_client()?;
    state.progress(window, "检查版本", 0, None, true);
    let release = fetch_release_cancelable(&client, version.as_deref(), &token).await?;
    let asset = select_release_asset(&release, &platform)?;

    let install_dir = core_install_dir()?;
    let base_dir = core_base_dir()?;
    let staging_dir = base_dir.join("cpa-core.staging");
    let backup_dir = base_dir.join("cpa-core.backup");
    let download_dir = base_dir.join("cpa-core.download");

    if current_core_status(None, None)?.running {
        return Err("CPA 内核正在运行，请先停止后再安装或更新".to_string());
    }

    reset_dir(&staging_dir)?;
    reset_dir(&download_dir)?;

    let archive_file_name = Path::new(&asset.name)
        .file_name()
        .and_then(|file_name| file_name.to_str())
        .ok_or_else(|| format!("非法 asset 文件名: {}", asset.name))?;
    let archive_path = download_dir.join(archive_file_name);

    let downloaded = download_asset(
        &client,
        &asset.browser_download_url,
        &archive_path,
        asset.size,
        asset.digest.as_deref(),
        window,
        state,
        &token,
    )
    .await?;
    validate_downloaded_asset(asset, &downloaded)?;

    ensure_not_cancelled(&token, Some(&archive_path))?;
    state.progress(
        window,
        "解压中",
        downloaded.size,
        Some(downloaded.size),
        false,
    );
    match platform.archive_kind.as_str() {
        "tar.gz" => extract_tar_gz(&archive_path, &staging_dir)?,
        "zip" => extract_zip(&archive_path, &staging_dir)?,
        other => return Err(format!("不支持的压缩包类型: {other}")),
    }
    ensure_not_cancelled(&token, Some(&archive_path))?;

    let binary_path = find_core_binary(&staging_dir)
        .ok_or_else(|| "解压后未找到 CPA 内核二进制文件".to_string())?;
    let binary_relative_path = binary_path
        .strip_prefix(&staging_dir)
        .map_err(|err| format!("计算内核二进制相对路径失败: {err}"))?
        .to_path_buf();
    write_core_metadata(
        &staging_dir,
        &CoreMetadata {
            version: normalize_version(&release.tag_name),
            asset_name: asset.name.clone(),
            installed_at_unix: unix_now(),
        },
    )?;

    replace_install_dir(&install_dir, &staging_dir, &backup_dir)?;
    let _ = fs::remove_dir_all(&download_dir);

    Ok(CoreInstallResult {
        version: normalize_version(&release.tag_name),
        asset_name: asset.name.clone(),
        install_dir: path_to_string(&install_dir),
        binary_path: Some(path_to_string(&install_dir.join(binary_relative_path))),
    })
}

async fn fetch_release(
    client: &reqwest::Client,
    version: Option<&str>,
) -> Result<GithubRelease, String> {
    let api_result = fetch_release_from_api(client, version).await;
    match api_result {
        Ok(release) => Ok(release),
        Err(api_error) => fetch_release_from_page(client, version)
            .await
            .map_err(|page_error| {
                format!("{api_error}；备用 release 页面请求也失败: {page_error}")
            }),
    }
}

async fn fetch_release_from_api(
    client: &reqwest::Client,
    version: Option<&str>,
) -> Result<GithubRelease, String> {
    let url = version.map_or_else(
        || RELEASE_API_URL.to_string(),
        |version| {
            format!(
                "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/tags/{}",
                normalize_version(version)
            )
        },
    );

    let response = client
        .get(&url)
        .header(reqwest::header::ACCEPT, GITHUB_API_ACCEPT)
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send()
        .await
        .map_err(|err| format!("GitHub API 请求失败: {err}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("读取 GitHub API 响应失败: {err}"))?;
    if !status.is_success() {
        return Err(format_github_error(status.as_u16(), &body));
    }
    serde_json::from_str::<GithubRelease>(&body).map_err(|err| {
        format!(
            "解析 GitHub release 失败: {err}; body={}",
            truncate_for_error(&body)
        )
    })
}

async fn fetch_release_from_page(
    client: &reqwest::Client,
    version: Option<&str>,
) -> Result<GithubRelease, String> {
    let page_url = version
        .map(|value| format!("{}{}/", RELEASE_TAG_PAGE_PREFIX, normalize_version(value)))
        .unwrap_or_else(|| RELEASE_PAGE_URL.to_string());
    let response = client
        .get(&page_url)
        .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send()
        .await
        .map_err(|err| format!("GitHub release 页面请求失败: {err}"))?;
    let status = response.status();
    let final_url = response.url().clone();
    let body = response
        .text()
        .await
        .map_err(|err| format!("读取 GitHub release 页面失败: {err}"))?;
    if !status.is_success() {
        return Err(format_github_error(status.as_u16(), &body));
    }

    let tag = version
        .map(normalize_version)
        .or_else(|| release_tag_from_url(&final_url))
        .ok_or_else(|| "GitHub release 页面没有返回版本标签".to_string())?;
    let assets_url = format!("{}{tag}", RELEASE_ASSETS_PAGE_PREFIX);
    let assets_response = client
        .get(&assets_url)
        .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send()
        .await
        .map_err(|err| format!("GitHub release 资产页面请求失败: {err}"))?;
    let assets_status = assets_response.status();
    let assets_body = assets_response
        .text()
        .await
        .map_err(|err| format!("读取 GitHub release 资产页面失败: {err}"))?;
    if !assets_status.is_success() {
        return Err(format_github_error(assets_status.as_u16(), &assets_body));
    }

    let assets = parse_release_assets(&assets_body);
    if assets.is_empty() {
        return Err("GitHub release 页面没有找到可下载资产".to_string());
    }
    Ok(GithubRelease {
        tag_name: tag,
        assets,
    })
}

fn release_tag_from_url(url: &reqwest::Url) -> Option<String> {
    let mut segments = url.path_segments()?;
    let tag = segments.next_back()?.trim();
    if tag.is_empty() || tag == "latest" {
        None
    } else {
        Some(tag.to_string())
    }
}

fn parse_release_assets(html: &str) -> Vec<GithubAsset> {
    let mut assets = Vec::new();
    let mut cursor = 0;

    while let Some(relative_start) = html[cursor..].find("releases/download/") {
        let download_start = cursor + relative_start;
        let Some(href_start) = html[..download_start].rfind("href=\"") else {
            cursor = download_start + "releases/download/".len();
            continue;
        };
        let href_start = href_start + "href=\"".len();
        let Some(relative_end) = html[download_start..].find('"') else {
            break;
        };
        let href_end = download_start + relative_end;
        let href = &html[href_start..href_end];
        let Some(name) = href.rsplit('/').next().filter(|name| !name.is_empty()) else {
            cursor = href_end + 1;
            continue;
        };
        let item_end = html[href_end..]
            .find("</li>")
            .map(|offset| href_end + offset)
            .unwrap_or(html.len());
        let item = &html[href_start..item_end];
        let digest = item.find("sha256:").and_then(|offset| {
            let value = &item[offset + "sha256:".len()..];
            let hash: String = value
                .chars()
                .take_while(|character| character.is_ascii_hexdigit())
                .collect();
            (hash.len() == 64).then(|| format!("sha256:{hash}"))
        });
        let browser_download_url = if href.starts_with("http://") || href.starts_with("https://") {
            href.to_string()
        } else {
            format!("https://github.com{href}")
        };

        if !assets.iter().any(|asset: &GithubAsset| asset.name == name) {
            assets.push(GithubAsset {
                name: name.to_string(),
                browser_download_url,
                size: None,
                digest,
            });
        }
        cursor = href_end + 1;
    }

    assets
}

fn format_github_error(status: u16, body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(message) = value.get("message").and_then(|item| item.as_str()) {
            return format!("GitHub 返回错误 ({status}): {}", message.trim());
        }
    }
    let body = body.trim();
    if body.is_empty() {
        format!("GitHub 返回错误 ({status})")
    } else {
        format!("GitHub 返回错误 ({status}): {}", truncate_for_error(body))
    }
}

async fn fetch_release_cancelable(
    client: &reqwest::Client,
    version: Option<&str>,
    token: &CancellationToken,
) -> Result<GithubRelease, String> {
    tokio::select! {
        result = fetch_release(client, version) => result,
        _ = token.cancelled() => Err("已取消下载".to_string()),
    }
}

fn http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|err| format!("创建 HTTP 客户端失败: {err}"))
}

fn select_release_asset<'a>(
    release: &'a GithubRelease,
    platform: &CorePlatform,
) -> Result<&'a GithubAsset, String> {
    let version = normalize_version(&release.tag_name);
    let version = version.trim_start_matches('v');
    let expected_name = format!(
        "CLIProxyAPI_{}_{}_{}.{}",
        version, platform.asset_os, platform.asset_arch, platform.archive_kind
    );
    let mut matches = release
        .assets
        .iter()
        .filter(|asset| asset.name == expected_name && !asset.name.contains("_no-plugin"));
    let asset = matches
        .next()
        .ok_or_else(|| format!("未找到匹配当前平台的 release asset: {expected_name}"))?;

    if matches.next().is_some() {
        return Err(format!("找到多个匹配的 release asset: {expected_name}"));
    }

    Ok(asset)
}

// Download progress and cancellation require the complete transfer context here.
#[allow(clippy::too_many_arguments)]
async fn download_asset(
    client: &reqwest::Client,
    url: &str,
    archive_path: &Path,
    expected_total: Option<u64>,
    expected_digest: Option<&str>,
    window: &tauri::Window,
    state: &CoreDownloadState,
    token: &CancellationToken,
) -> Result<DownloadedArchive, String> {
    let result = download_asset_inner(
        client,
        url,
        archive_path,
        expected_total,
        expected_digest,
        window,
        state,
        token,
    )
    .await;
    if result.is_err() {
        let _ = fs::remove_file(archive_path);
    }

    result
}

#[allow(clippy::too_many_arguments)]
async fn download_asset_inner(
    client: &reqwest::Client,
    url: &str,
    archive_path: &Path,
    expected_total: Option<u64>,
    expected_digest: Option<&str>,
    window: &tauri::Window,
    state: &CoreDownloadState,
    token: &CancellationToken,
) -> Result<DownloadedArchive, String> {
    state.progress(window, "准备下载", 0, expected_total, true);
    ensure_not_cancelled(token, Some(archive_path))?;

    let request = client
        .get(url)
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .send();
    let response = tokio::select! {
        response = request => response.map_err(|err| format!("下载内核压缩包失败: {err}"))?,
        _ = token.cancelled() => return Err("已取消下载".to_string()),
    }
    .error_for_status()
    .map_err(|err| format!("下载地址返回错误状态: {err}"))?;
    let total = expected_total.or_else(|| response.content_length());
    let mut stream = response.bytes_stream();
    let mut file =
        File::create(archive_path).map_err(|err| format!("创建内核压缩包失败: {err}"))?;
    let mut downloaded = 0_u64;
    let mut hasher = Sha256::new();

    while let Some(chunk) = tokio::select! {
        chunk = stream.next() => chunk,
        _ = token.cancelled() => return Err("已取消下载".to_string()),
    } {
        ensure_not_cancelled(token, Some(archive_path))?;

        let chunk = chunk.map_err(|err| format!("读取下载数据失败: {err}"))?;
        file.write_all(&chunk)
            .map_err(|err| format!("保存下载数据失败: {err}"))?;
        hasher.update(&chunk);
        downloaded += chunk.len() as u64;
        state.progress(window, "下载中", downloaded, total, true);
    }

    file.flush()
        .map_err(|err| format!("刷新内核压缩包失败: {err}"))?;
    ensure_not_cancelled(token, Some(archive_path))?;

    let sha256 = format!("{:x}", hasher.finalize());
    validate_download_metadata(downloaded, expected_total, &sha256, expected_digest)?;

    Ok(DownloadedArchive {
        size: downloaded,
        sha256,
    })
}

fn ensure_not_cancelled(
    token: &CancellationToken,
    archive_path: Option<&Path>,
) -> Result<(), String> {
    if token.is_cancelled() {
        if let Some(archive_path) = archive_path {
            let _ = fs::remove_file(archive_path);
        }

        return Err("已取消下载".to_string());
    }

    Ok(())
}

fn current_core_platform() -> Result<CorePlatform, String> {
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let (asset_os, archive_kind) = match os {
        "linux" => ("linux", "tar.gz"),
        "macos" => ("darwin", "tar.gz"),
        "windows" => ("windows", "zip"),
        other => return Err(format!("不支持的操作系统: {other}")),
    };

    let asset_arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "aarch64",
        other => return Err(format!("不支持的 CPU 架构: {other}")),
    };

    Ok(CorePlatform {
        os: os.to_string(),
        arch: arch.to_string(),
        asset_os: asset_os.to_string(),
        asset_arch: asset_arch.to_string(),
        archive_kind: archive_kind.to_string(),
    })
}

fn current_core_status(
    process_state: Option<&CoreProcessState>,
    management_port: Option<u16>,
) -> Result<CoreStatus, String> {
    let install_dir = core_install_dir()?;
    let binary_path = find_core_binary(&install_dir);
    let installed = binary_path.is_some();
    let managed_pid = process_state.and_then(|state| state.managed_pid());
    let process_ids = binary_path
        .as_ref()
        .map(|path| find_core_process_ids(path))
        .unwrap_or_default();
    let process_id = managed_pid.or_else(|| process_ids.first().copied());
    let running =
        process_id.is_some() && management_port.map(is_management_port_open).unwrap_or(true);
    let current_version = read_core_metadata(&install_dir).map(|metadata| metadata.version);

    let message = if !installed {
        "未安装 CPA 内核，请先安装最新版".to_string()
    } else if running {
        "CPA 内核正在运行".to_string()
    } else {
        "CPA 内核已安装，当前未运行".to_string()
    };

    Ok(CoreStatus {
        installed,
        running,
        managed: managed_pid.is_some(),
        process_id,
        current_version,
        install_dir: path_to_string(&install_dir),
        binary_path: binary_path.map(|path| path_to_string(&path)),
        message,
    })
}

fn is_management_port_open(port: u16) -> bool {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpStream::connect_timeout(&address, Duration::from_millis(150)).is_ok()
}

fn start_core_process_inner(
    process_state: &CoreProcessState,
    gui_config: &GuiConfigFile,
) -> Result<(), String> {
    ensure_fixed_oauth_dir()?;
    let install_dir = core_install_dir()?;
    let binary_path = find_core_binary(&install_dir)
        .ok_or_else(|| "未安装 CPA 内核，请先安装最新版".to_string())?;

    if process_state.managed_pid().is_some() || is_core_running(&binary_path) {
        return Err("CPA 内核已经在运行".to_string());
    }
    let management_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), gui_config.port);
    if TcpStream::connect_timeout(&management_address, Duration::from_millis(250)).is_ok() {
        return Err(format!(
            "端口 {} 已被其他程序占用，请更换端口后重试",
            gui_config.port
        ));
    }

    let config_path = merge_core_config_for_start(&install_dir, gui_config)?;
    let config_path = path_to_string(&config_path);
    let mut command = Command::new(&binary_path);
    command
        .args(["-config", &config_path])
        .current_dir(&install_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_child_lifetime(&mut command);

    let mut child = command
        .spawn()
        .map_err(|err| format!("启动 CPA 内核失败: {err}"))?;

    if let Err(error) = wait_for_core_management_port(&mut child, management_address) {
        let _ = terminate_child(&mut child);
        return Err(error);
    }

    process_state.store_child(child)?;

    Ok(())
}

fn wait_for_core_management_port(child: &mut Child, address: SocketAddr) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("检查 CPA 内核启动状态失败: {err}"))?
        {
            return Err(format!("CPA 内核启动后立即退出: {status}"));
        }
        if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "CPA 内核启动超时：10 秒内未监听管理端口 {}",
                address.port()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn configure_child_lifetime(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;

        let parent_process_id = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) == -1 {
                    return Err(io::Error::last_os_error());
                }

                if libc::getppid() != parent_process_id {
                    return Err(io::Error::other(
                        "CPA GUI exited before the core process started",
                    ));
                }

                Ok(())
            });
        }
    }

    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

fn merge_core_config_for_start(
    install_dir: &Path,
    gui_config: &GuiConfigFile,
) -> Result<PathBuf, String> {
    let _config_guard = lock_core_config_file()?;
    let config_path = install_dir.join(CORE_CONFIG_FILE);
    let example_config_path = install_dir.join(CORE_EXAMPLE_CONFIG_FILE);
    if !example_config_path.is_file() {
        return Err(format!(
            "未找到内核配置模板: {}",
            path_to_string(&example_config_path)
        ));
    }

    let template = fs::read_to_string(&example_config_path).map_err(|err| {
        format!(
            "读取内核配置模板失败 {}: {err}",
            path_to_string(&example_config_path)
        )
    })?;
    let current = if config_path.is_file() {
        Some(fs::read_to_string(&config_path).map_err(|err| {
            format!(
                "读取现有内核配置失败 {}: {err}",
                path_to_string(&config_path)
            )
        })?)
    } else {
        None
    };
    let merged = merge_core_config_yaml(&template, current.as_deref(), gui_config)?;
    write_yaml_if_changed(&config_path, &merged)?;

    Ok(config_path)
}

fn patch_core_network_settings(config: &GuiConfigFile) -> Result<(), String> {
    let _config_guard = lock_core_config_file()?;
    let install_dir = core_install_dir()?;
    let config_path = install_dir.join(CORE_CONFIG_FILE);
    if !config_path.is_file() {
        return Ok(());
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|err| format!("读取内核配置失败 {}: {err}", path_to_string(&config_path)))?;
    let Some(updated) = patch_core_network_yaml(&content, config)? else {
        return Ok(());
    };
    write_yaml_if_changed(&config_path, &updated).map(|_| ())
}

fn patch_core_auth_dir(auth_dir: &str) -> Result<(), String> {
    patch_existing_core_config(|document| {
        document.set("auth-dir", auth_dir.to_string());
        Ok(())
    })
}

fn lock_core_config_file() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    CORE_CONFIG_FILE_LOCK
        .lock()
        .map_err(|_| "内核配置文件锁已损坏".to_string())
}

fn read_installed_core_config_settings() -> Result<CoreConfigSettings, String> {
    let _config_guard = lock_core_config_file()?;
    let (_, document) = read_core_config_document()?;
    core_config_settings_from_value(document.get())
}

fn current_core_config_settings(
    gui_config_state: &GuiConfigState,
) -> Result<CoreConfigSettings, String> {
    let config_path = core_install_dir()?.join(CORE_CONFIG_FILE);
    if config_path.is_file() {
        read_installed_core_config_settings()
    } else {
        let config = gui_config_state.snapshot()?;
        Ok(CoreConfigSettings::from(&config))
    }
}

fn patch_core_api_keys(api_keys: &[String]) -> Result<(), String> {
    let _config_guard = lock_core_config_file()?;
    let config_path = core_install_dir()?.join(CORE_CONFIG_FILE);
    if !config_path.is_file() {
        return Ok(());
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|err| format!("读取内核配置失败 {}: {err}", path_to_string(&config_path)))?;
    let updated = patch_core_api_keys_yaml(&content, api_keys)?;
    write_yaml_if_changed(&config_path, &updated)?;
    Ok(())
}

fn patch_core_management_secret_key(secret_key: &str) -> Result<(), String> {
    let _ = secret_key;
    let secret_key = DEFAULT_MANAGEMENT_SECRET_KEY.to_string();
    patch_existing_core_config(move |document| {
        set_yaml_edit_nested_value(document, "remote-management", "secret-key", secret_key);
        Ok(())
    })
}

fn patch_core_plugins_enabled(enabled: bool) -> Result<(), String> {
    patch_existing_core_config(|document| {
        set_yaml_edit_nested_value(document, "plugins", "enabled", enabled);
        Ok(())
    })
}

fn patch_core_routing_strategy(strategy: &str) -> Result<(), String> {
    let strategy = strategy.to_string();
    patch_existing_core_config(move |document| {
        set_yaml_edit_nested_value(document, "routing", "strategy", strategy);
        Ok(())
    })
}

fn patch_existing_core_config<F>(update: F) -> Result<(), String>
where
    F: FnOnce(&yaml_edit::Document) -> Result<(), String>,
{
    let _config_guard = lock_core_config_file()?;
    let config_path = core_install_dir()?.join(CORE_CONFIG_FILE);
    if !config_path.is_file() {
        return Ok(());
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|err| format!("读取内核配置失败 {}: {err}", path_to_string(&config_path)))?;
    let file = content
        .parse::<yaml_edit::YamlFile>()
        .map_err(|err| format!("解析内核配置失败: {err}"))?;
    let document = file
        .document()
        .ok_or_else(|| "内核配置没有 YAML 文档".to_string())?;
    update(&document)?;
    let updated = file.to_string();
    serde_norway::from_str::<serde_norway::Value>(&updated)
        .map_err(|err| format!("验证更新后的内核配置失败: {err}"))?;

    write_yaml_if_changed(&config_path, &updated)?;

    Ok(())
}

fn patch_core_api_keys_yaml(content: &str, api_keys: &[String]) -> Result<String, String> {
    let file = content
        .parse::<yaml_edit::YamlFile>()
        .map_err(|err| format!("解析内核配置失败: {err}"))?;
    let document = file
        .document()
        .ok_or_else(|| "内核配置没有 YAML 文档".to_string())?;
    clear_legacy_api_key_paths(&document);

    let content = file.to_string();
    let block = render_core_api_keys_yaml(api_keys)?;
    let updated = replace_top_level_yaml_block(&content, "api-keys", &block);
    serde_norway::from_str::<serde_norway::Value>(&updated)
        .map_err(|err| format!("验证更新后的内核配置失败: {err}"))?;
    Ok(updated)
}

fn render_core_api_keys_yaml(api_keys: &[String]) -> Result<String, String> {
    if api_keys.is_empty() {
        return Ok(String::new());
    }

    let sequence = serde_norway::Value::Sequence(
        api_keys
            .iter()
            .cloned()
            .map(serde_norway::Value::String)
            .collect(),
    );
    let serialized = serde_norway::to_string(&sequence)
        .map_err(|err| format!("生成内核鉴权密钥配置失败: {err}"))?;
    let mut block = String::from("api-keys:\n");
    for line in serialized.lines() {
        block.push_str("  ");
        block.push_str(line);
        block.push('\n');
    }
    Ok(block)
}

fn replace_top_level_yaml_block(content: &str, key: &str, block: &str) -> String {
    let lines = yaml_line_ranges(content);
    let key_prefix = format!("{key}:");

    if let Some((line_index, (start, end))) =
        lines.iter().copied().enumerate().find(|(_, range)| {
            let line = yaml_line_content(content, *range);
            !line.chars().next().is_some_and(char::is_whitespace) && line.starts_with(&key_prefix)
        })
    {
        let line = yaml_line_content(content, (start, end));
        let value = line[key_prefix.len()..].trim();
        let mut replace_end = end;
        if value.is_empty() || value.starts_with('#') {
            for (next_start, next_end) in lines.iter().copied().skip(line_index + 1) {
                let next = yaml_line_content(content, (next_start, next_end));
                if next.chars().next().is_some_and(char::is_whitespace) {
                    replace_end = next_end;
                } else {
                    break;
                }
            }
        }
        return replace_yaml_range(content, start, replace_end, block);
    }

    let insertion = lines
        .iter()
        .copied()
        .find(|range| yaml_line_content(content, *range).trim() == "# API keys for authentication")
        .map(|(_, end)| end)
        .or_else(|| {
            lines
                .iter()
                .copied()
                .find(|range| {
                    let line = yaml_line_content(content, *range);
                    !line.chars().next().is_some_and(char::is_whitespace)
                        && line.starts_with("auth-dir:")
                })
                .map(|(_, end)| end)
        })
        .unwrap_or(0);
    replace_yaml_range(content, insertion, insertion, block)
}

fn yaml_line_ranges(content: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = 0;
    for (index, character) in content.char_indices() {
        if character == '\n' {
            ranges.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < content.len() {
        ranges.push((start, content.len()));
    }
    ranges
}

fn yaml_line_content(content: &str, (start, end): (usize, usize)) -> &str {
    content[start..end].trim_end_matches(['\r', '\n'])
}

fn replace_yaml_range(content: &str, start: usize, end: usize, block: &str) -> String {
    let mut result = String::with_capacity(content.len() + block.len());
    result.push_str(&content[..start]);
    if !block.is_empty() {
        result.push_str(block);
        if !block.ends_with('\n') && (end < content.len() || content.ends_with('\n')) {
            result.push('\n');
        }
    }
    result.push_str(&content[end..]);
    result
}

fn clear_legacy_api_key_paths(document: &yaml_edit::Document) {
    use yaml_edit::path::YamlPath;

    document.remove_path("auth.providers.config-api-key.api-key-entries");
    document.remove_path("auth.providers.config-api-key.api-keys");
}

fn set_yaml_edit_nested_value(
    document: &yaml_edit::Document,
    section: &str,
    key: &str,
    value: impl yaml_edit::AsYaml,
) -> bool {
    if let Some(node) = document.get(section) {
        if let Some(mapping) = node.as_mapping() {
            mapping.set(key, value);
            return true;
        }
    }
    false
}

fn read_core_config_document() -> Result<(PathBuf, yaml_serde_edit::YamlValue), String> {
    let config_path = core_install_dir()?.join(CORE_CONFIG_FILE);
    if !config_path.is_file() {
        return Err("内核配置尚未生成，请先启动 CPA 内核".to_string());
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|err| format!("读取内核配置失败 {}: {err}", path_to_string(&config_path)))?;
    let document = yaml_serde_edit::YamlValue::parse(&content)
        .map_err(|err| format!("解析内核配置失败: {err}"))?;
    Ok((config_path, document))
}

fn core_config_settings_from_value(
    document: &serde_norway::Value,
) -> Result<CoreConfigSettings, String> {
    let root = document
        .as_mapping()
        .ok_or_else(|| "内核配置顶层必须是 YAML 映射".to_string())?;
    let api_keys = extract_core_api_keys(root)?
        .into_iter()
        .filter(|api_key| !is_example_core_api_key(api_key))
        .collect();
    let management_secret_key = extract_core_management_secret_key(root)?;
    let plugins_enabled = nested_yaml_value(root, &["plugins", "enabled"])
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| "plugins.enabled 必须是布尔值".to_string())
        })
        .transpose()?
        .unwrap_or(false);
    let routing_strategy = nested_yaml_value(root, &["routing", "strategy"])
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "routing.strategy 必须是字符串".to_string())
        })
        .transpose()?
        .unwrap_or_else(|| "round-robin".to_string());

    Ok(CoreConfigSettings {
        api_keys,
        management_secret_configured: management_secret_key
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
        plugins_enabled,
        routing_strategy,
        management_secret_key,
    })
}

fn extract_core_api_keys(root: &serde_norway::Mapping) -> Result<Vec<String>, String> {
    if let Some(value) = yaml_mapping_value(root, "api-keys") {
        return extract_api_key_sequence(value, "api-keys");
    }

    let legacy = nested_yaml_value(root, &["auth", "providers", "config-api-key"])
        .and_then(serde_norway::Value::as_mapping);
    let Some(legacy) = legacy else {
        return Ok(Vec::new());
    };
    let value = yaml_mapping_value(legacy, "api-key-entries")
        .or_else(|| yaml_mapping_value(legacy, "api-keys"));
    value
        .map(|value| extract_api_key_sequence(value, "auth.providers.config-api-key"))
        .transpose()
        .map(Option::unwrap_or_default)
}

fn extract_api_key_sequence(
    value: &serde_norway::Value,
    field_name: &str,
) -> Result<Vec<String>, String> {
    if value.is_null() {
        return Ok(Vec::new());
    }

    let sequence = value
        .as_sequence()
        .ok_or_else(|| format!("{field_name} 必须是数组"))?;
    sequence
        .iter()
        .filter_map(extract_api_key_value)
        .collect::<Result<Vec<_>, _>>()
}

fn extract_api_key_value(value: &serde_norway::Value) -> Option<Result<String, String>> {
    if let Some(value) = value.as_str() {
        let value = value.trim();
        return (!value.is_empty()).then(|| Ok(value.to_string()));
    }

    let mapping = value.as_mapping()?;
    for key in ["api-key", "apiKey", "key", "Key"] {
        if let Some(value) = yaml_mapping_value(mapping, key).and_then(serde_norway::Value::as_str)
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(Ok(value.to_string()));
            }
        }
    }

    Some(Err(
        "鉴权密钥条目必须是字符串或包含 key 字段的映射".to_string()
    ))
}

fn extract_core_management_secret_key(
    root: &serde_norway::Mapping,
) -> Result<Option<String>, String> {
    let Some(value) = nested_yaml_value(root, &["remote-management", "secret-key"]) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| "remote-management.secret-key 必须是字符串".to_string())?
        .trim()
        .to_string();
    if value.is_empty() || is_hashed_management_secret_key(&value) {
        return Ok(None);
    }
    Ok(Some(value))
}

#[cfg(test)]
fn set_core_api_keys(
    document: &mut serde_norway::Value,
    api_keys: Vec<String>,
) -> Result<(), String> {
    let root = document
        .as_mapping_mut()
        .ok_or_else(|| "内核配置顶层必须是 YAML 映射".to_string())?;
    root.insert(
        yaml_key("api-keys"),
        serde_norway::Value::Sequence(
            api_keys
                .into_iter()
                .map(serde_norway::Value::String)
                .collect(),
        ),
    );
    remove_legacy_api_keys(root);
    Ok(())
}

#[cfg(test)]
fn remove_legacy_api_keys(root: &mut serde_norway::Mapping) {
    let Some(auth) =
        yaml_mapping_value_mut(root, "auth").and_then(serde_norway::Value::as_mapping_mut)
    else {
        return;
    };
    let Some(providers) =
        yaml_mapping_value_mut(auth, "providers").and_then(serde_norway::Value::as_mapping_mut)
    else {
        return;
    };
    let Some(provider) = yaml_mapping_value_mut(providers, "config-api-key")
        .and_then(serde_norway::Value::as_mapping_mut)
    else {
        return;
    };
    provider.remove(yaml_key("api-key-entries"));
    provider.remove(yaml_key("api-keys"));
}

#[cfg(test)]
fn set_nested_yaml_value<T>(
    document: &mut serde_norway::Value,
    path: &[&str],
    value: T,
) -> Result<(), String>
where
    T: Into<serde_norway::Value>,
{
    if path.len() != 2 {
        return Err("内核配置路径无效".to_string());
    }

    let root = document
        .as_mapping_mut()
        .ok_or_else(|| "内核配置顶层必须是 YAML 映射".to_string())?;
    let section = root
        .entry(yaml_key(path[0]))
        .or_insert_with(|| serde_norway::Value::Mapping(serde_norway::Mapping::new()));
    let section = section
        .as_mapping_mut()
        .ok_or_else(|| format!("{} 必须是 YAML 映射", path[0]))?;
    section.insert(yaml_key(path[1]), value.into());
    Ok(())
}

fn nested_yaml_value<'a>(
    root: &'a serde_norway::Mapping,
    path: &[&str],
) -> Option<&'a serde_norway::Value> {
    let (first, rest) = path.split_first()?;
    let mut value = yaml_mapping_value(root, first)?;
    for key in rest {
        value = yaml_mapping_value(value.as_mapping()?, key)?;
    }
    Some(value)
}

fn yaml_mapping_value<'a>(
    mapping: &'a serde_norway::Mapping,
    key: &str,
) -> Option<&'a serde_norway::Value> {
    mapping.get(yaml_key(key))
}

#[cfg(test)]
fn yaml_mapping_value_mut<'a>(
    mapping: &'a mut serde_norway::Mapping,
    key: &str,
) -> Option<&'a mut serde_norway::Value> {
    mapping.get_mut(yaml_key(key))
}

fn yaml_key(key: &str) -> serde_norway::Value {
    serde_norway::Value::String(key.to_string())
}

fn management_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| format!("创建管理 API 客户端失败: {err}"))
}

fn management_authorization(config: &GuiConfigFile) -> Result<String, String> {
    let _ = config;
    Ok(format!("Bearer {DEFAULT_MANAGEMENT_SECRET_KEY}"))
}

fn management_endpoint(config: &GuiConfigFile, path: &str) -> Result<String, String> {
    if config.port == 0 {
        return Err("内核端口无效".to_string());
    }
    let path = path.trim_start_matches('/');
    Ok(format!(
        "http://127.0.0.1:{}/v0/management/{path}",
        config.port
    ))
}

fn normalize_management_oauth_provider(provider: &str) -> Result<String, String> {
    let key = provider.trim().to_ascii_lowercase().replace('_', "-");
    let key = match key.as_str() {
        "claude" | "anthropic" => "anthropic".to_string(),
        "anti-gravity" => "antigravity".to_string(),
        "grok" | "x-ai" | "x.ai" => "xai".to_string(),
        other => other.to_string(),
    };
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("无效的 OAuth 提供商".to_string());
    }
    Ok(key)
}

fn management_oauth_uses_webui_callback(provider_key: &str) -> bool {
    matches!(provider_key, "codex" | "anthropic" | "antigravity" | "xai")
}

async fn read_management_json<T>(response: reqwest::Response) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| format!("读取管理 API 响应失败: {err}"))?;
    if !status.is_success() {
        return Err(format_management_error(status.as_u16(), &text));
    }
    if text.trim().is_empty() {
        return Err("管理 API 返回了空响应".to_string());
    }
    serde_json::from_str::<T>(&text).map_err(|err| {
        format!(
            "解析管理 API 响应失败: {err}; body={}",
            truncate_for_error(&text)
        )
    })
}

async fn read_management_value(response: reqwest::Response) -> Result<serde_json::Value, String> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| format!("读取管理 API 响应失败: {err}"))?;
    if !status.is_success() {
        return Err(format_management_error(status.as_u16(), &text));
    }
    if text.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(value) => Ok(value),
        Err(_) => Ok(serde_json::Value::String(text)),
    }
}

async fn read_management_text(response: reqwest::Response) -> Result<String, String> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| format!("读取管理 API 响应失败: {err}"))?;
    if !status.is_success() {
        return Err(format_management_error(status.as_u16(), &text));
    }
    Ok(text)
}

fn format_management_error(status: u16, body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(message) = value
            .get("error")
            .and_then(|item| item.as_str())
            .or_else(|| value.get("message").and_then(|item| item.as_str()))
        {
            let message = message.trim();
            if !message.is_empty() {
                return format!("管理 API 错误 ({status}): {message}");
            }
        }
    }
    let body = body.trim();
    if body.is_empty() {
        format!("管理 API 错误 ({status})")
    } else {
        format!("管理 API 错误 ({status}): {}", truncate_for_error(body))
    }
}

fn truncate_for_error(value: &str) -> String {
    const LIMIT: usize = 240;
    let trimmed = value.trim();
    if trimmed.chars().count() <= LIMIT {
        return trimmed.to_string();
    }
    let shortened: String = trimmed.chars().take(LIMIT).collect();
    format!("{shortened}…")
}

fn open_external_url_inner(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("链接为空".to_string());
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("只允许打开 http/https 链接".to_string());
    }

    let result = {
        #[cfg(target_os = "windows")]
        {
            Command::new("cmd")
                .args(["/C", "start", "", url])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        }
        #[cfg(target_os = "macos")]
        {
            Command::new("open")
                .arg(url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Command::new("xdg-open")
                .arg(url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        }
    };

    result
        .map(|_| ())
        .map_err(|err| format!("打开浏览器失败: {err}"))
}

fn validate_core_api_key(api_key: &str) -> Result<(), String> {
    if api_key.is_empty() {
        return Err("鉴权密钥不能为空".to_string());
    }
    if !api_key.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err("鉴权密钥只能包含 ASCII 可见字符，且不能包含空格".to_string());
    }
    if is_example_core_api_key(api_key) {
        return Err("不能使用内核模板里的示例鉴权密钥".to_string());
    }
    Ok(())
}

fn validate_api_key_remark(remark: &str) -> Result<(), String> {
    if remark.chars().count() > 80 {
        return Err("密钥备注不能超过 80 个字符".to_string());
    }
    if remark.chars().any(char::is_control) {
        return Err("密钥备注不能包含换行或控制字符".to_string());
    }
    Ok(())
}

fn validate_management_secret_key(secret_key: &str) -> Result<(), String> {
    if secret_key != DEFAULT_MANAGEMENT_SECRET_KEY {
        return Err("管理密钥统一固定为 123456".to_string());
    }
    Ok(())
}

fn is_example_core_api_key(api_key: &str) -> bool {
    let value = api_key.trim();
    value == "your-api-key" || value.starts_with("your-api-key-")
}

fn is_hashed_management_secret_key(secret_key: &str) -> bool {
    let value = secret_key.trim();
    value.starts_with("$2a$")
        || value.starts_with("$2b$")
        || value.starts_with("$2y$")
        || value.starts_with("$argon2")
        || value.starts_with("$scrypt$")
        || value.starts_with("bcrypt:")
        || value.starts_with("argon2:")
        || value.starts_with("argon2id:")
        || value.starts_with("sha256:")
        || value.starts_with("sha512:")
}

fn validate_routing_strategy(strategy: &str) -> Result<(), String> {
    if matches!(strategy, "round-robin" | "fill-first") {
        return Ok(());
    }
    Err("路由策略只支持 round-robin 或 fill-first".to_string())
}

fn merge_core_config_yaml(
    template: &str,
    current: Option<&str>,
    config: &GuiConfigFile,
) -> Result<String, String> {
    let mut document = yaml_serde_edit::YamlValue::parse(template)
        .map_err(|err| format!("解析内核配置模板失败: {err}"))?;
    let mut merged = document.get().clone();

    if let Some(current) = current {
        let current = serde_norway::from_str::<serde_norway::Value>(current)
            .map_err(|err| format!("解析现有内核配置失败: {err}"))?;
        merge_yaml_values(&mut merged, current);
    }

    document.set(merged);
    apply_gui_managed_settings(&document.get_string(), config)
}

fn patch_core_network_yaml(
    content: &str,
    config: &GuiConfigFile,
) -> Result<Option<String>, String> {
    let mut document = yaml_serde_edit::YamlValue::parse(content)
        .map_err(|err| format!("解析内核配置失败: {err}"))?;
    let mut updated = document.get().clone();
    apply_network_settings(&mut updated, config)?;

    if updated == *document.get() {
        return Ok(None);
    }

    document.set(updated);
    Ok(Some(document.get_string()))
}

fn merge_yaml_values(base: &mut serde_norway::Value, current: serde_norway::Value) {
    match (base, current) {
        (
            serde_norway::Value::Mapping(base_mapping),
            serde_norway::Value::Mapping(current_mapping),
        ) => {
            for (key, current_value) in current_mapping {
                if let Some(base_value) = base_mapping.get_mut(&key) {
                    merge_yaml_values(base_value, current_value);
                } else {
                    base_mapping.insert(key, current_value);
                }
            }
        }
        (base, current) => *base = current,
    }
}

fn apply_network_settings(
    document: &mut serde_norway::Value,
    config: &GuiConfigFile,
) -> Result<(), String> {
    let mapping = document
        .as_mapping_mut()
        .ok_or_else(|| "内核配置顶层必须是 YAML 映射".to_string())?;

    let host = if config.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    mapping.insert(
        serde_norway::Value::String("host".to_string()),
        serde_norway::Value::String(host.to_string()),
    );
    mapping.insert(
        serde_norway::Value::String("port".to_string()),
        serde_norway::to_value(config.port).map_err(|err| format!("序列化内核端口失败: {err}"))?,
    );
    Ok(())
}

fn apply_gui_managed_settings(content: &str, config: &GuiConfigFile) -> Result<String, String> {
    let file = content
        .parse::<yaml_edit::YamlFile>()
        .map_err(|err| format!("解析合并后的内核配置失败: {err}"))?;
    let document = file
        .document()
        .ok_or_else(|| "合并后的内核配置没有 YAML 文档".to_string())?;
    let host = if config.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };
    document.set("host", host);
    document.set("port", config.port);
    document.set("auth-dir", config.auth_dir.clone());
    set_yaml_edit_nested_value(
        &document,
        "remote-management",
        "secret-key",
        DEFAULT_MANAGEMENT_SECRET_KEY,
    );
    set_yaml_edit_nested_value(&document, "plugins", "enabled", config.plugins_enabled);
    set_yaml_edit_nested_value(
        &document,
        "routing",
        "strategy",
        config.routing_strategy.clone(),
    );

    let updated =
        patch_core_api_keys_yaml(&file.to_string(), &gui_api_key_values(&config.api_keys))?;
    serde_norway::from_str::<serde_norway::Value>(&updated)
        .map_err(|err| format!("验证启动内核配置失败: {err}"))?;
    Ok(updated)
}

fn write_yaml_if_changed(path: &Path, content: &str) -> Result<bool, String> {
    if fs::read_to_string(path).ok().as_deref() == Some(content) {
        return Ok(false);
    }

    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config.yaml");
    let temporary_path = directory.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));

    let write_result = (|| -> io::Result<()> {
        let mut file = File::create(&temporary_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        replace_file_atomically(&temporary_path, path)
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!(
            "原子写入配置失败 {}: {error}",
            path_to_string(path)
        ));
    }

    Ok(true)
}

#[cfg(not(windows))]
fn replace_file_atomically(temporary_path: &Path, destination_path: &Path) -> io::Result<()> {
    fs::rename(temporary_path, destination_path)
}

#[cfg(windows)]
fn replace_file_atomically(temporary_path: &Path, destination_path: &Path) -> io::Result<()> {
    if !destination_path.exists() {
        return fs::rename(temporary_path, destination_path);
    }

    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::Storage::FileSystem::ReplaceFileW;

    let destination = destination_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replacement = temporary_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let replaced = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            replacement.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
        )
    };

    if replaced == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn fixed_oauth_dir() -> Result<PathBuf, String> {
    Ok(core_base_dir()?.join(OAUTH_DIR_NAME))
}

fn ensure_fixed_oauth_dir() -> Result<PathBuf, String> {
    let directory = fixed_oauth_dir()?;
    fs::create_dir_all(&directory)
        .map_err(|err| format!("创建固定凭证目录失败 {}: {err}", path_to_string(&directory)))?;
    Ok(directory)
}

fn load_or_create_gui_config() -> Result<GuiConfigFile, String> {
    ensure_fixed_oauth_dir()?;
    let config_path = gui_config_path()?;
    let legacy_config_path = legacy_gui_config_path()?;

    let (mut config, presence, mut changed) = if config_path.is_file() {
        let content = fs::read_to_string(&config_path)
            .map_err(|err| format!("读取 GUI 配置失败 {}: {err}", path_to_string(&config_path)))?;
        let config = toml::from_str::<GuiConfigFile>(&content)
            .map_err(|err| format!("解析 GUI 配置失败: {err}"))?;
        let presence = toml::from_str::<GuiConfigPresence>(&content)
            .map_err(|err| format!("解析 GUI 配置字段失败: {err}"))?;
        (config, presence, false)
    } else if legacy_config_path.is_file() {
        let content = fs::read_to_string(&legacy_config_path).map_err(|err| {
            format!(
                "读取旧 GUI 配置失败 {}: {err}",
                path_to_string(&legacy_config_path)
            )
        })?;
        let config = serde_yaml::from_str::<GuiConfigFile>(&content)
            .map_err(|err| format!("解析旧 GUI 配置失败: {err}"))?;
        let presence = serde_yaml::from_str::<GuiConfigPresence>(&content)
            .map_err(|err| format!("解析旧 GUI 配置字段失败: {err}"))?;
        (config, presence, true)
    } else {
        (GuiConfigFile::default(), GuiConfigPresence::default(), true)
    };

    let missing_core_settings = presence.api_keys.is_none()
        || presence.management_secret_key.is_none()
        || presence.plugins_enabled.is_none()
        || presence.routing_strategy.is_none();
    if missing_core_settings {
        if let Ok(core_settings) = read_installed_core_config_settings() {
            if presence.api_keys.is_none() {
                config.api_keys = merge_core_api_keys_with_gui_metadata(
                    &config.api_keys,
                    &core_settings.api_keys,
                    None,
                );
            }
            if presence.plugins_enabled.is_none() {
                config.plugins_enabled = core_settings.plugins_enabled;
            }
            if presence.routing_strategy.is_none() {
                config.routing_strategy = core_settings.routing_strategy;
            }
        }
        changed = true;
    }
    if presence.auth_dir.is_none() {
        changed = true;
    }
    changed |= sanitize_gui_config(&mut config)?;
    validate_gui_config(&config)?;
    if changed {
        write_gui_config(&config)?;
    }
    patch_core_auth_dir(&config.auth_dir)?;
    patch_core_api_keys(&gui_api_key_values(&config.api_keys))?;
    Ok(config)
}

#[cfg(test)]
fn apply_core_settings_to_gui_config(
    config: &mut GuiConfigFile,
    core_settings: &CoreConfigSettings,
) {
    config.api_keys =
        merge_core_api_keys_with_gui_metadata(&config.api_keys, &core_settings.api_keys, None);
    config.management_secret_key = DEFAULT_MANAGEMENT_SECRET_KEY.to_string();
    config.plugins_enabled = core_settings.plugins_enabled;
    config.routing_strategy = core_settings.routing_strategy.clone();
}

fn built_in_api_key_entry() -> GuiApiKeyEntry {
    GuiApiKeyEntry {
        key: DEFAULT_API_KEY.to_string(),
        remark: DEFAULT_API_KEY_REMARK.to_string(),
    }
}

fn gui_api_key_values(entries: &[GuiApiKeyEntry]) -> Vec<String> {
    entries.iter().map(|entry| entry.key.clone()).collect()
}

fn merge_core_api_keys_with_gui_metadata(
    existing: &[GuiApiKeyEntry],
    core_api_keys: &[String],
    added_api_key: Option<&GuiApiKeyEntry>,
) -> Vec<GuiApiKeyEntry> {
    let mut merged = vec![built_in_api_key_entry()];

    for api_key in core_api_keys {
        let api_key = api_key.trim();
        if api_key.is_empty() || api_key == DEFAULT_API_KEY || is_example_core_api_key(api_key) {
            continue;
        }
        if merged.iter().any(|entry| entry.key == api_key) {
            continue;
        }

        let remark = added_api_key
            .filter(|entry| entry.key == api_key)
            .map(|entry| entry.remark.clone())
            .or_else(|| {
                existing
                    .iter()
                    .find(|entry| entry.key == api_key)
                    .map(|entry| entry.remark.clone())
            })
            .unwrap_or_default();
        merged.push(GuiApiKeyEntry {
            key: api_key.to_string(),
            remark,
        });
    }

    merged
}

fn sanitize_gui_config(config: &mut GuiConfigFile) -> Result<bool, String> {
    let mut changed = false;
    let original_api_keys = config.api_keys.clone();
    let configured_keys = config
        .api_keys
        .iter()
        .map(|entry| entry.key.trim().to_string())
        .collect::<Vec<_>>();
    config.api_keys =
        merge_core_api_keys_with_gui_metadata(&config.api_keys, &configured_keys, None);
    for entry in &mut config.api_keys {
        entry.key = entry.key.trim().to_string();
        entry.remark = entry.remark.trim().to_string();
        if entry.key == DEFAULT_API_KEY {
            entry.remark = DEFAULT_API_KEY_REMARK.to_string();
        }
    }
    if config.api_keys != original_api_keys {
        changed = true;
    }
    if config.management_secret_key != DEFAULT_MANAGEMENT_SECRET_KEY {
        config.management_secret_key = DEFAULT_MANAGEMENT_SECRET_KEY.to_string();
        changed = true;
    }
    let auth_dir = path_to_string(&fixed_oauth_dir()?);
    if config.auth_dir != auth_dir {
        config.auth_dir = auth_dir;
        changed = true;
    }
    Ok(changed)
}

fn write_gui_config(config: &GuiConfigFile) -> Result<(), String> {
    validate_gui_config(config)?;
    let config_path = gui_config_path()?;
    let content =
        toml::to_string_pretty(config).map_err(|err| format!("序列化 GUI 配置失败: {err}"))?;
    write_yaml_if_changed(&config_path, &content).map(|_| ())
}

fn validate_gui_config(config: &GuiConfigFile) -> Result<(), String> {
    if config.port == 0 {
        return Err("GUI 配置端口必须在 1 到 65535 之间".to_string());
    }
    for entry in &config.api_keys {
        validate_core_api_key(&entry.key)?;
        validate_api_key_remark(&entry.remark)?;
    }
    if config.routing_strategy.trim().is_empty() {
        return Err("GUI 配置路由策略不能为空".to_string());
    }
    let expected_auth_dir = fixed_oauth_dir()?;
    if PathBuf::from(&config.auth_dir) != expected_auth_dir {
        return Err(format!(
            "凭证目录固定为 {}，不允许自定义",
            path_to_string(&expected_auth_dir)
        ));
    }
    validate_management_secret_key(&config.management_secret_key)?;

    Ok(())
}

fn gui_config_path() -> Result<PathBuf, String> {
    Ok(core_base_dir()?.join(GUI_CONFIG_FILE))
}

fn legacy_gui_config_path() -> Result<PathBuf, String> {
    Ok(core_base_dir()?.join(LEGACY_GUI_CONFIG_FILE))
}

fn stop_core_process_inner(process_state: &CoreProcessState) -> Result<(), String> {
    if let Some(mut child) = process_state.take_child() {
        terminate_child(&mut child)?;
        process_state.clear_lifetime_guard();
        return Ok(());
    }

    let install_dir = core_install_dir()?;
    let binary_path = find_core_binary(&install_dir)
        .ok_or_else(|| "未安装 CPA 内核，请先安装最新版".to_string())?;
    let process_ids = find_core_process_ids(&binary_path);

    if process_ids.is_empty() {
        return Err("CPA 内核当前未运行".to_string());
    }

    for process_id in process_ids {
        terminate_process_id(process_id)?;
    }

    Ok(())
}

fn core_install_dir() -> Result<PathBuf, String> {
    Ok(core_base_dir()?.join("cpa-core"))
}

fn core_base_dir() -> Result<PathBuf, String> {
    let exe_path = env::current_exe().map_err(|err| format!("读取当前程序路径失败: {err}"))?;
    exe_path
        .parent()
        .map(|path| path.to_path_buf())
        .ok_or_else(|| format!("当前程序路径没有父目录: {}", path_to_string(&exe_path)))
}

fn read_core_metadata(install_dir: &Path) -> Option<CoreMetadata> {
    let metadata_path = install_dir.join(CORE_METADATA_FILE);
    let content = fs::read_to_string(metadata_path).ok()?;
    serde_json::from_str(&content).ok()
}

fn write_core_metadata(install_dir: &Path, metadata: &CoreMetadata) -> Result<(), String> {
    let metadata_path = install_dir.join(CORE_METADATA_FILE);
    let content = serde_json::to_string_pretty(metadata)
        .map_err(|err| format!("生成内核元数据失败: {err}"))?;
    fs::write(metadata_path, content).map_err(|err| format!("写入内核元数据失败: {err}"))
}

fn validate_downloaded_asset(
    asset: &GithubAsset,
    downloaded: &DownloadedArchive,
) -> Result<(), String> {
    validate_download_metadata(
        downloaded.size,
        asset.size,
        &downloaded.sha256,
        asset.digest.as_deref(),
    )
}

fn validate_download_metadata(
    downloaded: u64,
    expected_total: Option<u64>,
    sha256: &str,
    expected_digest: Option<&str>,
) -> Result<(), String> {
    if let Some(expected_total) = expected_total {
        if downloaded != expected_total {
            return Err(format!(
                "下载大小校验失败: 实际 {downloaded} 字节，期望 {expected_total} 字节"
            ));
        }
    }

    if let Some(expected_digest) = expected_digest {
        let expected = expected_digest
            .strip_prefix("sha256:")
            .unwrap_or(expected_digest)
            .to_ascii_lowercase();

        if !expected.is_empty() && sha256 != expected {
            return Err("下载文件 SHA-256 校验失败".to_string());
        }
    }

    Ok(())
}

fn cleanup_core_work_dirs() -> Result<(), String> {
    let base_dir = core_base_dir()?;
    let mut last_error = None;

    for name in ["cpa-core.staging", "cpa-core.download"] {
        let path = base_dir.join(name);
        if path.exists() {
            if let Err(err) = fs::remove_dir_all(&path) {
                last_error = Some(format!("清理临时目录失败 {}: {err}", path_to_string(&path)));
            }
        }
    }

    if let Some(error) = last_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn normalize_version(version: &str) -> String {
    let version = version.trim();

    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn is_core_running(binary_path: &Path) -> bool {
    !find_core_process_ids(binary_path).is_empty()
}

fn find_core_process_ids(binary_path: &Path) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        find_core_process_ids_linux(binary_path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = binary_path;
        find_core_process_ids_by_name()
    }
}

#[cfg(target_os = "linux")]
fn find_core_process_ids_linux(binary_path: &Path) -> Vec<u32> {
    let Ok(expected) = fs::canonicalize(binary_path) else {
        return Vec::new();
    };
    let output = Command::new("pgrep")
        .args(["-x", core_binary_name()])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<u32>().ok())
        .filter(|pid| {
            fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .and_then(|path| fs::canonicalize(path).ok())
                .map(|path| path == expected)
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(all(not(target_os = "linux"), target_os = "windows"))]
fn find_core_process_ids_by_name() -> Vec<u32> {
    let image_name = core_binary_name();
    let filter = format!("IMAGENAME eq {image_name}");
    let output = Command::new("tasklist")
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let columns = line
                .trim()
                .trim_matches('"')
                .split("\",\"")
                .collect::<Vec<_>>();
            let name = columns.first()?;
            let pid = columns.get(1)?;

            name.eq_ignore_ascii_case(image_name)
                .then(|| pid.parse::<u32>().ok())
                .flatten()
        })
        .collect()
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn find_core_process_ids_by_name() -> Vec<u32> {
    Command::new("pgrep")
        .args(["-x", core_binary_name()])
        .output()
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn shutdown_managed_core(process_state: &CoreProcessState, gui_config_state: &GuiConfigState) {
    let was_running = process_state.managed_pid().is_some();
    let _ = gui_config_state.set_run_on_startup(was_running);

    if let Some(mut child) = process_state.take_child() {
        let _ = terminate_child(&mut child);
    }
    process_state.clear_lifetime_guard();
}

#[cfg(windows)]
fn attach_child_to_windows_job(child: &Child) -> Result<isize, String> {
    use std::{mem, os::windows::io::AsRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
    };

    unsafe {
        let job = CreateJobObjectW(ptr::null(), ptr::null());
        if job.is_null() {
            return Err(format!(
                "创建 CPA 内核进程作业失败: {}",
                io::Error::last_os_error()
            ));
        }

        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &information as *const _ as *const _,
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if configured == 0 {
            let error = io::Error::last_os_error();
            CloseHandle(job);
            return Err(format!("配置 CPA 内核进程作业失败: {error}"));
        }

        let process_handle = child.as_raw_handle() as HANDLE;
        if AssignProcessToJobObject(job, process_handle) == 0 {
            let error = io::Error::last_os_error();
            CloseHandle(job);
            return Err(format!("托管 CPA 内核子进程失败: {error}"));
        }

        Ok(job as isize)
    }
}

#[cfg(windows)]
fn close_windows_handle(handle: isize) {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};

    unsafe {
        CloseHandle(handle as HANDLE);
    }
}

fn terminate_child(child: &mut Child) -> Result<(), String> {
    let process_id = child.id();

    #[cfg(windows)]
    {
        child
            .kill()
            .map_err(|err| format!("关闭 CPA 内核进程失败: {err}"))?;
        child
            .wait()
            .map_err(|err| format!("等待 CPA 内核进程退出失败: {err}"))?;
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        send_process_signal(process_id, "TERM")?;

        for _ in 0..20 {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => thread::sleep(Duration::from_millis(100)),
                Err(err) => return Err(format!("检查 CPA 内核进程状态失败: {err}")),
            }
        }

        child
            .kill()
            .map_err(|err| format!("强制关闭 CPA 内核进程失败: {err}"))?;
        child
            .wait()
            .map_err(|err| format!("等待 CPA 内核进程退出失败: {err}"))?;

        Ok(())
    }
}

fn terminate_process_id(process_id: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        let process_id = process_id.to_string();
        let status = Command::new("taskkill")
            .args(["/PID", &process_id, "/T", "/F"])
            .status()
            .map_err(|err| format!("关闭 CPA 内核进程失败: {err}"))?;

        if status.success() {
            return Ok(());
        }

        return Err(format!("关闭 CPA 内核进程失败: PID {process_id}"));
    }

    #[cfg(not(windows))]
    {
        send_process_signal(process_id, "TERM")?;

        for _ in 0..20 {
            if !is_process_alive(process_id) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }

        send_process_signal(process_id, "KILL")
    }
}

#[cfg(not(windows))]
fn send_process_signal(process_id: u32, signal: &str) -> Result<(), String> {
    let status = Command::new("kill")
        .args([format!("-{signal}"), process_id.to_string()])
        .status()
        .map_err(|err| format!("发送进程信号失败: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("发送进程信号失败: PID {process_id}"))
    }
}

#[cfg(not(windows))]
fn is_process_alive(process_id: u32) -> bool {
    let process_id = process_id.to_string();
    Command::new("kill")
        .args(["-0", &process_id])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn reset_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path)
            .map_err(|err| format!("清理目录失败 {}: {err}", path_to_string(path)))?;
    }

    fs::create_dir_all(path).map_err(|err| format!("创建目录失败 {}: {err}", path_to_string(path)))
}

fn replace_install_dir(
    install_dir: &Path,
    staging_dir: &Path,
    backup_dir: &Path,
) -> Result<(), String> {
    if backup_dir.exists() {
        fs::remove_dir_all(backup_dir).map_err(|err| format!("清理备份目录失败: {err}"))?;
    }

    if install_dir.exists() {
        fs::rename(install_dir, backup_dir)
            .map_err(|err| format!("备份旧内核目录失败，请确认 CPA 内核未运行: {err}"))?;
    }

    if let Err(err) = fs::rename(staging_dir, install_dir) {
        if backup_dir.exists() {
            let _ = fs::rename(backup_dir, install_dir);
        }

        return Err(format!("切换新内核目录失败: {err}"));
    }

    if backup_dir.exists() {
        fs::remove_dir_all(backup_dir).map_err(|err| format!("删除旧内核备份目录失败: {err}"))?;
    }

    Ok(())
}

fn extract_tar_gz(archive_path: &Path, install_dir: &Path) -> Result<(), String> {
    let archive_file =
        File::open(archive_path).map_err(|err| format!("打开 tar.gz 失败: {err}"))?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|err| format!("读取 tar.gz 条目失败: {err}"))?;

    for entry in entries {
        let mut entry = entry.map_err(|err| format!("读取 tar.gz 条目失败: {err}"))?;
        let entry_path = entry
            .path()
            .map_err(|err| format!("读取 tar.gz 条目路径失败: {err}"))?;
        let out_path = checked_archive_path(install_dir, entry_path.as_ref())?;
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            fs::create_dir_all(&out_path).map_err(|err| format!("创建目录失败: {err}"))?;
        } else if entry_type.is_file() {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|err| format!("创建目录失败: {err}"))?;
            }
            entry
                .unpack(&out_path)
                .map_err(|err| format!("解压 tar.gz 文件失败: {err}"))?;
        } else {
            return Err(format!(
                "tar.gz 包含不支持的条目类型: {}",
                path_to_string(&out_path)
            ));
        }
    }

    Ok(())
}

fn extract_zip(archive_path: &Path, install_dir: &Path) -> Result<(), String> {
    let archive_file = File::open(archive_path).map_err(|err| format!("打开 zip 失败: {err}"))?;
    let mut archive =
        ZipArchive::new(archive_file).map_err(|err| format!("读取 zip 失败: {err}"))?;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| format!("读取 zip 条目失败: {err}"))?;
        let enclosed_name = file
            .enclosed_name()
            .ok_or_else(|| format!("zip 条目路径不安全: {}", file.name()))?;
        let out_path = checked_archive_path(install_dir, &enclosed_name)?;

        if is_zip_symlink(&file) {
            return Err(format!("zip 包含不支持的符号链接条目: {}", file.name()));
        }

        if file.is_dir() {
            fs::create_dir_all(&out_path).map_err(|err| format!("创建目录失败: {err}"))?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("创建目录失败: {err}"))?;
        }

        let mut out_file = File::create(&out_path).map_err(|err| format!("创建文件失败: {err}"))?;
        io::copy(&mut file, &mut out_file).map_err(|err| format!("写入文件失败: {err}"))?;

        #[cfg(unix)]
        if let Some(mode) = file.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&out_path, fs::Permissions::from_mode(mode))
                .map_err(|err| format!("设置文件权限失败: {err}"))?;
        }
    }

    Ok(())
}

fn checked_archive_path(base_dir: &Path, entry_path: &Path) -> Result<PathBuf, String> {
    if entry_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(format!(
            "压缩包条目路径不安全: {}",
            path_to_string(entry_path)
        ));
    }

    Ok(base_dir.join(entry_path))
}

fn is_zip_symlink(file: &zip::read::ZipFile<'_>) -> bool {
    file.unix_mode()
        .map(|mode| mode & 0o170000 == 0o120000)
        .unwrap_or(false)
}

fn find_core_binary(install_dir: &Path) -> Option<PathBuf> {
    let binary_path = install_dir.join(core_binary_name());
    if binary_path.is_file() {
        return Some(binary_path);
    }

    let mut dirs = vec![install_dir.to_path_buf()];

    while let Some(dir) = dirs.pop() {
        let entries = fs::read_dir(dir).ok()?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            } else if path
                .file_name()
                .and_then(|file_name| file_name.to_str())
                .map(|file_name| file_name == core_binary_name())
                .unwrap_or(false)
            {
                return Some(path);
            }
        }
    }

    None
}

fn core_binary_name() -> &'static str {
    if env::consts::OS == "windows" {
        "cli-proxy-api.exe"
    } else {
        "cli-proxy-api"
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn main() {
    let gui_config = match load_or_create_gui_config() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            let mut config = GuiConfigFile::default();
            if let Err(sanitize_error) = sanitize_gui_config(&mut config) {
                eprintln!("初始化固定凭证目录失败: {sanitize_error}");
            }
            config
        }
    };

    let app = tauri::Builder::default()
        .manage(CoreDownloadState::default())
        .manage(CoreProcessState::default())
        .manage(GuiConfigState::new(gui_config))
        .setup(|app| {
            let gui_config_state = app.state::<GuiConfigState>();
            let process_state = app.state::<CoreProcessState>();
            let config = gui_config_state.snapshot().map_err(io::Error::other)?;

            if config.run_on_startup {
                if let Err(error) = start_core_process_inner(process_state.inner(), &config) {
                    eprintln!("自动启动 CPA 内核失败: {error}");
                }
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            health_check,
            detect_core_platform,
            get_core_status,
            get_gui_settings,
            get_lan_ipv4,
            save_gui_settings,
            get_core_config_settings,
            add_core_api_key,
            delete_core_api_key,
            set_core_management_secret_key,
            clear_core_management_secret_key,
            management_request,
            upload_auth_file,
            download_auth_file,
            set_core_plugins_enabled,
            set_core_routing_strategy,
            start_oauth_login,
            get_oauth_status,
            submit_oauth_callback,
            open_external_url,
            check_latest_core,
            install_core_version,
            cancel_core_install,
            get_core_install_task,
            start_core_process,
            stop_core_process,
            restart_core_process
        ])
        .build(tauri::generate_context!())
        .expect("failed to build app");

    app.run(|app_handle, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            let process_state = app_handle.state::<CoreProcessState>();
            let gui_config_state = app_handle.state::<GuiConfigState>();
            shutdown_managed_core(process_state.inner(), gui_config_state.inner());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gui_config_defaults_are_stable() {
        let config = GuiConfigFile::default();
        let content = toml::to_string_pretty(&config).unwrap();

        assert!(content.contains("port = 8317"));
        assert!(content.contains("allow-lan = false"));
        assert!(content.contains("run-on-startup = false"));
        assert!(content.contains("auth-dir = "));
        assert!(content.contains("[[api-keys]]"));
        assert!(content.contains("key = \"123456\""));
        assert!(content.contains("remark = \"内置密钥\""));
        assert!(content.contains("management-secret-key = \"123456\""));
        assert!(content.contains("plugins-enabled = false"));
        assert!(content.contains("routing-strategy = \"round-robin\""));
    }

    #[test]
    fn legacy_string_api_keys_gain_remarks_and_keep_custom_keys() {
        let legacy = "port = 8317\nallow-lan = false\nrun-on-startup = false\nauth-dir = \"/tmp/oauth\"\napi-keys = [\"123456\", \"custom-key\"]\nmanagement-secret-key = \"123456\"\nplugins-enabled = false\nrouting-strategy = \"round-robin\"\n";
        let mut config = toml::from_str::<GuiConfigFile>(legacy).unwrap();

        assert!(sanitize_gui_config(&mut config).unwrap());
        assert_eq!(
            gui_api_key_values(&config.api_keys),
            vec!["123456", "custom-key"]
        );
        assert_eq!(config.api_keys[0].remark, DEFAULT_API_KEY_REMARK);
        assert!(config.api_keys[1].remark.is_empty());

        let serialized = toml::to_string_pretty(&config).unwrap();
        assert!(serialized.contains("[[api-keys]]"));
        assert!(serialized.contains("remark = \"内置密钥\""));
        let reparsed = toml::from_str::<GuiConfigFile>(&serialized).unwrap();
        assert_eq!(reparsed.api_keys, config.api_keys);
    }

    #[test]
    fn api_key_remarks_follow_matching_core_keys() {
        let existing = vec![
            built_in_api_key_entry(),
            GuiApiKeyEntry {
                key: "custom-key".to_string(),
                remark: "开发环境".to_string(),
            },
        ];
        let core_keys = vec!["custom-key".to_string(), "new-key".to_string()];

        let merged = merge_core_api_keys_with_gui_metadata(&existing, &core_keys, None);

        assert_eq!(
            gui_api_key_values(&merged),
            vec!["123456", "custom-key", "new-key"]
        );
        assert_eq!(merged[1].remark, "开发环境");
        assert!(merged[2].remark.is_empty());
    }

    #[test]
    fn core_config_view_exposes_api_key_metadata_for_the_webview() {
        let view = serde_json::to_value(CoreConfigView::from(&GuiConfigFile::default())).unwrap();

        assert_eq!(view["apiKeys"][0]["apiKey"], DEFAULT_API_KEY);
        assert_eq!(view["apiKeys"][0]["remark"], DEFAULT_API_KEY_REMARK);
        assert_eq!(view["apiKeys"][0]["builtIn"], true);
    }

    #[test]
    fn management_secret_key_is_normalized_to_fixed_value() {
        let mut config = GuiConfigFile {
            management_secret_key: "old-management-secret".to_string(),
            ..GuiConfigFile::default()
        };

        assert!(sanitize_gui_config(&mut config).unwrap());
        assert_eq!(config.management_secret_key, DEFAULT_MANAGEMENT_SECRET_KEY);

        let template = "remote-management:\n  secret-key: stale-secret\n";
        let merged = merge_core_config_yaml(template, None, &config).unwrap();
        let document = serde_norway::from_str::<serde_norway::Value>(&merged).unwrap();
        assert_eq!(
            document["remote-management"]["secret-key"],
            DEFAULT_MANAGEMENT_SECRET_KEY
        );
    }

    #[test]
    fn auth_directory_is_fixed_and_written_to_core_config() {
        let mut config = GuiConfigFile {
            auth_dir: "/tmp/user-selected-auth".to_string(),
            ..GuiConfigFile::default()
        };

        assert!(validate_gui_config(&config).is_err());
        assert!(sanitize_gui_config(&mut config).unwrap());
        assert_eq!(config.auth_dir, path_to_string(&fixed_oauth_dir().unwrap()));

        let merged = merge_core_config_yaml("auth-dir: ~/.cli-proxy-api\n", None, &config).unwrap();
        let document = serde_norway::from_str::<serde_norway::Value>(&merged).unwrap();
        assert_eq!(document["auth-dir"], config.auth_dir);
    }

    #[test]
    fn legacy_gui_config_can_seed_managed_core_settings() {
        let legacy = "port: 8317\nallow-lan: false\nrun-on-startup: true\n";
        let mut config = serde_yaml::from_str::<GuiConfigFile>(legacy).unwrap();
        let presence = serde_yaml::from_str::<GuiConfigPresence>(legacy).unwrap();
        let core_settings = CoreConfigSettings {
            api_keys: vec!["existing-key".to_string()],
            management_secret_configured: true,
            plugins_enabled: true,
            routing_strategy: "fill-first".to_string(),
            management_secret_key: Some("management-secret".to_string()),
        };

        assert!(presence.api_keys.is_none());
        assert!(presence.management_secret_key.is_none());
        assert!(presence.plugins_enabled.is_none());
        assert!(presence.routing_strategy.is_none());
        apply_core_settings_to_gui_config(&mut config, &core_settings);

        assert_eq!(
            gui_api_key_values(&config.api_keys),
            vec!["123456", "existing-key"]
        );
        assert_eq!(config.management_secret_key, DEFAULT_MANAGEMENT_SECRET_KEY);
        assert!(config.plugins_enabled);
        assert_eq!(config.routing_strategy, "fill-first");
        assert!(config.run_on_startup);
    }

    #[test]
    fn example_api_keys_are_not_persisted_as_gui_settings() {
        let input = "api-keys:\n  - your-api-key-1\n  - real-key\nremote-management:\n  secret-key: plain-management-secret\nplugins:\n  enabled: true\nrouting:\n  strategy: fill-first\n";
        let document = serde_norway::from_str::<serde_norway::Value>(input).unwrap();
        let core_settings = core_config_settings_from_value(&document).unwrap();
        let mut config = GuiConfigFile::default();

        apply_core_settings_to_gui_config(&mut config, &core_settings);

        assert_eq!(core_settings.api_keys, vec!["real-key"]);
        assert_eq!(
            gui_api_key_values(&config.api_keys),
            vec!["123456", "real-key"]
        );
        assert_eq!(
            core_settings.management_secret_key.as_deref(),
            Some("plain-management-secret")
        );
        assert_eq!(config.management_secret_key, DEFAULT_MANAGEMENT_SECRET_KEY);
        assert!(validate_core_api_key("your-api-key-3").is_err());
    }

    #[test]
    fn hashed_management_secret_is_not_imported_as_gui_source() {
        let input = "remote-management:\n  secret-key: $2a$10$abcdefghijklmnopqrstuuuuuuuuuuuuuuuuuuuuuuuuuuuuu\n";
        let document = serde_norway::from_str::<serde_norway::Value>(input).unwrap();
        let core_settings = core_config_settings_from_value(&document).unwrap();

        assert!(core_settings.management_secret_key.is_none());
        assert!(!core_settings.management_secret_configured);
    }

    #[test]
    fn runtime_network_patch_preserves_comments_and_other_settings() {
        let config = GuiConfigFile {
            port: 9527,
            allow_lan: true,
            run_on_startup: false,
            ..GuiConfigFile::default()
        };
        let input = "# Bind address\nhost: 127.0.0.1 # local only\n\n# Service port\nport: 8317 # default\ndebug: true\n";
        let updated = patch_core_network_yaml(input, &config)
            .unwrap()
            .expect("network settings should change");

        assert_eq!(
            updated,
            "# Bind address\nhost: 0.0.0.0 # local only\n\n# Service port\nport: 9527 # default\ndebug: true\n"
        );
        assert!(updated.contains("# Bind address"));
        assert!(updated.contains("# local only"));
        assert!(updated.contains("# Service port"));
        assert!(updated.contains("# default"));
        assert!(updated.contains("debug: true"));

        let document = serde_norway::from_str::<serde_norway::Value>(&updated).unwrap();
        assert_eq!(
            document["host"],
            serde_norway::Value::String("0.0.0.0".to_string())
        );
        assert_eq!(document["port"], serde_norway::to_value(9527_u16).unwrap());
    }

    #[test]
    fn runtime_network_patch_skips_unchanged_yaml() {
        let config = GuiConfigFile::default();
        let input = "host: 127.0.0.1\nport: 8317\n";

        assert!(patch_core_network_yaml(input, &config).unwrap().is_none());
    }

    #[test]
    fn core_config_controls_preserve_comments_and_unrelated_values() {
        let input = "# Client authentication\napi-keys:\n  - old-key\n\n# Plugin runtime\nplugins:\n  enabled: false # global switch\n  dir: plugins\n\n# Credential routing\nrouting:\n  strategy: round-robin # current strategy\n  session-affinity: true\n\ndebug: true # untouched\n";
        let mut document = yaml_serde_edit::YamlValue::parse(input).unwrap();
        let mut updated = document.get().clone();

        set_core_api_keys(
            &mut updated,
            vec!["old-key".to_string(), "new-key".to_string()],
        )
        .unwrap();
        set_nested_yaml_value(&mut updated, &["plugins", "enabled"], true).unwrap();
        set_nested_yaml_value(
            &mut updated,
            &["routing", "strategy"],
            "fill-first".to_string(),
        )
        .unwrap();
        document.set(updated);

        let rendered = document.get_string();
        assert!(rendered.contains("# Client authentication"));
        assert!(rendered.contains("# Plugin runtime"));
        assert!(rendered.contains("# global switch"));
        assert!(rendered.contains("# Credential routing"));
        assert!(rendered.contains("# current strategy"));
        assert!(rendered.contains("debug: true # untouched"));

        let settings = core_config_settings_from_value(document.get()).unwrap();
        assert_eq!(settings.api_keys, vec!["old-key", "new-key"]);
        assert!(settings.plugins_enabled);
        assert_eq!(settings.routing_strategy, "fill-first");
        assert_eq!(document.get()["plugins"]["dir"], "plugins");
        assert_eq!(document.get()["routing"]["session-affinity"], true);
    }

    #[test]
    fn yaml_edit_runtime_patches_supported_fields_without_reflowing_yaml() {
        let input = "# Client authentication\napi-keys:\n  - old-key\n\n# Plugin runtime\nplugins:\n  enabled: false # global switch\n  dir: plugins\n\n# Credential routing\nrouting:\n  strategy: round-robin # current strategy\n  session-affinity: true\n\ndebug: true # untouched\n";
        let file = input.parse::<yaml_edit::YamlFile>().unwrap();
        let document = file.document().unwrap();

        assert!(set_yaml_edit_nested_value(
            &document, "plugins", "enabled", true
        ));
        assert!(set_yaml_edit_nested_value(
            &document,
            "routing",
            "strategy",
            "fill-first".to_string()
        ));

        let rendered = patch_core_api_keys_yaml(
            &file.to_string(),
            &["new-key".to_string(), "backup-key".to_string()],
        )
        .unwrap();
        assert!(rendered.contains("# Client authentication"));
        assert!(rendered.contains("# Plugin runtime"));
        assert!(rendered.contains("# global switch"));
        assert!(rendered.contains("# Credential routing"));
        assert!(rendered.contains("# current strategy"));
        assert!(rendered.contains("debug: true # untouched"));
        assert!(rendered.contains("dir: plugins"));
        assert!(rendered.contains("session-affinity: true"));

        let settings =
            core_config_settings_from_value(&serde_norway::from_str(&rendered).unwrap()).unwrap();
        assert_eq!(settings.api_keys, vec!["new-key", "backup-key"]);
        assert!(settings.plugins_enabled);
        assert_eq!(settings.routing_strategy, "fill-first");
    }

    #[test]
    fn yaml_edit_runtime_patch_removes_empty_keys_and_skips_unsupported_sections() {
        let input = "# Client authentication\napi-keys:\n  - old-key\nplugins:\n  enabled: true\nrouting:\n  strategy: fill-first\n";
        let rendered = patch_core_api_keys_yaml(input, &[]).unwrap();
        let parsed = serde_norway::from_str::<serde_norway::Value>(&rendered).unwrap();
        let root = parsed.as_mapping().unwrap();
        assert!(yaml_mapping_value(root, "api-keys").is_none(), "{rendered}");
        assert_eq!(
            core_config_settings_from_value(&parsed).unwrap().api_keys,
            Vec::<String>::new()
        );

        let missing_api_keys = "host: 127.0.0.1\nport: 8317\n";
        let rendered = patch_core_api_keys_yaml(
            missing_api_keys,
            &["new-key".to_string(), "backup-key".to_string()],
        )
        .unwrap();
        let settings =
            core_config_settings_from_value(&serde_norway::from_str(&rendered).unwrap()).unwrap();
        assert_eq!(settings.api_keys, vec!["new-key", "backup-key"]);
        assert!(rendered.contains("host: 127.0.0.1"));
        assert!(rendered.contains("port: 8317"));

        // Nested plugin/routing sections are still optional for comment-preserving
        // runtime patches; missing maps remain unsupported and stay untouched.
        let unsupported = "host: 127.0.0.1\nport: 8317\n";
        let file = unsupported.parse::<yaml_edit::YamlFile>().unwrap();
        let document = file.document().unwrap();
        assert!(!set_yaml_edit_nested_value(
            &document, "plugins", "enabled", true
        ));
        assert!(!set_yaml_edit_nested_value(
            &document,
            "routing",
            "strategy",
            "fill-first".to_string()
        ));
        assert_eq!(file.to_string(), unsupported);
    }

    #[test]
    fn yaml_edit_runtime_patch_recreates_api_keys_after_delete_all() {
        let input = "# Client authentication\napi-keys:\n  - old-key\nplugins:\n  enabled: true\n";
        let cleared = patch_core_api_keys_yaml(input, &[]).unwrap();
        let rendered = patch_core_api_keys_yaml(&cleared, &["restored-key".to_string()]).unwrap();
        assert!(rendered.contains("# Client authentication"), "{rendered}");
        let settings =
            core_config_settings_from_value(&serde_norway::from_str(&rendered).unwrap()).unwrap();
        assert_eq!(settings.api_keys, vec!["restored-key"]);
    }

    #[test]
    fn yaml_edit_runtime_patch_adds_api_keys_to_core_style_config() {
        let input = "host: 127.0.0.1\nremote-management:\n# nested setting comment\n  allow-remote: false\nauth-dir: /tmp/oauth\n# API keys for authentication\n# Enable debug logging\ndebug: false\n\n# Optional payload configuration\n# payload:\n#   filter:\n#     - models:\n#         - name: \"gemini-2.5-pro\"\n#       params:\n#         - \"generationConfig.responseJsonSchema\"\n";
        let rendered =
            patch_core_api_keys_yaml(input, &["new-key".to_string(), "backup-key".to_string()])
                .unwrap();
        let parsed = serde_norway::from_str::<serde_norway::Value>(&rendered)
            .unwrap_or_else(|error| panic!("invalid YAML: {error}\n{rendered}"));
        let settings = core_config_settings_from_value(&parsed).unwrap();
        assert_eq!(settings.api_keys, vec!["new-key", "backup-key"]);
        assert!(rendered.contains("# Optional payload configuration"));
        assert!(rendered.contains("generationConfig.responseJsonSchema"));
        assert!(
            rendered.find("auth-dir: /tmp/oauth").unwrap() < rendered.find("api-keys:").unwrap()
        );
        assert!(rendered.find("api-keys:").unwrap() < rendered.find("debug: false").unwrap());
    }

    #[test]
    fn yaml_edit_runtime_patch_updates_existing_real_core_config() {
        let input = "host: 0.0.0.0\nremote-management:\n# nested comment\n  allow-remote: false\nauth-dir: /tmp/oauth\n# API keys for authentication\napi-keys:\n  - '123456'\n# Enable debug logging\ndebug: false\n\n# payload:\n#   filter:\n#     - models:\n#         - name: gemini\n";
        let rendered =
            patch_core_api_keys_yaml(input, &[DEFAULT_API_KEY.to_string(), "new-key".to_string()])
                .unwrap();
        let parsed = serde_norway::from_str::<serde_norway::Value>(&rendered)
            .unwrap_or_else(|error| panic!("invalid YAML: {error}\n{rendered}"));
        assert_eq!(
            core_config_settings_from_value(&parsed).unwrap().api_keys,
            vec![DEFAULT_API_KEY, "new-key"]
        );
    }

    #[test]
    fn yaml_edit_runtime_patch_migrates_legacy_api_key_entries() {
        let input = "auth:\n  providers:\n    config-api-key:\n      api-key-entries:\n        - api-key: first-key\n        - key: second-key\nplugins:\n  enabled: false\n";
        let rendered = patch_core_api_keys_yaml(input, &["migrated-key".to_string()]).unwrap();
        let parsed = serde_norway::from_str::<serde_norway::Value>(&rendered).unwrap();
        let settings = core_config_settings_from_value(&parsed).unwrap();
        assert_eq!(settings.api_keys, vec!["migrated-key"]);
        assert!(
            nested_yaml_value(
                parsed.as_mapping().unwrap(),
                &["auth", "providers", "config-api-key", "api-key-entries"]
            )
            .is_none(),
            "{rendered}"
        );
    }

    #[test]
    fn core_config_reads_legacy_api_key_entries() {
        let input = "auth:\n  providers:\n    config-api-key:\n      api-key-entries:\n        - api-key: first-key\n        - key: second-key\nplugins:\n  enabled: false\nrouting:\n  strategy: round-robin\n";
        let document = serde_norway::from_str::<serde_norway::Value>(input).unwrap();
        let settings = core_config_settings_from_value(&document).unwrap();

        assert_eq!(settings.api_keys, vec!["first-key", "second-key"]);
        assert!(!settings.plugins_enabled);
        assert_eq!(settings.routing_strategy, "round-robin");
    }

    #[test]
    fn core_config_validates_keys_and_routing_strategy() {
        assert!(validate_core_api_key("sk-valid_123").is_ok());
        assert!(validate_core_api_key("").is_err());
        assert!(validate_core_api_key("contains space").is_err());
        assert!(validate_routing_strategy("round-robin").is_ok());
        assert!(validate_routing_strategy("fill-first").is_ok());
        assert!(validate_routing_strategy("random").is_err());
    }

    #[test]
    fn unchanged_yaml_is_not_written_again() {
        let path = std::env::temp_dir().join(format!(
            "cpa-gui-unchanged-yaml-{}-{}.yaml",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let content = "host: 127.0.0.1\nport: 8317\n";
        fs::write(&path, content).unwrap();

        assert!(!write_yaml_if_changed(&path, content).unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), content);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn startup_merge_uses_template_and_preserves_current_values() {
        let template = "# Current release template\nhost: \"\" # template bind address\nport: 8317\n\n# Client authentication\napi-keys:\n  - template-key\n\n# Plugin runtime\nplugins:\n  enabled: false # plugin switch\n\n# Credential routing\nrouting:\n  strategy: round-robin # routing switch\n\n# New release option\nnew-option: true\nnested:\n  # Nested template comment\n  keep: template\n  added: from-template\nlist:\n  - template-item\n";
        let current = "host: 127.0.0.1\nport: 9000\nnested:\n  keep: current\n  current-only: retained\nlist:\n  - current-a\n  - current-b\nextra: true\n";
        let config = GuiConfigFile {
            port: 9527,
            allow_lan: true,
            run_on_startup: false,
            auth_dir: path_to_string(&fixed_oauth_dir().unwrap()),
            api_keys: vec![
                built_in_api_key_entry(),
                GuiApiKeyEntry {
                    key: "gui-key".to_string(),
                    remark: "测试密钥".to_string(),
                },
            ],
            management_secret_key: String::new(),
            plugins_enabled: true,
            routing_strategy: "fill-first".to_string(),
        };
        let merged = merge_core_config_yaml(template, Some(current), &config).unwrap();

        assert!(merged.contains("# Current release template"));
        assert!(merged.contains("# template bind address"), "{merged}");
        assert!(merged.contains("# New release option"));
        assert!(merged.contains("# Nested template comment"));

        let document = serde_norway::from_str::<serde_norway::Value>(&merged).unwrap();
        assert_eq!(
            document["host"],
            serde_norway::Value::String("0.0.0.0".to_string())
        );
        assert_eq!(document["port"], serde_norway::to_value(9527_u16).unwrap());
        assert_eq!(document["api-keys"][0], DEFAULT_API_KEY);
        assert_eq!(document["api-keys"][1], "gui-key");
        assert_eq!(document["plugins"]["enabled"], true, "{merged}");
        assert_eq!(document["routing"]["strategy"], "fill-first");
        assert_eq!(document["new-option"], serde_norway::Value::Bool(true));
        assert_eq!(
            document["nested"]["keep"],
            serde_norway::Value::String("current".to_string())
        );
        assert_eq!(
            document["nested"]["added"],
            serde_norway::Value::String("from-template".to_string())
        );
        assert_eq!(
            document["nested"]["current-only"],
            serde_norway::Value::String("retained".to_string())
        );
        assert_eq!(document["extra"], serde_norway::Value::Bool(true));
        assert_eq!(
            document["list"],
            serde_norway::Value::Sequence(vec![
                serde_norway::Value::String("current-a".to_string()),
                serde_norway::Value::String("current-b".to_string()),
            ])
        );
    }

    #[test]
    fn startup_merge_without_current_config_uses_gui_defaults() {
        let template = "# Template\nhost: \"\"\nport: 9000\napi-keys:\n  - template-key\nplugins:\n  enabled: true\nrouting:\n  strategy: fill-first\ndebug: false\n";
        let merged = merge_core_config_yaml(template, None, &GuiConfigFile::default()).unwrap();
        let document = serde_norway::from_str::<serde_norway::Value>(&merged).unwrap();

        assert!(merged.contains("# Template"));
        assert_eq!(
            document["host"],
            serde_norway::Value::String("127.0.0.1".to_string())
        );
        assert_eq!(document["port"], serde_norway::to_value(8317_u16).unwrap());
        assert_eq!(document["debug"], serde_norway::Value::Bool(false));
        assert_eq!(document["api-keys"][0], DEFAULT_API_KEY, "{merged}");
        assert_eq!(document["plugins"]["enabled"], false);
        assert_eq!(document["routing"]["strategy"], "round-robin");
    }

    #[test]
    fn release_page_assets_parse_download_links_and_sha256() {
        let html = r#"
          <li><a href="/router-for-me/CLIProxyAPI/releases/download/v1.2.3/checksums.txt">checksums.txt</a></li>
          <li><a href="/router-for-me/CLIProxyAPI/releases/download/v1.2.3/CLIProxyAPI_1.2.3_linux_amd64.tar.gz">asset</a>
            <span>sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</span>
          </li>
        "#;

        let assets = parse_release_assets(html);
        assert_eq!(assets.len(), 2);
        assert_eq!(assets[1].name, "CLIProxyAPI_1.2.3_linux_amd64.tar.gz");
        assert_eq!(
            assets[1].digest.as_deref(),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert!(assets[1]
            .browser_download_url
            .ends_with("/releases/download/v1.2.3/CLIProxyAPI_1.2.3_linux_amd64.tar.gz"));
    }
}
