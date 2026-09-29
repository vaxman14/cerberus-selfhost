using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Cerberus.Desktop;

internal sealed class RuntimeSupervisor : IDisposable
{
    private readonly List<Process> _children = [];
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(3) };
    private bool _disposed;

    public event Action<string>? StatusChanged;
    public string DataRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Cerberus");
    public string LogRoot => Path.Combine(DataRoot, "logs");
    private string RuntimeRoot => Path.Combine(AppContext.BaseDirectory, "runtime");
    private string ToolsRoot => Path.Combine(RuntimeRoot, "tools");

    public async Task<Uri> StartAsync()
    {
        Directory.CreateDirectory(DataRoot);
        Directory.CreateDirectory(LogRoot);
        var secretsRoot = Path.Combine(DataRoot, "secrets");
        Directory.CreateDirectory(secretsRoot);
        RestrictToCurrentUser(secretsRoot);

        var masterKey = EnsureSecret(Path.Combine(secretsRoot, "master_key"));
        var toolsToken = EnsureSecret(Path.Combine(secretsRoot, "tools_token"));
        var zapKey = EnsureSecret(Path.Combine(secretsRoot, "zap_api_key"));

        var backend = RequireFile(Path.Combine(RuntimeRoot, "cerberus-api", "cerberus-api.exe"));
        var toolsApi = RequireFile(Path.Combine(RuntimeRoot, "cerberus-tools", "cerberus-tools.exe"));
        var nuclei = RequireFile(Path.Combine(ToolsRoot, "nuclei.exe"));
        var templates = RequireDirectory(Path.Combine(ToolsRoot, "nuclei-templates"));
        var python = RequireFile(Path.Combine(ToolsRoot, "python", "python.exe"));
        var sqlmap = RequireFile(Path.Combine(ToolsRoot, "sqlmap", "sqlmap.py"));
        var node = RequireFile(Path.Combine(ToolsRoot, "node", "node.exe"));
        var lighthouse = RequireFile(Path.Combine(ToolsRoot, "node-packages", "node_modules", "lighthouse", "cli", "index.js"));
        var codex = RequireFile(Path.Combine(ToolsRoot, "node-packages", "node_modules", ".bin", "codex.cmd"));
        var java = RequireFile(Path.Combine(ToolsRoot, "jre", "bin", "java.exe"));
        var zapJar = RequireFile(Path.Combine(ToolsRoot, "zap", "zap-2.17.0.jar"));
        var chrome = FindChromium();

        var toolsPort = FreePort();
        var zapPort = FreePort();
        var apiPort = FreePort();

        StatusChanged?.Invoke("Starting OWASP ZAP…");
        var zapSecret = File.ReadAllText(zapKey).Trim();
        StartProcess("zap", java,
            $"-Xmx1536m -Djava.awt.headless=true -jar {Quote(zapJar)} -daemon -silent " +
            $"-host 127.0.0.1 -port {zapPort} -dir {Quote(Path.Combine(DataRoot, "zap"))} " +
            $"-config api.disablekey=false -config api.key={zapSecret} " +
            "-config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false");
        await WaitForAsync($"http://127.0.0.1:{zapPort}/JSON/core/view/version/?apikey={Uri.EscapeDataString(zapSecret)}", "OWASP ZAP", 90);

        StatusChanged?.Invoke("Starting Lighthouse, Nuclei, and sqlmap worker…");
        var toolEnvironment = new Dictionary<string, string>
        {
            ["CERBERUS_TOOLS_HOST"] = "127.0.0.1",
            ["CERBERUS_TOOLS_PORT"] = toolsPort.ToString(),
            ["CERBERUS_TOOLS_TOKEN_FILE"] = toolsToken,
            ["CERBERUS_LIGHTHOUSE_BIN"] = node,
            ["CERBERUS_LIGHTHOUSE_SCRIPT"] = lighthouse,
            ["CERBERUS_CHROME_PATH"] = chrome,
            ["CERBERUS_NUCLEI_BIN"] = nuclei,
            ["CERBERUS_NUCLEI_TEMPLATES"] = templates,
            ["CERBERUS_PYTHON_BIN"] = python,
            ["CERBERUS_SQLMAP_PATH"] = sqlmap,
            ["CERBERUS_SQLMAP_OUTPUT_DIR"] = Path.Combine(DataRoot, "sqlmap"),
            ["CERBERUS_TOOL_HOME"] = Path.Combine(DataRoot, "tools-home"),
        };
        StartProcess("tools", toolsApi, "", toolEnvironment);
        await WaitForAsync($"http://127.0.0.1:{toolsPort}/health", "scanner worker", 30);

        StatusChanged?.Invoke("Starting Cerberus…");
        var apiEnvironment = new Dictionary<string, string>
        {
            ["CERBERUS_API_HOST"] = "127.0.0.1",
            ["CERBERUS_API_PORT"] = apiPort.ToString(),
            ["CERBERUS_AUTH_MODE"] = "local",
            ["CERBERUS_COOKIE_SECURE"] = "false",
            ["CERBERUS_DB_PATH"] = Path.Combine(DataRoot, "cerberus.db"),
            ["CERBERUS_DATA_DIR"] = DataRoot,
            ["CERBERUS_CODEX_HOME"] = Path.Combine(DataRoot, "codex"),
            ["CERBERUS_CODEX_BIN"] = codex,
            ["CERBERUS_MASTER_KEY_FILE"] = masterKey,
            ["CERBERUS_TOOLS_URL"] = $"http://127.0.0.1:{toolsPort}",
            ["CERBERUS_TOOLS_TOKEN_FILE"] = toolsToken,
            ["CERBERUS_ENABLE_ACTIVE_SCANS"] = "true",
            ["ZAP_API"] = $"http://127.0.0.1:{zapPort}",
            ["ZAP_API_KEY_FILE"] = zapKey,
            ["CERBERUS_DESKTOP"] = "true",
            ["PATH"] = string.Join(Path.PathSeparator,
                Path.Combine(ToolsRoot, "node"),
                Path.Combine(ToolsRoot, "node-packages", "node_modules", ".bin"),
                Environment.GetEnvironmentVariable("PATH") ?? ""),
        };
        StartProcess("api", backend, "", apiEnvironment);
        var uri = new Uri($"http://127.0.0.1:{apiPort}/");
        await WaitForAsync(new Uri(uri, "health").ToString(), "Cerberus API", 30);
        StatusChanged?.Invoke("Ready");
        return uri;
    }

    public async Task ExportBackupAsync(string destination)
    {
        var executable = RequireFile(Path.Combine(RuntimeRoot, "cerberus-backupctl", "cerberus-backupctl.exe"));
        var temporary = destination + ".pending";
        try
        {
            await RunUtilityAsync(executable, "export", new Dictionary<string, string>
            {
                ["CERBERUS_DB_PATH"] = Path.Combine(DataRoot, "cerberus.db"),
                ["CERBERUS_MASTER_KEY_FILE"] = Path.Combine(DataRoot, "secrets", "master_key"),
            }, binaryOutput: temporary);
            await RunUtilityAsync(executable, $"verify {Quote(temporary)}", null);
            File.Move(temporary, destination, true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public async Task ResetPasswordAsync(string username, string password)
    {
        var executable = RequireFile(Path.Combine(RuntimeRoot, "cerberus-userctl", "cerberus-userctl.exe"));
        var passwordFile = Path.Combine(DataRoot, "secrets", $"password-{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(passwordFile, password);
            await RunUtilityAsync(executable,
                $"reset-password --username {Quote(username)} --password-file {Quote(passwordFile)}",
                new Dictionary<string, string>
                {
                    ["CERBERUS_DB_PATH"] = Path.Combine(DataRoot, "cerberus.db"),
                });
        }
        finally
        {
            if (File.Exists(passwordFile)) File.Delete(passwordFile);
        }
    }

    private static async Task RunUtilityAsync(string executable, string arguments,
        IReadOnlyDictionary<string, string>? environment, string? binaryOutput = null)
    {
        var start = new ProcessStartInfo(executable, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (environment is not null)
            foreach (var pair in environment)
                start.Environment[pair.Key] = pair.Value;
        using var process = Process.Start(start)
            ?? throw new InvalidOperationException("Cerberus utility could not start.");
        Task outputTask;
        if (binaryOutput is not null)
        {
            await using var output = new FileStream(binaryOutput, FileMode.Create, FileAccess.Write,
                FileShare.None, 81920, useAsync: true);
            outputTask = process.StandardOutput.BaseStream.CopyToAsync(output);
            var errorTask = process.StandardError.ReadToEndAsync();
            await Task.WhenAll(outputTask, process.WaitForExitAsync());
            var error = await errorTask;
            if (process.ExitCode != 0)
                throw new InvalidOperationException(error.Trim());
            return;
        }
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (process.ExitCode != 0)
            throw new InvalidOperationException((stderr + Environment.NewLine + stdout).Trim());
    }

    private Process StartProcess(string name, string executable, string arguments,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var start = new ProcessStartInfo(executable, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(executable)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        if (environment is not null)
            foreach (var pair in environment)
                start.Environment[pair.Key] = pair.Value;

        var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        var logPath = Path.Combine(LogRoot, $"{name}.log");
        process.OutputDataReceived += (_, args) => AppendLog(logPath, args.Data);
        process.ErrorDataReceived += (_, args) => AppendLog(logPath, args.Data);
        if (!process.Start())
            throw new InvalidOperationException($"Could not start {name}.");
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        _children.Add(process);
        return process;
    }

    private async Task WaitForAsync(string address, string service, int seconds)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        Exception? lastError = null;
        while (DateTime.UtcNow < deadline)
        {
            var exited = _children.LastOrDefault()?.HasExited == true;
            if (exited)
                throw new InvalidOperationException($"{service} exited during startup. Open logs for details.");
            try
            {
                using var response = await _http.GetAsync(address);
                if (response.StatusCode == HttpStatusCode.OK)
                    return;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                lastError = ex;
            }
            await Task.Delay(500);
        }
        throw new TimeoutException($"{service} did not become ready in {seconds} seconds: {lastError?.Message}");
    }

    private string FindChromium()
    {
        var bundled = Path.Combine(ToolsRoot, "chrome", "chrome.exe");
        if (File.Exists(bundled))
            return bundled;
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft", "Edge", "Application", "msedge.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Google", "Chrome", "Application", "chrome.exe"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "Application", "chrome.exe"),
        };
        return candidates.FirstOrDefault(File.Exists)
            ?? throw new FileNotFoundException("Lighthouse requires Microsoft Edge, Google Chrome, or the bundled Chromium runtime.");
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static string EnsureSecret(string path)
    {
        if (!File.Exists(path))
            File.WriteAllText(path, Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant());
        return path;
    }

    private static void RestrictToCurrentUser(string directory)
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid))
            return;
        using var process = Process.Start(new ProcessStartInfo("icacls.exe",
            $"{Quote(directory)} /inheritance:r /grant:r *{sid}:(OI)(CI)F")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        process?.WaitForExit(10_000);
        if (process is null || process.ExitCode != 0)
            throw new InvalidOperationException("Could not secure Cerberus's local secret directory.");
    }

    private static string RequireFile(string path) => File.Exists(path)
        ? path : throw new FileNotFoundException($"Required runtime file is missing: {path}");
    private static string RequireDirectory(string path) => Directory.Exists(path)
        ? path : throw new DirectoryNotFoundException($"Required runtime directory is missing: {path}");
    private static string Quote(string value) => $"\"{value.Replace("\"", "\\\"")}\"";

    private static readonly object LogLock = new();
    private static void AppendLog(string path, string? line)
    {
        if (line is null) return;
        lock (LogLock)
            File.AppendAllText(path, $"{DateTimeOffset.Now:O} {line}{Environment.NewLine}");
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        foreach (var process in _children.AsEnumerable().Reverse())
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) { }
            finally { process.Dispose(); }
        }
        _http.Dispose();
    }
}
