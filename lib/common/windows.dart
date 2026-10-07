import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flclashx/common/common.dart';
import 'package:flclashx/enum/enum.dart';
import 'package:path/path.dart';
import 'package:win32/win32.dart';

class Windows {
  factory Windows() {
    _instance ??= Windows._internal();
    return _instance!;
  }

  Windows._internal() {
    _shell32 = DynamicLibrary.open('shell32.dll');
    try {
      _uxtheme = DynamicLibrary.open('uxtheme.dll');
    } catch (e) {
      // Ignore if uxtheme.dll is not available
    }
  }
  static Windows? _instance;
  late DynamicLibrary _shell32;
  late DynamicLibrary _uxtheme;

  final Map<String, Uint8List> _processIconCache = {};
  final Set<String> _missingProcessIcons = {};
  List<String> _knownProcessPaths = const [];
  Future<void>? _iconLoadFuture;

  bool _readThemeValue(String valueName) {
    try {
      return using((arena) {
        final keyPath =
            r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'
                .toNativeUtf16(allocator: arena);
        final valueNamePtr = valueName.toNativeUtf16(allocator: arena);
        final phkResult = arena<HKEY>();

        var result = RegOpenKeyEx(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, phkResult);
        if (result != ERROR_SUCCESS) return false;

        final hKey = phkResult.value;
        final data = arena<DWORD>();
        final dataSize = arena<DWORD>();
        dataSize.value = sizeOf<DWORD>();

        result = RegQueryValueEx(hKey, valueNamePtr, nullptr, nullptr, data.cast(), dataSize);
        RegCloseKey(hKey);
        if (result != ERROR_SUCCESS) return false;

        return data.value == 0;
      });
    } catch (e) {
      return false;
    }
  }

  bool isDarkMode() => _readThemeValue('AppsUseLightTheme');

  bool isSystemDarkMode() => _readThemeValue('SystemUsesLightTheme');

  void enableDarkModeForApp() {
    try {
      final isDark = isDarkMode();
      if (!isDark) return;

      try {
        final kernel32 = DynamicLibrary.open('kernel32.dll');
        final moduleName = 'uxtheme.dll'.toNativeUtf16();

        final getProcAddressFunc = kernel32.lookupFunction<
            IntPtr Function(IntPtr hModule, Pointer<Utf8> lpProcName),
            int Function(
                int hModule, Pointer<Utf8> lpProcName)>('GetProcAddress');

        final getModuleHandleFunc = kernel32.lookupFunction<
            IntPtr Function(Pointer<Utf16> lpModuleName),
            int Function(Pointer<Utf16> lpModuleName)>('GetModuleHandleW');

        final uxthemeHandle = getModuleHandleFunc(moduleName);
        calloc.free(moduleName);

        if (uxthemeHandle != 0) {
          final ordinal135 = Pointer<Utf8>.fromAddress(135);
          final setPreferredAppModePtr =
              getProcAddressFunc(uxthemeHandle, ordinal135);

          if (setPreferredAppModePtr != 0) {
            final setPreferredAppMode =
                Pointer<NativeFunction<Int32 Function(Int32)>>.fromAddress(
                        setPreferredAppModePtr)
                    .asFunction<int Function(int)>();
            setPreferredAppMode(1);
          } else {
            final ordinal133 = Pointer<Utf8>.fromAddress(133);
            final allowDarkModePtr =
                getProcAddressFunc(uxthemeHandle, ordinal133);

            if (allowDarkModePtr != 0) {
              final allowDarkModeForApp =
                  Pointer<NativeFunction<Int32 Function(Int32)>>.fromAddress(
                          allowDarkModePtr)
                      .asFunction<int Function(int)>();
              allowDarkModeForApp(1); // TRUE
            }
          }

          // Ordinal 136 = FlushMenuThemes
          final ordinal136 = Pointer<Utf8>.fromAddress(136);
          final flushMenuThemesPtr =
              getProcAddressFunc(uxthemeHandle, ordinal136);

          if (flushMenuThemesPtr != 0) {
            final flushMenuThemes =
                Pointer<NativeFunction<Void Function()>>.fromAddress(
                        flushMenuThemesPtr)
                    .asFunction<void Function()>();
            flushMenuThemes();
          }
        }
      } catch (_) {
      // FFI call may fail on unsupported Windows versions
    }
    } catch (_) {
      // FFI call may fail on unsupported Windows versions
    }
  }

  void applyDarkModeToMenu(int hwnd) {
    if (hwnd == 0) return;

    try {
      final isDark = isDarkMode();

      final themeName = isDark ? 'DarkMode_Explorer'.toNativeUtf16() : nullptr;

      try {
        final setWindowTheme = _uxtheme.lookupFunction<
            Int32 Function(IntPtr hwnd, Pointer<Utf16> pszSubAppName,
                Pointer<Utf16> pszSubIdList),
            int Function(int hwnd, Pointer<Utf16> pszSubAppName,
                Pointer<Utf16> pszSubIdList)>('SetWindowTheme');

        setWindowTheme(hwnd, themeName, nullptr);
      } catch (_) {
      // FFI call may fail on unsupported Windows versions
    }

      if (themeName != nullptr) {
        calloc.free(themeName);
      }
    } catch (_) {
      // FFI call may fail on unsupported Windows versions
    }
  }

  bool runas(String command, String arguments) {
    final commandPtr = command.toNativeUtf16();
    final argumentsPtr = arguments.toNativeUtf16();
    final operationPtr = 'runas'.toNativeUtf16();

    final shellExecute = _shell32.lookupFunction<
        Int32 Function(
            Pointer<Utf16> hwnd,
            Pointer<Utf16> lpOperation,
            Pointer<Utf16> lpFile,
            Pointer<Utf16> lpParameters,
            Pointer<Utf16> lpDirectory,
            Int32 nShowCmd),
        int Function(
            Pointer<Utf16> hwnd,
            Pointer<Utf16> lpOperation,
            Pointer<Utf16> lpFile,
            Pointer<Utf16> lpParameters,
            Pointer<Utf16> lpDirectory,
            int nShowCmd)>('ShellExecuteW');

    final result = shellExecute(
      nullptr,
      operationPtr,
      commandPtr,
      argumentsPtr,
      nullptr,
      1,
    );

    calloc.free(commandPtr);
    calloc.free(argumentsPtr);
    calloc.free(operationPtr);

    commonPrint.log("windows runas: $command $arguments resultCode:$result");

    if (result < 42) {
      return false;
    }
    return true;
  }

  /// Returns currently running Win32 processes whose executable path can be
  /// resolved without elevation. The full path is used as the process-filter ID.
  Future<List<Map<String, String>>> getRunningProcesses() async {
    const script = r'''
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
Get-CimInstance Win32_Process |
  Where-Object { $_.ExecutablePath } |
  ForEach-Object {
    [PSCustomObject]@{
      name = $_.Name
      path = $_.ExecutablePath
    }
  } |
  Sort-Object path -Unique |
  ConvertTo-Json -Compress
''';

    try {
      final result = await Process.run(
        'powershell.exe',
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
      );
      if (result.exitCode != 0) {
        commonPrint.log(
          'Windows process enumeration failed: ${result.stderr}',
        );
        return [];
      }

      final output = result.stdout.toString().trim();
      if (output.isEmpty) return [];

      final decoded = jsonDecode(output);
      final rows = decoded is List ? decoded : [decoded];
      final processes = <String, Map<String, String>>{};

      for (final row in rows) {
        if (row is! Map) continue;
        final path = row['path']?.toString().trim();
        if (path == null || path.isEmpty) continue;
        final name = row['name']?.toString().trim();
        processes.putIfAbsent(
          path.toLowerCase(),
          () => {
            'name': (name == null || name.isEmpty) ? basename(path) : name,
            'path': path,
          },
        );
      }

      final resultList = processes.values.toList();
      resultList.sort(
        (a, b) => (a['name'] ?? '').toLowerCase().compareTo(
              (b['name'] ?? '').toLowerCase(),
            ),
      );
      _knownProcessPaths = resultList
          .map((process) => process['path'])
          .whereType<String>()
          .toList(growable: false);
      _iconLoadFuture = null;
      return resultList;
    } catch (e) {
      commonPrint.log('Windows process enumeration failed: $e');
      return [];
    }
  }

  /// Returns the executable's associated Windows icon as PNG bytes.
  ///
  /// Running-process icons are extracted in one PowerShell batch and cached.
  /// A previously selected executable that is no longer running falls back to
  /// a single-path extraction, also cached.
  Future<Uint8List?> getExecutableIcon(String executablePath) async {
    final path = executablePath.trim();
    if (path.isEmpty) return null;

    final key = path.toLowerCase();
    final cached = _processIconCache[key];
    if (cached != null) return cached;
    if (_missingProcessIcons.contains(key)) return null;

    if (_knownProcessPaths.any((item) => item.toLowerCase() == key)) {
      final pending = _iconLoadFuture ??= _loadKnownProcessIcons();
      try {
        await pending;
      } finally {
        if (identical(_iconLoadFuture, pending)) {
          _iconLoadFuture = null;
        }
      }

      final loaded = _processIconCache[key];
      if (loaded != null) return loaded;
      if (_missingProcessIcons.contains(key)) return null;
    }

    final extracted = await _extractExecutableIcons([path]);
    if (extracted == null) return null;
    _storeExtractedIcons([path], extracted);
    return _processIconCache[key];
  }

  Future<void> _loadKnownProcessIcons() async {
    final paths = _knownProcessPaths
        .where((path) {
          final key = path.toLowerCase();
          return !_processIconCache.containsKey(key) &&
              !_missingProcessIcons.contains(key);
        })
        .toSet()
        .toList();

    if (paths.isEmpty) return;

    final extracted = await _extractExecutableIcons(paths);
    if (extracted == null) return;
    _storeExtractedIcons(paths, extracted);
  }

  void _storeExtractedIcons(
    List<String> requestedPaths,
    Map<String, Uint8List> extracted,
  ) {
    for (final entry in extracted.entries) {
      _processIconCache[entry.key.toLowerCase()] = entry.value;
      _missingProcessIcons.remove(entry.key.toLowerCase());
    }

    for (final path in requestedPaths) {
      final key = path.toLowerCase();
      if (!_processIconCache.containsKey(key)) {
        _missingProcessIcons.add(key);
      }
    }
  }

  Future<Map<String, Uint8List>?> _extractExecutableIcons(
    List<String> executablePaths,
  ) async {
    if (executablePaths.isEmpty) return {};

    const script = r'''
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
Add-Type -AssemblyName System.Drawing

$json = [System.Text.Encoding]::UTF8.GetString(
  [System.Convert]::FromBase64String($env:FLCLASHX_ICON_PATHS)
)
$paths = @($json | ConvertFrom-Json)

$result = foreach ($path in $paths) {
  $iconData = $null
  try {
    if (Test-Path -LiteralPath $path) {
      $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
      if ($null -ne $icon) {
        $bitmap = $icon.ToBitmap()
        $stream = New-Object System.IO.MemoryStream
        try {
          $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
          $iconData = [System.Convert]::ToBase64String($stream.ToArray())
        }
        finally {
          $stream.Dispose()
          $bitmap.Dispose()
          $icon.Dispose()
        }
      }
    }
  }
  catch {}

  [PSCustomObject]@{
    path = $path
    icon = $iconData
  }
}

$result | ConvertTo-Json -Compress
''';

    final payload = base64Encode(
      utf8.encode(jsonEncode(executablePaths)),
    );

    try {
      final result = await Process.run(
        'powershell.exe',
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
        environment: {
          'FLCLASHX_ICON_PATHS': payload,
        },
      );

      if (result.exitCode != 0) {
        commonPrint.log(
          'Windows executable icon extraction failed: ${result.stderr}',
        );
        return null;
      }

      final output = result.stdout.toString().trim();
      if (output.isEmpty) return {};

      final decoded = jsonDecode(output);
      final rows = decoded is List ? decoded : [decoded];
      final icons = <String, Uint8List>{};

      for (final row in rows) {
        if (row is! Map) continue;
        final path = row['path']?.toString().trim();
        final icon = row['icon']?.toString().trim();
        if (path == null ||
            path.isEmpty ||
            icon == null ||
            icon.isEmpty) {
          continue;
        }

        try {
          icons[path] = base64Decode(icon);
        } catch (_) {
          // Ignore a malformed icon and keep the generic fallback in the UI.
        }
      }

      return icons;
    } catch (e) {
      commonPrint.log('Windows executable icon extraction failed: $e');
      return null;
    }
  }

  Future<void> _killProcess(int port) async {
    final result = await Process.run('netstat', ['-ano']);
    final lines = result.stdout.toString().trim().split('\n');
    for (final line in lines) {
      if (!line.contains(":$port") || !line.contains("LISTENING")) {
        continue;
      }
      final parts = line.trim().split(RegExp(r'\s+'));
      final pid = int.tryParse(parts.last);
      if (pid != null) {
        await Process.run('taskkill', ['/PID', pid.toString(), '/F']);
      }
    }
  }

  Future<WindowsHelperServiceStatus> checkService() async {
    // final qcResult = await Process.run('sc', ['qc', appHelperService]);
    // final qcOutput = qcResult.stdout.toString();
    // if (qcResult.exitCode != 0 || !qcOutput.contains(appPath.helperPath)) {
    //   return WindowsHelperServiceStatus.none;
    // }
    final result = await Process.run('sc', ['query', appHelperService]);
    if (result.exitCode != 0) {
      return WindowsHelperServiceStatus.none;
    }
    final output = result.stdout.toString();
    if (output.contains("RUNNING") && await request.pingHelper()) {
      return WindowsHelperServiceStatus.running;
    }
    return WindowsHelperServiceStatus.presence;
  }

  /// Install the helper service (requires UAC elevation).
  /// This should only be called when the service is not installed.
  /// After installation, sets security descriptor to allow non-admin users
  /// to start/stop the service without UAC.
  Future<bool> installService() async {
    final status = await checkService();

    if (status == WindowsHelperServiceStatus.running) {
      return true;
    }

    await _killProcess(helperPort);

    final coreHash = await coreUpdater.calcCoreSha256();
    final command = [
      "/c",
      if (status == WindowsHelperServiceStatus.presence) ...[
        "sc",
        "delete",
        appHelperService,
        "&&",
      ],
      "sc",
      "create",
      appHelperService,
      'binPath= "${appPath.helperPath}"',
      'start= auto',
      "&&",
      "sc",
      "start",
      appHelperService,
      // Sync the helper's core allow-list while elevation is already granted,
      // so a previously updated core isn't refused by a stale hash.
      if (coreHash != null) ...[
        "&&",
        "echo",
        '$coreHash>',
        '"${appPath.allowedCoreHashPath}"',
      ],
    ].join(" ");

    final res = runas("cmd.exe", command);

    await Future.delayed(
      const Duration(milliseconds: 300),
    );

    return res;
  }

  /// Try to start an existing service without UAC.
  /// Returns true if the service was started successfully or is already running.
  /// Returns false if the service is not installed or failed to start.
  Future<bool> tryStartExistingService() async {
    final status = await checkService();

    if (status == WindowsHelperServiceStatus.running) {
      return true;
    }

    if (status == WindowsHelperServiceStatus.none) {
      return false;
    }

    // Service exists but not running - try to start it without elevation
    final result = await Process.run('sc', ['start', appHelperService]);

    if (result.exitCode == 0) {
      // Wait for service to fully start
      await Future.delayed(const Duration(milliseconds: 500));
      // Verify it's actually running and responding
      final newStatus = await checkService();
      return newStatus == WindowsHelperServiceStatus.running;
    }

    return false;
  }

  /// Register the service - will request UAC only if service is not installed.
  /// If the service is already installed, it will try to start it without UAC.
  Future<bool> registerService() async {
    // First, try to start existing service without UAC
    if (await tryStartExistingService()) {
      return true;
    }

    // Service not installed or couldn't start - need to install with UAC
    return installService();
  }

  Future<bool> startService() async {
    final status = await checkService();

    if (status == WindowsHelperServiceStatus.running) {
      return true;
    }

    if (status == WindowsHelperServiceStatus.none) {
      return false;
    }

    final result = await Process.run('sc', ['start', appHelperService]);

    if (result.exitCode == 0) {
      await Future.delayed(const Duration(milliseconds: 500));
      return true;
    }

    return false;
  }

  Future<bool> stopService() async {
    final status = await checkService();

    if (status == WindowsHelperServiceStatus.none) {
      return true;
    }

    final result = await Process.run('sc', ['stop', appHelperService]);

    if (result.exitCode == 0) {
      await Future.delayed(const Duration(milliseconds: 500));
      return true;
    }

    return false;
  }

  Future<bool> registerTask(String appName) async {
    final taskXml = '''
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Triggers>
    <LogonTrigger/>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"${Platform.resolvedExecutable}"</Command>
    </Exec>
  </Actions>
</Task>''';
    final taskPath = join(await appPath.tempPath, "task.xml");
    await File(taskPath).create(recursive: true);
    await File(taskPath)
        .writeAsBytes(taskXml.encodeUtf16LeWithBom, flush: true);
    final commandLine = [
      '/Create',
      '/TN',
      appName,
      '/XML',
      "%s",
      '/F',
    ].join(" ");
    return runas(
      'schtasks',
      commandLine.replaceFirst("%s", taskPath),
    );
  }
}

final windows = Platform.isWindows ? Windows() : null;
