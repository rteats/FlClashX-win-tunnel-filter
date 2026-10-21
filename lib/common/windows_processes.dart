import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart';

import 'print.dart';
import 'windows_process_filter.dart';

class WindowsProcessCatalog {
  final Map<String, Uint8List> _iconCache = {};
  final Set<String> _missingIcons = {};
  List<String> _knownPaths = const [];
  Future<void>? _iconLoadFuture;

  Uint8List? getCachedExecutableIcon(String executablePath) =>
      _iconCache[executablePath.trim().toLowerCase()];

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

      final resultList = processes.values.toList()
        ..sort(
          (a, b) => (a['name'] ?? '').toLowerCase().compareTo(
                (b['name'] ?? '').toLowerCase(),
              ),
        );
      _knownPaths = resultList
          .map((process) => process['path'])
          .whereType<String>()
          .toList(growable: false);
      _iconLoadFuture = null;
      return resultList;
    } catch (error) {
      commonPrint.log('Windows process enumeration failed: $error');
      return [];
    }
  }

  Future<Uint8List?> getExecutableIcon(String executablePath) async {
    final path = executablePath.trim();
    if (path.isEmpty || isWindowsProcessPattern(path)) return null;

    final key = path.toLowerCase();
    final cached = _iconCache[key];
    if (cached != null) return cached;
    if (_missingIcons.contains(key)) return null;

    if (_knownPaths.any((item) => item.toLowerCase() == key)) {
      final pending = _iconLoadFuture ??= _loadKnownProcessIcons();
      try {
        await pending;
      } finally {
        if (identical(_iconLoadFuture, pending)) {
          _iconLoadFuture = null;
        }
      }
      final loaded = _iconCache[key];
      if (loaded != null) return loaded;
      if (_missingIcons.contains(key)) return null;
    }

    final extracted = await _extractExecutableIcons([path]);
    if (extracted == null) return null;
    _storeExtractedIcons([path], extracted);
    return _iconCache[key];
  }

  Future<void> _loadKnownProcessIcons() async {
    final paths = _knownPaths
        .where((path) {
          final key = path.toLowerCase();
          return !_iconCache.containsKey(key) && !_missingIcons.contains(key);
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
      final key = entry.key.toLowerCase();
      _iconCache[key] = entry.value;
      _missingIcons.remove(key);
    }
    for (final path in requestedPaths) {
      final key = path.toLowerCase();
      if (!_iconCache.containsKey(key)) {
        _missingIcons.add(key);
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

    final payload = base64Encode(utf8.encode(jsonEncode(executablePaths)));

    try {
      final result = await Process.run(
        'powershell.exe',
        ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
        stdoutEncoding: utf8,
        stderrEncoding: utf8,
        environment: {'FLCLASHX_ICON_PATHS': payload},
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
        } catch (_) {}
      }
      return icons;
    } catch (error) {
      commonPrint.log('Windows executable icon extraction failed: $error');
      return null;
    }
  }
}

final windowsProcessCatalog =
    Platform.isWindows ? WindowsProcessCatalog() : null;
