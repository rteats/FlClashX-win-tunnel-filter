import 'package:fl_clash/enum/enum.dart';
import 'package:path/path.dart' as p;

const windowsProcessAccessConfigKey = '__flclashx_windows_process_access';

bool isWindowsProcessPattern(String value) =>
    value.contains('*') || value.contains('?');

String windowsProcessEntryLabel(String value) {
  final label = p.windows.basename(value.trim());
  return label.isEmpty ? value.trim() : label;
}

/// Applies Windows process-based access control to a Mihomo runtime config.
///
/// Exact paths use PROCESS-PATH. Entries containing `*` or `?` use Mihomo's
/// native PROCESS-PATH-WILDCARD matcher.
List<String> applyWindowsProcessAccessControl({
  required Map<String, dynamic> rawConfig,
  required bool enabled,
  required AccessControlMode accessMode,
  required List<String> selectedPaths,
  required Mode clashMode,
  required List<String> originalRules,
}) {
  final selected = selectedPaths
      .map((path) => path.trim())
      .where((path) => path.isNotEmpty)
      .toSet()
      .toList();

  if (!enabled || selected.isEmpty || clashMode == Mode.direct) {
    return List<String>.from(originalRules);
  }

  rawConfig['find-process-mode'] = FindProcessMode.always.name;
  final matchers = selected.map(_processMatcher).toList();

  if (clashMode == Mode.global) {
    // Global mode bypasses rules, so reproduce it in rule mode while inserting
    // the process access-control rules.
    rawConfig['mode'] = Mode.rule.name;
    if (accessMode == AccessControlMode.rejectSelected) {
      return [
        ...matchers.map((matcher) => '$matcher,DIRECT'),
        'MATCH,GLOBAL',
      ];
    }
    return [
      ...matchers.map((matcher) => '$matcher,GLOBAL'),
      'MATCH,DIRECT',
    ];
  }

  if (accessMode == AccessControlMode.rejectSelected) {
    return [
      ...matchers.map((matcher) => '$matcher,DIRECT'),
      ...originalRules,
    ];
  }

  // Whitelist mode lets selected processes continue through the original
  // profile rule tree and sends every other process DIRECT.
  final existingSubRules = rawConfig['sub-rules'];
  final subRules = <String, dynamic>{};
  if (existingSubRules is Map) {
    for (final entry in existingSubRules.entries) {
      subRules[entry.key.toString()] = entry.value;
    }
  }

  var key = '__flclashx_windows_access';
  var suffix = 1;
  while (subRules.containsKey(key)) {
    key = '__flclashx_windows_access_${suffix++}';
  }

  subRules[key] = List<String>.from(originalRules);
  rawConfig['sub-rules'] = subRules;

  return [
    ...matchers.map((matcher) => 'SUB-RULE,($matcher),$key'),
    'MATCH,DIRECT',
  ];
}

List<String> applyWindowsProcessAccessPayload({
  required Map<String, dynamic> rawConfig,
  required Object? payload,
  required Mode clashMode,
  required List<String> originalRules,
}) {
  if (payload is! Map) {
    return List<String>.from(originalRules);
  }

  final modeName = payload['mode']?.toString();
  final accessMode = AccessControlMode.values.where(
    (mode) => mode.name == modeName,
  ).firstOrNull;
  final paths = switch (payload['paths']) {
    final List values => values.map((value) => value.toString()).toList(),
    _ => <String>[],
  };

  if (accessMode == null) {
    return List<String>.from(originalRules);
  }

  return applyWindowsProcessAccessControl(
    rawConfig: rawConfig,
    enabled: payload['enabled'] == true,
    accessMode: accessMode,
    selectedPaths: paths,
    clashMode: clashMode,
    originalRules: originalRules,
  );
}

String _processMatcher(String executablePath) {
  if (isWindowsProcessPattern(executablePath)) {
    // Commas delimit Clash rule fields. If a path contains one, retain useful
    // wildcard behavior by matching only the executable name.
    if (executablePath.contains(',')) {
      return 'PROCESS-NAME-WILDCARD,${p.windows.basename(executablePath)}';
    }
    return 'PROCESS-PATH-WILDCARD,$executablePath';
  }

  // SUB-RULE wraps the matcher in parentheses. Keep the conservative fallback
  // used by the previous Windows implementation for ambiguous exact paths.
  if (executablePath.contains(',') ||
      executablePath.contains('(') ||
      executablePath.contains(')')) {
    return 'PROCESS-NAME,${p.windows.basename(executablePath)}';
  }
  return 'PROCESS-PATH,$executablePath';
}
