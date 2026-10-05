import 'package:flclashx/enum/enum.dart';
import 'package:path/path.dart' as p;

/// Applies Windows process-based access control to a Mihomo runtime config.
///
/// This intentionally changes only Mihomo routing. Selected processes still
/// enter the TUN adapter; blacklist mode sends them DIRECT once Mihomo has
/// identified the originating executable.
List<dynamic> applyWindowsProcessAccessControl({
  required Map<String, dynamic> rawConfig,
  required bool enabled,
  required AccessControlMode accessMode,
  required List<String> selectedPaths,
  required Mode clashMode,
  required List<dynamic> originalRules,
}) {
  final selected = selectedPaths
      .map((path) => path.trim())
      .where((path) => path.isNotEmpty)
      .toSet()
      .toList();

  if (!enabled || selected.isEmpty || clashMode == Mode.direct) {
    return List<dynamic>.from(originalRules);
  }

  rawConfig['find-process-mode'] = FindProcessMode.always.name;
  final matchers = selected.map(_processMatcher).toList();

  if (clashMode == Mode.global) {
    // Global mode bypasses the rule engine, so reproduce its semantics in rule
    // mode while inserting the process filter.
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

  // Whitelist mode must let selected processes continue through the profile's
  // original rule set while every other process goes DIRECT.
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

  subRules[key] = List<dynamic>.from(originalRules);
  rawConfig['sub-rules'] = subRules;

  return [
    ...matchers.map((matcher) => 'SUB-RULE,($matcher),$key'),
    'MATCH,DIRECT',
  ];
}

String _processMatcher(String executablePath) {
  // Clash rules are comma-delimited and SUB-RULE wraps the matcher in
  // parentheses. Fall back to the executable name for unusual paths that
  // would make that grammar ambiguous.
  if (executablePath.contains(',') ||
      executablePath.contains('(') ||
      executablePath.contains(')')) {
    return 'PROCESS-NAME,${p.windows.basename(executablePath)}';
  }
  return 'PROCESS-PATH,$executablePath';
}
