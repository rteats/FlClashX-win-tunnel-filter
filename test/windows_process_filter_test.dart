import 'dart:io';
import 'dart:typed_data';

import 'package:flclashx/common/windows.dart';
import 'package:flclashx/common/windows_process_filter.dart';
import 'package:flclashx/enum/enum.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('blacklist prepends DIRECT process rules and preserves profile rules', () {
    final config = <String, dynamic>{'mode': 'rule'};
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.rejectSelected,
      selectedPaths: [r'C:\Games\Steam\steam.exe'],
      clashMode: Mode.rule,
      originalRules: ['DOMAIN-SUFFIX,example.com,Proxy', 'MATCH,DIRECT'],
    );

    expect(config['find-process-mode'], 'always');
    expect(
      rules,
      [
        r'PROCESS-PATH,C:\Games\Steam\steam.exe,DIRECT',
        'DOMAIN-SUFFIX,example.com,Proxy',
        'MATCH,DIRECT',
      ],
    );
  });

  test('whitelist routes selected process through original rules as sub-rule', () {
    final config = <String, dynamic>{
      'mode': 'rule',
      'sub-rules': {
        'existing': ['MATCH,DIRECT'],
      },
    };
    final original = ['DOMAIN-SUFFIX,example.com,Proxy', 'MATCH,DIRECT'];

    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.acceptSelected,
      selectedPaths: [r'C:\Program Files\Browser\browser.exe'],
      clashMode: Mode.rule,
      originalRules: original,
    );

    expect(
      rules,
      [
        r'SUB-RULE,(PROCESS-PATH,C:\Program Files\Browser\browser.exe),__flclashx_windows_access',
        'MATCH,DIRECT',
      ],
    );
    expect(
      config['sub-rules']['__flclashx_windows_access'],
      original,
    );
    expect(config['sub-rules']['existing'], ['MATCH,DIRECT']);
  });

  test('global whitelist keeps selected apps on GLOBAL and bypasses others', () {
    final config = <String, dynamic>{'mode': 'global'};
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.acceptSelected,
      selectedPaths: [r'C:\Apps\chat.exe'],
      clashMode: Mode.global,
      originalRules: ['MATCH,Proxy'],
    );

    expect(config['mode'], 'rule');
    expect(
      rules,
      [
        r'PROCESS-PATH,C:\Apps\chat.exe,GLOBAL',
        'MATCH,DIRECT',
      ],
    );
  });

  test('unusual paths fall back to PROCESS-NAME grammar', () {
    final config = <String, dynamic>{'mode': 'rule'};
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.rejectSelected,
      selectedPaths: [r'C:\Apps (Legacy)\tool.exe'],
      clashMode: Mode.rule,
      originalRules: ['MATCH,Proxy'],
    );

    expect(rules.first, 'PROCESS-NAME,tool.exe,DIRECT');
  });


  test('Windows executable icon extraction returns PNG', () async {
    if (!Platform.isWindows) return;

    final systemRoot = Platform.environment['SystemRoot'] ?? r'C:\Windows';
    final candidates = [
      r'$systemRoot\System32\WindowsPowerShell\v1.0\powershell.exe',
      r'$systemRoot\System32\cmd.exe',
      r'$systemRoot\explorer.exe',
    ];

    Uint8List? icon;
    for (final executable in candidates) {
      if (!File(executable).existsSync()) continue;
      icon = await windows!.getExecutableIcon(executable);
      if (icon != null) break;
    }

    expect(
      icon,
      isNotNull,
      reason: 'Windows should expose an associated icon for at least one '
          'standard shell executable',
    );
    expect(icon!.length, greaterThan(8));
    expect(
      icon.sublist(0, 8),
      equals([137, 80, 78, 71, 13, 10, 26, 10]),
    );
  });

  test('empty selection leaves routing unchanged', () {
    final config = <String, dynamic>{'mode': 'rule'};
    final original = ['MATCH,Proxy'];
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.acceptSelected,
      selectedPaths: const [],
      clashMode: Mode.rule,
      originalRules: original,
    );

    expect(rules, original);
    expect(config.containsKey('find-process-mode'), isFalse);
  });
}
