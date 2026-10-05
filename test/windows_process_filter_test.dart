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
      selectedPaths: [r'C:\\Games\\Steam\\steam.exe'],
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
      selectedPaths: [r'C:\\Program Files\\Browser\\browser.exe'],
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
      selectedPaths: [r'C:\\Apps\\chat.exe'],
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
