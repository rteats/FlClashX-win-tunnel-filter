import 'package:fl_clash/common/windows_process_filter.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('immutable subscription config accepts injected Windows access settings', () {
    final subscription = Map<String, dynamic>.unmodifiable({
      'mode': 'rule',
      'proxies': [
        {'name': 'Sweden', 'type': 'ss', 'server': 'example.com'},
      ],
      'proxy-groups': [
        {'name': 'Countries', 'type': 'select', 'proxies': ['Sweden']},
      ],
      'rules': ['MATCH,Countries'],
    });

    final prepared = withWindowsProcessAccessConfig(
      rawConfig: subscription,
      enabled: true,
      accessMode: AccessControlMode.rejectSelected,
      selectedPaths: [r'C:\Games\Versions\*\Game.exe'],
    );

    expect(prepared, isNot(same(subscription)));
    expect(prepared['proxies'], subscription['proxies']);
    expect(prepared['proxy-groups'], subscription['proxy-groups']);
    expect(prepared['rules'], subscription['rules']);
    expect(subscription.containsKey(windowsProcessAccessConfigKey), isFalse);
    expect(prepared[windowsProcessAccessConfigKey], {
      'enabled': true,
      'mode': 'rejectSelected',
      'paths': [r'C:\Games\Versions\*\Game.exe'],
    });
    expect(() => subscription['injected'] = true, throwsUnsupportedError);

    // Only the prepared config is sent to profile generation.
    final payload = prepared.remove(windowsProcessAccessConfigKey);
    final rules = applyWindowsProcessAccessPayload(
      rawConfig: prepared,
      payload: payload,
      clashMode: Mode.rule,
      originalRules: List<String>.from(prepared['rules'] as List),
    );
    expect(rules.last, 'MATCH,Countries');
    expect(rules.first, startsWith('PROCESS-PATH-WILDCARD,'));
    expect(prepared['proxy-groups'], subscription['proxy-groups']);
  });

  test('injection copies selected paths instead of sharing mutable state', () {
    final paths = [r'C:\Games\client.exe'];
    final subscription = <String, dynamic>{'rules': ['MATCH,Proxy']};
    final prepared = withWindowsProcessAccessConfig(
      rawConfig: subscription,
      enabled: false,
      accessMode: AccessControlMode.acceptSelected,
      selectedPaths: paths,
    );
    paths.clear();

    expect(subscription.containsKey(windowsProcessAccessConfigKey), isFalse);
    expect((prepared[windowsProcessAccessConfigKey] as Map)['paths'], [
      r'C:\Games\client.exe',
    ]);
  });

  test('exact paths keep PROCESS-PATH matching', () {
    final config = <String, dynamic>{'mode': 'rule'};
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.rejectSelected,
      selectedPaths: [r'C:\Games\Steam\steam.exe'],
      clashMode: Mode.rule,
      originalRules: ['MATCH,Proxy'],
    );

    expect(config['find-process-mode'], FindProcessMode.always.name);
    expect(
      rules,
      [
        r'PROCESS-PATH,C:\Games\Steam\steam.exe,DIRECT',
        'MATCH,Proxy',
      ],
    );
  });

  test('wildcard paths use Mihomo PROCESS-PATH-WILDCARD', () {
    final config = <String, dynamic>{'mode': 'rule'};
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.rejectSelected,
      selectedPaths: [
        r'C:\Users\me\AppData\Local\Roblox\Versions\*\RobloxPlayerBeta.exe',
      ],
      clashMode: Mode.rule,
      originalRules: ['MATCH,Proxy'],
    );

    expect(
      rules.first,
      r'PROCESS-PATH-WILDCARD,C:\Users\me\AppData\Local\Roblox\Versions\*\RobloxPlayerBeta.exe,DIRECT',
    );
  });

  test('question-mark wildcard is recognized', () {
    expect(isWindowsProcessPattern(r'C:\Apps\v?\client.exe'), isTrue);
    expect(isWindowsProcessPattern(r'C:\Apps\v1\client.exe'), isFalse);
  });

  test('whitelist wildcard enters original profile sub-rule', () {
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
      selectedPaths: [r'C:\Apps\Versions\*\client.exe'],
      clashMode: Mode.rule,
      originalRules: original,
    );

    expect(
      rules,
      [
        r'SUB-RULE,(PROCESS-PATH-WILDCARD,C:\Apps\Versions\*\client.exe),__flclashx_windows_access',
        'MATCH,DIRECT',
      ],
    );
    expect(
      config['sub-rules']['__flclashx_windows_access'],
      original,
    );
    expect(config['sub-rules']['existing'], ['MATCH,DIRECT']);
  });

  test('global blacklist keeps unmatched apps on GLOBAL', () {
    final config = <String, dynamic>{'mode': 'global'};
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: true,
      accessMode: AccessControlMode.rejectSelected,
      selectedPaths: [r'C:\Apps\Versions\*\client.exe'],
      clashMode: Mode.global,
      originalRules: ['MATCH,Proxy'],
    );

    expect(config['mode'], Mode.rule.name);
    expect(
      rules,
      [
        r'PROCESS-PATH-WILDCARD,C:\Apps\Versions\*\client.exe,DIRECT',
        'MATCH,GLOBAL',
      ],
    );
  });

  test('disabled access control leaves rules untouched', () {
    final config = <String, dynamic>{'mode': 'rule'};
    final original = ['MATCH,Proxy'];
    final rules = applyWindowsProcessAccessControl(
      rawConfig: config,
      enabled: false,
      accessMode: AccessControlMode.rejectSelected,
      selectedPaths: [r'C:\Apps\*\client.exe'],
      clashMode: Mode.rule,
      originalRules: original,
    );

    expect(rules, original);
    expect(config.containsKey('find-process-mode'), isFalse);
  });

  test('payload adapter ignores malformed payload', () {
    final config = <String, dynamic>{'mode': 'rule'};
    final original = ['MATCH,Proxy'];

    expect(
      applyWindowsProcessAccessPayload(
        rawConfig: config,
        payload: {'enabled': true, 'mode': 'bad', 'paths': ['*']},
        clashMode: Mode.rule,
        originalRules: original,
      ),
      original,
    );
  });
}
