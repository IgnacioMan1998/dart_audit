import 'package:yaml/yaml.dart';

/// A finding from pubspec.yaml analysis.
class PubspecFinding {
  const PubspecFinding({
    required this.rule,
    required this.severity,
    required this.description,
    this.packageName,
  });

  final String rule;
  final String severity;
  final String description;
  final String? packageName;

  Map<String, dynamic> toJson() => {
        'rule': rule,
        'severity': severity,
        'description': description,
        if (packageName != null) 'packageName': packageName,
      };
}

/// Scans pubspec.yaml for suspicious dependency patterns:
/// - Git dependencies pointing to unknown repos
/// - Dependencies with unusually broad version constraints
/// - Dependencies with `ref:` pointing to branches (not tags)
/// - Path dependencies (should not be in published packages)
/// - Wildcard or "any" version constraints
class PubspecScanner {
  static const _suspiciousGitHosts = [
    'pastebin.com',
    'hastebin.com',
    'dpaste.org',
  ];

  /// Scans a parsed pubspec.yaml for suspicious patterns.
  List<PubspecFinding> scan(YamlMap pubspec) {
    final findings = <PubspecFinding>[];

    _checkDependencies(findings, pubspec, 'dependencies');
    _checkDependencies(findings, pubspec, 'dev_dependencies');
    _checkDependencyOverrides(findings, pubspec);
    _checkSdkConstraints(findings, pubspec);

    return findings;
  }

  void _checkDependencies(
    List<PubspecFinding> findings,
    YamlMap pubspec,
    String section,
  ) {
    final deps = pubspec[section] as YamlMap?;
    if (deps == null) return;

    for (final entry in deps.entries) {
      final name = entry.key as String;
      final value = entry.value;

      if (value is String) {
        if (value.trim() == '*') {
          findings.add(PubspecFinding(
            rule: 'WILDCARD_VERSION',
            severity: 'HIGH',
            description: 'Dependency "$name" uses wildcard version constraint '
                '"*" — resolves to any version including malicious updates',
            packageName: name,
          ));
        }

        if (value.trim() == 'any') {
          findings.add(PubspecFinding(
            rule: 'ANY_VERSION',
            severity: 'HIGH',
            description: 'Dependency "$name" uses "any" constraint — '
                'no version pinning, accepts any version',
            packageName: name,
          ));
        }
      } else if (value is YamlMap) {
        _checkGitDependency(findings, name, value);
        _checkPathDependency(findings, name, value);
      }
    }
  }

  void _checkGitDependency(
    List<PubspecFinding> findings,
    String name,
    YamlMap spec,
  ) {
    final git = spec['git'] as YamlMap?;
    if (git == null) return;

    final url = git['url'] as String?;
    if (url == null) return;

    for (final host in _suspiciousGitHosts) {
      if (url.contains(host)) {
        findings.add(PubspecFinding(
          rule: 'SUSPICIOUS_GIT_HOST',
          severity: 'CRITICAL',
          description: 'Dependency "$name" uses git URL from suspicious host: $url',
          packageName: name,
        ));
      }
    }

    if (RegExp(r'https?://\d+\.\d+\.\d+\.\d+').hasMatch(url)) {
      findings.add(PubspecFinding(
        rule: 'GIT_IP_ADDRESS',
        severity: 'CRITICAL',
        description: 'Dependency "$name" uses git URL with raw IP address: $url',
        packageName: name,
      ));
    }

    final ref = git['ref'] as String?;
    if (ref != null &&
        (ref == 'main' || ref == 'master' || ref == 'dev' || ref == 'HEAD')) {
      findings.add(PubspecFinding(
        rule: 'GIT_BRANCH_REF',
        severity: 'HIGH',
        description: 'Dependency "$name" uses git ref "$ref" — '
            'branch references are mutable and can be force-pushed',
        packageName: name,
      ));
    }
  }

  void _checkPathDependency(
    List<PubspecFinding> findings,
    String name,
    YamlMap spec,
  ) {
    final path = spec['path'] as String?;
    if (path == null) return;

    findings.add(PubspecFinding(
      rule: 'PATH_DEPENDENCY',
      severity: 'MEDIUM',
      description: 'Dependency "$name" uses path reference: $path — '
          'path dependencies cannot be resolved by other projects',
      packageName: name,
    ));
  }

  void _checkDependencyOverrides(
    List<PubspecFinding> findings,
    YamlMap pubspec,
  ) {
    final overrides = pubspec['dependency_overrides'] as YamlMap?;
    if (overrides == null) return;

    for (final entry in overrides.entries) {
      final name = entry.key as String;
      final value = entry.value;

      if (value is String) {
        findings.add(PubspecFinding(
          rule: 'DEPENDENCY_OVERRIDE',
          severity: 'MEDIUM',
          description: 'Dependency override for "$name" to version "$value" — '
              'overrides bypass normal version resolution',
          packageName: name,
        ));
      } else if (value is YamlMap) {
        _checkGitDependency(findings, name, value);
      }
    }
  }

  void _checkSdkConstraints(
    List<PubspecFinding> findings,
    YamlMap pubspec,
  ) {
    final environment = pubspec['environment'] as YamlMap?;
    if (environment == null) return;

    final sdk = environment['sdk'] as String?;
    if (sdk != null && sdk.contains('<3.0.0')) {
      findings.add(PubspecFinding(
        rule: 'OLD_SDK_CONSTRAINT',
        severity: 'LOW',
        description: 'SDK constraint "$sdk" targets Dart <3.0.0 — '
            'older SDK may have known vulnerabilities (e.g. CVE-2026-27704)',
      ));
    }
  }
}
