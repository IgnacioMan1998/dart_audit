import 'dart:convert';

import 'package:http/http.dart' as http;

/// A finding from dependency confusion analysis.
class ConfusionFinding {
  const ConfusionFinding({
    required this.rule,
    required this.severity,
    required this.description,
    required this.packageName,
    this.publicVersion,
  });

  final String rule;
  final String severity;
  final String description;
  final String packageName;
  final String? publicVersion;

  Map<String, dynamic> toJson() => {
        'rule': rule,
        'severity': severity,
        'description': description,
        'packageName': packageName,
        if (publicVersion != null) 'publicVersion': publicVersion,
      };
}

/// Detects potential dependency confusion attacks by checking if local
/// package names exist on pub.dev with unexpected versions or patterns
/// that suggest an attacker may be squatting on internal names.
class ConfusionDetector {
  ConfusionDetector({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;
  static const _pubApi = 'https://pub.dev/api';
  static const _timeout = Duration(seconds: 10);

  /// Analyzes local dependency names for potential confusion with public packages.
  ///
  /// [localDeps] are the dependency names from the user's pubspec.yaml.
  /// Returns findings for packages that match suspicious patterns.
  Future<List<ConfusionFinding>> analyze(List<String> localDeps) async {
    final findings = <ConfusionFinding>[];

    for (final name in localDeps) {
      final result = await _checkPackage(name);
      if (result != null) findings.add(result);
    }

    return findings;
  }

  Future<ConfusionFinding?> _checkPackage(String name) async {
    try {
      final response = await _client
          .get(Uri.parse('$_pubApi/packages/$name'))
          .timeout(_timeout);

      if (response.statusCode == 404) {
        // Package doesn't exist on pub.dev — this is fine for local/private
        // packages but could indicate confusion if someone ELSE publishes it.
        return null;
      }

      if (response.statusCode != 200) return null;

      final meta = jsonDecode(response.body) as Map<String, dynamic>;
      return _analyzeMetadata(name, meta);
    } catch (_) {
      return null;
    }
  }

  ConfusionFinding? _analyzeMetadata(String name, Map<String, dynamic> meta) {
    // Check for suspicious version patterns.
    final versions = meta['versions'] as List?;
    if (versions != null && versions.isNotEmpty) {
      final latestVersion =
          (meta['latest'] as Map<String, dynamic>?)?['version'] as String?;

      if (latestVersion != null && _isSuspiciousVersion(latestVersion)) {
        return ConfusionFinding(
          rule: 'SUSPICIOUS_VERSION',
          severity: 'HIGH',
          description: 'Package "$name" has suspicious version "$latestVersion" — '
              'unusually high version number may indicate version inflation attack '
              '(dependency confusion)',
          packageName: name,
          publicVersion: latestVersion,
        );
      }
    }

    return null;
  }

  /// Detects version inflation: version numbers that are abnormally high
  /// for a new or low-popularity package.
  bool _isSuspiciousVersion(String version) {
    // Parse major version.
    final parts = version.split('.');
    if (parts.isEmpty) return false;

    final major = int.tryParse(parts[0]);
    if (major == null) return false;

    // Version > 1000 is extremely suspicious.
    if (major > 1000) return true;

    // Version > 100 with many pre-release tags is suspicious.
    if (major > 100 && version.contains('-')) return true;

    // Version > 50 is worth flagging.
    if (major > 50) return true;

    return false;
  }
}
