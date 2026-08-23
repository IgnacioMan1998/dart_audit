/// A finding from typosquatting analysis.
class TyposquatFinding {
  const TyposquatFinding({
    required this.rule,
    required this.severity,
    required this.description,
    required this.localPackage,
    this.matchedPublicPackage,
  });

  final String rule;
  final String severity;
  final String description;
  final String localPackage;
  final String? matchedPublicPackage;

  Map<String, dynamic> toJson() => {
        'rule': rule,
        'severity': severity,
        'description': description,
        'localPackage': localPackage,
        if (matchedPublicPackage != null)
          'matchedPublicPackage': matchedPublicPackage,
      };
}

/// Detects potential typosquatting and dependency confusion in local
/// dependency names by comparing against known popular pub.dev packages.
class TyposquatDetector {
  /// High-confidence list of popular Dart/Flutter packages.
  static const _popularPackages = {
    'http', 'path', 'args', 'yaml', 'json', 'crypto', 'convert',
    'collection', 'async', 'io', 'ffi', 'html', 'math',
    'flutter', 'flutter_test', 'flutter_driver', 'flutter_localizations',
    'provider', 'riverpod', 'bloc', 'get_it', 'injectable',
    'dio', 'retrofit', 'chopper',
    'shared_preferences', 'hive', 'sqflite', 'moor', 'drift',
    'freezed', 'json_serializable', 'build_runner',
    'intl', 'uuid', 'meta',
    'cached_network_image', 'image', 'video_player',
    'firebase_core', 'firebase_auth', 'firebase_messaging',
    'google_fonts', 'url_launcher', 'path_provider',
    'permission_handler', 'device_info_plus', 'package_info_plus',
    'connectivity_plus', 'battery_plus', 'sensors_plus',
    'flutter_riverpod', 'hooks_riverpod', 'flutter_hooks',
    'go_router', 'auto_route', 'beamer',
    'hive_flutter', 'isar', 'objectbox',
    'lottie', 'rive', 'flutter_svg',
    'google_maps_flutter', 'mapbox_gl',
    'geolocator', 'google_maps',
    'camera', 'gallery_saver',
    'share_plus', 'flutter_local_notifications',
    'in_app_purchase', 'google_mobile_ads',
    'webview_flutter', 'flutter_inappwebview',
    'pull_to_refresh', 'sliver_tools',
    'flutter_screenutil', 'responsive_builder',
    'gap', 'styled_widget',
  };

  static final _transformations = [
    _TransformPattern(
      RegExp(r'^flutter[_-]'),
      'PREFIX_FLUTTER',
      'Adds "flutter_" prefix — common confusion attack',
    ),
    _TransformPattern(
      RegExp(r'[_-]flutter$'),
      'SUFFIX_FLUTTER',
      'Adds "_flutter" suffix — common confusion attack',
    ),
    _TransformPattern(
      RegExp(r'^(dart|pub)[_-]'),
      'PREFIX_DART_PUB',
      'Adds "dart_" or "pub_" prefix — confusion with official packages',
    ),
  ];

  /// Analyzes [localPackageNames] against known popular packages.
  List<TyposquatFinding> analyze(List<String> localPackageNames) {
    final findings = <TyposquatFinding>[];

    for (final name in localPackageNames) {
      final normalizedName = name.toLowerCase().replaceAll(RegExp(r'[-_]'), '');

      final isKnownPopular = _popularPackages.any(
        (p) => p.toLowerCase().replaceAll(RegExp(r'[-_]'), '') == normalizedName,
      );
      if (isKnownPopular) continue;

      _checkLevenshtein(findings, name);
      _checkTransformations(findings, name);
      _checkSuspiciousAffixes(findings, name);
    }

    return findings;
  }

  void _checkLevenshtein(List<TyposquatFinding> findings, String name) {
    final normalizedName = name.toLowerCase().replaceAll(RegExp(r'[-_]'), '');

    for (final popular in _popularPackages) {
      final normalizedPopular = popular.toLowerCase().replaceAll(RegExp(r'[-_]'), '');

      if (normalizedName == normalizedPopular) continue;

      final distance = _levenshtein(normalizedName, normalizedPopular);

      if (distance == 1 && normalizedName.length >= 3) {
        findings.add(TyposquatFinding(
          rule: 'LEVENSHTEIN_1',
          severity: 'CRITICAL',
          description: 'Package "$name" differs by 1 edit from popular '
              'package "$popular" — likely typosquatting',
          localPackage: name,
          matchedPublicPackage: popular,
        ));
        return;
      }

      if (distance == 2 && normalizedName.length >= 5) {
        findings.add(TyposquatFinding(
          rule: 'LEVENSHTEIN_2',
          severity: 'HIGH',
          description: 'Package "$name" differs by 2 edits from popular '
              'package "$popular" — possible typosquatting',
          localPackage: name,
          matchedPublicPackage: popular,
        ));
        return;
      }
    }
  }

  void _checkTransformations(List<TyposquatFinding> findings, String name) {
    for (final transform in _transformations) {
      if (transform.pattern.hasMatch(name)) {
        final stripped = name
            .replaceAll(RegExp(r'^flutter[_-]'), '')
            .replaceAll(RegExp(r'[_-]flutter$'), '')
            .replaceAll(RegExp(r'^(dart|pub)[_-]'), '');

        if (_popularPackages.contains(stripped)) {
          findings.add(TyposquatFinding(
            rule: transform.rule,
            severity: 'HIGH',
            description: '${transform.description} — '
                '"$name" looks like it wraps "$stripped"',
            localPackage: name,
            matchedPublicPackage: stripped,
          ));
        }
      }
    }
  }

  void _checkSuspiciousAffixes(List<TyposquatFinding> findings, String name) {
    final popularNames = _popularPackages.toList()..sort((a, b) => b.length.compareTo(a.length));
    for (final popular in popularNames) {
      if (name.length <= popular.length) continue;

      if (name.startsWith(popular) &&
          (name.length == popular.length + 1 ||
              name[popular.length] == '-' ||
              name[popular.length] == '_')) {
        final suffix = name.substring(popular.length + 1);
        if (suffix.length <= 4 && !_isCommonSuffix(suffix)) {
          findings.add(
            TyposquatFinding(
              rule: 'SUSPICIOUS_SUFFIX',
              severity: 'MEDIUM',
              description: 'Package "$name" appears to be "$popular" with '
                  'suspicious suffix "$suffix" — verify this is intentional',
              localPackage: name,
              matchedPublicPackage: popular,
            ),
          );
        }
      }
    }
  }

  bool _isCommonSuffix(String suffix) {
    const common = {'core', 'lite', 'plus', 'pro', 'extra', 'utils', 'util',
      'helpers', 'helper', 'extensions', 'ext', 'plugin', 'adapter'};
    return common.contains(suffix.toLowerCase());
  }

  static int _levenshtein(String a, String b) {
    if (a.isEmpty) return b.length;
    if (b.isEmpty) return a.length;

    final matrix = List.generate(
      a.length + 1,
      (i) => List.generate(b.length + 1, (j) => 0),
    );

    for (var i = 0; i <= a.length; i++) {
      matrix[i][0] = i;
    }
    for (var j = 0; j <= b.length; j++) {
      matrix[0][j] = j;
    }

    for (var i = 1; i <= a.length; i++) {
      for (var j = 1; j <= b.length; j++) {
        final cost = a[i - 1] == b[j - 1] ? 0 : 1;
        matrix[i][j] = [
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost,
        ].reduce((a, b) => a < b ? a : b);
      }
    }

    return matrix[a.length][b.length];
  }
}

class _TransformPattern {
  const _TransformPattern(this.pattern, this.rule, this.description);
  final RegExp pattern;
  final String rule;
  final String description;
}
