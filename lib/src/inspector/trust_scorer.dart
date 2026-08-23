import 'dart:convert';

import 'package:http/http.dart' as http;

/// Trust-related metadata for a pub.dev package.
class PackageTrustInfo {
  const PackageTrustInfo({
    required this.packageName,
    this.version,
    this.createdAt,
    this.lastPublishedAt,
    this.popularityScore,
    this.likeCount,
    this.grantedPoints,
    this.maxPoints,
    this.publisher,
    this.isVerifiedPublisher = false,
    this.downloadCount30Days,
    this.findings = const [],
  });

  final String packageName;
  final String? version;
  final DateTime? createdAt;
  final DateTime? lastPublishedAt;
  final double? popularityScore;
  final int? likeCount;
  final int? grantedPoints;
  final int? maxPoints;
  final String? publisher;
  final bool isVerifiedPublisher;
  final int? downloadCount30Days;
  final List<TrustFinding> findings;

  bool get isTrusted => findings.isEmpty || !findings.any((f) => f.severity == 'CRITICAL');

  Map<String, dynamic> toJson() => {
        'package': packageName,
        'version': version,
        'createdAt': createdAt?.toIso8601String(),
        'lastPublishedAt': lastPublishedAt?.toIso8601String(),
        'popularityScore': popularityScore,
        'likeCount': likeCount,
        'grantedPoints': grantedPoints,
        'maxPoints': maxPoints,
        'publisher': publisher,
        'isVerifiedPublisher': isVerifiedPublisher,
        'downloadCount30Days': downloadCount30Days,
        'findings': findings.map((f) => f.toJson()).toList(),
      };
}

/// A trust-related finding for a package.
class TrustFinding {
  const TrustFinding({
    required this.rule,
    required this.severity,
    required this.description,
  });

  final String rule;
  final String severity;
  final String description;

  Map<String, dynamic> toJson() => {
        'rule': rule,
        'severity': severity,
        'description': description,
      };
}

/// Fetches pub.dev metadata and scores for a package to assess trust.
class TrustScorer {
  TrustScorer({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;
  static const _pubApi = 'https://pub.dev/api';
  static const _timeout = Duration(seconds: 15);

  /// Minimum age in days before a package is considered "fresh" (higher risk).
  static const _freshThresholdDays = 7;

  /// Minimum likes to be considered established.
  static const _minLikesForEstablished = 5;

  /// Minimum downloads (30 days) to be considered established.
  static const _minDownloadsForEstablished = 100;

  /// Fetches trust info for [packageName] and assesses risk.
  ///
  /// Returns null if the package doesn't exist on pub.dev.
  Future<PackageTrustInfo?> assess(String packageName) async {
    try {
      // 1. Fetch package metadata.
      final metaResponse = await _client
          .get(Uri.parse('$_pubApi/packages/$packageName'))
          .timeout(_timeout);

      if (metaResponse.statusCode == 404) return null;
      if (metaResponse.statusCode != 200) return null;

      final meta = jsonDecode(metaResponse.body) as Map<String, dynamic>;

      // 2. Fetch score data.
      final scoreResponse = await _client
          .get(Uri.parse('$_pubApi/packages/$packageName/score'))
          .timeout(_timeout);

      Map<String, dynamic>? score;
      if (scoreResponse.statusCode == 200) {
        score = jsonDecode(scoreResponse.body) as Map<String, dynamic>;
      }

      return _analyzePackage(meta, score);
    } catch (_) {
      // Network errors should not block the audit.
      return null;
    }
  }

  PackageTrustInfo _analyzePackage(
    Map<String, dynamic> meta,
    Map<String, dynamic>? score,
  ) {
    final findings = <TrustFinding>[];

    // Extract metadata.
    final latest = meta['latest'] as Map<String, dynamic>?;
    final version = latest?['version'] as String?;

    final createdAtStr = meta['created'] as String?;
    final createdAt = createdAtStr != null ? DateTime.tryParse(createdAtStr) : null;

    final lastPublishedStr = latest?['published'] as String?;
    final lastPublished = lastPublishedStr != null
        ? DateTime.tryParse(lastPublishedStr)
        : null;

    // Score data.
    final popularity = score?['popularityScore'] as double?;
    final likes = score?['likeCount'] as int?;
    final grantedPoints = score?['grantedPoints'] as int?;
    final maxPoints = score?['maxPoints'] as int?;

    // Publisher data.
    final publisher = meta['publisher'] as String?;
    final isVerified = publisher != null && publisher.isNotEmpty;

    // Download counts (if available in score response).
    final downloadCount = score?['downloadCount30Days'] as int?;

    // ── Trust analysis ──────────────────────────────────────────────────────
    final now = DateTime.now().toUtc();

    // Check package age.
    if (createdAt != null) {
      final ageDays = now.difference(createdAt).inDays;
      if (ageDays < _freshThresholdDays) {
        findings.add(TrustFinding(
          rule: 'FRESH_PACKAGE',
          severity: 'CRITICAL',
          description: 'Package is only $ageDays day(s) old — '
              'recently published packages are the #1 vector for supply chain attacks '
              '(Shai-Hulud, Axios compromise all used newly published versions)',
        ));
      } else if (ageDays < 30) {
        findings.add(TrustFinding(
          rule: 'YOUNG_PACKAGE',
          severity: 'MEDIUM',
          description: 'Package is $ageDays day(s) old — relatively new, verify author reputation',
        ));
      }
    }

    // Check popularity.
    if (likes != null && likes < _minLikesForEstablished) {
      findings.add(TrustFinding(
        rule: 'LOW_LIKES',
        severity: 'MEDIUM',
        description: 'Package has only $likes like(s) — low community endorsement',
      ));
    }

    // Check downloads.
    if (downloadCount != null && downloadCount < _minDownloadsForEstablished) {
      findings.add(TrustFinding(
        rule: 'LOW_DOWNLOADS',
        severity: 'MEDIUM',
        description: 'Package has only $downloadCount download(s) in 30 days — '
            'very low usage increases risk of typosquatting or dependency confusion',
      ));
    }

    // Check publisher verification.
    if (!isVerified) {
      findings.add(TrustFinding(
        rule: 'UNVERIFIED_PUBLISHER',
        severity: 'HIGH',
        description: 'Package has no verified publisher — '
            'maintainer identity is unverified',
      ));
    }

    // Check pub points.
    if (grantedPoints != null && maxPoints != null && maxPoints > 0) {
      final ratio = grantedPoints / maxPoints;
      if (ratio < 0.5) {
        findings.add(TrustFinding(
          rule: 'LOW_QUALITY_SCORE',
          severity: 'MEDIUM',
          description: 'Low pub points: $grantedPoints/$maxPoints '
              '(${(ratio * 100).toStringAsFixed(0)}%) — may indicate poor maintenance',
        ));
      }
    }

    // Check if the latest version is very fresh (< 24 hours).
    if (lastPublished != null) {
      final hoursSincePublish = now.difference(lastPublished).inHours;
      if (hoursSincePublish < 24) {
        findings.add(TrustFinding(
          rule: 'FRESH_RELEASE',
          severity: 'CRITICAL',
          description: 'Latest version published only ${hoursSincePublish}h ago — '
              'malicious versions are typically caught within 24-48 hours; '
              'wait before installing',
        ));
      }
    }

    return PackageTrustInfo(
      packageName: meta['name'] as String? ?? '',
      version: version,
      createdAt: createdAt,
      lastPublishedAt: lastPublished,
      popularityScore: popularity,
      likeCount: likes,
      grantedPoints: grantedPoints,
      maxPoints: maxPoints,
      publisher: publisher,
      isVerifiedPublisher: isVerified,
      downloadCount30Days: downloadCount,
      findings: findings,
    );
  }
}
