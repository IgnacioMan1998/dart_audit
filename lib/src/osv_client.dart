import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;

import 'lockfile_parser.dart';

// OSV.dev batch query endpoint — supports the Pub ecosystem natively.
const _osvBatchUrl = 'https://api.osv.dev/v1/querybatch';

// Maximum packages per batch (OSV.dev limit is 1000, we stay conservative).
const _batchSize = 100;

// HTTP request timeout.
const _requestTimeout = Duration(seconds: 30);

// Max retry attempts on transient errors.
const _maxRetries = 3;

/// Severity level mapped from OSV CVSS data.
enum OsvSeverity {
  critical,
  high,
  medium,
  low,
  unknown;

  /// Parses a severity string (case-insensitive) to [OsvSeverity].
  static OsvSeverity fromString(String s) => switch (s.toUpperCase()) {
        'CRITICAL' => OsvSeverity.critical,
        'HIGH' => OsvSeverity.high,
        'MEDIUM' || 'MODERATE' => OsvSeverity.medium,
        'LOW' => OsvSeverity.low,
        _ => OsvSeverity.unknown,
      };

  /// Returns a numeric priority (lower = more severe). Useful for filtering.
  int get priority => switch (this) {
        OsvSeverity.critical => 0,
        OsvSeverity.high => 1,
        OsvSeverity.medium => 2,
        OsvSeverity.low => 3,
        OsvSeverity.unknown => 4,
      };
}

/// A single vulnerability returned by OSV.dev.
class OsvVulnerability {
  const OsvVulnerability({
    required this.id,
    required this.summary,
    required this.severity,
    required this.fixedVersion,
    required this.aliases,
    required this.detailsUrl,
  });

  /// Primary vulnerability ID (e.g. `'GHSA-xxxx-xxxx-xxxx'`).
  final String id;

  /// Short human-readable description.
  final String summary;

  final OsvSeverity severity;

  /// The first version that fixes the vulnerability, if known.
  final String? fixedVersion;

  /// Alternative IDs (CVE-yyyy-xxxxx, etc.).
  final List<String> aliases;

  /// Link to the full advisory.
  final String detailsUrl;

  Map<String, dynamic> toJson() => {
        'id': id,
        'summary': summary,
        'severity': severity.name,
        'fixedVersion': fixedVersion,
        'aliases': aliases,
        'detailsUrl': detailsUrl,
      };
}

/// A package together with any vulnerabilities found for it.
class PackageAuditResult {
  const PackageAuditResult({
    required this.package,
    required this.vulnerabilities,
  });

  final LockedPackage package;
  final List<OsvVulnerability> vulnerabilities;

  bool get isVulnerable => vulnerabilities.isNotEmpty;

  Map<String, dynamic> toJson() => {
        'name': package.name,
        'version': package.version,
        'isDirect': package.isDirect,
        'vulnerabilities': vulnerabilities.map((v) => v.toJson()).toList(),
      };
}

/// Queries the OSV.dev batch API for all [packages] and returns audit results.
///
/// Packages are sent in batches of [_batchSize] to respect API limits.
/// Each batch is retried up to [_maxRetries] times on transient errors.
/// An optional [onBatchProgress] callback is called after each batch with
/// the number of packages processed so far and the total.
/// Throws [http.ClientException] on network errors after all retries.
Future<List<PackageAuditResult>> queryOsv(
  List<LockedPackage> packages, {
  http.Client? client,
  void Function(int done, int total)? onBatchProgress,
}) async {
  final httpClient = client ?? http.Client();
  final results = <PackageAuditResult>[];

  try {
    for (var i = 0; i < packages.length; i += _batchSize) {
      final batch = packages.sublist(
        i,
        (i + _batchSize).clamp(0, packages.length),
      );
      final batchResults = await _queryBatchWithRetry(batch, httpClient);
      results.addAll(batchResults);
      onBatchProgress?.call(
        (i + batch.length).clamp(0, packages.length),
        packages.length,
      );
    }
  } finally {
    if (client == null) httpClient.close();
  }

  return results;
}

Future<List<PackageAuditResult>> _queryBatchWithRetry(
  List<LockedPackage> batch,
  http.Client httpClient,
) async {
  Object? lastError;
  for (var attempt = 1; attempt <= _maxRetries; attempt++) {
    try {
      return await _queryBatch(batch, httpClient);
    } on SocketException catch (e) {
      lastError = e;
    } on http.ClientException catch (e) {
      // Retry only on server errors (5xx), not client errors (4xx).
      lastError = e;
      if (e.message.contains('4')) rethrow;
    } on TimeoutException catch (e) {
      lastError = e;
    }
    if (attempt < _maxRetries) {
      // Exponential back-off: 1s, 2s, 4s…
      await Future<void>.delayed(Duration(seconds: 1 << (attempt - 1)));
    }
  }
  throw http.ClientException('OSV.dev request failed after $_maxRetries attempts: $lastError');
}

Future<List<PackageAuditResult>> _queryBatch(
  List<LockedPackage> batch,
  http.Client httpClient,
) async {
  final body = jsonEncode({
    'queries': [
      for (final pkg in batch)
        {
          'version': pkg.version,
          'package': {'name': pkg.name, 'ecosystem': 'Pub'},
        },
    ],
  });

  final response = await httpClient
      .post(
        Uri.parse(_osvBatchUrl),
        headers: {'Content-Type': 'application/json'},
        body: body,
      )
      .timeout(_requestTimeout);

  if (response.statusCode != 200) {
    throw http.ClientException(
      'OSV.dev API returned ${response.statusCode}: ${response.body}',
    );
  }

  final json = jsonDecode(response.body) as Map<String, dynamic>;
  final rawResults = (json['results'] as List?) ?? [];

  final auditResults = <PackageAuditResult>[];

  for (var i = 0; i < batch.length; i++) {
    final pkg = batch[i];
    final rawVulns = (rawResults.elementAtOrNull(i)?['vulns'] as List?) ?? [];

    final vulns = rawVulns
        .map((v) => _parseVuln(v as Map<String, dynamic>, pkg.name))
        .toList();

    auditResults.add(PackageAuditResult(package: pkg, vulnerabilities: vulns));
  }

  return auditResults;
}

OsvVulnerability _parseVuln(Map<String, dynamic> v, String packageName) {
  final id = v['id'] as String? ?? 'UNKNOWN';
  final summary = v['summary'] as String? ?? '(no summary)';
  final aliases = ((v['aliases'] as List?) ?? []).cast<String>();
  final detailsUrl = 'https://osv.dev/vulnerability/$id';

  final severity = _resolveSeverity(v);
  final fixedVersion = _resolveFixedVersion(v, packageName);

  return OsvVulnerability(
    id: id,
    summary: summary,
    severity: severity,
    fixedVersion: fixedVersion,
    aliases: aliases,
    detailsUrl: detailsUrl,
  );
}

OsvSeverity _resolveSeverity(Map<String, dynamic> v) {
  // 1. Try top-level severity array (CVSS scores).
  final severityList = (v['severity'] as List?) ?? [];
  for (final s in severityList) {
    final type = (s['type'] as String?)?.toUpperCase() ?? '';
    final score = s['score'] as String?;
    if (score == null) continue;

    // CVSS v3.x vectors look like: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    // The base score can be derived from the vector or may be stored separately.
    if (type == 'CVSS_V3' || type == 'CVSS_V2') {
      final numericScore = _extractCvssScore(score);
      if (numericScore != null) return _scoreToSeverity(numericScore);
    }
  }

  // 2. Fallback: database_specific.severity (pub.dev advisory format).
  final dbSpecific = v['database_specific'] as Map<String, dynamic>?;
  final severityStr = (dbSpecific?['severity'] as String?) ?? '';
  if (severityStr.isNotEmpty) return OsvSeverity.fromString(severityStr);

  // 3. Fallback: affected[].database_specific.severity.
  for (final affected in (v['affected'] as List?) ?? []) {
    final affectedDb =
        (affected as Map<String, dynamic>)['database_specific'] as Map<String, dynamic>?;
    final s = (affectedDb?['severity'] as String?) ?? '';
    if (s.isNotEmpty) return OsvSeverity.fromString(s);
  }

  return OsvSeverity.unknown;
}

double? _extractCvssScore(String vector) {
  // Plain numeric score (some OSV records use this).
  final plain = double.tryParse(vector);
  if (plain != null) return plain;

  // CVSS v3.x vector string — extract base score from the /S: component.
  // OSV sometimes embeds it as "score" alongside the vector; if not, we
  // approximate from the vector's severity label in database_specific instead.
  // As a heuristic: look for a numeric suffix after a slash or space.
  final match = RegExp(r'(\d+\.\d+)$').firstMatch(vector.trim());
  if (match != null) return double.tryParse(match.group(1)!);

  return null;
}

OsvSeverity _scoreToSeverity(double score) {
  if (score >= 9.0) return OsvSeverity.critical;
  if (score >= 7.0) return OsvSeverity.high;
  if (score >= 4.0) return OsvSeverity.medium;
  return OsvSeverity.low;
}

String? _resolveFixedVersion(Map<String, dynamic> v, String packageName) {
  final affectedList = (v['affected'] as List?) ?? [];
  for (final affected in affectedList) {
    final affectedMap = affected as Map<String, dynamic>;
    final pkg = affectedMap['package'] as Map<String, dynamic>?;
    if (pkg?['name'] != packageName) continue;

    // Check ECOSYSTEM ranges for explicit 'fixed' events.
    final ranges = (affectedMap['ranges'] as List?) ?? [];
    for (final range in ranges) {
      final rangeMap = range as Map<String, dynamic>;
      final events = (rangeMap['events'] as List?) ?? [];
      for (final event in events) {
        final eventMap = event as Map<String, dynamic>;
        final fixed = eventMap['fixed'] as String?;
        if (fixed != null && fixed.isNotEmpty) return fixed;
      }
    }
  }
  return null;
}
