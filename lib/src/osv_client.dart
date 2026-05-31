import 'dart:convert';

import 'package:http/http.dart' as http;

import 'lockfile_parser.dart';

// OSV.dev batch query endpoint — supports the Pub ecosystem natively.
const _osvBatchUrl = 'https://api.osv.dev/v1/querybatch';

// Maximum packages per batch (OSV.dev limit is 1000, we stay conservative).
const _batchSize = 100;

/// Severity level mapped from OSV CVSS data.
enum OsvSeverity { critical, high, medium, low, unknown }

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
}

/// Queries the OSV.dev batch API for all [packages] and returns audit results.
///
/// Packages are sent in batches of [_batchSize] to respect API limits.
/// Throws [http.ClientException] on network errors.
Future<List<PackageAuditResult>> queryOsv(
  List<LockedPackage> packages, {
  http.Client? client,
}) async {
  final httpClient = client ?? http.Client();
  final results = <PackageAuditResult>[];

  try {
    // Process in batches.
    for (var i = 0; i < packages.length; i += _batchSize) {
      final batch = packages.sublist(
        i,
        (i + _batchSize).clamp(0, packages.length),
      );
      final batchResults = await _queryBatch(batch, httpClient);
      results.addAll(batchResults);
    }
  } finally {
    if (client == null) httpClient.close();
  }

  return results;
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

  final response = await httpClient.post(
    Uri.parse(_osvBatchUrl),
    headers: {'Content-Type': 'application/json'},
    body: body,
  );

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
    final rawVulns =
        (rawResults.elementAtOrNull(i)?['vulns'] as List?) ?? [];

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

  // Resolve severity from the database_specific block (pub.dev) or CVSS scores.
  final severity = _resolveSeverity(v);

  // Find the fixed version from the affected[].ranges[].events list.
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
  // OSV records may carry a top-level severity array with CVSS scores.
  final severityList = (v['severity'] as List?) ?? [];
  for (final s in severityList) {
    final score = s['score'] as String?;
    if (score == null) continue;
    // CVSS v3 base score is embedded in the vector string after 'AV:'.
    // Simpler: parse CVSS numerical score if present.
    final numericScore = _extractCvssScore(score);
    if (numericScore != null) {
      return _scoreToSeverity(numericScore);
    }
  }

  // Fallback: database_specific.severity (pub.dev advisory format).
  final dbSpecific = v['database_specific'] as Map<String, dynamic>?;
  final severityStr =
      (dbSpecific?['severity'] as String?)?.toUpperCase() ?? '';
  return switch (severityStr) {
    'CRITICAL' => OsvSeverity.critical,
    'HIGH' => OsvSeverity.high,
    'MEDIUM' || 'MODERATE' => OsvSeverity.medium,
    'LOW' => OsvSeverity.low,
    _ => OsvSeverity.unknown,
  };
}

double? _extractCvssScore(String vector) {
  // Some OSV entries include the score directly as a plain number.
  final plain = double.tryParse(vector);
  if (plain != null) return plain;
  return null;
}

OsvSeverity _scoreToSeverity(double score) {
  if (score >= 9.0) return OsvSeverity.critical;
  if (score >= 7.0) return OsvSeverity.high;
  if (score >= 4.0) return OsvSeverity.medium;
  return OsvSeverity.low;
}

String? _resolveFixedVersion(
  Map<String, dynamic> v,
  String packageName,
) {
  final affectedList = (v['affected'] as List?) ?? [];
  for (final affected in affectedList) {
    final affectedMap = affected as Map<String, dynamic>;
    final pkg = affectedMap['package'] as Map<String, dynamic>?;
    if (pkg?['name'] != packageName) continue;

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

    // Alternatively, versions list has explicit fixed entries.
    final versions = (affectedMap['versions'] as List?)?.cast<String>() ?? [];
    if (versions.isNotEmpty) return null; // affected list, no explicit fix
  }
  return null;
}
