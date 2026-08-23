import 'dart:convert';
import 'dart:io';

import 'color_output.dart' as c;
import 'inspector/package_inspector.dart';

export 'color_output.dart' show disableColor;

String _red(String s) => c.red(s);
String _yellow(String s) => c.yellow(s);
String _green(String s) => c.green(s);
String _bold(String s) => c.bold(s);
String _dim(String s) => c.dim(s);

/// Prints an [InspectionReport] as formatted JSON.
void printJsonInspectionReport(InspectionReport report) {
  stdout.writeln(const JsonEncoder.withIndent('  ').convert(report.toJson()));
}

/// Prints a human-readable [InspectionReport] and returns the risk score.
int printInspectionReport(InspectionReport report) {
  final pkg = '${report.packageName} ${report.version}';

  stdout.writeln();
  stdout.writeln(
    _bold('dart_audit') +
        _dim(' — Source Inspection · $pkg · ${report.dartFileCount} file(s) analyzed'),
  );
  stdout.writeln(_dim('─' * 60));

  // ── Trust info ──────────────────────────────────────────────────────────
  if (report.trustInfo != null) {
    final trust = report.trustInfo!;
    stdout.writeln();
    stdout.writeln(_bold('  Package Trust Assessment'));
    if (trust.createdAt != null) {
      final ageDays = DateTime.now().difference(trust.createdAt!).inDays;
      stdout.writeln('  Age: ${_bold('$ageDays days')} (created ${trust.createdAt!.toIso8601String().substring(0, 10)})');
    }
    if (trust.likeCount != null) {
      stdout.writeln('  Likes: ${trust.likeCount}');
    }
    if (trust.downloadCount30Days != null) {
      stdout.writeln('  Downloads (30d): ${trust.downloadCount30Days}');
    }
    if (trust.publisher != null && trust.publisher!.isNotEmpty) {
      final verified = trust.isVerifiedPublisher ? _green('verified') : _yellow('unverified');
      stdout.writeln('  Publisher: ${trust.publisher} ($verified)');
    } else {
      stdout.writeln('  Publisher: ${_red('none')}');
    }
    if (trust.findings.isNotEmpty) {
      stdout.writeln();
      for (final f in trust.findings) {
        final label = _severityLabel(f.rule == 'FRESH_PACKAGE' || f.rule == 'FRESH_RELEASE'
            ? 'CRITICAL'
            : f.severity);
        stdout.writeln('  $label ${f.description}');
      }
    }
    stdout.writeln();
  }

  if (report.isClean) {
    stdout.writeln(_green('  ✔ No suspicious patterns found.'));
    stdout.writeln(_green('  ✔ No high-entropy strings detected.'));
    stdout.writeln(_green('  ✔ No invisible Unicode characters.'));
    stdout.writeln(_green('  ✔ No malicious archive structures.'));
  } else {
    // ── Unicode findings (Trojan Source / GlassWorm) ─────────────────────
    if (report.unicodeFindings.isNotEmpty) {
      stdout.writeln(_bold('  Unicode Security Findings (${report.unicodeFindings.length}):'));
      stdout.writeln();
      for (final f in report.unicodeFindings) {
        final label = _severityLabel(f.severity);
        stdout.writeln('  $label ${_bold(f.file)}:${f.line}');
        stdout.writeln('    Rule    : ${f.rule}');
        stdout.writeln('    Code    : ${f.codepoint}');
        stdout.writeln('    Detail  : ${f.description}');
        stdout.writeln('    Snippet : ${_dim(f.snippet)}');
        stdout.writeln();
      }
    }

    // ── Regex findings ────────────────────────────────────────────────────
    if (report.regexFindings.isNotEmpty) {
      stdout.writeln(_bold('  Regex Findings (${report.regexFindings.length}):'));
      stdout.writeln();
      for (final f in report.regexFindings) {
        final label = _severityLabel(f.severity);
        stdout.writeln('  $label ${_bold(f.file)}:${f.line}');
        stdout.writeln('    Rule    : ${f.rule}');
        stdout.writeln('    Detail  : ${f.description}');
        stdout.writeln('    Snippet : ${_dim(f.snippet)}');
        stdout.writeln();
      }
    }

    // ── Entropy findings ──────────────────────────────────────────────────
    if (report.entropyFindings.isNotEmpty) {
      stdout.writeln(_bold('  Entropy Findings (${report.entropyFindings.length}):'));
      stdout.writeln();
      for (final f in report.entropyFindings) {
        final label = _severityLabel(f.severity);
        final entropyStr = f.entropy.toStringAsFixed(1);
        stdout.writeln(
          '  $label ${_bold(f.file)}:${f.line} — Entropy: $entropyStr bits',
        );
        stdout.writeln('    Detail  : High-entropy string literal (possible obfuscation/encryption)');
        stdout.writeln('    Snippet : ${_dim(f.snippet)}');
        stdout.writeln();
      }
    }
  }

  // ── Risk score summary ────────────────────────────────────────────────────
  stdout.writeln(_dim('─' * 60));
  final scoreStr = 'Risk Score: ${report.riskScore}/100 — ${report.riskLabel}';

  if (report.riskScore == 0) {
    stdout.writeln(_green(_bold('  $scoreStr')));
  } else if (report.isSuspicious) {
    stdout.writeln(_red(_bold('  $scoreStr — Do NOT install without review')));
  } else {
    stdout.writeln(_yellow(_bold('  $scoreStr')));
  }

  // ── Finding summary ──────────────────────────────────────────────────────
  final totalFindings = report.regexFindings.length +
      report.entropyFindings.length +
      report.unicodeFindings.length +
      report.archiveFindings.length +
      (report.trustInfo?.findings.length ?? 0);
  if (totalFindings > 0) {
    stdout.writeln(_dim('  Total findings: $totalFindings'));
  }

  stdout.writeln(_dim('─' * 60));
  stdout.writeln();

  return report.riskScore;
}

String _severityLabel(String severity) {
  // Map trust-specific rules to display labels.
  final normalized = switch (severity) {
    'FRESH_PACKAGE' || 'FRESH_RELEASE' => 'CRITICAL',
    'YOUNG_PACKAGE' || 'LOW_LIKES' || 'LOW_DOWNLOADS' => 'MEDIUM',
    'UNVERIFIED_PUBLISHER' => 'HIGH',
    'LOW_QUALITY_SCORE' => 'MEDIUM',
    _ => severity,
  };
  return switch (normalized) {
    'CRITICAL' => _red('[CRITICAL]'),
    'HIGH' => _red('[HIGH]    '),
    'MEDIUM' => _yellow('[MEDIUM]  '),
    _ => _dim('[LOW]     '),
  };
}
