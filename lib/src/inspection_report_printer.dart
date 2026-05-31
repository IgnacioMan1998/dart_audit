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

  if (report.isClean) {
    stdout.writeln();
    stdout.writeln(_green('✔ No suspicious patterns found.'));
    stdout.writeln(_green('✔ No high-entropy strings detected.'));
  } else {
    // ── Regex findings ────────────────────────────────────────────────────
    if (report.regexFindings.isNotEmpty) {
      stdout.writeln();
      for (final f in report.regexFindings) {
        final label = _severityLabel(f.severity);
        stdout.writeln('$label ${_bold(f.file)}:${f.line}');
        stdout.writeln('  Rule    : ${f.rule}');
        stdout.writeln('  Detail  : ${f.description}');
        stdout.writeln('  Snippet : ${_dim(f.snippet)}');
        stdout.writeln();
      }
    }

    // ── Entropy findings ──────────────────────────────────────────────────
    if (report.entropyFindings.isNotEmpty) {
      for (final f in report.entropyFindings) {
        final label = _severityLabel(f.severity);
        final entropyStr = f.entropy.toStringAsFixed(1);
        stdout.writeln(
          '$label ${_bold(f.file)}:${f.line} — Entropy: $entropyStr bits',
        );
        stdout.writeln('  Detail  : High-entropy string literal (possible obfuscation/encryption)');
        stdout.writeln('  Snippet : ${_dim(f.snippet)}');
        stdout.writeln();
      }
    }
  }

  // ── Risk score summary ────────────────────────────────────────────────────
  stdout.writeln(_dim('─' * 60));
  final scoreStr = 'Risk Score: ${report.riskScore}/100 — ${report.riskLabel}';

  if (report.riskScore == 0) {
    stdout.writeln(_green(_bold(scoreStr)));
  } else if (report.isSuspicious) {
    stdout.writeln(_red(_bold('$scoreStr — Do NOT install without review')));
  } else {
    stdout.writeln(_yellow(_bold(scoreStr)));
  }

  stdout.writeln(_dim('─' * 60));
  stdout.writeln();

  return report.riskScore;
}

String _severityLabel(String severity) => switch (severity) {
      'CRITICAL' => _red('[CRITICAL]'),
      'HIGH' => _red('[HIGH]    '),
      'MEDIUM' => _yellow('[MEDIUM]  '),
      _ => _dim('[LOW]     '),
    };
