import 'dart:io';
import 'dart:math';

/// A high-entropy string literal found during source scanning.
class EntropyFinding {
  const EntropyFinding({
    required this.file,
    required this.line,
    required this.entropy,
    required this.severity,
    required this.snippet,
  });

  /// Relative path of the file where the finding was made.
  final String file;

  /// 1-based line number.
  final int line;

  /// Shannon entropy in bits.
  final double entropy;

  /// `'HIGH'` (entropy > 5.5) or `'MEDIUM'` (entropy > 4.5).
  final String severity;

  /// The suspicious string literal (truncated to 60 chars).
  final String snippet;

  Map<String, dynamic> toJson() => {
        'file': file,
        'line': line,
        'entropy': double.parse(entropy.toStringAsFixed(2)),
        'severity': severity,
        'snippet': snippet,
      };
}

/// Scans Dart source files for string literals with abnormally high Shannon
/// entropy, which may indicate obfuscated, encrypted, or generated content.
///
/// Thresholds (industry standard):
/// - Normal English text: ~3.5 bits
/// - Compressed/obfuscated: > 4.5 bits  → MEDIUM
/// - Encrypted / truly random: > 5.5 bits → HIGH
class EntropyScanner {
  /// Shannon entropy threshold to emit a MEDIUM finding (bits).
  static const mediumThreshold = 4.5;

  /// Shannon entropy threshold to emit a HIGH finding (bits).
  static const highThreshold = 5.5;

  /// Minimum string length to analyze (short strings are too noisy).
  static const _minLength = 20;

  /// Captures string literals between single or double quotes.
  static final _stringLiteralRe = RegExp(r'''['"]([^'"]{20,})['"]''');

  /// Scans all `.dart` files in [sourceDir] recursively and returns findings.
  Future<List<EntropyFinding>> scan(Directory sourceDir) async {
    final findings = <EntropyFinding>[];
    final basePath = sourceDir.path;

    await for (final entity in sourceDir.list(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;

      final relativePath = entity.path.startsWith(basePath)
          ? entity.path.substring(basePath.length + 1)
          : entity.path;

      final lines = await entity.readAsLines();

      for (var i = 0; i < lines.length; i++) {
        for (final match in _stringLiteralRe.allMatches(lines[i])) {
          final str = match.group(1)!;
          if (str.length < _minLength) continue;

          final entropy = _shannonEntropy(str);
          if (entropy <= mediumThreshold) continue;

          findings.add(EntropyFinding(
            file: relativePath,
            line: i + 1,
            entropy: entropy,
            severity: entropy > highThreshold ? 'HIGH' : 'MEDIUM',
            snippet: str.substring(0, min(60, str.length)),
          ));
        }
      }
    }

    // Sort HIGH before MEDIUM, then by file+line.
    findings.sort((a, b) {
      if (a.severity != b.severity) {
        return a.severity == 'HIGH' ? -1 : 1;
      }
      final fileDiff = a.file.compareTo(b.file);
      if (fileDiff != 0) return fileDiff;
      return a.line.compareTo(b.line);
    });

    return findings;
  }

  /// Calculates the Shannon entropy of [s] in bits per character.
  ///
  /// Formula: H = -∑ p(c) · log₂(p(c))
  static double _shannonEntropy(String s) {
    if (s.isEmpty) return 0;
    final freq = <int, int>{};
    for (final codeUnit in s.codeUnits) {
      freq[codeUnit] = (freq[codeUnit] ?? 0) + 1;
    }
    var entropy = 0.0;
    for (final count in freq.values) {
      final p = count / s.length;
      entropy -= p * (log(p) / ln2);
    }
    return entropy;
  }
}
