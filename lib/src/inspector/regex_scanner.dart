import 'dart:io';

/// A pattern match found during regex-based source scanning.
class RegexFinding {
  const RegexFinding({
    required this.file,
    required this.line,
    required this.rule,
    required this.severity,
    required this.description,
    required this.snippet,
  });

  /// Relative path of the file where the finding was made.
  final String file;

  /// 1-based line number.
  final int line;

  /// Rule identifier (e.g. `'PROCESS_RUN'`).
  final String rule;

  /// `'CRITICAL'`, `'HIGH'`, `'MEDIUM'`, or `'LOW'`.
  final String severity;

  /// Human-readable explanation of the risk.
  final String description;

  /// Trimmed line content where the match was found (max 120 chars).
  final String snippet;

  Map<String, dynamic> toJson() => {
        'file': file,
        'line': line,
        'rule': rule,
        'severity': severity,
        'description': description,
        'snippet': snippet,
      };
}

/// A single detection rule applied by [RegexScanner].
class _Rule {
  const _Rule({
    required this.severity,
    required this.pattern,
    required this.description,
  });

  final String severity;
  final String pattern;
  final String description;
}

/// Scans Dart source files inside [sourceDir] for suspicious code patterns
/// using a curated set of regular-expression rules.
class RegexScanner {
  /// All detection rules, keyed by rule ID.
  static const _rules = <String, _Rule>{
    // ── Suspicious network ──────────────────────────────────────────────────
    'HARDCODED_URL': _Rule(
      severity: 'HIGH',
      pattern:
          r'''https?://(?!pub\.dev|dart\.dev|google\.com|github\.com|flutter\.dev|raw\.githubusercontent\.com|api\.osv\.dev)[^\s'"]{10,}''',
      description: 'URL hardcoded to unknown domain',
    ),
    'RAW_SOCKET': _Rule(
      severity: 'HIGH',
      pattern: r'RawSocket\.|ServerSocket\.|Socket\.connect',
      description: 'Raw socket usage (may be legitimate — verify context)',
    ),

    // ── Process execution ───────────────────────────────────────────────────
    'PROCESS_RUN': _Rule(
      severity: 'CRITICAL',
      pattern: r'Process\.run\(|Process\.start\(',
      description: 'OS process execution',
    ),
    'SHELL_INJECTION': _Rule(
      severity: 'CRITICAL',
      pattern: r'''Process\.(?:run|start)\s*\(\s*['"](?:bash|sh|cmd|powershell|zsh|/bin/)''',
      description: 'Direct shell invocation',
    ),

    // ── Sensitive filesystem access ─────────────────────────────────────────
    'SENSITIVE_FILE_ACCESS': _Rule(
      severity: 'HIGH',
      pattern: r'''File\s*\(\s*['"](?:/etc/|/proc/|~?/\.ssh/|C:\\Windows\\|AppData\\)''',
      description: 'Access to sensitive system path',
    ),

    // ── Obfuscation ─────────────────────────────────────────────────────────
    'HEX_ENCODING': _Rule(
      severity: 'MEDIUM',
      pattern: r'(?:\\x[0-9a-fA-F]{2}){4,}',
      description: 'Hex-encoded byte sequence (≥4 consecutive bytes)',
    ),
    'BASE64_EVAL': _Rule(
      severity: 'HIGH',
      pattern: r'base64(?:Decode|\.decode)[\s\S]{0,200}(?:Isolate\.spawn|loadLibrary)',
      description: 'Base64-decoded data used with dynamic code execution',
    ),
    'UNICODE_ESCAPE': _Rule(
      severity: 'MEDIUM',
      pattern: r'(?:\\u[0-9a-fA-F]{4}){4,}',
      description: 'Multiple consecutive unicode escapes (possible obfuscation)',
    ),
    'CHAR_CODE_CONCAT': _Rule(
      severity: 'MEDIUM',
      pattern: r'String\.fromCharCode\s*\(.+\)\s*\+',
      description: 'String construction from concatenated char codes',
    ),

    // ── Cryptomining ────────────────────────────────────────────────────────
    'CRYPTO_MINING': _Rule(
      severity: 'CRITICAL',
      pattern: r'(?:stratum\+tcp|mining\.pool|coinhive|monero|xmrig)',
      description: 'Cryptomining-related keyword',
    ),

    // ── Backdoors / reverse shells ──────────────────────────────────────────
    'BACKDOOR_PATTERNS': _Rule(
      severity: 'CRITICAL',
      pattern: r'(?:reverse.?shell|bind.?shell|/dev/tcp|netcat\b)',
      description: 'Backdoor or reverse-shell pattern',
    ),

    // ── Data exfiltration ───────────────────────────────────────────────────
    'DATA_EXFIL': _Rule(
      severity: 'HIGH',
      pattern:
          r'(?:SharedPreferences|FlutterSecureStorage|Keychain)[\s\S]{0,200}https?://',
      description: 'Stored data potentially sent to external URL',
    ),

    // ── Dynamic code loading ────────────────────────────────────────────────
    'DYNAMIC_LIBRARY': _Rule(
      severity: 'HIGH',
      pattern: r'DynamicLibrary\.open\s*\(',
      description: 'Dynamic native library loading',
    ),
    'ISOLATE_SPAWN_URI': _Rule(
      severity: 'HIGH',
      pattern: r'Isolate\.spawnUri\s*\(',
      description: 'Remote code loading via Isolate.spawnUri',
    ),
  };

  /// Scans all `.dart` files in [sourceDir] recursively and returns findings.
  Future<List<RegexFinding>> scan(Directory sourceDir) async {
    final findings = <RegexFinding>[];
    final basePath = sourceDir.path;

    await for (final entity in sourceDir.list(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;

      final relativePath = entity.path.startsWith(basePath)
          ? entity.path.substring(basePath.length + 1)
          : entity.path;

      final lines = await entity.readAsLines();

      for (final entry in _rules.entries) {
        final ruleId = entry.key;
        final rule = entry.value;
        final regex = RegExp(rule.pattern, caseSensitive: false);

        for (var i = 0; i < lines.length; i++) {
          if (regex.hasMatch(lines[i])) {
            findings.add(RegexFinding(
              file: relativePath,
              line: i + 1,
              rule: ruleId,
              severity: rule.severity,
              description: rule.description,
              snippet: lines[i].trim().substring(
                    0,
                    lines[i].trim().length.clamp(0, 120),
                  ),
            ));
          }
        }
      }
    }

    // Sort: CRITICAL first, then HIGH, MEDIUM, LOW; then by file+line.
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    findings.sort((a, b) {
      final severityDiff =
          order.indexOf(a.severity) - order.indexOf(b.severity);
      if (severityDiff != 0) return severityDiff;
      final fileDiff = a.file.compareTo(b.file);
      if (fileDiff != 0) return fileDiff;
      return a.line.compareTo(b.line);
    });

    return findings;
  }
}
