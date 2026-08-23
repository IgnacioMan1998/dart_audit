import 'dart:io';

/// A suspicious Unicode character finding.
class UnicodeFinding {
  const UnicodeFinding({
    required this.file,
    required this.line,
    required this.rule,
    required this.severity,
    required this.description,
    required this.snippet,
    required this.codepoint,
  });

  final String file;
  final int line;

  /// Rule identifier (e.g. `'BIDI_OVERRIDE'`, `'HOMOGLYPH'`, `'PUA_CARRIER'`).
  final String rule;

  /// `'CRITICAL'` or `'HIGH'`.
  final String severity;

  final String description;

  /// Line content with the suspicious character marked.
  final String snippet;

  /// The Unicode codepoint as a hex string (e.g. `'U+202E'`).
  final String codepoint;

  Map<String, dynamic> toJson() => {
        'file': file,
        'line': line,
        'rule': rule,
        'severity': severity,
        'description': description,
        'snippet': snippet,
        'codepoint': codepoint,
      };
}

/// Detects Trojan Source attacks (CVE-2021-42574), GlassWorm PUA carriers,
/// homoglyphs, and other suspicious Unicode patterns in Dart source files.
class UnicodeScanner {
  // ── Bidi control characters (CVE-2021-42574) ─────────────────────────────
  // These are invisible characters that can reorder how code is displayed
  // vs how the compiler sees it.
  static const _bidiChars = {
    0x061C: 'ARABIC LETTER MARK',
    0x200E: 'LEFT-TO-RIGHT MARK',
    0x200F: 'RIGHT-TO-LEFT MARK',
    0x202A: 'LEFT-TO-RIGHT EMBEDDING',
    0x202B: 'RIGHT-TO-LEFT EMBEDDING',
    0x202C: 'POP DIRECTIONAL FORMATTING',
    0x202D: 'LEFT-TO-RIGHT OVERRIDE',
    0x202E: 'RIGHT-TO-LEFT OVERRIDE',
    0x2066: 'LEFT-TO-RIGHT ISOLATE',
    0x2067: 'RIGHT-TO-LEFT ISOLATE',
    0x2068: 'FIRST STRONG ISOLATE',
    0x2069: 'POP DIRECTIONAL ISOLATE',
  };

  // ── Zero-width characters (potential steganography) ──────────────────────
  static const _zeroWidthChars = {
    0x200B: 'ZERO WIDTH SPACE',
    0x200C: 'ZERO WIDTH NON-JOINER',
    0x200D: 'ZERO WIDTH JOINER',
    0xFEFF: 'BYTE ORDER MARK (BOM)',
    0x00AD: 'SOFT HYPHEN',
    0x2060: 'WORD JOINER',
    0x180E: 'MONGOLIAN VOWEL SEPARATOR',
  };

  // ── GlassWorm PUA carriers (U+FE00-U+FE0F, U+E0100-U+E01EF) ────────────
  // These render as zero-width whitespace but carry hidden payloads.
  static bool _isPuaCarrier(int cp) {
    return (cp >= 0xFE00 && cp <= 0xFE0F) || // Variation Selectors 1-16
        (cp >= 0xE0100 && cp <= 0xE01EF); // Variation Selectors Supplement
  }

  // ── Homoglyph detection ──────────────────────────────────────────────────
  // Characters that look identical to ASCII but have different codepoints.
  static final _homoglyphs = <int, String>{
    // Cyrillic lookalikes
    0x0430: 'а (Cyrillic a → looks like Latin a)',
    0x0435: 'е (Cyrillic ie → looks like Latin e)',
    0x043E: 'о (Cyrillic o → looks like Latin o)',
    0x0440: 'р (Cyrillic er → looks like Latin p)',
    0x0441: 'с (Cyrillic es → looks like Latin c)',
    0x0443: 'у (Cyrillic u → looks like Latin y)',
    0x0456: 'і (Ukrainian i → looks like Latin i)',
    0x0458: 'ј (Cyrillic je → looks like Latin j)',
    // Greek lookalikes
    0x03B1: 'α (Greek alpha → looks like Latin a)',
    0x03B5: 'ε (Greek epsilon → looks like Latin e)',
    0x03BF: 'ο (Greek omicron → looks like Latin o)',
    0x03C1: 'ρ (Greek rho → looks like Latin p)',
    // Fullwidth ASCII
    0xFF41: 'ａ (Fullwidth a)',
    0xFF45: 'ｅ (Fullwidth e)',
    0xFF4F: 'ｏ (Fullwidth o)',
  };

  /// Scans all `.dart` files in [sourceDir] for suspicious Unicode patterns.
  Future<List<UnicodeFinding>> scan(Directory sourceDir) async {
    final findings = <UnicodeFinding>[];
    final basePath = sourceDir.path;

    await for (final entity in sourceDir.list(recursive: true)) {
      if (entity is! File || !entity.path.endsWith('.dart')) continue;

      final relativePath = entity.path.startsWith(basePath)
          ? entity.path.substring(basePath.length + 1)
          : entity.path;

      final content = await entity.readAsString();
      final lines = content.split('\n');

      for (var i = 0; i < lines.length; i++) {
        final line = lines[i];
        _scanLine(findings, relativePath, i + 1, line);
      }
    }

    // Sort: CRITICAL first, then HIGH; then by file+line.
    const order = ['CRITICAL', 'HIGH'];
    findings.sort((a, b) {
      final severityDiff = order.indexOf(a.severity) - order.indexOf(b.severity);
      if (severityDiff != 0) return severityDiff;
      final fileDiff = a.file.compareTo(b.file);
      if (fileDiff != 0) return fileDiff;
      return a.line.compareTo(b.line);
    });

    return findings;
  }

  void _scanLine(
    List<UnicodeFinding> findings,
    String file,
    int line,
    String content,
  ) {
    for (var i = 0; i < content.length; i++) {
      final cp = content.codeUnitAt(i);

      // Check bidi characters.
      if (_bidiChars.containsKey(cp)) {
        findings.add(UnicodeFinding(
          file: file,
          line: line,
          rule: 'BIDI_OVERRIDE',
          severity: 'CRITICAL',
          description: 'Invisible bidi control character: ${_bidiChars[cp]}',
          snippet: _makeSnippet(content, i),
          codepoint: 'U+${cp.toRadixString(16).toUpperCase().padLeft(4, '0')}',
        ));
      }

      // Check zero-width characters.
      if (_zeroWidthChars.containsKey(cp)) {
        findings.add(UnicodeFinding(
          file: file,
          line: line,
          rule: 'ZERO_WIDTH',
          severity: 'HIGH',
          description: 'Invisible character: ${_zeroWidthChars[cp]}',
          snippet: _makeSnippet(content, i),
          codepoint: 'U+${cp.toRadixString(16).toUpperCase().padLeft(4, '0')}',
        ));
      }

      // Check GlassWorm PUA carriers.
      if (_isPuaCarrier(cp)) {
        findings.add(UnicodeFinding(
          file: file,
          line: line,
          rule: 'PUA_CARRIER',
          severity: 'CRITICAL',
          description: 'Unicode Variation Selector (potential payload carrier — GlassWorm pattern)',
          snippet: _makeSnippet(content, i),
          codepoint: 'U+${cp.toRadixString(16).toUpperCase().padLeft(4, '0')}',
        ));
      }

      // Check homoglyphs.
      if (_homoglyphs.containsKey(cp)) {
        findings.add(UnicodeFinding(
          file: file,
          line: line,
          rule: 'HOMOGLYPH',
          severity: 'HIGH',
          description: 'Confusable character: ${_homoglyphs[cp]}',
          snippet: _makeSnippet(content, i),
          codepoint: 'U+${cp.toRadixString(16).toUpperCase().padLeft(4, '0')}',
        ));
      }
    }
  }

  String _makeSnippet(String line, int position) {
    final start = (position - 15).clamp(0, line.length);
    final end = (position + 15).clamp(0, line.length);
    final prefix = start > 0 ? '...' : '';
    final suffix = end < line.length ? '...' : '';
    final segment = line.substring(start, end);

    // Mark the suspicious character with ← markers.
    final markPos = (position - start).clamp(0, segment.length);
    final marked = '${segment.substring(0, markPos)}'
        '◄HERE►'
        '${segment.substring(markPos)}';

    return '$prefix$marked$suffix';
  }
}
