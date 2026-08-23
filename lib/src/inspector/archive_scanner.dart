import 'package:archive/archive.dart';

/// A security finding from scanning a tar.gz archive.
class ArchiveFinding {
  const ArchiveFinding({
    required this.rule,
    required this.severity,
    required this.description,
    required this.entryName,
    this.targetPath,
  });

  final String rule;
  final String severity;
  final String description;
  final String entryName;
  final String? targetPath;

  Map<String, dynamic> toJson() => {
        'rule': rule,
        'severity': severity,
        'description': description,
        'entryName': entryName,
        if (targetPath != null) 'targetPath': targetPath,
      };
}

/// Result of scanning a tar.gz archive for security issues.
class ArchiveScanResult {
  const ArchiveScanResult({
    required this.totalEntries,
    required this.fileCount,
    required this.dartFileCount,
    required this.findings,
  });

  final int totalEntries;
  final int fileCount;
  final int dartFileCount;
  final List<ArchiveFinding> findings;

  bool get isClean => findings.isEmpty;
  bool get isSuspicious => findings.any((f) => f.severity == 'CRITICAL');
}

/// Scans tar.gz archive bytes for malicious structures:
/// - Path traversal via ../ (CVE-2026-27704 vector)
/// - Absolute path entries
/// - Symlink indicators in entry names
/// - Entries with excessively long names (evasion attempt)
class ArchiveScanner {
  static const _maxNameLength = 4096;

  /// Scans decoded [archive] for security issues.
  ArchiveScanResult scan(Archive archive) {
    final findings = <ArchiveFinding>[];
    var fileCount = 0;
    var dartFileCount = 0;

    for (final entry in archive) {
      if (entry.isFile) {
        fileCount++;
        if (entry.name.endsWith('.dart')) dartFileCount++;
      }

      final name = entry.name;

      // Check entry name length.
      if (name.length > _maxNameLength) {
        findings.add(ArchiveFinding(
          rule: 'OVERLONG_NAME',
          severity: 'HIGH',
          description: 'Archive entry name exceeds $_maxNameLength characters '
              '(${name.length}) — potential buffer overflow or evasion attempt',
          entryName: name,
        ));
      }

      // Normalize the path and check for traversal.
      final normalized = _normalizePath(name);
      if (normalized.startsWith('..') || normalized.contains('/../')) {
        findings.add(ArchiveFinding(
          rule: 'PATH_TRAVERSAL',
          severity: 'CRITICAL',
          description: 'Path traversal detected — entry escapes extraction root',
          entryName: name,
        ));
      }

      // Check for absolute paths.
      if (name.startsWith('/') || name.startsWith('\\')) {
        findings.add(ArchiveFinding(
          rule: 'ABSOLUTE_PATH',
          severity: 'CRITICAL',
          description: 'Absolute path in archive — will write to filesystem root',
          entryName: name,
        ));
      }

      // Check for symlink-like patterns in entry name (../ in path segments).
      final segments = name.split('/');
      for (var i = 0; i < segments.length; i++) {
        if (segments[i] == '..') {
          findings.add(ArchiveFinding(
            rule: 'PARENT_TRAVERSAL',
            severity: 'CRITICAL',
            description: 'Entry path contains ".." segment — potential symlink traversal '
                '(CVE-2026-27704 vector)',
            entryName: name,
          ));
          break;
        }
      }

      // Check for hidden files that might be executed.
      final basename = name.split('/').last;
      if (basename.startsWith('.') && basename.isNotEmpty) {
        final extension = _getDartFileExtension(basename);
        if (extension != null) {
          findings.add(ArchiveFinding(
            rule: 'HIDDEN_EXECUTABLE',
            severity: 'HIGH',
            description: 'Hidden file with executable extension: $basename',
            entryName: name,
          ));
        }
      }
    }

    // Sort: CRITICAL first, then HIGH.
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    findings.sort((a, b) {
      final diff = order.indexOf(a.severity) - order.indexOf(b.severity);
      if (diff != 0) return diff;
      return a.entryName.compareTo(b.entryName);
    });

    return ArchiveScanResult(
      totalEntries: archive.length,
      fileCount: fileCount,
      dartFileCount: dartFileCount,
      findings: findings,
    );
  }

  static String _normalizePath(String path) {
    final cleaned = path.replaceAll(r'\', '/');
    final parts = cleaned.split('/').where((p) => p.isNotEmpty).toList();
    final resolved = <String>[];
    for (final part in parts) {
      if (part == '.') continue;
      if (part == '..') {
        if (resolved.isNotEmpty) resolved.removeLast();
      } else {
        resolved.add(part);
      }
    }
    return resolved.join('/');
  }

  static String? _getDartFileExtension(String filename) {
    const executableExtensions = ['.dart', '.sh', '.bat', '.cmd', '.ps1'];
    for (final ext in executableExtensions) {
      if (filename.endsWith(ext)) return ext;
    }
    return null;
  }
}
