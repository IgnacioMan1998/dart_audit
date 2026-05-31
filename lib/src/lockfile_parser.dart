import 'dart:io';

import 'package:yaml/yaml.dart';

/// A resolved package dependency read from `pubspec.lock`.
class LockedPackage {
  const LockedPackage({
    required this.name,
    required this.version,
    required this.source,
    required this.isDirect,
  });

  /// Package name as it appears in pub.dev.
  final String name;

  /// Exact resolved version string (e.g. `'5.8.0+1'`).
  final String version;

  /// Where the package comes from: `'hosted'`, `'git'`, `'path'`, `'sdk'`.
  final String source;

  /// `true` for packages listed directly in `pubspec.yaml`.
  final bool isDirect;

  @override
  String toString() => '$name $version ($source${isDirect ? ', direct' : ''})';
}

/// Result of parsing a `pubspec.lock` file.
class ParsedLockfile {
  const ParsedLockfile({
    required this.hostedPackages,
    required this.skippedPackages,
  });

  /// Packages from pub.dev — auditable via OSV.dev.
  final List<LockedPackage> hostedPackages;

  /// Packages from git/path/sdk — not auditable via OSV.dev.
  final List<LockedPackage> skippedPackages;
}

/// Parses a `pubspec.lock` file and returns all resolved packages.
///
/// [hostedPackages] contains `hosted` (pub.dev) packages auditable by OSV.dev.
/// [skippedPackages] contains `git`, `path`, and `sdk` packages that cannot
/// be audited.
///
/// Throws [FileSystemException] if the file does not exist.
/// Throws [FormatException] if the file is not valid YAML.
ParsedLockfile parseLockfile(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    throw FileSystemException(
      'pubspec.lock not found. Run "dart pub get" first.',
      path,
    );
  }

  final yaml = loadYaml(file.readAsStringSync()) as YamlMap;
  final packages = yaml['packages'] as YamlMap?;
  if (packages == null) return const ParsedLockfile(hostedPackages: [], skippedPackages: []);

  final hosted = <LockedPackage>[];
  final skipped = <LockedPackage>[];

  for (final entry in packages.entries) {
    final name = entry.key as String;
    final info = entry.value as YamlMap;

    final source = (info['source'] as String?) ?? 'unknown';
    final version = (info['version'] as String?) ?? '';
    final dependency = (info['dependency'] as String?) ?? '';
    final isDirect = dependency.startsWith('direct');

    final pkg = LockedPackage(
      name: name,
      version: version,
      source: source,
      isDirect: isDirect,
    );

    if (source == 'hosted') {
      hosted.add(pkg);
    } else {
      skipped.add(pkg);
    }
  }

  // Deterministic order: direct deps first, then transitive, alphabetically.
  int byDirectThenName(LockedPackage a, LockedPackage b) {
    if (a.isDirect != b.isDirect) return a.isDirect ? -1 : 1;
    return a.name.compareTo(b.name);
  }

  hosted.sort(byDirectThenName);
  skipped.sort(byDirectThenName);

  return ParsedLockfile(hostedPackages: hosted, skippedPackages: skipped);
}

