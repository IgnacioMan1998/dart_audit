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

/// Parses a `pubspec.lock` file and returns all resolved packages.
///
/// Only `hosted` (pub.dev) packages are returned — `path`, `git`, and `sdk`
/// sources are skipped because OSV.dev indexes pub.dev packages only.
///
/// Throws [FileSystemException] if the file does not exist.
/// Throws [FormatException] if the file is not valid YAML.
List<LockedPackage> parseLockfile(String path) {
  final file = File(path);
  if (!file.existsSync()) {
    throw FileSystemException(
      'pubspec.lock not found. Run "dart pub get" first.',
      path,
    );
  }

  final yaml = loadYaml(file.readAsStringSync()) as YamlMap;
  final packages = yaml['packages'] as YamlMap?;
  if (packages == null) return [];

  final result = <LockedPackage>[];

  for (final entry in packages.entries) {
    final name = entry.key as String;
    final info = entry.value as YamlMap;

    final source = (info['source'] as String?) ?? 'unknown';

    // OSV.dev only indexes pub.dev hosted packages.
    if (source != 'hosted') continue;

    final version = (info['version'] as String?) ?? '';
    final dependency = (info['dependency'] as String?) ?? '';
    final isDirect = dependency.startsWith('direct');

    result.add(LockedPackage(
      name: name,
      version: version,
      source: source,
      isDirect: isDirect,
    ));
  }

  // Deterministic order: direct deps first, then transitive, alphabetically.
  result.sort((a, b) {
    if (a.isDirect != b.isDirect) return a.isDirect ? -1 : 1;
    return a.name.compareTo(b.name);
  });

  return result;
}
