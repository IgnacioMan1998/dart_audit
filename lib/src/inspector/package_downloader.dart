import 'dart:convert';
import 'dart:io';

import 'package:archive/archive.dart';
import 'package:http/http.dart' as http;

const _pubApi = 'https://pub.dev/api/packages';
const _downloadTimeout = Duration(seconds: 60);

/// Downloads and extracts the Dart source files of a pub.dev package version
/// into a temporary directory. Only `.dart` files are extracted.
class PackageDownloader {
  PackageDownloader({http.Client? client}) : _client = client ?? http.Client();

  final http.Client _client;

  /// Downloads [packageName] at [version] and extracts `.dart` files into a
  /// temporary directory. Returns the directory; the caller is responsible for
  /// deleting it when done.
  ///
  /// Throws [PackageNotFoundException] if the package/version is not on pub.dev.
  /// Throws [http.ClientException] on network errors.
  Future<Directory> download(
    String packageName,
    String version, {
    void Function(String status)? onStatus,
  }) async {
    onStatus?.call('Fetching metadata for $packageName $version...');

    // 1. Resolve archive URL from pub.dev API.
    final metaResponse = await _client
        .get(Uri.parse('$_pubApi/$packageName/versions/$version'))
        .timeout(_downloadTimeout);

    if (metaResponse.statusCode == 404) {
      throw PackageNotFoundException(packageName, version);
    }
    if (metaResponse.statusCode != 200) {
      throw http.ClientException(
        'pub.dev API returned ${metaResponse.statusCode} for $packageName $version',
      );
    }

    final meta = jsonDecode(metaResponse.body) as Map<String, dynamic>;
    final archiveUrl = meta['archive_url'] as String?;
    if (archiveUrl == null) {
      throw http.ClientException('No archive_url in pub.dev response for $packageName $version');
    }

    // 2. Download the .tar.gz archive.
    onStatus?.call('Downloading source archive...');
    final archiveResponse =
        await _client.get(Uri.parse(archiveUrl)).timeout(_downloadTimeout);

    if (archiveResponse.statusCode != 200) {
      throw http.ClientException(
        'Failed to download archive for $packageName $version (${archiveResponse.statusCode})',
      );
    }

    // 3. Decompress and extract only .dart files.
    final tempDir = await Directory.systemTemp
        .createTemp('dart_audit_${packageName}_${version}_');

    try {
      final archive = TarDecoder().decodeBytes(
        GZipDecoder().decodeBytes(archiveResponse.bodyBytes),
      );

      var fileCount = 0;
      for (final file in archive) {
        if (!file.isFile) continue;
        // Normalize path: some archives have a leading component.
        final relativePath = _normalizePath(file.name);
        if (!relativePath.endsWith('.dart')) continue;

        final outFile = File('${tempDir.path}/$relativePath');
        await outFile.create(recursive: true);
        await outFile.writeAsBytes(file.content as List<int>);
        fileCount++;
      }

      onStatus?.call('Extracted $fileCount Dart file(s).');
    } catch (_) {
      // Clean up temp dir if extraction fails.
      await tempDir.delete(recursive: true);
      rethrow;
    }

    return tempDir;
  }

  /// Strips a leading path component that pub.dev archives sometimes include
  /// (e.g. `http-1.2.0/lib/src/foo.dart` → `lib/src/foo.dart`).
  static String _normalizePath(String name) {
    // Remove leading slash or drive letter.
    final cleaned = name.replaceAll(r'\', '/').replaceAll(RegExp(r'^/'), '');
    // Drop first component if it looks like "package-version/".
    final firstSlash = cleaned.indexOf('/');
    if (firstSlash > 0) {
      final first = cleaned.substring(0, firstSlash);
      // Heuristic: first component contains a digit (version number).
      if (RegExp(r'\d').hasMatch(first)) {
        return cleaned.substring(firstSlash + 1);
      }
    }
    return cleaned;
  }
}

/// Thrown when a package/version combination does not exist on pub.dev.
class PackageNotFoundException implements Exception {
  PackageNotFoundException(this.packageName, this.version);

  final String packageName;
  final String version;

  @override
  String toString() =>
      'Package $packageName@$version not found on pub.dev. '
      'Check the name and version are correct.';
}
