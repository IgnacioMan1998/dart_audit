import 'dart:io';

/// Manages installation and removal of git pre-commit hooks for dart_audit.
class GitHookManager {
  const GitHookManager({this.workingDirectory});

  final String? workingDirectory;

  String get _root => workingDirectory ?? Directory.current.path;

  /// Installs the dart_audit pre-commit hook.
  ///
  /// Uses Git's configured hooks path, so it also works in linked worktrees.
  /// An existing hook is never overwritten.
  bool installHook() {
    final preCommitFile = _resolvePreCommitFile();
    if (preCommitFile.existsSync()) {
      if (isHookInstalled()) return true;
      throw FileSystemException(
        'A pre-commit hook already exists at ${preCommitFile.path}. It was not modified.',
        preCommitFile.path,
      );
    }

    preCommitFile.parent.createSync(recursive: true);
    preCommitFile.writeAsStringSync(_hookContent);

    if (!Platform.isWindows) {
      final result = Process.runSync('chmod', ['+x', preCommitFile.path]);
      if (result.exitCode != 0) {
        throw FileSystemException(
          'Could not make the pre-commit hook executable.',
          preCommitFile.path,
        );
      }
    }

    return true;
  }

  /// Removes only a hook that was installed by dart_audit.
  bool removeHook() {
    final preCommitFile = _resolvePreCommitFile();
    if (!preCommitFile.existsSync() || !isHookInstalled()) return false;
    preCommitFile.deleteSync();
    return true;
  }

  /// Checks whether dart_audit owns the currently configured pre-commit hook.
  bool isHookInstalled() {
    try {
      final preCommitFile = _resolvePreCommitFile();
      return preCommitFile.existsSync() &&
          preCommitFile.readAsStringSync().contains(_marker);
    } on FileSystemException {
      return false;
    }
  }

  File _resolvePreCommitFile() {
    final result = Process.runSync(
      'git',
      ['rev-parse', '--git-path', 'hooks/pre-commit'],
      workingDirectory: _root,
    );
    if (result.exitCode != 0) {
      throw FileSystemException(
        'No Git repository found. Please run this command inside a Git repository.',
        _root,
      );
    }

    final path = (result.stdout as String).trim();
    if (path.isEmpty) {
      throw FileSystemException('Git did not return a hooks path.', _root);
    }
    final isAbsolute = path.startsWith('/') || RegExp(r'^[A-Za-z]:[\\/]').hasMatch(path);
    return File(isAbsolute ? path : '$_root/$path');
  }

  static const _marker = '# Installed by dart_audit hook install';

  static const _hookContent = r'''#!/bin/sh
# Installed by dart_audit hook install

set -u

STAGED_FILES=$(git diff --cached --name-only -- pubspec.yaml pubspec.lock)
[ -n "$STAGED_FILES" ] || exit 0

TEMP_DIR=$(mktemp -d) || exit 1
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

if git diff --cached --name-only -- pubspec.lock | grep -qx 'pubspec.lock'; then
  git show :pubspec.lock > "$TEMP_DIR/pubspec.lock" || exit 1
  echo "dart_audit: Scanning staged pubspec.lock before commit..."
  dart_audit audit --lockfile "$TEMP_DIR/pubspec.lock" || exit 1
fi

if git diff --cached --name-only -- pubspec.yaml | grep -qx 'pubspec.yaml'; then
  git show :pubspec.yaml > "$TEMP_DIR/pubspec.yaml" || exit 1
  echo "dart_audit: Checking staged pubspec.yaml before commit..."
  dart_audit typosquat --pubspec "$TEMP_DIR/pubspec.yaml" || exit 1
fi
''';
}
