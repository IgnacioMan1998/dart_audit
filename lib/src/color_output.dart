import 'dart:io';

/// Whether ANSI color codes should be emitted.
/// Defaults to `true` when stdout is connected to a terminal.
bool colorEnabled = stdout.hasTerminal;

/// Disables ANSI color output. Call once at startup (e.g. when `--no-color`
/// is passed) before any output is printed.
void disableColor() => colorEnabled = false;

String red(String s) => colorEnabled ? '\x1B[31m$s\x1B[0m' : s;
String yellow(String s) => colorEnabled ? '\x1B[33m$s\x1B[0m' : s;
String cyan(String s) => colorEnabled ? '\x1B[36m$s\x1B[0m' : s;
String green(String s) => colorEnabled ? '\x1B[32m$s\x1B[0m' : s;
String bold(String s) => colorEnabled ? '\x1B[1m$s\x1B[0m' : s;
String dim(String s) => colorEnabled ? '\x1B[2m$s\x1B[0m' : s;
