# hipa-security-file

A decryptor for `query_security_file`

## Build

```sh
zig build
```

Portable C11; Zig is only the build driver.

## Usage

Reads stdin, writes stdout, so it pipes with `curl`:

```sh
curl -s '.../query_security_file?file_key=xxx' | hipa-secfile > config.xml
hipa-secfile response.raw config.xml     # or from a file
```