# hipa-security-file

> This tool, which I built a few months ago, was leaked by someone.
> Gatekeeping became pointless, so I'm making it public.

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

## Notes

By modifying the response with this tool, you can intentionally disable
`mhypbase`'s load flag.

## Disclaimer

This project is provided for educational and research purposes only. It is
offered "as is", without warranty of any kind, express or implied. The author
accepts no liability for any damage, loss, or legal consequence arising from
its use. You are solely responsible for ensuring that your use complies with
all applicable laws and with the terms of service of any third party. Use at
your own risk.