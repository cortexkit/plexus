# Third-party notices

This file records notices for third-party code and data that plexus compiles
into its binaries outside Cargo's dependency graph, the license elections it
makes for dependencies that offer a choice, and the test material it copies
from other repositories. plexus itself is licensed under the MIT License in
[LICENSE](LICENSE).

Full texts of the longer licenses referenced below are in [LICENSES/](LICENSES/).
Ship this file and that directory with every binary distribution of
`ck-plexus` or `ck-plexus-admin`, not only with the source.

## Cargo dependencies

Crates resolved by Cargo keep their own licenses. The locked graphs are
`Cargo.lock` (the workspace and both shipped binaries),
`crates/plexus-probe/guest/Cargo.lock` (the embedded probe guest).
Every external package in these graphs comes from crates.io
and declares a license; each declaration includes a permissive option.

To list each package with its declared license:

```sh
cargo metadata --locked --format-version 1 \
  | python3 -c 'import json,sys; [print(p["name"], p["version"], p["license"]) for p in json.load(sys.stdin)["packages"]]'
```

Repeat with `--manifest-path crates/plexus-probe/guest/Cargo.toml` for the guest
graph. The `license` field is the crate's declaration; the crate's published
source carries the license and copyright files themselves.

Where a declaration joins licenses with `AND`, both apply. The ones that matter
for a binary distribution are recorded in the sections below: `ring`
(`Apache-2.0 AND ISC`), `encoding_rs` (`(Apache-2.0 OR MIT) AND BSD-3-Clause`)
and `unicode-ident` (`(MIT OR Apache-2.0) AND Unicode-3.0`).

## License elections

### `zip` 9.0.3: MIT

The Actions artifact reader uses `zip` under its declared **MIT** license, with
default features disabled and only the flate2/zlib-rs deflate backend enabled.
Source: https://github.com/zip-rs/zip2. Its upstream test archives are not copied
or distributed by plexus; artifact tests generate their own archives in memory.

Two dependencies offer a copyleft license as one alternative among permissive
ones. plexus uses them under the permissive license only.

### `ittapi` and `ittapi-sys` 0.4.0: BSD-3-Clause

Declared `GPL-2.0-only OR BSD-3-Clause`. plexus elects **BSD-3-Clause**. These
crates reach the main graph through Wasmtime's profiling support on x86_64
Linux, macOS and Windows. Source: https://github.com/intel/ittapi.

```text
Copyright (c) 2019 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### `r-efi` 5.3.0 and 6.0.0: MIT or Apache-2.0

Declared `MIT OR Apache-2.0 OR LGPL-2.1-or-later`. plexus elects **MIT or
Apache-2.0**, not LGPL. The crate is reached through `getrandom` only on UEFI
targets, which plexus does not build for. Copyright Red Hat, Inc., Microsoft
Corporation, David Rheinsberg and the other contributors listed in the crate's
`AUTHORS` file. Source: https://github.com/r-efi/r-efi. The Apache-2.0 text is
in [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).

## Embedded probe guest

`ck-plexus` embeds `crates/plexus-probe/assets/plexus-probe-guest.wasm` with
`include_bytes!`, so the guest is redistributed in every copy of the binary.
It is built from `crates/plexus-probe/guest/` for `wasm32-wasip1` by
`scripts/build-probe-guest.sh`, which pins WASI SDK 24.0. The module checked in
at the time of writing is 1,074,508 bytes with SHA-256
`43c251d6e6c4d3641ccb837487fa15aae83a7e825860244a9573bcd9a5baf5a0`.
It was rebuilt on Linux with Rust 1.99.0 and WASI SDK 24.0, with build paths
remapped to neutral prefixes; two clean builds at different checkout, Cargo
home, SDK and target-directory paths produced identical bytes. See the
[guest build provenance](crates/plexus-probe/guest/README.md#build-provenance).

The guest contains the following components in addition to its Cargo
dependencies (`rquickjs`, `serde`, `serde_json` and their dependencies).

### rquickjs 0.12.2: MIT

Rust bindings to QuickJS. Source: https://github.com/DelSkayn/rquickjs.

```text
MIT License

Copyright (c) 2020 Mees Delzenne
Copyright (c) 2025 Rquickjs Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### QuickJS-NG 0.15.1: MIT

The JavaScript engine, vendored as C source in `rquickjs-sys` 0.12.2 and
compiled into the guest. Source: https://github.com/quickjs-ng/quickjs. Its
Unicode tables are generated from Unicode Character Database data; see
[Unicode data](#unicode-data).

```text
The MIT License (MIT)

Copyright (c) 2017-2026 Fabrice Bellard
Copyright (c) 2017-2024 Charlie Gordon
Copyright (c) 2023-2026 Ben Noordhuis
Copyright (c) 2023-2026 Saúl Ibarra Corretgé

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### WASI libc (from WASI SDK 24)

The guest links WASI libc as built by WASI SDK 24, which pins wasi-libc at
commit `b9ef79d7dbd47c6c5bafdae760823467c2f60b70`
(https://github.com/WebAssembly/wasi-libc). Its top-level license reads:

```text
wasi-libc as a whole is multi-licensed under the
Apache License v2.0 with LLVM Exceptions, the Apache License v2.0, and
the MIT License. See the LICENSE-APACHE-LLVM, LICENSE-APACHE and LICENSE-MIT
files, respectively, for details.

Portions of this software are derived from third-party works covered by
their own licenses:

dlmalloc/                     - CC0; see the notice in malloc.c for details
emmalloc/                     - MIT; see the notice in emmalloc.c for details
libc-bottom-half/cloudlibc/   - BSD-2-Clause; see the LICENSE file for details
libc-top-half/musl/           - MIT; see the COPYRIGHT file for details

wasi-libc's changes to these files are multi-licensed under the
Apache License v2.0 with LLVM Exceptions, the Apache License v2.0,
the MIT License, and the original licenses of the third-party works.
```

The Apache License v2.0 with LLVM Exceptions is in
[LICENSES/Apache-2.0-WITH-LLVM-exception.txt](LICENSES/Apache-2.0-WITH-LLVM-exception.txt).
musl's copyright and license file is reproduced unchanged in
[LICENSES/musl-COPYRIGHT.txt](LICENSES/musl-COPYRIGHT.txt). The cloudlibc
license is:

```text
Copyright (c) 2015-2017 Nuxi (https://nuxi.nl/) and contributors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
```

dlmalloc is dedicated to the public domain under CC0 and carries no notice
requirement.

### Rust standard library and compiler runtime

The guest, like both host binaries, links the Rust standard library for its
target. Rust is copyright The Rust Project Contributors and is licensed under
the MIT License or the Apache License 2.0, at the user's option; plexus uses it
under the Apache License 2.0 in [LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).
Some standard-library files carry their own notices; each Rust release lists
them in its `COPYRIGHT-library.html` (see
https://github.com/rust-lang/rust/blob/main/COPYRIGHT). The WASI SDK sysroot
also supplies LLVM compiler-rt builtins under the Apache License v2.0 with LLVM
Exceptions.

## Bundled SQLite

`rusqlite` is built with its `bundled` feature, so `libsqlite3-sys` 0.30.1
compiles SQLite 3.46.0 (source ID
`2024-05-23 13:25:27 96c92aba00c8375bc32fafcdf12429c58bd8aabfcadab6683e35bbb9cdebf19e`)
into both host binaries. SQLite itself is in the public domain
(https://www.sqlite.org/copyright.html). The `libsqlite3-sys` wrapper is MIT
licensed (source: https://github.com/rusqlite/rusqlite):

```text
Copyright (c) 2014-2021 The rusqlite developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## ring 0.17.14

`ring` (https://github.com/briansmith/ring) supplies the TLS cryptography for
outbound vendor and bus connections and compiles bundled C and assembly code, part of it
derived from BoringSSL. It is declared `Apache-2.0 AND ISC`: both licenses
apply, each to different files. Its license files are reproduced unchanged:

- [LICENSES/ring-LICENSE.txt](LICENSES/ring-LICENSE.txt): which license covers which code.
- [LICENSES/ring-LICENSE-other-bits.txt](LICENSES/ring-LICENSE-other-bits.txt): the ISC license, copyright 2015-2025 Brian Smith.
- [LICENSES/ring-LICENSE-BoringSSL.txt](LICENSES/ring-LICENSE-BoringSSL.txt): the BoringSSL-derived code's license and notices.

The `once_cell` polyfill inside `ring` is MIT or Apache-2.0; plexus uses it
under Apache-2.0.

## Unicode data

Unicode Character Database data and data derived from it are compiled into the
binaries by several components: the ICU4X crates (`icu_normalizer_data`,
`icu_properties_data`, `icu_collections` and the related `zerovec`, `yoke`,
`tinystr`, `litemap`, `writeable` and `potential_utf` crates, declared
`Unicode-3.0`), `unicode-ident` (declared `(MIT OR Apache-2.0) AND
Unicode-3.0`), and QuickJS-NG's generated `libunicode-table.h` in the probe
guest. The Unicode License v3 is in
[LICENSES/Unicode-3.0.txt](LICENSES/Unicode-3.0.txt) (copyright 1991-2023
Unicode, Inc.).

## Web PKI root certificates

`webpki-roots` 0.26.11 and 1.0.9 (https://github.com/rustls/webpki-roots)
embed Mozilla's root certificate list, derived from Common CA Database (CCADB)
data, for verifying vendor TLS certificates. The data is licensed under the
Community Data License Agreement Permissive 2.0, reproduced in
[LICENSES/CDLA-Permissive-2.0.txt](LICENSES/CDLA-Permissive-2.0.txt).

## encoding_rs 0.8.35

`encoding_rs` is copyright Mozilla Foundation and used under Apache-2.0. It
includes data derived from the WHATWG Encoding Standard, licensed under the
BSD 3-Clause License in
[LICENSES/encoding_rs-LICENSE-WHATWG.txt](LICENSES/encoding_rs-LICENSE-WHATWG.txt)
(copyright WHATWG: Apple, Google, Mozilla, Microsoft).

## Vendored test material

The following test vectors, fixtures and contract texts are copied from other
repositories so that tests and CI run from this repository alone. None of them
is compiled into a shipped binary.

### Copies from Prefrontal, cortexkit-cloud and cortexkit-account

Prefrontal is distributed under the Sustainable Use License, and
cortexkit-cloud and cortexkit-account have no published license. All three are
owned by Ufuk Altinok, who
permits publishing the copies listed here under this repository's MIT License.
The copies are:

- From Prefrontal (https://github.com/cortexkit/prefrontal):
  - `crates/plexus-core/tests/fixtures/agent-registry/replies.json`, from
    commit `d3ac85d72a7be955c3b0405908246cbb00c61ac2`.
  - `crates/plexus-module/tests/fixtures/elicitation-requester-v1/`, from
    commit `0862c4977602eab9ba50fd5e84658843c7fb2b69`: the JSON vectors and
    `UPSTREAM-README.md`, the upstream contract description.
  - `crates/plexus-module/tests/fixtures/fetch-plan-v1/`: `pf-call-keys.json`
    and the four `relayed-*.json` vectors, from commit
    `e3674ba137889909be06d5d59c85a59f27661f0e`.
    `relayed-web-search-from-opencode-plugin.json` has been modified: it
    omits a retired token field.
  - `crates/plexus-module/tests/fixtures/core-web-search/` (`schema.json` and
    `description.json`), from commit
    `55bdc54475387f5b4178cc40cb56d0df74b7bc53`, and the inputs and expected
    rendering strings in `crates/plexus-module/src/web_search_rendering_tests.rs`
    taken from the same commit's tests. The description has since been changed
    in this repository.
  - The three `*-body.json` files in
    `crates/plexus-module/tests/fixtures/cingulate-consent-requester/vectors/consent-requester-v1/`
    (`grant_lost-body.json`, `reconcile-body.json`, `reenable-body.json`),
    which Cingulate copied from Prefrontal's
    `test-vectors/flow-decision-card-v2/` request inputs.
- From cortexkit-cloud (https://github.com/cortexkit/cortexkit-cloud):
  - `crates/plexus-module/tests/fixtures/webhook-relay/`, from commit
    `908eba9f442e3cf1a95772bfae81808816074a4c`: the `*.jsonl` test vectors and
    `WIRE-CONTRACT.md`, which reproduces lines 242-422 of
    `docs/designs/webhook-relay-spec.md`.
- From cortexkit-account (https://github.com/cortexkit/cortexkit-account):
  - `crates/plexus-conformance/fixtures/account/two-key-overlap-samples.json`,
    from `workers/account/test/fixtures/two-key-overlap-samples.json` at commit
    `f56471b90e49d107663dd16193b243e70acf93dd`: synthetic JWT and key-rotation
    test vectors.

The README or SOURCE file in each directory, or the entry above, records the
exact source path.

### Copies from Cingulate: MIT

Cingulate (https://github.com/cortexkit/cingulate) is licensed under the MIT
License with the notice `Copyright (c) 2026 Ufuk Altinok`. Its license text is
byte-for-byte the same as this repository's [LICENSE](LICENSE). The copies
are:

- `crates/plexus-module/tests/fixtures/cingulate-consent-requester/`, from
  commit `08129bb9166caa2f521258ea65379d83833f4a2a`: the consent requester
  contracts `contracts/consent-requester-v1.md` and
  `contracts/consent-requester-v2.md`, and the vectors under `vectors/`. The
  three Prefrontal-origin bodies listed above are part of this directory.
- `crates/plexus-module/tests/fixtures/permissions-v1/`, from commit
  `a87da8c86f526f2d489adc433517246e1399e604`: the `provider-*` vectors,
  `README.md` and `SHA256SUMS`. `SOURCE.md` is this repository's addition.

### Copy from broca: MIT

`crates/plexus-module/tests/fixtures/fetch-plan-v1/broca-head-plexus-direct.json`
is the fetch plan published in broca (https://github.com/cortexkit/broca) at
`crates/broca-fetch-plan/tests/fixtures/fetch-plan-v1/plans/broca-head-plexus-direct.json`,
licensed under the MIT License with the notice
`Copyright (c) 2026 Ufuk Altinok`, the same text as this repository's
[LICENSE](LICENSE).

### AFT gh shim wire goldens: MIT

`crates/plexus-core/tests/fixtures/gh_shim_wire/` copies AFT's
`docs/investigations/gh-shim-wire-goldens/` at commit `5d879f59f`
(https://github.com/cortexkit/aft). `PROVENANCE.md` is this repository's
addition; every other file is AFT's.

```text
MIT License

Copyright (c) 2025 Ufuk Altinok

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Rust source excerpts in the grep.app capture

`crates/plexus-core/tests/fixtures/grep_app/search.sse` is a recorded grep.app
search response. It quotes code snippets from rust-lang/rust and
rust-lang/rust-clippy, which are copyright The Rust Project Contributors and
licensed under the MIT License or the Apache License 2.0, at the user's option.

### Captured public content

Some fixtures quote public material for parser tests: GitHub issue, pull
request, workflow and release objects from public `cortexkit` repositories
(`crates/plexus-core/tests/fixtures/event-envelope-v2/`,
`crates/plexus-core/tests/fixtures/mc289_get_comments.json` and
`crates/plexus-core/tests/fixtures/github_timeline/`), and a search reply built
from Exa's published API documentation
(`crates/plexus-module/tests/fixtures/web_search/exa_search_reply.json`). Their
text belongs to its authors and is not relicensed by this repository's MIT
License. Each directory's README records where the material came from.

## Algorithms and specifications

- The civil-date conversion in `crates/plexus-core/src/poller.rs`
  (`days_from_civil` and its inverse) follows Howard Hinnant's date algorithms
  (https://howardhinnant.github.io/date_algorithms.html), which their author
  dedicates to the public domain.
- `crates/plexus-core/src/jcs.rs` implements RFC 8785, JSON Canonicalization
  Scheme (https://www.rfc-editor.org/rfc/rfc8785). The golden tests in
  `crates/plexus-core/tests/it/jcs_golden.rs` use the RFC's examples. RFC 8785
  is copyright (c) 2020 IETF Trust and the persons identified as the document
  authors, and is used under the IETF Trust's Legal Provisions Relating to
  IETF Documents (https://trustee.ietf.org/license-info).

## License texts in LICENSES/

| File | License |
|---|---|
| [Apache-2.0.txt](LICENSES/Apache-2.0.txt) | Apache License 2.0 |
| [Apache-2.0-WITH-LLVM-exception.txt](LICENSES/Apache-2.0-WITH-LLVM-exception.txt) | Apache License 2.0 with LLVM Exceptions (Wasmtime, WASI libc, compiler-rt) |
| [CDLA-Permissive-2.0.txt](LICENSES/CDLA-Permissive-2.0.txt) | Community Data License Agreement Permissive 2.0 (`webpki-roots`) |
| [Unicode-3.0.txt](LICENSES/Unicode-3.0.txt) | Unicode License v3 |
| [musl-COPYRIGHT.txt](LICENSES/musl-COPYRIGHT.txt) | musl libc copyright and MIT license |
| [ring-LICENSE.txt](LICENSES/ring-LICENSE.txt), [ring-LICENSE-other-bits.txt](LICENSES/ring-LICENSE-other-bits.txt), [ring-LICENSE-BoringSSL.txt](LICENSES/ring-LICENSE-BoringSSL.txt) | `ring` and its BoringSSL-derived code |
| [encoding_rs-LICENSE-WHATWG.txt](LICENSES/encoding_rs-LICENSE-WHATWG.txt) | BSD 3-Clause, WHATWG encoding data |

Each file is the upstream text, unchanged. `Apache-2.0.txt` is from
https://www.apache.org/licenses/LICENSE-2.0.txt; the others are from the
published crate or the pinned wasi-libc commit named above.
