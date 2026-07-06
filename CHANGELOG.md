# Changelog

## [0.5.0](https://github.com/canboat/canboat-rs/compare/v0.4.0...v0.5.0) (2026-07-06)


### Features

* **io:** read Navico .nif and SocketCAN .pcap captures ([5e5ccfc](https://github.com/canboat/canboat-rs/commit/5e5ccfcb6db4565880d591c97193d3cc5fed8403))
* **io:** read Navico .nif and SocketCAN .pcap captures ([9821de7](https://github.com/canboat/canboat-rs/commit/9821de7714d1ff7188b3ffba14337b860ce59074))
* **tui:** Turbo Pascal UI — menus, file browser, async save, faster timeline ([787ea93](https://github.com/canboat/canboat-rs/commit/787ea938f618447ff02a6cfbda207e82e3d23549))
* **tui:** update UI to Turbo Pascal like — menus, file browser, async save, perf & fixes ([4b7cc18](https://github.com/canboat/canboat-rs/commit/4b7cc1891f77766c60534485eac413b5ced09158))


### Bug Fixes

* **core:** decode STRING_LAU with 0xff encoding byte as an empty field ([987fe13](https://github.com/canboat/canboat-rs/commit/987fe135bb8231f827f3c96fed772b2967b8d43a))
* **core:** decode STRING_LAU with 0xff encoding byte as empty ([6b9b4d3](https://github.com/canboat/canboat-rs/commit/6b9b4d3060e1bd0f46bef9d8f300136d70ac541f))
* **core:** parse canboat's dash-separated timestamp in parse_iso_ms ([1fc507d](https://github.com/canboat/canboat-rs/commit/1fc507d41f4d01f4151cc68e720826ba0a5b81be))
* **tui:** keep the PGN-load rate bar visible on the selected row ([17164e2](https://github.com/canboat/canboat-rs/commit/17164e2d53c441abd58802d8f2ede18c007f3c44))
* **tui:** label on-request PGNs "on request" instead of a fake cadence ([82484ad](https://github.com/canboat/canboat-rs/commit/82484adf4bc543e41e1e6044f6b8a6847100d3d3))
* **tui:** PGN-load rate is occurrences over capture duration ([dd74c1a](https://github.com/canboat/canboat-rs/commit/dd74c1aac6e459bf1827465c0e439415cf9fa135))
* **tui:** show a robust median cadence for the device-detail "every" ([b62190e](https://github.com/canboat/canboat-rs/commit/b62190ef5886867043d1c91eb477c02fb5c7373a))

## [0.4.0](https://github.com/canboat/canboat-rs/compare/v0.3.0...v0.4.0) (2026-07-05)


### Features

* **canboat-core:** decode ISO_NAME dynamic field values ([43cc23b](https://github.com/canboat/canboat-rs/commit/43cc23bf034a7b7c07d0302bec790b828b744ad4))
* **canboat-core:** vendor schema inside the crate, pin + gate upstream sync ([76865fb](https://github.com/canboat/canboat-rs/commit/76865fbdb9f08afa5fe6ad209cb63ac67b202570))
* **canboat-pipeline:** binary WirePgn transport, canonical pipeline ports, performance ([465a138](https://github.com/canboat/canboat-rs/commit/465a138e6a75a9dad5243775dd97a3f2d56f6093))
* **canboat-pipeline:** live control channel for the NMEA0183 filter ([f13dbd5](https://github.com/canboat/canboat-rs/commit/f13dbd56d92716cb368c3bedb10468c86151be44))
* **canboat-pipeline:** per-device NMEA0183 filter keyed by NAME ([c2b1a73](https://github.com/canboat/canboat-rs/commit/c2b1a733671438523246c0dd7d1f95bc5d22bf11))
* **canboat-pipeline:** per-device NMEA0183 filter with live control channel and TUI ([37500ab](https://github.com/canboat/canboat-rs/commit/37500ab1e1a35ab1c75e192295433bf7b595aac1))
* **canboat-pipeline:** rate-limit NMEA0183 output to 1 Hz ([cf5a171](https://github.com/canboat/canboat-rs/commit/cf5a17132105142673426d76a38955dda52f6398))
* **canboat-pipeline:** rate-limit NMEA0183 output to 1 Hz ([5259eb6](https://github.com/canboat/canboat-rs/commit/5259eb69dfe57a616731baab9f447a2270661542))
* **canboat-tui:** NMEA0183 filter mode ([d124ea4](https://github.com/canboat/canboat-rs/commit/d124ea4d787c19ffa472e34eefdd4792b270e541))
* **canboat-wire:** binary WirePgn transport for pipeline consumers ([dd2dbe9](https://github.com/canboat/canboat-rs/commit/dd2dbe956f2abfd02f622c0466e6664857a4ff48))
* startup banner with binary version and canboat.json version ([40cf05a](https://github.com/canboat/canboat-rs/commit/40cf05abf51f9deef09adabcb48b158483b6661b))


### Bug Fixes

* **canboat-core:** don't let frame 0 complete a fast packet off stale bits ([3544487](https://github.com/canboat/canboat-rs/commit/35444879a3c361f0546920eee6e04e316c01922a))
* **canboat-core:** don't let frame 0 complete a fast packet off stale bits ([1d04646](https://github.com/canboat/canboat-rs/commit/1d046467eedb27a7466e9b42f2ea7f866730a793))


### Performance Improvements

* **canboat-pipeline:** batch TCP output, serialize JSON once per record ([8f37772](https://github.com/canboat/canboat-rs/commit/8f377727fd3c49737097d5528fd6d72922ea80b3))
* **canboat-pipeline:** batch TCP output, serialize JSON once per record ([4956f9b](https://github.com/canboat/canboat-rs/commit/4956f9b262b9d4287d49a2b2c9f7e5a880bbb160))

## [0.3.0](https://github.com/canboat/canboat-rs/compare/v0.2.0...v0.3.0) (2026-07-04)


### Features

* **analyser:** compile canboat.json into the canboat-core crate ([4036686](https://github.com/canboat/canboat-rs/commit/40366863cb81ac70dcf181adfd277aa0bdb6c602))
* **canboat-core:** ISO Transport Protocol reassembly ([0202997](https://github.com/canboat/canboat-rs/commit/0202997cafe004629244d4e92c00ef85186cc43f))
* **canboat-tui:** connecting modal + fatal-error modal ([26b6a68](https://github.com/canboat/canboat-rs/commit/26b6a6885fa5fba9d257d8331de33ceecf597b6d))
* **canboat-tui:** correct interval in log mode + hide age ([a2ef747](https://github.com/canboat/canboat-rs/commit/a2ef74780a1c81ce0eecba606f066e34f43ae121))
* **canboat-tui:** interactive TUI for n2kd / canboat-pipeline ([9aae7ab](https://github.com/canboat/canboat-rs/commit/9aae7abe85190504b06eb3cfea70f1f1f9c90663))
* **canboat-tui:** log-file replay mode + analyzer library extraction ([b57828c](https://github.com/canboat/canboat-rs/commit/b57828ca8da76c5bdda2e3f9d2d6b4b216a193bd))
* **canboat-tui:** measured transmission interval per PGN row ([f0a1bbe](https://github.com/canboat/canboat-rs/commit/f0a1bbe05e3b718c1d206449ea16f183c04b3172))
* **canboat-tui:** persistent NAME → info cache + return-to on EntryDetail ([c4774d6](https://github.com/canboat/canboat-rs/commit/c4774d625f1f6202b53b4154dc7d1bd9eb1a1901))
* **canboat-tui:** require --host or --log; suppress connect modal in log mode ([cc77dc5](https://github.com/canboat/canboat-rs/commit/cc77dc5cfcbf310e2dd1e81c04aa4ce4a4d9cd1d))
* **canboat-tui:** scrollable entry-detail screen ([53b4523](https://github.com/canboat/canboat-rs/commit/53b45238ec26839adf8b36722235ef25d426dc37))
* **canboat-tui:** surface non-OK PGN 126208 ACKs as status-bar alerts ([0c2ccef](https://github.com/canboat/canboat-rs/commit/0c2ccef868c2d4d281ec2a83e418a6c29c090bef))
* **canboat-tui:** TimeView + per-entry history + ←/→ instance nav ([b4eaed7](https://github.com/canboat/canboat-rs/commit/b4eaed7984a6c9b93ad9904ed05b846270eaf132))
* **canboat-tui:** TimeView search + PGN filter + source multi-select ([842c1ba](https://github.com/canboat/canboat-rs/commit/842c1ba8743fdab658cc1a1d55f93cf3d973f1bc))
* **canboat-tui:** writable-gated overrides; show silenced PGNs ([438a225](https://github.com/canboat/canboat-rs/commit/438a225c2dae7b877759ec12b94d8222610b92f7))
* embed copyright string in help texts, logs, and source files ([5953248](https://github.com/canboat/canboat-rs/commit/59532486f11ebbcc832b04440abf36bb7b763c44))


### Bug Fixes

* accept up to 1785-byte payloads + route TUI logs to a file ([e38e110](https://github.com/canboat/canboat-rs/commit/e38e11014b0dcceee46931c5f182a65d90027bf9))
* **canboat-core:** prefer specific no-Match variant over Fallback range catch-all ([cf2750a](https://github.com/canboat/canboat-rs/commit/cf2750ab1a7982a76e333a81c3d86f0acabfd59e))
* **canboat-core:** treat PGN 126464 Function Code as primary-key ([e74ffac](https://github.com/canboat/canboat-rs/commit/e74ffac5f22f70b6d06ea094fe8405fcd42a6e05))
* **canboat-tui:** advertise `t timeline` in Devices + DeviceDetail hints ([85f91c6](https://github.com/canboat/canboat-rs/commit/85f91c615daf4c2778ae71303741b5ec98647527))
* **canboat-tui:** bump connect timeout to 10s ([5958582](https://github.com/canboat/canboat-rs/commit/59585820f9805c23c7447bebc2ef5772051c9736))
* **canboat-tui:** emit PGN 126208 Request (fn 0), not Command (fn 1) ([b1e629b](https://github.com/canboat/canboat-rs/commit/b1e629b35e5200e30019048ff4eca9601a8f50f9))
* **canboat-tui:** non-blocking startup with bounded connect timeouts ([ebdd321](https://github.com/canboat/canboat-rs/commit/ebdd321945f68d4c4fc81e1a0c3b54e99b17e2f4))
* **canboat-tui:** per-screen keybinding hint bars ([586243b](https://github.com/canboat/canboat-rs/commit/586243b07f447d846794bb1f7ebf72b533640ec8))
* **canboat-tui:** preserve field order in entry-detail JSON view ([1adefa9](https://github.com/canboat/canboat-rs/commit/1adefa98188bd5893273f9a856c47361cafee115))
* **canboat-tui:** round measured interval to a stable step ([7be0f0e](https://github.com/canboat/canboat-rs/commit/7be0f0ed55898e25f5da4948c77a420f49384ed8))
* **canboat-tui:** stop column-shift on first ↓ in device list ([9827575](https://github.com/canboat/canboat-rs/commit/982757532ff036d42ce8f43d1f105ec68c613998))
* repair stale oversized-len test, emit C's match pseudo-unit in text mode ([cd843da](https://github.com/canboat/canboat-rs/commit/cd843da0651f886acb4301c16d3cc8b8a3769911))
