# Changelog

User-facing changes for each published version. New release entries are inserted automatically by Python Semantic Release.

<!-- version list -->

## v0.7.1 (2026-10-24)

### Bug Fixes

- Normalize resource IDs before metadata lookup
  ([`5c53078`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5c530782e0556423901a520d7ad3a180dd144d59))

### Code Style

- Format resource normalization regression tests
  ([`944da5f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/944da5ffcd18b8dbcc4de39b13fe9754c2b8d0a1))

### Documentation

- Clarify canonical resource resolution contract
  ([`41609ef`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/41609ef21f984a72ebf4dea14463174b3a2c78d6))

### Testing

- Cover resource normalization across authorization paths
  ([`504e2d0`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/504e2d0dab883146608183bc50b5930eb84e0244))


## v0.7.0 (2026-10-24)

### Bug Fixes

- Require resolved MCP Context annotation
  ([`2c6c6c9`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2c6c6c994ca66207bec96d4771db1752c2d52fa0))

### Build System

- Add optional MCP SDK extra
  ([`35906d3`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/35906d33cedfcde7c7b411e71879e4867ba3e5f5))

### Code Style

- Finalize sorted test imports
  ([`e7a8019`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/e7a8019519aed136aa6f05766e434de413c48b7c))

- Fix MCP adapter lint findings
  ([`2534b0d`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2534b0debe7f71cd87261d03747134161df759ff))

- Format async MCP test principal resolver
  ([`5195e26`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5195e26b0c1b7c05e6181f4b1854bd9246e232d5))

- Format MCP context resolver
  ([`71baf43`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/71baf431cbe681ba6ccd67219a2df3e82faedb84))

- Normalize MCP test imports
  ([`8ff5b2f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/8ff5b2f92542911014e471de4023028c96b9c70d))

- Order MCP adapter test imports
  ([`8741e0d`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/8741e0da0fc0134baa184b4154c926cc639c65a6))

- Restore Ruff-sorted test imports
  ([`08756b9`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/08756b91ef29270574814ace4ed876a97b825fd9))

- Sort MCP adapter test imports
  ([`d701cfc`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/d701cfc348f5200599a0f7ed0102dd194214e6ae))

### Continuous Integration

- Diagnose MCP test import ordering
  ([`06d5776`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/06d57763469f60814e5bc1f237aee4e9bddbd492))

- Remove temporary import diagnostic
  ([`f03a962`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f03a962f7bda8303c8fe6a93d864f20e2000652f))

- Scope MCP smoke-test policy to trusted role
  ([`6a038cd`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6a038cd1c3af42f6ab1f45f4ced04559677ae742))

- Scope MCP smoke-test policy to trusted role
  ([`eeceef9`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/eeceef938e2de7dd277243a7b493ec6fbe35210c))

- Smoke-test optional MCP tool adapter
  ([`5fe8562`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5fe85625f5c098ff7c3676fa828b26102a25f7b0))

- Smoke-test optional MCP tool adapter
  ([`f0fe066`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f0fe06652f55f69c524c18ece237bcaf32eb9479))

### Documentation

- Add MCP tool authorization guide
  ([`d1b236d`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/d1b236d812f3ff0964edae614d193db8b9d8633b))

- Clarify MCP authorization boundary in docs/audit-events.md
  ([`646d9ff`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/646d9ff91f4417798ad043072862e403b8f59572))

- Clarify MCP authorization boundary in README.md
  ([`12783df`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/12783df65c18e8349ad469a75c7074b429dd9422))

- Clarify MCP security boundary in docs/threat-model.md
  ([`babb362`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/babb3624c170504b1d0955e7db4c1bd83611581c))

- Clarify MCP security boundary in SECURITY.md
  ([`5aa4513`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5aa4513d090b14afcaeef61bf7960f94f7d34153))

- Distinguish MCP audit correlation fields
  ([`28734bd`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/28734bd29c80ddf757b72a6d253dc2fee060a16e))

- Document optional MCP tool authorization
  ([`367d652`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/367d6526bf0f7aad72b875c1925e74f6d0c3604b))

- Format MCP README example
  ([`867a588`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/867a588a99b427a1b7dd92a48790b211eddd7249))

### Features

- Add optional MCP tool authorization adapter
  ([`41170a9`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/41170a9e729bc9760ae91382389f1f1499fc9ff0))

- Add secured MCP server example
  ([`a79af73`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/a79af735ef2b92cb206160efac844d0c369e2795))

### Testing

- Add principal role to async MCP policy
  ([`73dcd7f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/73dcd7f18e3b056936f89f447ce4612a3651f7b9))

- Assert MCP denials as protocol error results
  ([`d57dbe8`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/d57dbe8788e0b113dc820a8f16ebc6197647fe1c))

- Cover MCP tool authorization adapter
  ([`d3854df`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/d3854dfa352b4c0e6bb8b18b7112fbb3c7e35377))

- Import audit event from public API
  ([`f21b7a0`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f21b7a00d03cf3df90f001f1bef06b178aa8450e))

- Remove function call from context default
  ([`ba4f99e`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/ba4f99ef0fdfb55b6adda78d88297507af6118a7))

- Tighten MCP context validation case
  ([`45f7fc6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/45f7fc62873aca053cd80472e2f6a096f6323242))


## v0.6.0 (2026-10-24)

### Bug Fixes

- Scope audit summary to current demo run
  ([`3056bb6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3056bb6f562cbf8496419b3a7256709ab43d02dd))

- Tighten end-to-end demo types and formatting
  ([`e686d61`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/e686d614bb863907dc6914aa6a2400f1594e5f85))

### Chores

- Ignore local security demo databases
  ([`9cea72d`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/9cea72d9516ebc8d5abcad0cc300722ae3257cdb))

### Documentation

- Document end-to-end security workflow
  ([`869ceb2`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/869ceb2433c0159650efbb12dfc2a6770dad676c))

### Features

- Add end-to-end secure agent workflow demo
  ([`8978a5e`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/8978a5e9dbcac57b498419b76dbbb04e7172a8bb))

### Testing

- Account for checkpoint resume audit events
  ([`18fc945`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/18fc945a8a35c452670932e5a831d2dd5c6f4b28))

- Cover end-to-end security workflow
  ([`5c40cba`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5c40cbad14b87f3a887fcfb73f553c2a85a15376))

- Verify demo reports remain scoped across persistent runs
  ([`64d0fe8`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/64d0fe89c3425e98bbd158740ed09996329931c7))


## v0.5.1 (2026-10-24)

### Documentation

- Sync README with v0.5.0 security APIs
  ([`ce83ce9`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/ce83ce9f3f694cc99df71b3c4af4b8e3f6505e27))


## v0.5.0 (2026-10-24)

### Bug Fixes

- Annotate all guard overloads for policy registry
  ([`596d2d8`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/596d2d87dcc07338970e92675e1cf3d16565bd9c))

- Audit the exact active policy snapshot
  ([`e079c02`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/e079c021140c4c43626f0897a1692326e4acc255))

- Audit the exact active policy snapshot
  ([`6066145`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6066145e71eb8b10e7f4ad2930fc898d253265e9))

- Narrow policy registry type in middleware
  ([`b70561f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/b70561f4f0e6a0fcf27bbb47cf51d6bce241b814))

- Narrow policy registry type when capturing guard snapshot
  ([`7d29aa5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/7d29aa51faadf3f3768d07b6050b0275d8b0e8e0))

- Normalize audit hash serialization for lint
  ([`eb93b86`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/eb93b864db91c40ae60715adb16a9ed5a81af37b))

- Preserve the guard policy validation message
  ([`fa83c13`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/fa83c131a8752ccff76e15d20abf8f9eef698603))

- Preserve the middleware policy validation message
  ([`8dfe06b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/8dfe06be5a6aa7013babb80139b32317b226da55))

- Use unambiguous hash-chain separators
  ([`662540a`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/662540a9b98f1c365419709e89010cd1badbc203))

### Code Style

- Format ABAC test condition
  ([`6d04359`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6d043597eb70d34b1689217b6f9d98aed90219b0))

- Format policy registry test update
  ([`d8a349b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/d8a349b91c56aabe9efd0980fcc30d4273b876b2))

- Format replay assertion
  ([`5210af4`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5210af4f4bc6ac3fddb8bd81fedfbfcbe974035e))

- Match formatter spacing for added tests
  ([`3a7307e`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3a7307e2290f94fa76e59f0d2a06c16594065d3d))

- Match formatter spacing for added tests
  ([`7db15f2`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/7db15f2e95420a9a9e6b33e354a5f4a6b70022f4))

- Match formatter spacing for added tests
  ([`a623ecc`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/a623eccdddd17a2c9b0d12998d366071aec44d23))

- Match formatter spacing for added tests
  ([`ad06f21`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/ad06f21dc368e86b89e013785d15f88d841c3837))

- Normalize approval store end-of-file
  ([`68a7fa6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/68a7fa60b44644557c8cf64c4a02cd968996ea03))

- Normalize approval-store test SQL
  ([`bd5e950`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/bd5e9504a8f54ef4c77be66871e57cc788f5bb07))

- Normalize policy registry conditions
  ([`83a734b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/83a734b67f5c3aadc718bfa46641a242f4924596))

- Normalize rollback compare-and-swap
  ([`a256530`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/a2565305625715a6267c0b94368e0b6620981359))

- Normalize test file endings
  ([`6892eda`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6892eda631f684a7c7c3c724e8cf78387d216ca5))

- Normalize test file endings
  ([`5b4495d`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5b4495d3c28ade6441642fcfa391e5dfc7f379f3))

- Normalize test file endings
  ([`162ad7c`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/162ad7c66509d2d14235b40d9142c680d10dcb1e))

- Normalize test file endings
  ([`3de23a5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3de23a586fd5df72f8450630b849d00397fc31b7))

- Simplify audit hash-chain query
  ([`0f84a12`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/0f84a12c25b04c76aa4d389377fff15ddc0ab9df))

- Sort standard library imports
  ([`cbce22f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/cbce22f6552aab382e83aef993eb8685d82d0994))

- Sort standard library imports
  ([`e28b7c8`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/e28b7c8610de34bf29309eb7a93d82d578b2d0a4))

- Wrap audit pagination validation
  ([`62d63aa`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/62d63aa1479aa9ac2f498f3b384463ea4fe6a2ac))

- Wrap middleware request fixture
  ([`9fdc51c`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/9fdc51c3e9aeb831e6d5a7961942b94412e9a9ac))

- Wrap middleware validation and metadata
  ([`5a755be`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5a755bea9d1fdee0a4dd691a66aa4e73549a7525))

- Wrap policy snapshot audit metadata
  ([`3abcbe2`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3abcbe25fb1ef8290c5ea37373a186b686460326))

### Documentation

- Add secure approval store integration guide
  ([`386fd82`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/386fd82733f5bc6391242c0554b2ffb5b881dfd0))

- Clarify approval fingerprint retention boundary
  ([`4289de4`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/4289de48734d27951df7e84c436350bcfe41b1c5))

- Clarify built-in approval store security boundary
  ([`29f9349`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/29f93497d6262974492d6e0760af919fb31cc027))

- Document operational security primitives
  ([`281c31b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/281c31b3004bf3b8a95f8efdc7827b312ee73773))

- Document SQLite audit durability and chain limits
  ([`5fad683`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5fad68324494891fc27c34f76b4c9a5ce1abd8ea))

- Explain atomic policy publication and rollback
  ([`f81912f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f81912feaa55ca63ffc6b97c0f8e6791d05e2f7d))

- Explain trusted reviewer binding in middleware
  ([`2f189c6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2f189c6da2bf8abd326c5a8f7eb9b023d393c5d2))

- Update threat model for atomic policy, approval, and audit stores
  ([`54b74be`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/54b74be749677c40fc42f4dbf1dd76e1a60a1757))

### Features

- Add atomic policy registry and rollback
  ([`3a13c53`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3a13c5381d9a95d89858e10b7a8f40d5c91c0aa2))

- Add durable single-use approval store
  ([`c1c48c5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/c1c48c5f5266042304f19c8aab147864d12e73b2))

- Add durable tamper-evident SQLite audit sink
  ([`6180970`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/61809702c2d5ad2a118ee919328b0ed36b8ccfe3))

- Export approval, policy registry, and audit persistence APIs
  ([`7adea59`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/7adea598c790bb2c99549d938112168ad0b0fb3c))

- Integrate approval store and live policy snapshots into middleware
  ([`cecc360`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/cecc360598c340b5379b0bda1382a353f8c01f52))

- Support atomic policy registry in callable guards
  ([`f18d260`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f18d260d42a585af2bb138146f669eecdf073758))

### Refactoring

- Simplify policy registry middleware tests
  ([`2521578`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2521578acc8bc52a606d96674a3df6ad219092c8))

### Testing

- Add authorization invariant and adversarial property checks
  ([`5283db2`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5283db2a1a204ac93152779bf013f699a146cb50))

- Cover approval expiry, replay, and concurrent consumption
  ([`50c5b67`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/50c5b67886394643694499e9fc1a016df8ac146a))

- Cover atomic policy reload, rollback, and guard integration
  ([`8ccc35d`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/8ccc35d18cc544017b014da7f0f3d96f595d27a6))

- Cover audit event validation and callback misuse
  ([`f34ca20`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f34ca20e6cc6a270a8af061f2058a3e9346d0c44))

- Cover durable audit persistence and tamper detection
  ([`77f632b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/77f632b5da33a94b5330bd80c5963fbd94334c17))

- Cover invalid policy registry inputs and stale rollback
  ([`f1f4d31`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f1f4d319e867319569f664852da2ddbe44f43021))

- Cover malformed and mismatched audit chain payloads
  ([`de994e7`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/de994e72bd1754901e6321ef2a35acd268ca152e))

- Cover middleware approval grants and policy snapshots
  ([`bb521cf`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/bb521cff9c9508128054ae0c3bd3a1e2d592055e))

- Cover optional middleware resolver validation
  ([`1c5d529`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/1c5d5291eab3ac2ed641819ff9936a5122356cdf))

- Cover structured audit and correlation resolver validation
  ([`bcbdab5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/bcbdab538e770700cc983df2d3aabf6ccd860ec9))

- Verify approval transactions roll back on database failures
  ([`77c7573`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/77c7573f3eb8f93081f97c89364b8885602507f9))

- Verify concurrent audit appends preserve hash-chain integrity
  ([`7a0480e`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/7a0480e2e30609301843525fa329934a9f593091))

- Verify concurrent policy updates use compare-and-swap
  ([`5dee8b4`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5dee8b450d92a327f89bd4ff7c2143e4e866a500))


## v0.4.0 (2026-10-24)

### Features

- **audit**: Add structured authorization events and OpenTelemetry integration
  ([`ca721fd`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/ca721fde07032fc0c9ce788cc8e4a2c4b17db239))


## v0.3.1 (2026-10-24)

### Bug Fixes

- **validation**: Enforce strict semantic versions for policy bundles
  ([`6e8d7a9`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6e8d7a9a1f22b948f84ebb23c1e0458d720ba2e8))


## v0.3.0 (2026-10-24)

### Bug Fixes

- **bundle**: Compare effective outcomes in policy simulation
  ([`2e1112a`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2e1112a00426a79e178009850d5b3a040ee5b2eb))

- **bundle**: Import diagnostic severity enum
  ([`0a956fc`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/0a956fc849e9fd066c776e4ff1a451bbf72433a0))

- **bundle**: Normalize invalid policy version errors
  ([`bc68672`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/bc6867259f36733668ee1f2c02a15abe49c16f2b))

- **bundle**: Parse declared rule effects into typed enums
  ([`02004c6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/02004c688af5e1dbfb83664b1f4ba7ff0641bb64))

- **bundle**: Reject duplicate YAML keys and normalize file errors
  ([`fa86bb0`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/fa86bb057c9a7df8a7c150a359cf667a5421aac5))

- **bundle**: Remove redundant parser type ignores
  ([`232c8c2`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/232c8c26cf97819fd3b2b5b2a7e02019647d2afb))

- **bundle**: Strictly validate schema and condition field types
  ([`790974f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/790974f4241528408b3b4c0421314856df413b77))

- **bundle**: Type simulation and explanation APIs
  ([`90ba29e`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/90ba29ec9e8dd93cb1b3ec285a5b0bab25a1e789))

- **example**: Print policy bundle report sections cleanly
  ([`538feee`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/538feee9987f7d307fdcdaa52691007cc6f02200))

### Build System

- **dev**: Install PyYAML typing stubs for strict mypy
  ([`ce67b10`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/ce67b10ebcd639017185c5b41587788920c703e8))

### Code Style

- **api**: Organize public bundle exports
  ([`3da3ac0`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3da3ac0e8c7fa303df432e08a602ad5c6aed4a4b))

- **bundle**: Align source with formatter output
  ([`8696d04`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/8696d0402cde23448f5e6689191ce4be6b14fefd))

- **bundle**: Align test module with formatter output
  ([`2b7f419`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2b7f4192792cf5294c610215a111057d8e9e5608))

- **bundle**: Normalize spacing before file tests
  ([`4960129`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/4960129a303287d757ac1751b468980ba672166f))

- **bundle**: Normalize spacing before parser edge tests
  ([`65f27e5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/65f27e59081ba8305976dc043714b751af755b35))

- **bundle**: Satisfy import and line-length checks
  ([`4122adc`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/4122adcf337232e0355756a81be817b6e380c819))

- **bundle**: Separate JSON parser tests consistently
  ([`9832ce5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/9832ce5fcb22fe1d9eab0de30a98b3cc1267cd4d))

- **bundle**: Wrap long test expressions
  ([`df2b0b7`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/df2b0b74a0fba11c3a31de05bc0fcf03eb022114))

- **policy**: Follow formatter for numeric comparison condition
  ([`bf1f80c`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/bf1f80c481cc28efcb78e7f84cf6300fc977bfc0))

- **policy**: Wrap long explanation condition
  ([`706a73e`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/706a73e41ddd0a6be503e2b671f25fcbfa27b2cc))

### Documentation

- **bundle**: Document declarative policy workflow
  ([`01264f6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/01264f60d9243c8c0178186f74279e1ac88168d5))

- **bundle**: Explain policy format lint and simulation
  ([`278c7c3`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/278c7c38cbcfc2c16757986ae1e00153ab36f02a))

- **example**: Add policy bundle simulation workflow
  ([`640fa1a`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/640fa1a9efd8d21687497a148168368c6c457548))

- **example**: Add tenant-aware payroll policy bundle
  ([`2f47872`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2f4787234456e46105bf26147c769cde0bbf3ff6))

- **security**: Document policy bundle trust boundaries
  ([`6b0e0e1`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6b0e0e1c7b87ba1d0b12b264fdc4095727d8c6d2))

### Features

- **api**: Export policy bundle and diagnostic APIs
  ([`53708d6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/53708d634cf292be5560384dff2968e86ffd46ad))

- **bundle**: Add immutable versioned policy bundles
  ([`db868f8`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/db868f86ce16c7a48aaa307600b15ed05c3fef07))

- **bundle**: Lint broad policy scopes and redundant conditions
  ([`3cae776`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3cae776f5abacde473e48b11f1d03fa72167aab9))

- **bundle**: Load and save policy bundles by file type
  ([`db2a149`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/db2a149c1bcda2b6319ab5a1d082f5a8378b34ab))

- **bundle**: Simulate candidate policy and baseline outcomes
  ([`97c2ceb`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/97c2ceb11ebd905cc7e506f458b3932557930abf))

- **package**: Add optional YAML policy bundle support
  ([`51c567a`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/51c567a5270f1b0c2c6adb2c12edb43af9f516fb))

- **policy**: Explain authorization decisions by rule
  ([`d850ce1`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/d850ce191cb6cc806935978ff88dd423ead686a1))

### Testing

- **bundle**: Assert simulation report omits request fields
  ([`765277b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/765277ba92763c9db661d3c97f5c4e36af59aa5b))

- **bundle**: Cover file formats and strict YAML validation
  ([`b02580f`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/b02580f36d9e18edef50f7bdb070dbb0b2b8d132))

- **bundle**: Cover policy simulation and baseline diffs
  ([`5933735`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/5933735167bf703d262aa38356cb56b6730d9125))

- **bundle**: Cover strict parser failure paths
  ([`c0e86ad`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/c0e86ad9263eed505b7fc3593e9903d10a502d5a))

- **bundle**: Cover strict policy serialization and validation
  ([`25b5127`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/25b51276bd326d4fc5fcbbd7a7a02571fb692d1d))

- **bundle**: Distinguish outcome changes from reason changes
  ([`616a0e6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/616a0e61bfa2ad61011d28cdad8a0feba0d1c23b))

- **bundle**: Exercise JSON recursion handling without deep fixtures
  ([`7626db6`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/7626db60d29e1dd2a740f7acd9dfd2d5388509c2))

- **bundle**: Reject non-string policy versions
  ([`b2cde1a`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/b2cde1a40caea1ad018559ddd4cc9e6e71e49681))

- **bundle**: Type invalid file path fixture correctly
  ([`3d2d0a5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/3d2d0a58df72ae0799feb91c71b8a5d06adbb628))

- **bundle**: Type temporary policy paths correctly
  ([`c563972`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/c563972bc57216e471a8ddad13eed1cb3f534af3))

- **bundle**: Use raw regex strings for expected errors
  ([`f8a6fb1`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/f8a6fb10013ceaa2e020141a119c668b2186a7bd))

- **bundle**: Verify policy lint diagnostics
  ([`e1db607`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/e1db6079aa46110d063e5453321418f7e3cc27ba))

- **example**: Exercise policy bundle workflow end to end
  ([`e9f36c5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/e9f36c55145935d4dc6ad02ce97b462e77da016d))

- **policy**: Cover built-in attribute paths and safe comparisons
  ([`41a5e79`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/41a5e79fa9142ccf69afbcc95f7224259d5ae69b))

- **policy**: Verify explain traces and safe redaction
  ([`a94eaa5`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/a94eaa535560cf9bb29d810dc83538c0cfeb4056))


## v0.2.0 (2026-10-24)

### Features

- **abac**: Add attribute-based authorization
  ([`6d78f3b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6d78f3b852990194b05819254b42cbdcd7a87adc))


## v0.1.1 (2026-10-24)

### Bug Fixes

- **release**: Publish every project update to PyPI
  ([`0b80b08`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/0b80b08028e595accc12900cfc46fc474868f5d4))

### Documentation

- Polish README for package users
  ([`2c7ad21`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2c7ad2158dad3f6fad6934a54f61a19db36aa0a6))


## 0.1.0

- Initial public release of the deterministic authorization policy engine.
- Default-deny policy evaluation with deny-overrides semantics and constrained wildcards.
- Synchronous and asynchronous callable protection.
- Optional LangChain/LangGraph agent middleware for tool-call authorization.
- Human-approval interrupts for selected sensitive actions.
- Security guidance covering trusted identity, resource resolution, auditing, and downstream enforcement.
