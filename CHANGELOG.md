# Changelog

User-facing changes for each published version. New release entries are inserted automatically by Python Semantic Release.

<!-- version list -->

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
