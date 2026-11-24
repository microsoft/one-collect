# Cargo Features - Optional Capabilities Design Document

## Overview

Cargo features let consumers choose functionality without building dependencies
for capabilities they do not use. This can reduce compilation and dependency
maintenance while preserving a useful default configuration. Removing unused
code at link time does not remove its packages from the build graph.

Use a shared core and a small set of optional capabilities. The goal is useful
configurations with clear boundaries, not the fewest possible dependencies.

## Feature Boundaries

The core is the functionality available without optional features. Keep the APIs
and infrastructure required for basic collection there. A dependency can be
optional only if the core does not need it.

Name features after consumer-visible capabilities, such as `scripting` or
`export-pprof`, rather than the libraries that implement them. Gate each
capability's APIs, implementation, and required dependencies together.

Add a feature when:

- The library remains useful to consumers who do not need the capability.
- The capability's APIs and implementation can be separated from the core.
- The dependencies or compilation it avoids justify the added implementation,
  documentation, and testing.

Prefer a small set of capability-level features over switches for individual
helpers or dependencies. If a feature boundary requires substantial
restructuring, evaluate that restructuring separately.

Select platform-specific dependencies through Cargo target conditions. Use
features to select optional functionality within supported platforms.

## Compatibility and Composition

Keep the default configuration useful and consistent for typical consumers.
Making an existing capability optional should preserve its default APIs and
behavior. Changing its default availability is a separate compatibility decision.
Evaluate new capabilities against the same intended default experience, rather
than automatically including or excluding them.

Consumers can use `default-features = false` and select required capabilities.
Cargo features are additive: disabling defaults on one dependency declaration
does not turn off features requested elsewhere for the same package. Enabling
additional features must not disable existing capabilities or break a supported
configuration.

Declare feature relationships explicitly in `Cargo.toml`. Enable the dependencies
and other capabilities a feature needs, but no unrelated ones. Shared dependencies
remain enabled whenever at least one selected capability needs them.

If tests outside an optional capability need one of its dependencies, declare it
in `[dev-dependencies]` so those tests still work with the capability disabled.

## Validation and Documentation

For each new or changed feature boundary:

- Check compilation with defaults, with no optional features, and with only the
  feature and its declared prerequisites enabled.
- Run the capability's tests when enabled and verify tests for other capabilities
  still work when it is disabled.
- Inspect normal and build dependencies, excluding development dependencies.
  Confirm that disabling the feature removes dependencies not needed by the
  remaining configuration.
- Run these checks on each affected supported platform.
- Document what the feature enables, its default status, and its prerequisites.
  Update affected examples and callers.

Choose additional combinations to test based on shared code and dependencies;
testing every possible combination is not required.
