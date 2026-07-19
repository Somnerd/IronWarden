# Title: [CONFIG] Implement Unified Configurator & Error Mapping (WP-101)

## Category: Developer Experience (DX) / Configuration

## Description
Configuration loading is scattered across different modules, rule directory scanning crashes on boot if non-rule YAML files exist, and paths are hardcoded.

We need to implement a unified `GlobalConfig` resolver that prioritizes Environment Variables -> `config/config.yaml` file -> System Fallback Defaults.

## Technical Specifications
1.  **Design GlobalConfig Schema:** Create `GlobalConfig` struct in `warden/src/configurator.rs` using `serde`.
2.  **Enforce Strict Mode by Default:** If configuration files/directories are missing, the application must print a critical log and exit (`exit(1)`), unless the user explicitly opts in to defaults via `allow_fallback` configuration.
3.  **Directory Renaming:** Rename the default rules directory from `config/regions/` to `config/rules/`.
4.  **Refactor Main Entrypoint:** Replace ad-hoc env parses in `app/src/main.rs` with values from the resolved `GlobalConfig`.
5.  **Standardize Errors:** Convert parsing failures into clear `SovereignError::ConfigError` variants with line and file details.
