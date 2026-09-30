//! CLI and service helpers for the meow-rs proxy kernel.
//!
//! Library surface used by the `meow` binary: systemd unit and launchd
//! plist generation, geodata fetch, and subscription refresh. The binary
//! wires configuration, the tunnel, listeners, DNS, and the REST API
//! together.

#[cfg(any(target_os = "linux", test))]
pub mod arp;
pub mod geodata_fetch;
pub mod subscription_refresh;

/// launchd label for the macOS user agent plist.
pub const LAUNCHD_LABEL: &str = "com.meow.proxy";

/// True when `a` and `b` resolve to the same directory entry, with `..`,
/// repeated separators, and symlinks (e.g. macOS `/var` → `/private/var`)
/// normalized away. Returns false when either path cannot be resolved.
/// Used by the macOS `uninstall` guard to admit only a literal
/// `$HOME` == `/var/root` without a prefix-match bypass like
/// `/var/root/../Users/x` (issue #678).
pub fn same_resolved_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    matches!(
        (std::fs::canonicalize(a), std::fs::canonicalize(b)),
        (Ok(x), Ok(y)) if x == y
    )
}

/// Escape a value for interpolation into a plist `<string>` node
/// (issue #677): `&`, `<`, `>` are required and `"`/`'` are escaped too —
/// a stray `]]>` or a quote in a HOME-derived path must not break the XML.
fn plist_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Reject characters XML 1.0 cannot represent — escaping is not an option
/// for them (issue #677). POSIX allows control chars in filenames, so a
/// deliberately weird `$HOME` could still produce an invalid plist; the
/// only correct handling is a clear error. `\r` is rejected too: XML
/// line-ending normalization rewrites it to `\n`, silently diverging from
/// the real path. `\n`/`\t` round-trip unharmed and are allowed.
fn check_plist_char(field: &str, value: &str) -> anyhow::Result<()> {
    let bad = value.chars().find(|&ch| {
        (ch < ' ' && ch != '\n' && ch != '\t') || matches!(ch, '\u{FFFE}' | '\u{FFFF}')
    });
    if let Some(ch) = bad {
        anyhow::bail!(
            "{field} contains a character XML cannot represent (U+{:04X}): {value:?}",
            ch as u32
        );
    }
    Ok(())
}

/// Generate a launchd user-agent plist for the meow service (macOS).
///
/// Every interpolated path goes through `plist_escape` — the plist is
/// XML, so an unescaped `&`/`<`/`"` in the binary, config, work, or log
/// path would produce a malformed file `launchctl bootstrap` rejects.
///
/// Returns an error when a path contains characters XML 1.0 cannot
/// represent at all (see `check_plist_char`).
///
/// # Arguments
/// * `exe_path` - Absolute path to the meow binary
/// * `config_path` - Absolute path to the installed configuration file
/// * `work_dir` - `WorkingDirectory` for the service
/// * `log_dir` - Directory receiving `Standard{Out,Error}Path` logs
pub fn generate_launchd_plist(
    exe_path: &str,
    config_path: &str,
    work_dir: &str,
    log_dir: &str,
) -> anyhow::Result<String> {
    check_plist_char("exe_path", exe_path)?;
    check_plist_char("config_path", config_path)?;
    check_plist_char("work_dir", work_dir)?;
    check_plist_char("log_dir", log_dir)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>-f</string>
        <string>{config}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{work_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>{log_dir}/meow.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/meow.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exe = plist_escape(exe_path),
        config = plist_escape(config_path),
        work_dir = plist_escape(work_dir),
        log_dir = plist_escape(log_dir),
    ))
}

/// Generate a systemd unit file for the meow service.
///
/// Returns the unit file content as a string.
///
/// # Arguments
/// * `exe_path` - Absolute path to the meow binary
/// * `config_path` - Absolute path to the configuration file
pub fn generate_systemd_unit(exe_path: &str, config_path: &str) -> String {
    let work_dir = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();

    format!(
        r#"[Unit]
Description=meow-rs proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_path} -f {config_path}
WorkingDirectory={work_dir}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={work_dir}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
    )
}
