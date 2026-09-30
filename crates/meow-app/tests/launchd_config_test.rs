//! launchd plist generation tests (issue #677).
//!
//! The plist is XML: every interpolated path must be entity-escaped so a
//! `&`/`<`/`"`/`'` in the binary, config, work, or log path cannot produce
//! a malformed file that `launchctl bootstrap` rejects.

fn assert_plist_contains(plist: &str, needles: &[&str], context: &str) {
    for needle in needles {
        assert!(
            plist.contains(needle),
            "[{context}] missing {needle:?}\ngenerated plist:\n{plist}"
        );
    }
}

#[test]
fn launchd_plist_contains_expected_keys() {
    let plist = meow_app::generate_launchd_plist(
        "/opt/meow/bin/meow",
        "/Users/alice/Library/Application Support/meow/config.yaml",
        "/Users/alice/Library/Application Support/meow",
        "/Users/alice/Library/Logs/meow",
    )
    .expect("benign paths must generate");
    assert_plist_contains(
        &plist,
        &[
            "<string>com.meow.proxy</string>",
            "<string>/opt/meow/bin/meow</string>",
            "<string>/Users/alice/Library/Application Support/meow/config.yaml</string>",
            "<key>WorkingDirectory</key>",
            "<string>/Users/alice/Library/Application Support/meow</string>",
            "<key>SoftResourceLimits</key>",
            "<integer>65536</integer>",
            "<string>/Users/alice/Library/Logs/meow/meow.log</string>",
            "<string>/Users/alice/Library/Logs/meow/meow.err.log</string>",
        ],
        "expected keys",
    );
}

#[test]
fn launchd_plist_escapes_xml_special_chars_in_paths() {
    // Every interpolated slot is exercised with a hostile path fragment.
    let plist = meow_app::generate_launchd_plist(
        "/opt/a&b/meow",
        "/Users/bob <admin>/meow/config.yaml",
        "/Users/bob <admin>/meow",
        "/tmp/\"quoted\"/logs",
    )
    .expect("XML-escapable paths must generate");

    assert_plist_contains(
        &plist,
        &[
            "<string>/opt/a&amp;b/meow</string>",
            "<string>/Users/bob &lt;admin&gt;/meow/config.yaml</string>",
            "<string>/tmp/&quot;quoted&quot;/logs/meow.log</string>",
        ],
        "escaped entities",
    );

    assert_plist_contains(
        &plist,
        &["<string>/Users/bob &lt;admin&gt;/meow</string>"],
        "work_dir escaped",
    );

    // The raw metacharacters must not survive inside a <string> value.
    // Check the exact values rather than banning chars file-wide (the
    // DOCTYPE line legitimately contains `"` and `/` sequences).
    for raw in [
        "<string>/opt/a&b/meow</string>",
        "<string>/Users/bob <admin>/meow/config.yaml</string>",
        "<string>/Users/bob <admin>/meow</string>",
        "/tmp/\"quoted\"/logs",
    ] {
        assert!(
            !plist.contains(raw),
            "unescaped value {raw:?} survived in plist:\n{plist}"
        );
    }
}

#[test]
fn launchd_plist_escapes_ampersand_before_other_entities() {
    // `&` must expand before `<`/`>` — otherwise `&lt;` would double-escape
    // into `&amp;lt;`.
    let plist = meow_app::generate_launchd_plist("/x/a<&>b", "/x/config.yaml", "/x", "/x/logs")
        .expect("entity-order case must generate");
    assert_plist_contains(
        &plist,
        &["<string>/x/a&lt;&amp;&gt;b</string>"],
        "entity order",
    );
    assert!(
        !plist.contains("&amp;lt;") && !plist.contains("&amp;gt;"),
        "double-escaped entity found in plist:\n{plist}"
    );

    // `]]>` is illegal verbatim inside XML character data (§2.4) — the
    // `>` rule must defuse it.
    let plist = meow_app::generate_launchd_plist("/x/a]]>b", "/x/config.yaml", "/x", "/x/logs")
        .expect("]]> case must generate");
    assert_plist_contains(&plist, &["<string>/x/a]]&gt;b</string>"], "]]> escape");
    assert!(!plist.contains("]]>"), "raw ]]> survived:\n{plist}");
}

#[test]
fn launchd_plist_string_nodes_are_well_formed() {
    // Cheap structural check without an XML dep: the template's seven
    // `<string>` nodes must stay balanced — a dropped tag or a stray
    // literal `</string>` inside a value would skew the counts. (A
    // value containing a legal `\n` can legitimately split a node
    // across lines, so the check is global rather than per-line.)
    let plist = meow_app::generate_launchd_plist(
        "/opt/meow/meow",
        "/Users/a&b/config.yaml",
        "/Users/a&b",
        "/Users/a&b/logs",
    )
    .expect("well-formed case must generate");
    let mut opens = 0usize;
    let mut closes = 0usize;
    for line in plist.lines() {
        opens += line.matches("<string>").count();
        closes += line.matches("</string>").count();
    }
    assert_eq!(opens, closes, "unbalanced <string> nodes:\n{plist}");
}

#[test]
fn launchd_plist_rejects_xml_unrepresentable_chars() {
    // Control chars below 0x20 (except \n/\t) and U+FFFE/U+FFFF cannot be
    // entity-escaped — the generator must refuse rather than emit a plist
    // launchd would reject anyway (issue #677).
    for (label, bad) in [
        ("C0 control", "/x/a\x07b"),
        ("carriage return (normalizes to \\n)", "/x/a\rb"),
        ("U+FFFE", "/x/a\u{FFFE}b"),
        ("U+FFFF", "/x/a\u{FFFF}b"),
    ] {
        let err = meow_app::generate_launchd_plist(bad, "/x/config.yaml", "/x", "/x/logs")
            .expect_err(&format!("[{label}] path must be rejected"));
        assert!(
            err.to_string().contains("XML cannot represent"),
            "[{label}] unexpected error message: {err}"
        );
    }

    // \n and \t are legal XML chars that round-trip unharmed — allowed.
    meow_app::generate_launchd_plist("/x/a\nb", "/x/config.yaml", "/x", "/x/a\tb")
        .expect("newline/tab paths remain legal XML");
}
