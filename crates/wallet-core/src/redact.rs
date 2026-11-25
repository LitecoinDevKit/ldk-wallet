//! Secret and payload redaction for `Debug` impls, error strings, and diagnostic logs.
//!
//! Enforces the redaction contract for Hardening items 15 and 16:
//! - URL userinfo (`scheme://user:pass@host`) -> `scheme://[redacted]@host`
//! - Storage-tagged secrets (`aezeed:...`, `bip39:...`, `xprv:...`) -> `<tag>:[redacted]`
//! - Extended private keys (`xprv`/`zprv`/`Ltpv`/`tprv`/...) and WIF keys -> `[redacted-key]`
//! - Hex blobs longer than 64 hex digits (raw MWEB tx payloads, PSBTs, full key buffers) ->
//!   `[redacted-hex]`, while preserving 64-char `txid`/`wtxid`/`output_id`/`block_hash` tokens
//! - Runs of 12+ BIP39/aezeed wordlist words -> `[redacted-mnemonic]`

use bdk_wallet::keys::bip39::Language;

const XPRV_PREFIXES: &[&str] = &[
    "xprv", "yprv", "zprv", "Yprv", "Zprv", "tprv", "uprv", "vprv", "Uprv", "Vprv", "Ltpv", "Mtpv",
    "ttpv",
];

/// Strip `user:pass@` userinfo from any URL embedded in `msg` so RPC or Electrum
/// credentials never reach logs, `Debug` output, or UI error text.
pub(crate) fn redact_userinfo(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(idx) = rest.find("://") {
        let (head, tail) = rest.split_at(idx + 3);
        out.push_str(head);
        let authority_end = tail
            .find([
                '/', '?', '#', ' ', '\t', '\n', '\r', ')', ']', '}', '"', '\'', ',', ';',
            ])
            .unwrap_or(tail.len());
        let authority = &tail[..authority_end];
        if let Some(at) = authority.rfind('@') {
            out.push_str("[redacted]@");
            out.push_str(&authority[at + 1..]);
        } else {
            out.push_str(authority);
        }
        rest = &tail[authority_end..];
    }
    out.push_str(rest);
    out
}

pub(crate) fn redact_opt_url(url: &Option<String>) -> Option<String> {
    url.as_ref().map(|u| redact_userinfo(u))
}

/// Scrub credentials, mnemonics, extended/WIF private keys, and raw transaction
/// hex (>64 hex chars) from a log or error line, while keeping 64-char txids,
/// wtxids, MWEB output IDs, and block hashes intact.
pub(crate) fn scrub_log_line(msg: &str) -> String {
    let step1 = redact_userinfo(msg);
    let step2 = scrub_tagged_payloads(&step1);
    let step3 = scrub_tokens_and_hex(&step2);
    scrub_mnemonic_runs(&step3)
}

fn scrub_tagged_payloads(input: &str) -> String {
    let mut out = input.to_string();
    for tag in ["aezeed:", "bip39:", "xprv:"] {
        while let Some(pos) = out.find(tag) {
            let after = pos + tag.len();
            let tail = &out[after..];
            if tail.starts_with("[redacted]") {
                // Already scrubbed; advance past it by temporarily splitting.
                let mut next = String::with_capacity(out.len());
                next.push_str(&out[..after + "[redacted]".len()]);
                next.push_str(&scrub_tagged_payloads(&out[after + "[redacted]".len()..]));
                return next;
            }
            let end = if tag == "xprv:" {
                tail.find(|c: char| !is_base58_char(c))
                    .unwrap_or(tail.len())
            } else {
                // Tagged mnemonic/aezeed payloads span words and optional `\n<passphrase>`
                // up to a closing quote/ delimiter or end of string.
                tail.find(['"', '\'', ')', ']', '}']).unwrap_or(tail.len())
            };
            out.replace_range(after..after + end, "[redacted]");
        }
    }
    out
}

fn is_base58_char(c: char) -> bool {
    matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
}

fn looks_like_xprv(core: &str) -> bool {
    if core.len() < 50 || core.len() > 130 {
        return false;
    }
    XPRV_PREFIXES.iter().any(|p| core.starts_with(p)) && core.chars().all(is_base58_char)
}

fn looks_like_wif(core: &str) -> bool {
    if !(51..=52).contains(&core.len()) {
        return false;
    }
    let Some(first) = core.chars().next() else {
        return false;
    };
    if !matches!(first, '5' | 'K' | 'L' | 'T' | '6' | 'c') {
        return false;
    }
    if !core.chars().all(is_base58_char) {
        return false;
    }
    let has_upper = core.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = core.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = core.chars().any(|c| c.is_ascii_digit());
    has_upper && has_lower && has_digit
}

fn scrub_tokens_and_hex(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let ch = input[i..].chars().next().unwrap();
        if is_base58_char(ch) || ch == '0' {
            let start = i;
            // Check `0x` + hex run first.
            if bytes[i] == b'0'
                && i + 2 < bytes.len()
                && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
                && bytes[i + 2].is_ascii_hexdigit()
            {
                let mut j = i + 2;
                while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                let hex_len = j - (i + 2);
                if hex_len > 64 {
                    out.push_str("[redacted-hex]");
                } else {
                    out.push_str(&input[start..j]);
                }
                i = j;
                continue;
            }

            // Consume contiguous alphanumeric run to inspect as hex / xprv / WIF.
            let mut j = i;
            while j < bytes.len()
                && input[j..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                j += input[j..].chars().next().unwrap().len_utf8();
            }
            let token = &input[start..j];
            if looks_like_xprv(token) || looks_like_wif(token) {
                out.push_str("[redacted-key]");
            } else if token.len() > 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.push_str("[redacted-hex]");
            } else {
                out.push_str(token);
            }
            i = j;
        } else {
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn is_wordlist_word(word: &str) -> bool {
    if !(3..=8).contains(&word.len()) || !word.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let lower = word.to_ascii_lowercase();
    Language::English.find_word(&lower).is_some()
}

fn scrub_mnemonic_runs(input: &str) -> String {
    // Collect contiguous ASCII-alphabetic word spans.
    let mut words: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    for (idx, ch) in input.char_indices() {
        if ch.is_ascii_alphabetic() {
            if start.is_none() {
                start = Some(idx);
            }
        } else if let Some(s) = start.take() {
            words.push((s, idx));
        }
    }
    if let Some(s) = start {
        words.push((s, input.len()));
    }
    if words.len() < 12 {
        return input.to_string();
    }

    // Partition words into whitespace-separated runs (punctuation like `="`, `, `, `. ` breaks a run).
    let mut redact_ranges: Vec<(usize, usize)> = Vec::new();
    let mut run_start = 0usize;
    while run_start < words.len() {
        let mut run_end = run_start + 1;
        while run_end < words.len() {
            let gap = &input[words[run_end - 1].1..words[run_end].0];
            if !gap.is_empty() && gap.bytes().all(|b| b.is_ascii_whitespace()) {
                run_end += 1;
            } else {
                break;
            }
        }
        let run = &words[run_start..run_end];
        if run.len() >= 12 {
            let flags: Vec<bool> = run
                .iter()
                .map(|&(s, e)| is_wordlist_word(&input[s..e]))
                .collect();
            let mut redact_tok = vec![false; run.len()];
            let mut idx = 0usize;
            while idx + 12 <= run.len() {
                let all_len_ok = (idx..idx + 12).all(|k| {
                    let len = run[k].1 - run[k].0;
                    (3..=12).contains(&len)
                });
                let hits = (idx..idx + 12).filter(|&k| flags[k]).count();
                if all_len_ok && hits >= 11 {
                    let mut end = idx + 12;
                    while end < run.len() && flags[end] {
                        end += 1;
                    }
                    for flag in &mut redact_tok[idx..end] {
                        *flag = true;
                    }
                    idx = end;
                } else {
                    idx += 1;
                }
            }
            let mut k = 0usize;
            while k < run.len() {
                if redact_tok[k] {
                    let byte_start = run[k].0;
                    while k + 1 < run.len() && redact_tok[k + 1] {
                        k += 1;
                    }
                    let byte_end = run[k].1;
                    redact_ranges.push((byte_start, byte_end));
                }
                k += 1;
            }
        }
        run_start = run_end;
    }

    if redact_ranges.is_empty() {
        return input.to_string();
    }

    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    for (s, e) in redact_ranges {
        out.push_str(&input[cursor..s]);
        out.push_str("[redacted-mnemonic]");
        cursor = e;
    }
    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_64_char_ids_and_redacts_longer_hex() {
        let txid = "ab".repeat(32);
        let raw_tx = "02000000".to_string() + &"cd".repeat(80);
        let line = format!("churn broadcast txid={txid} raw={raw_tx}");
        let scrubbed = scrub_log_line(&line);
        assert!(
            scrubbed.contains(&txid),
            "64-char txid must remain: {scrubbed}"
        );
        assert!(
            !scrubbed.contains(&raw_tx),
            "raw tx hex must be scrubbed: {scrubbed}"
        );
        assert!(scrubbed.contains("[redacted-hex]"));
    }

    #[test]
    fn scrubs_mnemonics_xprv_wif_and_urls_without_harming_prose() {
        let prose = "MWEB sync finished at height 12345 with 2 peers and 0 warnings";
        assert_eq!(scrub_log_line(prose), prose);

        let bip39 = "failed on \"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\"";
        let s1 = scrub_log_line(bip39);
        assert!(!s1.contains("abandon"), "{s1}");
        assert!(s1.contains("[redacted-mnemonic]"), "{s1}");

        let xprv = "key xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi leaked";
        let s2 = scrub_log_line(xprv);
        assert!(!s2.contains("xprv9s21"), "{s2}");
        assert!(s2.contains("[redacted-key]"), "{s2}");

        let url = "RPC http://alice:hunter2@127.0.0.1:9332: connection refused";
        let s3 = scrub_log_line(url);
        assert!(!s3.contains("hunter2") && !s3.contains("alice"), "{s3}");
        assert!(s3.contains("http://[redacted]@127.0.0.1:9332"), "{s3}");

        let tagged = "payload=aezeed:able abstract acoustic\nmy-secret-pass";
        let s4 = scrub_log_line(tagged);
        assert!(
            !s4.contains("acoustic") && !s4.contains("my-secret-pass"),
            "{s4}"
        );
    }
}
