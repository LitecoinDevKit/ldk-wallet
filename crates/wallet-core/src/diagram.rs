//! State diagrams generated from transition tables and kept in sync with docs.

use std::fmt::Debug;
use std::fs;
use std::path::Path;

/// Mermaid `stateDiagram-v2` for `rows`, one edge per `(from, to)` pair with
/// the events that take it joined into the label.
pub(crate) fn mermaid<S, E>(start: (S, &str), rows: &[(S, E, S)], finals: &[S]) -> String
where
    S: Copy + PartialEq + Debug,
    E: Debug,
{
    let mut edges: Vec<(S, S, Vec<String>)> = Vec::new();
    for (from, event, to) in rows {
        let label = format!("{event:?}");
        match edges.iter_mut().find(|(f, t, _)| f == from && t == to) {
            Some((_, _, labels)) => labels.push(label),
            None => edges.push((*from, *to, vec![label])),
        }
    }
    let mut out = String::from("stateDiagram-v2\n");
    out.push_str(&format!("    [*] --> {:?}: {}\n", start.0, start.1));
    for (from, to, labels) in edges {
        out.push_str(&format!("    {from:?} --> {to:?}: {}\n", labels.join(", ")));
    }
    for state in finals {
        out.push_str(&format!("    {state:?} --> [*]\n"));
    }
    out
}

/// Compare `diagram` with the block between the `name` markers in `doc` (a path
/// from the repo root). With `UPDATE_DIAGRAMS` set, rewrite the block instead.
pub(crate) fn check_doc(doc: &str, name: &str, diagram: &str, regenerate: &str) {
    let begin = format!("<!-- {name}:begin (generated; do not edit) -->\n");
    let end = format!("<!-- {name}:end -->");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(doc);
    let text = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
    let start = text
        .find(&begin)
        .unwrap_or_else(|| panic!("begin marker in {doc}"))
        + begin.len();
    let stop = text
        .find(&end)
        .unwrap_or_else(|| panic!("end marker in {doc}"));
    let expected = format!("```mermaid\n{diagram}```\n");
    if std::env::var_os("UPDATE_DIAGRAMS").is_some() {
        fs::write(
            &path,
            format!("{}{}{}", &text[..start], expected, &text[stop..]),
        )
        .unwrap();
        return;
    }
    assert_eq!(
        &text[start..stop],
        expected,
        "{doc} is stale. Run {regenerate}"
    );
}
