//! The start-up banner, in the colours of the Kokino painting (ui/img/painting.jpg):
//! ochre, gold and brown brush strokes of hair, olive and moss, the sky-blue
//! face and the green eyes.
//!
//! Shown only when standard output is a terminal, so piped and redirected
//! output stays plain. Colours follow anstream: off when NO_COLOR is set or
//! the output is not a terminal, and switched on in the Windows console.
//! Terminals that show 24-bit colour get the painting's own colours; the
//! others get the nearest of the 256 standard ones.

use std::io::{IsTerminal, Write};

/// A painting colour: 24-bit, and the nearest xterm-256 colour.
#[derive(Clone, Copy)]
struct Paint(u8, u8, u8, u8);

const DEEP: Paint = Paint(87, 71, 53, 94);
const BROWN: Paint = Paint(113, 84, 53, 94);
const UMBER: Paint = Paint(144, 102, 49, 130);
const OCHRE: Paint = Paint(160, 120, 45, 136);
const OLIVE: Paint = Paint(178, 154, 47, 142);
const GOLD: Paint = Paint(214, 180, 42, 178);
const YELLOW: Paint = Paint(238, 208, 60, 221);
const MOSS: Paint = Paint(140, 140, 40, 100);
const FACE: Paint = Paint(99, 161, 219, 74);
const EYE: Paint = Paint(130, 200, 50, 113);
const PALE: Paint = Paint(225, 220, 205, 253);

/// The strokes of the hair, dark to light and back, as the brush runs.
const STROKES: [Paint; 12] = [DEEP, BROWN, UMBER, OCHRE, OLIVE, GOLD, YELLOW, GOLD, OLIVE, MOSS, OCHRE, UMBER];

const SITE: &str = "https://kokino.zeroscience.mk";

/// KOKINO in plain ASCII (figlet "big"), one row per line.
const WORD: [&str; 6] = [
    r" _  __   ____    _  __  _____  _   _    ____  ",
    r"| |/ /  / __ \  | |/ / |_   _|| \ | |  / __ \ ",
    r"| ' /  | |  | | | ' /    | |  |  \| | | |  | |",
    r"|  <   | |  | | |  <     | |  | . ` | | |  | |",
    r"| . \  | |__| | | . \   _| |_ | |\  | | |__| |",
    r"|_|\_\  \____/  |_|\_\ |_____||_| \_|  \____/ ",
];

fn truecolor() -> bool {
    // The Windows console and Windows Terminal show 24-bit colour; elsewhere
    // the terminal says so in COLORTERM (macOS Terminal does not).
    cfg!(windows) || std::env::var("COLORTERM").is_ok_and(|v| v.contains("truecolor") || v.contains("24bit"))
}

fn fg(p: Paint, tc: bool) -> String {
    if tc {
        format!("\x1b[38;2;{};{};{}m", p.0, p.1, p.2)
    } else {
        format!("\x1b[38;5;{}m", p.3)
    }
}

const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Whether to show the banner at all: only to a person at a terminal.
pub fn wanted() -> bool {
    std::io::stdout().is_terminal()
}

/// The banner: the word in brush strokes, the face peeking out of the hair,
/// and the name, version and maker.
pub fn print(version: &str) {
    if !wanted() {
        return;
    }
    let tc = truecolor();
    let mut out = anstream::stdout();
    let mut s = String::from("\n");
    for (row, line) in WORD.iter().enumerate() {
        s.push_str("  ");
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                s.push(' ');
                continue;
            }
            // Diagonal bands, like the strokes of the painting.
            let p = STROKES[((col + 2 * row) / 3) % STROKES.len()];
            s.push_str(&fg(p, tc));
            s.push_str(BOLD);
            s.push(ch);
            s.push_str(RESET);
        }
        s.push('\n');
    }
    // The face in the hair: strokes, then blue around green eyes.
    let hair = |s: &mut String, n: usize, start: usize, ch: char| {
        for i in 0..n {
            s.push_str(&fg(STROKES[(start + i / 2) % STROKES.len()], tc));
            s.push(ch);
        }
        s.push_str(RESET);
    };
    s.push_str("  ");
    hair(&mut s, 15, 0, '\\');
    s.push_str(&format!(" {f}( {b}{e}o{r}{f} )-( {b}{e}o{r}{f} ){r} ", f = fg(FACE, tc), e = fg(EYE, tc), b = BOLD, r = RESET));
    hair(&mut s, 15, 6, '/');
    s.push('\n');
    s.push_str(&format!(
        "  {p}F O R E N S I C   T O O L K I T{r}   {g}{b}v{version}{r}  {m}by{r} {e}Zero Science Lab{r}\n  {f}{SITE}{r}   {p}{now}{r}\n\n",
        p = fg(PALE, tc),
        g = fg(GOLD, tc),
        b = BOLD,
        m = fg(MOSS, tc),
        e = fg(EYE, tc),
        f = fg(FACE, tc),
        r = RESET,
        now = to_seconds(&kokino_core::time::human_full(&kokino_core::time::now_iso())),
    ));
    let _ = out.write_all(s.as_bytes());
    let _ = out.flush();
}

/// One start-up line: a label in gold, the text after it as is, and any
/// address in it in the face's blue.
pub fn line(label: &str, text: &str) {
    let tc = truecolor();
    let mut out = anstream::stdout();
    let text = text
        .split(' ')
        .map(|w| if w.starts_with("http://") || w.starts_with("https://") { format!("{}{}{}", fg(FACE, tc), w, RESET) } else { w.to_string() })
        .collect::<Vec<_>>()
        .join(" ");
    let label = if label.is_empty() { String::new() } else { format!("{}{}{}{}", fg(GOLD, tc), BOLD, label, RESET) };
    let pad = " ".repeat(7usize.saturating_sub(label_width(&label)));
    let _ = writeln!(out, "{}{}{}", label, pad, text);
}

/// "23-11-2026 21:47:17.555 UTC+1" to "23-11-2026 21:47:17 UTC+1".
fn to_seconds(t: &str) -> String {
    match t.find('.') {
        Some(i) => {
            let end = t[i + 1..].find(|c: char| !c.is_ascii_digit()).map(|j| i + 1 + j).unwrap_or(t.len());
            format!("{}{}", &t[..i], &t[end..])
        }
        None => t.to_string(),
    }
}

/// Printable width of a label (escape codes do not count).
fn label_width(s: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        match (esc, c) {
            (false, '\x1b') => esc = true,
            (true, 'm') => esc = false,
            (true, _) => {}
            _ => n += 1,
        }
    }
    n
}

/// A quiet line (hints), in moss.
pub fn note(text: &str) {
    let mut out = anstream::stdout();
    let _ = writeln!(out, "{}{}{}", fg(MOSS, truecolor()), text, RESET);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_rows_line_up_and_are_ascii() {
        let w = WORD[0].len();
        assert!(WORD.iter().all(|l| l.len() == w && l.is_ascii()), "{:?}", WORD.map(|l| l.len()));
        assert_eq!(label_width(&format!("{}{}Open:{}", fg(GOLD, true), BOLD, RESET)), 5);
        assert_eq!(to_seconds("23-11-2026 21:47:17.555 UTC+1"), "23-11-2026 21:47:17 UTC+1");
        assert_eq!(to_seconds("23-11-2026 21:47:17 UTC"), "23-11-2026 21:47:17 UTC");
    }
}
