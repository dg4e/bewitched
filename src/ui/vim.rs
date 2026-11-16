//! Optional vim-style modal keybindings for the hex view.
//!
//! This module is a pure key-sequence parser: it turns keystrokes (with counts
//! and multi-key prefixes such as `dd`, `gg`, `r41`, `m3`) into [`Cmd`]s that
//! the app then executes. Keeping it free of GUI/document state makes the
//! grammar unit-testable.

/// File remembering whether vim mode is on between launches.
fn setting_path() -> std::path::PathBuf {
    crate::ops::config_dir().join("vim_mode")
}

/// Whether vim mode was left enabled last session.
pub fn load_enabled() -> bool {
    std::fs::read_to_string(setting_path())
        .map(|s| s.trim() == "on")
        .unwrap_or(false)
}

/// Remember the vim-mode toggle for the next launch (best effort).
pub fn save_enabled(on: bool) {
    let path = setting_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, if on { "on\n" } else { "off\n" });
}

/// The vim mode the editor is in. Insert/replace typing is handled by the
/// regular editing code; `Normal` and `Visual` interpret keys as commands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Normal,
    Visual,
    /// Typing edits the document (`i`/`a`/`I`/`A` insert, `R` overwrite).
    Insert,
}

/// A keystroke fed to the parser.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Input {
    /// A typed character (from a text event; shift already applied).
    Char(char),
    /// A Ctrl-chord, lower-cased letter (`Ctrl+D` → `Ctrl('d')`).
    Ctrl(char),
    Esc,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Motion {
    Left,
    Right,
    Up,
    Down,
    /// `w`: start of the next word (byte group).
    WordFwd,
    /// `b`: start of the previous word (byte group).
    WordBack,
    /// `e`: end of the current/next word (byte group).
    WordEnd,
    /// `0` / `^`: first byte of the row.
    RowStart,
    /// `$`: last byte of the row.
    RowEnd,
    /// `gg`: start of the file, or row `n` (1-based) with a count.
    FileStart,
    /// `G`: last byte of the file, or row `n` (1-based) with a count.
    FileEnd,
    PageDown,
    PageUp,
    HalfPageDown,
    HalfPageUp,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cmd {
    /// Move the cursor. `count` is the repeat (or the row number for
    /// `gg`/`G`, where `explicit` says a count was actually typed).
    Move {
        motion: Motion,
        count: usize,
        explicit: bool,
    },
    /// `i`: insert before the cursor.
    Insert,
    /// `a`: insert after the cursor.
    Append,
    /// `I`: insert at row start.
    InsertRowStart,
    /// `A`: insert after row end.
    AppendRowEnd,
    /// `R`: overwrite ("replace") typing mode.
    ReplaceMode,
    /// `r`: overwrite `count` bytes with `byte`.
    ReplaceByte {
        byte: u8,
        count: usize,
    },
    /// `x` / `Del`: delete `count` bytes at the cursor (yanked).
    DeleteFwd(usize),
    /// `X`: delete `count` bytes before the cursor (yanked).
    DeleteBack(usize),
    /// `dd`: delete `count` whole rows (yanked).
    DeleteRows(usize),
    /// `D`: delete to the end of the row (yanked).
    DeleteToRowEnd,
    /// `yy`: yank `count` whole rows.
    YankRows(usize),
    /// `p`: paste after the cursor, `count` times.
    PasteAfter(usize),
    /// `P`: paste before the cursor, `count` times.
    PasteBefore(usize),
    /// `~`: flip ASCII case of `count` bytes.
    ToggleCase(usize),
    Undo(usize),
    Redo(usize),
    /// `v`: enter (or leave) visual mode.
    ToggleVisual,
    /// `o` in visual: jump to the other end of the selection.
    VisualSwap,
    /// `d`/`x` in visual: delete the selection (yanked).
    VisualDelete,
    /// `y` in visual: yank the selection.
    VisualYank,
    /// `/` or `?`: open the search window.
    Search,
    /// `n`: next match.
    SearchNext,
    /// `N`: previous match.
    SearchPrev,
    /// `:`: open go-to-address.
    Goto,
    /// `m0`-`m9`: set bookmark.
    SetMark(usize),
    /// `'0`-`'9` (or `` `0 ``): jump to bookmark.
    JumpMark(usize),
    /// Esc: leave insert/visual, cancel a pending sequence.
    Escape,
}

/// Parser state for one editor.
#[derive(Default)]
pub struct Vim {
    count: Option<usize>,
    /// Multi-key prefix waiting for its next key: `g`, `d`, `y`, `r`, `m`, `'`.
    pending: Option<char>,
    /// The high nibble typed after `r` in the hex pane.
    r_high: Option<u8>,
}

impl Vim {
    /// What has been typed so far of an incomplete command (for the status bar).
    pub fn pending_text(&self) -> String {
        let mut s = String::new();
        if let Some(c) = self.count {
            s.push_str(&c.to_string());
        }
        if let Some(p) = self.pending {
            s.push(p);
        }
        if let Some(h) = self.r_high {
            s.push(char::from_digit(h as u32, 16).unwrap_or('?'));
        }
        s
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Feed one keystroke in `Normal`/`Visual` mode. `hex_pane` selects how
    /// `r` reads its replacement (two hex digits vs. one character).
    /// Returns a command once a full sequence has been typed.
    pub fn feed(&mut self, input: Input, mode: Mode, hex_pane: bool) -> Option<Cmd> {
        let c = match input {
            Input::Esc => {
                self.reset();
                return Some(Cmd::Escape);
            }
            Input::Ctrl(k) => {
                let n = self.take_count();
                self.pending = None;
                self.r_high = None;
                let mv = |motion| Cmd::Move {
                    motion,
                    count: n,
                    explicit: false,
                };
                return match k {
                    'f' => Some(mv(Motion::PageDown)),
                    'b' => Some(mv(Motion::PageUp)),
                    'd' => Some(mv(Motion::HalfPageDown)),
                    'u' => Some(mv(Motion::HalfPageUp)),
                    'r' => Some(Cmd::Redo(n)),
                    _ => None,
                };
            }
            Input::Char(c) => c,
        };

        // Second key of a multi-key sequence.
        if let Some(p) = self.pending {
            return self.finish_pending(p, c, hex_pane);
        }

        // Count prefix (a leading `0` is the row-start motion, not a digit).
        if let Some(d) = c.to_digit(10) {
            if d != 0 || self.count.is_some() {
                let cur = self.count.unwrap_or(0);
                self.count = Some(
                    cur.saturating_mul(10)
                        .saturating_add(d as usize)
                        .min(1 << 40),
                );
                return None;
            }
        }

        let explicit = self.count.is_some();
        let n = self.take_count();
        let mv = |motion| {
            Some(Cmd::Move {
                motion,
                count: n,
                explicit,
            })
        };
        let visual = mode == Mode::Visual;
        match c {
            'h' | ' ' => mv(Motion::Left),
            'l' => mv(Motion::Right),
            'k' => mv(Motion::Up),
            'j' => mv(Motion::Down),
            'w' => mv(Motion::WordFwd),
            'b' => mv(Motion::WordBack),
            'e' => mv(Motion::WordEnd),
            '0' | '^' => mv(Motion::RowStart),
            '$' => mv(Motion::RowEnd),
            'G' => mv(Motion::FileEnd),
            'v' => Some(Cmd::ToggleVisual),
            'o' if visual => Some(Cmd::VisualSwap),
            'd' | 'x' if visual => Some(Cmd::VisualDelete),
            'y' if visual => Some(Cmd::VisualYank),
            'i' => Some(Cmd::Insert),
            'a' => Some(Cmd::Append),
            'I' => Some(Cmd::InsertRowStart),
            'A' => Some(Cmd::AppendRowEnd),
            'R' => Some(Cmd::ReplaceMode),
            'x' => Some(Cmd::DeleteFwd(n)),
            'X' => Some(Cmd::DeleteBack(n)),
            'D' => Some(Cmd::DeleteToRowEnd),
            'p' => Some(Cmd::PasteAfter(n)),
            'P' => Some(Cmd::PasteBefore(n)),
            '~' => Some(Cmd::ToggleCase(n)),
            'u' => Some(Cmd::Undo(n)),
            '/' | '?' => Some(Cmd::Search),
            'n' => Some(Cmd::SearchNext),
            'N' => Some(Cmd::SearchPrev),
            ':' => Some(Cmd::Goto),
            'g' | 'd' | 'y' | 'r' | 'm' | '\'' | '`' => {
                // keep the count for the completed sequence
                if explicit {
                    self.count = Some(n);
                }
                self.pending = Some(c);
                None
            }
            _ => None,
        }
    }

    fn take_count(&mut self) -> usize {
        self.count.take().unwrap_or(1).max(1)
    }

    fn finish_pending(&mut self, p: char, c: char, hex_pane: bool) -> Option<Cmd> {
        if p == 'r' && hex_pane {
            // `r` in the hex pane takes two hex digits: the new byte value.
            let Some(d) = c.to_digit(16) else {
                self.reset();
                return None;
            };
            match self.r_high.take() {
                None => {
                    self.r_high = Some(d as u8);
                    return None;
                }
                Some(hi) => {
                    self.pending = None;
                    let count = self.take_count();
                    return Some(Cmd::ReplaceByte {
                        byte: (hi << 4) | d as u8,
                        count,
                    });
                }
            }
        }
        self.pending = None;
        let explicit = self.count.is_some();
        let n = self.take_count();
        match (p, c) {
            ('g', 'g') => Some(Cmd::Move {
                motion: Motion::FileStart,
                count: n,
                explicit,
            }),
            ('d', 'd') => Some(Cmd::DeleteRows(n)),
            ('y', 'y') => Some(Cmd::YankRows(n)),
            ('r', c) if (c as u32) < 0x100 && !c.is_control() => Some(Cmd::ReplaceByte {
                byte: c as u8,
                count: n,
            }),
            ('m', c) => c.to_digit(10).map(|d| Cmd::SetMark(d as usize)),
            ('\'' | '`', c) => c.to_digit(10).map(|d| Cmd::JumpMark(d as usize)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(v: &mut Vim, keys: &str, mode: Mode, hex: bool) -> Vec<Cmd> {
        keys.chars()
            .filter_map(|c| v.feed(Input::Char(c), mode, hex))
            .collect()
    }

    fn normal(keys: &str) -> Vec<Cmd> {
        run(&mut Vim::default(), keys, Mode::Normal, true)
    }

    #[test]
    fn motions_with_counts() {
        assert_eq!(
            normal("3j"),
            vec![Cmd::Move {
                motion: Motion::Down,
                count: 3,
                explicit: true
            }]
        );
        assert_eq!(
            normal("12l"),
            vec![Cmd::Move {
                motion: Motion::Right,
                count: 12,
                explicit: true
            }]
        );
        assert_eq!(
            normal("0"),
            vec![Cmd::Move {
                motion: Motion::RowStart,
                count: 1,
                explicit: false
            }]
        );
        assert_eq!(
            normal("10G"),
            vec![Cmd::Move {
                motion: Motion::FileEnd,
                count: 10,
                explicit: true
            }]
        );
        assert_eq!(
            normal("gg"),
            vec![Cmd::Move {
                motion: Motion::FileStart,
                count: 1,
                explicit: false
            }]
        );
        assert_eq!(
            normal("5gg"),
            vec![Cmd::Move {
                motion: Motion::FileStart,
                count: 5,
                explicit: true
            }]
        );
    }

    #[test]
    fn operators() {
        assert_eq!(normal("dd"), vec![Cmd::DeleteRows(1)]);
        assert_eq!(normal("2dd"), vec![Cmd::DeleteRows(2)]);
        assert_eq!(normal("3yy"), vec![Cmd::YankRows(3)]);
        assert_eq!(normal("4x"), vec![Cmd::DeleteFwd(4)]);
        assert_eq!(normal("u"), vec![Cmd::Undo(1)]);
        assert_eq!(normal("2p"), vec![Cmd::PasteAfter(2)]);
        // an unknown second key cancels the sequence
        assert_eq!(normal("dzx"), vec![Cmd::DeleteFwd(1)]);
    }

    #[test]
    fn replace_byte_hex_and_text() {
        assert_eq!(
            normal("r4f"),
            vec![Cmd::ReplaceByte {
                byte: 0x4f,
                count: 1
            }]
        );
        assert_eq!(
            normal("3rff"),
            vec![Cmd::ReplaceByte {
                byte: 0xff,
                count: 3
            }]
        );
        let mut v = Vim::default();
        assert_eq!(
            run(&mut v, "rA", Mode::Normal, false),
            vec![Cmd::ReplaceByte {
                byte: b'A',
                count: 1
            }]
        );
        // non-hex digit in the hex pane cancels
        assert_eq!(normal("rzj").len(), 1);
    }

    #[test]
    fn marks() {
        assert_eq!(normal("m3"), vec![Cmd::SetMark(3)]);
        assert_eq!(normal("'3"), vec![Cmd::JumpMark(3)]);
        assert_eq!(normal("`7"), vec![Cmd::JumpMark(7)]);
    }

    #[test]
    fn visual_mode_keys() {
        let mut v = Vim::default();
        assert_eq!(
            run(&mut v, "d", Mode::Visual, true),
            vec![Cmd::VisualDelete]
        );
        assert_eq!(run(&mut v, "y", Mode::Visual, true), vec![Cmd::VisualYank]);
        assert_eq!(run(&mut v, "o", Mode::Visual, true), vec![Cmd::VisualSwap]);
    }

    #[test]
    fn ctrl_and_escape() {
        let mut v = Vim::default();
        assert_eq!(v.feed(Input::Char('4'), Mode::Normal, true), None);
        assert_eq!(v.pending_text(), "4");
        assert_eq!(
            v.feed(Input::Ctrl('d'), Mode::Normal, true),
            Some(Cmd::Move {
                motion: Motion::HalfPageDown,
                count: 4,
                explicit: false
            })
        );
        assert_eq!(v.feed(Input::Char('d'), Mode::Normal, true), None);
        assert_eq!(v.feed(Input::Esc, Mode::Normal, true), Some(Cmd::Escape));
        assert_eq!(v.pending_text(), "");
        assert_eq!(
            v.feed(Input::Ctrl('r'), Mode::Normal, true),
            Some(Cmd::Redo(1))
        );
    }
}
