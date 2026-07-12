//! Character-set decoders for the text pane: ANSI (Latin-1), DOS (CP437),
//! EBCDIC (CP037) and Macintosh (Mac Roman). Each maps a raw byte to the glyph
//! to display, or `None` for "show a placeholder dot".

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Charset {
    Ansi,
    Dos,
    Ebcdic,
    Mac,
}

impl Charset {
    pub const ALL: &'static [Charset] =
        &[Charset::Ansi, Charset::Dos, Charset::Ebcdic, Charset::Mac];

    pub fn name(self) -> &'static str {
        match self {
            Charset::Ansi => "ANSI (Latin-1)",
            Charset::Dos => "DOS (CP437)",
            Charset::Ebcdic => "EBCDIC",
            Charset::Mac => "Macintosh",
        }
    }

    /// Decode a byte to a printable glyph, or `None` for non-printable.
    pub fn decode(self, b: u8) -> Option<char> {
        match self {
            Charset::Ansi => ansi(b),
            Charset::Dos => dos(b),
            Charset::Ebcdic => ebcdic(b),
            Charset::Mac => mac(b),
        }
    }
}

fn ansi(b: u8) -> Option<char> {
    match b {
        0x20..=0x7e => Some(b as char),
        0xa0..=0xff => Some(b as char), // Latin-1: codepoint == byte
        _ => None,
    }
}

// CP437 high half (0x80..=0xFF), 128 glyphs.
const CP437_HIGH: &str =
    "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";

fn dos(b: u8) -> Option<char> {
    match b {
        0x20..=0x7e => Some(b as char),
        0x80..=0xff => CP437_HIGH.chars().nth((b - 0x80) as usize),
        _ => None,
    }
}

// Mac Roman high half (0x80..=0xFF), 128 glyphs.
const MACROMAN_HIGH: &str =
    "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»… ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ\u{f8ff}ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";

fn mac(b: u8) -> Option<char> {
    match b {
        0x20..=0x7e => Some(b as char),
        0x80..=0xff => MACROMAN_HIGH.chars().nth((b - 0x80) as usize),
        _ => None,
    }
}

// EBCDIC (CP037) printable subset.
fn ebcdic(b: u8) -> Option<char> {
    let c = match b {
        0x40 => ' ',
        0x4b => '.',
        0x4c => '<',
        0x4d => '(',
        0x4e => '+',
        0x4f => '|',
        0x50 => '&',
        0x5a => '!',
        0x5b => '$',
        0x5c => '*',
        0x5d => ')',
        0x5e => ';',
        0x60 => '-',
        0x61 => '/',
        0x6b => ',',
        0x6c => '%',
        0x6d => '_',
        0x6e => '>',
        0x6f => '?',
        0x7a => ':',
        0x7d => '\'',
        0x7e => '=',
        0x7f => '"',
        0x81..=0x89 => (b'a' + (b - 0x81)) as char,
        0x91..=0x99 => (b'j' + (b - 0x91)) as char,
        0xa2..=0xa9 => (b's' + (b - 0xa2)) as char,
        0xc1..=0xc9 => (b'A' + (b - 0xc1)) as char,
        0xd1..=0xd9 => (b'J' + (b - 0xd1)) as char,
        0xe2..=0xe9 => (b'S' + (b - 0xe2)) as char,
        0xf0..=0xf9 => (b'0' + (b - 0xf0)) as char,
        _ => return None,
    };
    Some(c)
}
