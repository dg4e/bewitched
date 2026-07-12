//! Kaitai-inspired nested structure parser.
//!
//! A compact, pure-Rust DSL that parses a binary into a *tree* of named, typed
//! fields. Beyond the flat [`super::template`] engine it supports user-defined
//! sub-types, `repeat` (count / end-of-stream / until-condition), conditional
//! fields (`if`), enums, and an expression language that references earlier
//! fields. It is its own format (not the Kaitai `.ksy` YAML), kept small enough
//! to stay dependency-free and unit-testable.
//!
//! ## DSL
//! ```text
//! endian le                      # default byte order (le | be)
//!
//! seq:                           # the root sequence
//!   magic_field magic("PNG")     # literal-bytes assertion
//!   length u32be                 # uint; per-type le/be overrides the default
//!   chunk_type ascii(4)          # N-byte ASCII string (N is an expression)
//!   chunks chunk repeat-eos      # array of a user type until end of stream
//!   flags u8
//!   name ascii(16) if(flags & 1) # conditional field
//!
//! type chunk:                    # a user-defined type
//!   len u32be
//!   data bytes(len)
//!
//! enum color:                    # named values
//!   0 grayscale
//!   2 rgb
//! ```
//! Field line: `<name> <type> [modifiers...]`. Modifiers: `if(EXPR)`,
//! `repeat(EXPR)`, `repeat-eos`, `repeat-until(EXPR)`, `enum(NAME)`. In a
//! `repeat-until` the special variable `_` is the just-read element's value.

use std::collections::HashMap;

use crate::data::ByteReader;

// ============================ expression engine ============================

#[derive(Clone, Debug)]
enum Expr {
    Int(i64),
    Var(String),
    Unary(char, Box<Expr>),
    Bin(String, Box<Expr>, Box<Expr>),
}

struct Scope {
    stack: Vec<HashMap<String, i64>>,
}

impl Scope {
    fn new() -> Self {
        Self {
            stack: vec![HashMap::new()],
        }
    }
    fn push(&mut self) {
        self.stack.push(HashMap::new());
    }
    fn pop(&mut self) {
        self.stack.pop();
    }
    fn set(&mut self, k: &str, v: i64) {
        self.stack.last_mut().unwrap().insert(k.to_string(), v);
    }
    fn get(&self, k: &str) -> Option<i64> {
        self.stack.iter().rev().find_map(|m| m.get(k).copied())
    }
}

fn lex_expr(s: &str) -> Result<Vec<String>, String> {
    let b: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_alphabetic() || c == '_' || c == '.' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == '_' || b[i] == '.') {
                i += 1;
            }
            out.push(b[start..i].iter().collect());
        } else if c.is_ascii_digit() {
            let start = i;
            if c == '0' && i + 1 < b.len() && (b[i + 1] == 'x' || b[i + 1] == 'X') {
                i += 2;
                while i < b.len() && b[i].is_ascii_hexdigit() {
                    i += 1;
                }
            } else {
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
            }
            out.push(b[start..i].iter().collect());
        } else {
            // multi-char operators first
            let two: String = b[i..(i + 2).min(b.len())].iter().collect();
            if ["==", "!=", "<=", ">=", "<<", ">>", "&&", "||"].contains(&two.as_str()) {
                out.push(two);
                i += 2;
            } else if "+-*/%&|^~!<>()".contains(c) {
                out.push(c.to_string());
                i += 1;
            } else {
                return Err(format!("bad character '{c}' in expression"));
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<String>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(|s| s.as_str())
    }
    fn next(&mut self) -> Option<String> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }
    fn eat(&mut self, t: &str) -> bool {
        if self.peek() == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    // precedence-climbing
    fn parse(&mut self) -> Result<Expr, String> {
        self.or_expr()
    }
    fn binary(
        &mut self,
        ops: &[&str],
        next: fn(&mut Parser) -> Result<Expr, String>,
    ) -> Result<Expr, String> {
        let mut lhs = next(self)?;
        while let Some(op) = self.peek() {
            if ops.contains(&op) {
                let op = self.next().unwrap();
                let rhs = next(self)?;
                lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn or_expr(&mut self) -> Result<Expr, String> {
        self.binary(&["||"], Parser::and_expr)
    }
    fn and_expr(&mut self) -> Result<Expr, String> {
        self.binary(&["&&"], Parser::bor)
    }
    fn bor(&mut self) -> Result<Expr, String> {
        self.binary(&["|"], Parser::bxor)
    }
    fn bxor(&mut self) -> Result<Expr, String> {
        self.binary(&["^"], Parser::band)
    }
    fn band(&mut self) -> Result<Expr, String> {
        self.binary(&["&"], Parser::eq)
    }
    fn eq(&mut self) -> Result<Expr, String> {
        self.binary(&["==", "!="], Parser::cmp)
    }
    fn cmp(&mut self) -> Result<Expr, String> {
        self.binary(&["<", "<=", ">", ">="], Parser::shift)
    }
    fn shift(&mut self) -> Result<Expr, String> {
        self.binary(&["<<", ">>"], Parser::add)
    }
    fn add(&mut self) -> Result<Expr, String> {
        self.binary(&["+", "-"], Parser::mul)
    }
    fn mul(&mut self) -> Result<Expr, String> {
        self.binary(&["*", "/", "%"], Parser::unary)
    }
    fn unary(&mut self) -> Result<Expr, String> {
        if let Some(op) = self.peek() {
            if op == "-" || op == "~" || op == "!" {
                let c = self.next().unwrap().chars().next().unwrap();
                return Ok(Expr::Unary(c, Box::new(self.unary()?)));
            }
        }
        self.primary()
    }
    fn primary(&mut self) -> Result<Expr, String> {
        let t = self.next().ok_or("unexpected end of expression")?;
        if t == "(" {
            let e = self.parse()?;
            if !self.eat(")") {
                return Err("missing ')'".into());
            }
            return Ok(e);
        }
        if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            return i64::from_str_radix(h, 16)
                .map(Expr::Int)
                .map_err(|_| "bad hex".into());
        }
        if t.chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            return t
                .parse::<i64>()
                .map(Expr::Int)
                .map_err(|_| "bad number".into());
        }
        Ok(Expr::Var(t))
    }
}

fn parse_expr(s: &str) -> Result<Expr, String> {
    let toks = lex_expr(s)?;
    if toks.is_empty() {
        return Err("empty expression".into());
    }
    let mut p = Parser { toks, pos: 0 };
    let e = p.parse()?;
    if p.pos != p.toks.len() {
        return Err(format!(
            "trailing tokens in expression near '{}'",
            p.toks[p.pos]
        ));
    }
    Ok(e)
}

fn eval(e: &Expr, scope: &Scope) -> Result<i64, String> {
    Ok(match e {
        Expr::Int(n) => *n,
        Expr::Var(v) => scope.get(v).ok_or_else(|| format!("unknown field '{v}'"))?,
        Expr::Unary(op, x) => {
            let v = eval(x, scope)?;
            match op {
                // wrapping_neg so `-i64::MIN` (from a crafted field value) can't panic
                '-' => v.wrapping_neg(),
                '~' => !v,
                '!' => (v == 0) as i64,
                _ => return Err("bad unary".into()),
            }
        }
        Expr::Bin(op, a, b) => {
            let l = eval(a, scope)?;
            let r = eval(b, scope)?;
            // Operands can be file-derived (a u64 field cast to i64), so all
            // arithmetic must be panic-free: wrapping for +/-/*, checked div/rem
            // (guards `i64::MIN / -1`), and bounded shift amounts.
            match op.as_str() {
                "+" => l.wrapping_add(r),
                "-" => l.wrapping_sub(r),
                "*" => l.wrapping_mul(r),
                "/" => {
                    if r == 0 {
                        return Err("divide by zero".into());
                    }
                    l.checked_div(r).ok_or("integer overflow in '/'")?
                }
                "%" => {
                    if r == 0 {
                        return Err("modulo by zero".into());
                    }
                    l.checked_rem(r).ok_or("integer overflow in '%'")?
                }
                "&" => l & r,
                "|" => l | r,
                "^" => l ^ r,
                "<<" => {
                    if !(0..64).contains(&r) {
                        return Err("shift amount out of range".into());
                    }
                    l.wrapping_shl(r as u32)
                }
                ">>" => {
                    if !(0..64).contains(&r) {
                        return Err("shift amount out of range".into());
                    }
                    l.wrapping_shr(r as u32)
                }
                "==" => (l == r) as i64,
                "!=" => (l != r) as i64,
                "<" => (l < r) as i64,
                "<=" => (l <= r) as i64,
                ">" => (l > r) as i64,
                ">=" => (l >= r) as i64,
                "&&" => ((l != 0) && (r != 0)) as i64,
                "||" => ((l != 0) || (r != 0)) as i64,
                _ => return Err(format!("bad operator '{op}'")),
            }
        }
    })
}

// ================================ AST ====================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Debug)]
enum FieldType {
    U(usize, Option<Endian>),
    S(usize, Option<Endian>),
    F(usize, Option<Endian>),
    Ascii(Expr),
    Bytes(Expr),
    Magic(Vec<u8>),
    User(String),
}

#[derive(Clone, Debug)]
enum Repeat {
    No,
    Count(Expr),
    Eos,
    Until(Expr),
}

#[derive(Clone, Debug)]
struct Field {
    name: String,
    ty: FieldType,
    repeat: Repeat,
    cond: Option<Expr>,
    enumref: Option<String>,
}

pub struct Schema {
    endian: Endian,
    root: Vec<Field>,
    types: HashMap<String, Vec<Field>>,
    enums: HashMap<String, HashMap<i64, String>>,
}

// ============================ DSL parser =================================

/// Split a line into tokens, keeping balanced `(...)` groups (with internal
/// spaces) as part of a single token.
fn tokenize_line(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth -= 1;
                cur.push(c);
            }
            c if c.is_whitespace() && depth == 0 => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `name(inner)` -> (name, inner); otherwise None.
fn split_call(tok: &str) -> Option<(&str, &str)> {
    let open = tok.find('(')?;
    if !tok.ends_with(')') {
        return None;
    }
    Some((&tok[..open], &tok[open + 1..tok.len() - 1]))
}

fn scalar_type(tok: &str) -> Option<FieldType> {
    let (base, endian) = if let Some(b) = tok.strip_suffix("le") {
        (b, Some(Endian::Little))
    } else if let Some(b) = tok.strip_suffix("be") {
        (b, Some(Endian::Big))
    } else {
        (tok, None)
    };
    // Width in bytes, restricted to whole-byte widths that fit a u64. This
    // rejects malformed widths like `u0`, `u9`, or `s128` whose downstream
    // shift (`64 - w*8`) and reads would otherwise underflow / truncate.
    let width = |c: &str| -> Option<usize> {
        let bits: usize = c.parse().ok()?;
        (bits != 0 && bits % 8 == 0 && bits <= 64).then_some(bits / 8)
    };
    if base.len() < 2 {
        return None;
    }
    let (prefix, rest) = base.split_at(1);
    let w = width(rest)?;
    match prefix {
        "u" => Some(FieldType::U(w, endian)),
        "s" => Some(FieldType::S(w, endian)),
        // floats only exist at 32/64 bits
        "f" if w == 4 || w == 8 => Some(FieldType::F(w, endian)),
        _ => None,
    }
}

fn parse_magic(inner: &str) -> Result<Vec<u8>, String> {
    let inner = inner.trim();
    if let Some(s) = inner.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Ok(s.as_bytes().to_vec());
    }
    inner
        .split_whitespace()
        .map(|t| {
            u8::from_str_radix(t.trim_start_matches("0x"), 16)
                .map_err(|_| format!("bad magic byte '{t}'"))
        })
        .collect()
}

fn parse_field(line: &str, known_types: &[String]) -> Result<Field, String> {
    let toks = tokenize_line(line);
    if toks.len() < 2 {
        return Err(format!("field needs a name and type: '{line}'"));
    }
    let name = toks[0].clone();
    let type_tok = &toks[1];

    let ty = if let Some((head, inner)) = split_call(type_tok) {
        match head {
            "ascii" | "str" | "bytes" if head != "magic" => {
                let cnt = parse_expr(inner)?;
                if head == "bytes" {
                    FieldType::Bytes(cnt)
                } else {
                    FieldType::Ascii(cnt)
                }
            }
            "magic" => FieldType::Magic(parse_magic(inner)?),
            other => return Err(format!("unknown type '{other}'")),
        }
    } else if let Some(t) = scalar_type(type_tok) {
        t
    } else if known_types.iter().any(|t| t == type_tok) {
        FieldType::User(type_tok.clone())
    } else {
        return Err(format!("unknown type '{type_tok}' for field '{name}'"));
    };

    let mut field = Field {
        name,
        ty,
        repeat: Repeat::No,
        cond: None,
        enumref: None,
    };

    for m in &toks[2..] {
        if m == "repeat-eos" {
            field.repeat = Repeat::Eos;
            continue;
        }
        let (head, inner) = split_call(m).ok_or_else(|| format!("bad modifier '{m}'"))?;
        match head {
            "if" => field.cond = Some(parse_expr(inner)?),
            "repeat" => field.repeat = Repeat::Count(parse_expr(inner)?),
            "repeat-until" => field.repeat = Repeat::Until(parse_expr(inner)?),
            "enum" => field.enumref = Some(inner.trim().to_string()),
            other => return Err(format!("unknown modifier '{other}'")),
        }
    }
    Ok(field)
}

impl Schema {
    pub fn parse(src: &str) -> Result<Schema, String> {
        // group into (indent, content, lineno), dropping comments/blanks
        let lines: Vec<(usize, String, usize)> = src
            .lines()
            .enumerate()
            .filter_map(|(n, raw)| {
                let content = raw.split('#').next().unwrap_or("");
                let trimmed = content.trim_end();
                if trimmed.trim().is_empty() {
                    return None;
                }
                let indent = trimmed.len() - trimmed.trim_start().len();
                Some((indent, trimmed.trim().to_string(), n + 1))
            })
            .collect();

        // first pass: collect type/enum names so field parsing can resolve them
        let mut type_names: Vec<String> = Vec::new();
        for (_, c, _) in &lines {
            if let Some(rest) = c.strip_prefix("type ") {
                if let Some(name) = rest.trim().strip_suffix(':') {
                    type_names.push(name.trim().to_string());
                }
            }
        }

        let mut schema = Schema {
            endian: Endian::Little,
            root: Vec::new(),
            types: HashMap::new(),
            enums: HashMap::new(),
        };

        let mut i = 0;
        while i < lines.len() {
            let (indent, content, lineno) = &lines[i];
            let err = |m: String| format!("line {lineno}: {m}");
            if *indent != 0 {
                return Err(err(format!("unexpected indentation: '{content}'")));
            }
            if let Some(e) = content.strip_prefix("endian ") {
                schema.endian = match e.trim() {
                    "le" => Endian::Little,
                    "be" => Endian::Big,
                    o => return Err(err(format!("endian must be le|be, got '{o}'"))),
                };
                i += 1;
            } else if content == "seq:"
                || content.starts_with("type ")
                || content.starts_with("enum ")
            {
                // gather body lines (indent > 0) following this header
                let mut body = Vec::new();
                let mut j = i + 1;
                while j < lines.len() && lines[j].0 > 0 {
                    body.push((lines[j].1.clone(), lines[j].2));
                    j += 1;
                }
                if content == "seq:" {
                    for (bl, ln) in &body {
                        schema.root.push(
                            parse_field(bl, &type_names).map_err(|m| format!("line {ln}: {m}"))?,
                        );
                    }
                } else if let Some(rest) = content.strip_prefix("type ") {
                    let name = rest
                        .trim()
                        .strip_suffix(':')
                        .ok_or_else(|| err("type needs ':'".into()))?
                        .trim();
                    let mut fields = Vec::new();
                    for (bl, ln) in &body {
                        fields.push(
                            parse_field(bl, &type_names).map_err(|m| format!("line {ln}: {m}"))?,
                        );
                    }
                    schema.types.insert(name.to_string(), fields);
                } else if let Some(rest) = content.strip_prefix("enum ") {
                    let name = rest
                        .trim()
                        .strip_suffix(':')
                        .ok_or_else(|| err("enum needs ':'".into()))?
                        .trim();
                    let mut map = HashMap::new();
                    for (bl, ln) in &body {
                        let mut it = bl.splitn(2, char::is_whitespace);
                        let num = it.next().unwrap_or("");
                        let label = it.next().unwrap_or("").trim();
                        let n = super::parse_int_lit(num)
                            .and_then(|v| i64::try_from(v).ok())
                            .ok_or_else(|| format!("line {ln}: bad enum value '{num}'"))?;
                        map.insert(n, label.to_string());
                    }
                    schema.enums.insert(name.to_string(), map);
                }
                i = j;
            } else {
                return Err(err(format!("unexpected statement '{content}'")));
            }
        }
        if schema.root.is_empty() {
            return Err("schema has no 'seq:' block".into());
        }
        Ok(schema)
    }
}

// ============================ interpreter ================================

/// A parsed node in the structure tree.
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub kind: String,
    pub value: String,
    pub children: Vec<Node>,
}

const MAX_NODES: usize = 200_000;
const MAX_DEPTH: usize = 64;

struct Interp<'a> {
    reader: &'a dyn ByteReader,
    schema: &'a Schema,
    pos: u64,
    nodes: usize,
}

impl<'a> Interp<'a> {
    fn read_uint(&mut self, n: usize, le: bool) -> Result<u64, String> {
        let mut buf = vec![0u8; n];
        if self.reader.read_at(self.pos, &mut buf) != n {
            return Err(format!("unexpected end of data at {:#X}", self.pos));
        }
        self.pos += n as u64;
        let mut v = 0u64;
        if le {
            for &b in buf.iter().rev() {
                v = (v << 8) | b as u64;
            }
        } else {
            for &b in &buf {
                v = (v << 8) | b as u64;
            }
        }
        Ok(v)
    }

    fn endian_of(&self, o: Option<Endian>) -> bool {
        matches!(o.unwrap_or(self.schema.endian), Endian::Little)
    }

    /// Read one instance of a field's base type (no repeat handling). Returns the
    /// node plus an optional integer value for the scope.
    fn read_one(
        &mut self,
        name: &str,
        ty: &FieldType,
        enumref: &Option<String>,
        scope: &mut Scope,
        depth: usize,
    ) -> Result<(Node, Option<i64>), String> {
        if depth > MAX_DEPTH {
            return Err("structure nested too deep".into());
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err("too many fields (runaway repeat?)".into());
        }
        let start = self.pos;
        match ty {
            FieldType::U(w, e) => {
                let v = self.read_uint(*w, self.endian_of(*e))?;
                let scalar = v as i64;
                let value = match enumref.as_ref().and_then(|en| self.schema.enums.get(en)) {
                    Some(map) => match map.get(&scalar) {
                        Some(label) => format!("{label} ({v})"),
                        None => format!("{v}"),
                    },
                    None => format!("{v}"),
                };
                Ok((
                    self.leaf(name, start, format!("u{}", w * 8), value),
                    Some(scalar),
                ))
            }
            FieldType::S(w, e) => {
                let raw = self.read_uint(*w, self.endian_of(*e))?;
                let shift = 64 - w * 8;
                let v = ((raw << shift) as i64) >> shift;
                Ok((
                    self.leaf(name, start, format!("s{}", w * 8), v.to_string()),
                    Some(v),
                ))
            }
            FieldType::F(w, e) => {
                let raw = self.read_uint(*w, self.endian_of(*e))?;
                let value = if *w == 4 {
                    f32::from_bits(raw as u32).to_string()
                } else {
                    f64::from_bits(raw).to_string()
                };
                Ok((self.leaf(name, start, format!("f{}", w * 8), value), None))
            }
            FieldType::Ascii(cnt) => {
                let n = eval(cnt, scope)?.max(0) as usize;
                let bytes = self.read_bytes(n)?;
                let s = String::from_utf8_lossy(&bytes)
                    .trim_end_matches('\0')
                    .to_string();
                Ok((self.leaf(name, start, "ascii".into(), s), None))
            }
            FieldType::Bytes(cnt) => {
                let n = eval(cnt, scope)?.max(0) as usize;
                let bytes = self.read_bytes(n)?;
                let preview: String = bytes
                    .iter()
                    .take(16)
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let value = if bytes.len() > 16 {
                    format!("{preview} … ({} bytes)", bytes.len())
                } else {
                    preview
                };
                Ok((self.leaf(name, start, "bytes".into(), value), None))
            }
            FieldType::Magic(m) => {
                let got = self.read_bytes(m.len())?;
                if &got != m {
                    return Err(format!("magic mismatch at {start:#X}"));
                }
                Ok((
                    self.leaf(
                        name,
                        start,
                        "magic".into(),
                        String::from_utf8_lossy(m).into_owned(),
                    ),
                    None,
                ))
            }
            FieldType::User(tname) => {
                let fields = self
                    .schema
                    .types
                    .get(tname)
                    .ok_or_else(|| format!("unknown type '{tname}'"))?
                    .clone();
                scope.push();
                let mut children = Vec::new();
                for f in &fields {
                    self.run_field(f, scope, &mut children, depth + 1)?;
                }
                scope.pop();
                let mut node = Node {
                    name: name.to_string(),
                    offset: start,
                    size: self.pos - start,
                    kind: tname.clone(),
                    value: String::new(),
                    children,
                };
                node.size = self.pos - start;
                Ok((node, None))
            }
        }
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        let buf = self.reader.read_range(self.pos, n);
        if buf.len() < n {
            return Err(format!("unexpected end of data at {:#X}", self.pos));
        }
        self.pos += n as u64;
        Ok(buf)
    }

    fn leaf(&self, name: &str, offset: u64, kind: String, value: String) -> Node {
        Node {
            name: name.to_string(),
            offset,
            size: self.pos - offset,
            kind,
            value,
            children: Vec::new(),
        }
    }

    /// Handle one schema field (condition, repeat) appending result nodes to `out`.
    fn run_field(
        &mut self,
        f: &Field,
        scope: &mut Scope,
        out: &mut Vec<Node>,
        depth: usize,
    ) -> Result<(), String> {
        if let Some(c) = &f.cond {
            if eval(c, scope)? == 0 {
                return Ok(());
            }
        }
        match &f.repeat {
            Repeat::No => {
                let (node, scalar) = self.read_one(&f.name, &f.ty, &f.enumref, scope, depth)?;
                if let Some(v) = scalar {
                    scope.set(&f.name, v);
                }
                out.push(node);
            }
            _ => {
                let start = self.pos;
                let mut children = Vec::new();
                let mut idx = 0usize;
                let count = match &f.repeat {
                    Repeat::Count(e) => Some(eval(e, scope)?.max(0) as usize),
                    _ => None,
                };
                loop {
                    if let Some(c) = count {
                        if idx >= c {
                            break;
                        }
                    } else if matches!(f.repeat, Repeat::Eos) && self.pos >= self.reader.len() {
                        break;
                    }
                    let before = self.pos;
                    let (mut node, scalar) = self.read_one(
                        &format!("{}[{idx}]", f.name),
                        &f.ty,
                        &f.enumref,
                        scope,
                        depth,
                    )?;
                    node.name = format!("{}[{idx}]", f.name);
                    let elem_val = scalar;
                    children.push(node);
                    idx += 1;
                    // guard against zero-width elements in eos/until loops
                    if self.pos == before && !matches!(f.repeat, Repeat::Count(_)) {
                        break;
                    }
                    if let Repeat::Until(e) = &f.repeat {
                        scope.set("_", elem_val.unwrap_or(0));
                        if eval(e, scope)? != 0 {
                            break;
                        }
                    }
                    if children.len() > MAX_NODES {
                        return Err("runaway repeat".into());
                    }
                }
                out.push(Node {
                    name: f.name.clone(),
                    offset: start,
                    size: self.pos - start,
                    kind: format!("[{}]", children.len()),
                    value: String::new(),
                    children,
                });
            }
        }
        Ok(())
    }
}

/// Parse `reader` starting at `start` against `schema`, returning the root node.
pub fn apply(schema: &Schema, reader: &dyn ByteReader, start: u64) -> Result<Node, String> {
    let mut interp = Interp {
        reader,
        schema,
        pos: start,
        nodes: 0,
    };
    let mut scope = Scope::new();
    let mut children = Vec::new();
    for f in &schema.root {
        interp.run_field(f, &mut scope, &mut children, 0)?;
    }
    Ok(Node {
        name: "root".into(),
        offset: start,
        size: interp.pos - start,
        kind: "struct".into(),
        value: String::new(),
        children,
    })
}

/// Render a node tree as indented text (for CLI / previews).
pub fn render_tree(node: &Node, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    let val = if node.value.is_empty() {
        String::new()
    } else {
        format!(" = {}", node.value)
    };
    out.push_str(&format!(
        "{pad}{:#010X}  {} : {}{}\n",
        node.offset, node.name, node.kind, val
    ));
    for c in &node.children {
        render_tree(c, indent + 1, out);
    }
}

/// Built-in example schemas: (display name, source).
pub const BUILTINS: &[(&str, &str)] = &[
    (
        "PNG",
        "endian be\n\nseq:\n  magic magic(89 50 4E 47 0D 0A 1A 0A)\n  chunks chunk repeat-eos\n\ntype chunk:\n  length u32be\n  ctype ascii(4)\n  data bytes(length)\n  crc u32be\n",
    ),
    (
        "GIF",
        "endian le\n\nseq:\n  magic magic(\"GIF\")\n  version ascii(3)\n  width u16\n  height u16\n  flags u8\n  bg_color u8\n  aspect u8\n",
    ),
    (
        "ELF64 header",
        "endian le\n\nseq:\n  magic magic(7F 45 4C 46)\n  ei_class u8\n  ei_data u8\n  ei_version u8\n  ei_osabi u8\n  pad bytes(8)\n  e_type u16 enum(et)\n  e_machine u16\n  e_version u32\n  e_entry u64\n  e_phoff u64\n  e_shoff u64\n  e_flags u32\n  e_ehsize u16\n  e_phentsize u16\n  e_phnum u16\n  e_shentsize u16\n  e_shnum u16\n  e_shstrndx u16\n\nenum et:\n  1 relocatable\n  2 executable\n  3 shared\n  4 core\n",
    ),
    (
        "WAV header",
        "endian le\n\nseq:\n  riff magic(\"RIFF\")\n  size u32\n  wave magic(\"WAVE\")\n  fmt_id ascii(4)\n  fmt_size u32\n  audio_format u16\n  channels u16\n  sample_rate u32\n  byte_rate u32\n  block_align u16\n  bits_per_sample u16\n",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Document, MemSource};
    use std::sync::Arc;

    fn doc(b: &[u8]) -> Document {
        Document::from_source(Arc::new(MemSource::new(b.to_vec(), "t")))
    }

    fn child<'a>(n: &'a Node, name: &str) -> &'a Node {
        n.children
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no child '{name}'"))
    }

    // ---- expression engine ----
    #[test]
    fn expr_arithmetic_and_precedence() {
        let mut s = Scope::new();
        s.set("a", 10);
        s.set("flags", 0x81);
        let ev = |src: &str, sc: &Scope| eval(&parse_expr(src).unwrap(), sc).unwrap();
        assert_eq!(ev("2 + 3 * 4", &s), 14);
        assert_eq!(ev("(2 + 3) * 4", &s), 20);
        assert_eq!(ev("a - 4", &s), 6);
        assert_eq!(ev("flags & 0x80", &s), 0x80);
        assert_eq!(ev("flags & 1 != 0", &s), 1); // == binds looser than &? we eval & first
        assert_eq!(ev("a > 5 && a < 20", &s), 1);
        assert_eq!(ev("1 << 4", &s), 16);
        assert_eq!(ev("~0 & 0xFF", &s), 0xFF);
    }

    #[test]
    fn expr_errors() {
        assert!(parse_expr("1 +").is_err());
        assert!(parse_expr("(1 + 2").is_err());
        let s = Scope::new();
        assert!(eval(&parse_expr("missing").unwrap(), &s).is_err());
        assert!(eval(&parse_expr("1 / 0").unwrap(), &s).is_err());
    }

    #[test]
    fn expr_is_panic_free_on_adversarial_operands() {
        // Operands can be file-derived (a u64 field as i64), so every arithmetic
        // path must avoid panics in BOTH debug and release.
        let mut s = Scope::new();
        s.set("min", i64::MIN);
        s.set("max", i64::MAX);
        let ev = |src: &str, sc: &Scope| eval(&parse_expr(src).unwrap(), sc);
        // i64::MIN / -1 and % -1 overflow — must be a clean error, not a panic.
        assert!(ev("min / -1", &s).is_err());
        assert!(ev("min % -1", &s).is_err());
        // Shift counts outside 0..64 are rejected, not masked/UB.
        assert!(ev("1 << 64", &s).is_err());
        assert!(ev("1 << -1", &s).is_err());
        assert!(ev("1 >> 64", &s).is_err());
        // +,-,*, unary - wrap instead of panicking on overflow.
        assert_eq!(ev("max + 1", &s).unwrap(), i64::MIN);
        assert_eq!(ev("max * 2", &s).unwrap(), -2);
        assert_eq!(ev("-min", &s).unwrap(), i64::MIN);
    }

    #[test]
    fn rejects_oversized_scalar_widths() {
        // `s128`/`u128` would underflow `64 - w*8`; `u0`/`f16` are nonsense.
        assert!(Schema::parse("seq:\n  x s128\n").is_err());
        assert!(Schema::parse("seq:\n  x u128\n").is_err());
        assert!(Schema::parse("seq:\n  x u0\n").is_err());
        assert!(Schema::parse("seq:\n  x f16\n").is_err());
        // Valid whole-byte widths still parse.
        assert!(Schema::parse("seq:\n  x u64\n").is_ok());
        assert!(Schema::parse("seq:\n  x s8\n").is_ok());
        assert!(Schema::parse("seq:\n  x f32\n").is_ok());
    }

    #[test]
    fn divide_by_minus_one_via_file_value_does_not_panic() {
        // x = i64::MIN read as u64, used in `x / -1` — end-to-end through apply.
        let schema = Schema::parse("endian le\nseq:\n  x u64\n  y u8 if(x / -1)\n").unwrap();
        let data = [0, 0, 0, 0, 0, 0, 0, 0x80, 0xAA]; // x = 0x8000_0000_0000_0000
        assert!(apply(&schema, &doc(&data), 0).is_err());
    }

    // ---- structure parsing ----
    #[test]
    fn flat_fields_and_endian() {
        let s = Schema::parse("endian le\nseq:\n  a u16\n  b u16be\n").unwrap();
        let d = doc(&[0x34, 0x12, 0x12, 0x34]);
        let root = apply(&s, &d, 0).unwrap();
        assert_eq!(child(&root, "a").value, "4660"); // 0x1234 LE
        assert_eq!(child(&root, "b").value, "4660"); // 0x1234 BE
    }

    #[test]
    fn png_chunks_repeat_eos_and_nested() {
        // PNG sig + one IHDR chunk (len=13)
        let mut data = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        data.extend_from_slice(&13u32.to_be_bytes());
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&[0u8; 13]);
        data.extend_from_slice(&0u32.to_be_bytes()); // crc
        let s = Schema::parse(BUILTINS[0].1).unwrap();
        let root = apply(&s, &doc(&data), 0).unwrap();
        let chunks = child(&root, "chunks");
        assert_eq!(chunks.children.len(), 1);
        let c0 = &chunks.children[0];
        assert_eq!(child(c0, "length").value, "13");
        assert_eq!(child(c0, "ctype").value, "IHDR");
        assert_eq!(child(c0, "data").size, 13);
    }

    #[test]
    fn conditional_field() {
        let s =
            Schema::parse("endian le\nseq:\n  flags u8\n  name ascii(3) if(flags & 1)\n").unwrap();
        // flag set -> name present
        let on = apply(&s, &doc(b"\x01abc"), 0).unwrap();
        assert_eq!(child(&on, "name").value, "abc");
        // flag clear -> name skipped
        let off = apply(&s, &doc(b"\x00abc"), 0).unwrap();
        assert!(off.children.iter().all(|c| c.name != "name"));
    }

    #[test]
    fn repeat_count_and_until() {
        // repeat(count)
        let s = Schema::parse("endian le\nseq:\n  n u8\n  vals u8 repeat(n)\n").unwrap();
        let root = apply(&s, &doc(&[3, 10, 20, 30, 99]), 0).unwrap();
        assert_eq!(child(&root, "vals").children.len(), 3);

        // repeat-until a null terminator (_ is the element value)
        let s2 = Schema::parse("endian le\nseq:\n  str u8 repeat-until(_ == 0)\n").unwrap();
        let root2 = apply(&s2, &doc(b"hi\x00rest"), 0).unwrap();
        let arr = child(&root2, "str");
        assert_eq!(arr.children.len(), 3); // 'h','i',0
    }

    #[test]
    fn enum_labels() {
        let s = Schema::parse(BUILTINS[2].1).unwrap();
        let mut data = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
        data.extend_from_slice(&[0u8; 8]); // pad
        data.extend_from_slice(&2u16.to_le_bytes()); // e_type = executable
        data.resize(64, 0);
        let root = apply(&s, &doc(&data), 0).unwrap();
        assert!(child(&root, "e_type").value.contains("executable"));
    }

    #[test]
    fn magic_mismatch_and_eod() {
        let s = Schema::parse("endian le\nseq:\n  m magic(\"GIF\")\n").unwrap();
        assert!(apply(&s, &doc(b"XXX"), 0)
            .unwrap_err()
            .contains("magic mismatch"));
        let s2 = Schema::parse("endian le\nseq:\n  a u32\n").unwrap();
        assert!(apply(&s2, &doc(b"\x01"), 0)
            .unwrap_err()
            .contains("end of data"));
    }

    #[test]
    fn all_builtins_parse() {
        for (name, src) in BUILTINS {
            Schema::parse(src).unwrap_or_else(|e| panic!("builtin {name}: {e}"));
        }
    }

    #[test]
    fn render_tree_works() {
        let s = Schema::parse("endian le\nseq:\n  a u8\n").unwrap();
        let root = apply(&s, &doc(&[42]), 0).unwrap();
        let mut out = String::new();
        render_tree(&root, 0, &mut out);
        assert!(out.contains("a : u8 = 42"));
    }

    #[test]
    fn parse_reports_errors() {
        assert!(Schema::parse("seq:\n  x notatype\n").is_err());
        assert!(Schema::parse("endian sideways\nseq:\n  a u8\n").is_err());
        assert!(Schema::parse("endian le\n").is_err()); // no seq
    }
}
