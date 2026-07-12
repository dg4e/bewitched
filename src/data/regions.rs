//! Foldable regions ("data-folds").
//!
//! A document can carry a set of named regions. Memory/RAM sources in particular
//! are described as a list of sections: accessible ones can be folded by the
//! user, and inaccessible ones are hidden (folded) by default. The [`ViewMap`]
//! turns the document length plus the region set into the ordered sequence of
//! visual rows the hex view should draw — data rows interleaved with one-line
//! fold markers — and maps offsets to/from visual rows.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub len: u64,
    pub label: String,
    pub accessible: bool,
    pub folded: bool,
}

impl Region {
    pub fn new(start: u64, len: u64, label: impl Into<String>) -> Self {
        Self {
            start,
            len,
            label: label.into(),
            accessible: true,
            folded: false,
        }
    }

    pub fn inaccessible(start: u64, len: u64, label: impl Into<String>) -> Self {
        Self {
            start,
            len,
            label: label.into(),
            accessible: false,
            folded: true, // hidden by default
        }
    }

    pub fn end(&self) -> u64 {
        self.start + self.len
    }

    fn collapsed(&self) -> bool {
        self.folded
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockKind {
    /// Plain data rows.
    Data,
    /// A collapsed region rendered as a single marker row.
    Fold(usize),
}

#[derive(Clone, Copy, Debug)]
struct Block {
    row_start: usize,
    rows: usize,
    off_start: u64,
    off_len: u64,
    kind: BlockKind,
}

/// What a single visual row contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowItem {
    /// A data row: `base` is the offset of the first byte on the row.
    Data { base: u64 },
    /// A fold marker for region `region`.
    Fold { region: usize },
}

pub struct ViewMap {
    blocks: Vec<Block>,
    total_rows: usize,
    bpr: u64,
}

impl ViewMap {
    /// Build a view map. `regions` need not be sorted; overlapping/out-of-range
    /// regions are clamped and skipped defensively.
    pub fn build(total: u64, regions: &[Region], bytes_per_row: usize) -> Self {
        let bpr = bytes_per_row.max(1) as u64;
        // Index + sort regions by start, dropping zero-length / out-of-range ones.
        let mut idx: Vec<usize> = (0..regions.len())
            .filter(|&i| regions[i].len > 0 && regions[i].start < total)
            .collect();
        idx.sort_by_key(|&i| regions[i].start);

        let mut blocks: Vec<Block> = Vec::new();
        let mut row = 0usize;
        let mut pos = 0u64;

        let push = |blocks: &mut Vec<Block>,
                    row: &mut usize,
                    off_start: u64,
                    off_len: u64,
                    kind: BlockKind| {
            if off_len == 0 {
                return;
            }
            let rows = match kind {
                BlockKind::Data => off_len.div_ceil(bpr) as usize,
                BlockKind::Fold(_) => 1,
            };
            blocks.push(Block {
                row_start: *row,
                rows,
                off_start,
                off_len,
                kind,
            });
            *row += rows;
        };

        for &i in &idx {
            let r = &regions[i];
            let start = r.start;
            let end = r.end().min(total);
            if start < pos {
                // overlaps a previous region; skip to keep the map consistent
                continue;
            }
            if start > pos {
                push(&mut blocks, &mut row, pos, start - pos, BlockKind::Data);
            }
            let rlen = end - start;
            if r.collapsed() {
                push(&mut blocks, &mut row, start, rlen, BlockKind::Fold(i));
            } else {
                push(&mut blocks, &mut row, start, rlen, BlockKind::Data);
            }
            pos = end;
        }
        if pos < total {
            push(&mut blocks, &mut row, pos, total - pos, BlockKind::Data);
        }

        Self {
            blocks,
            total_rows: row,
            bpr,
        }
    }

    pub fn total_rows(&self) -> usize {
        self.total_rows
    }

    /// Resolve a visual row index to its content.
    pub fn row(&self, r: usize) -> Option<RowItem> {
        // binary search for the block whose [row_start, row_start+rows) holds r
        let bi = match self.blocks.binary_search_by(|b| {
            if r < b.row_start {
                std::cmp::Ordering::Greater
            } else if r >= b.row_start + b.rows {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(i) => i,
            Err(_) => return None,
        };
        let b = self.blocks[bi];
        match b.kind {
            BlockKind::Fold(region) => Some(RowItem::Fold { region }),
            BlockKind::Data => {
                let base = b.off_start + (r - b.row_start) as u64 * self.bpr;
                Some(RowItem::Data { base })
            }
        }
    }

    /// Map a document offset to the visual row that displays it (a data row, or
    /// the fold marker if the offset is inside a collapsed region).
    pub fn offset_to_row(&self, off: u64) -> Option<usize> {
        for b in &self.blocks {
            if off >= b.off_start && off < b.off_start + b.off_len {
                return Some(match b.kind {
                    BlockKind::Fold(_) => b.row_start,
                    BlockKind::Data => b.row_start + ((off - b.off_start) / self.bpr) as usize,
                });
            }
        }
        // offset == total: last row
        if off
            >= self
                .blocks
                .last()
                .map(|b| b.off_start + b.off_len)
                .unwrap_or(0)
        {
            return self.total_rows.checked_sub(1);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_regions_is_plain() {
        let vm = ViewMap::build(40, &[], 16);
        assert_eq!(vm.total_rows(), 3); // ceil(40/16)
        assert_eq!(vm.row(0), Some(RowItem::Data { base: 0 }));
        assert_eq!(vm.row(1), Some(RowItem::Data { base: 16 }));
        assert_eq!(vm.row(2), Some(RowItem::Data { base: 32 }));
        assert_eq!(vm.row(3), None);
    }

    #[test]
    fn folded_region_collapses_to_one_row() {
        // [0,16) data | [16,80) folded | [80,96) data
        let mut r = Region::new(16, 64, "blob");
        r.folded = true;
        let vm = ViewMap::build(96, &[r], 16);
        // row0 data@0, row1 fold, row2 data@80
        assert_eq!(vm.total_rows(), 3);
        assert_eq!(vm.row(0), Some(RowItem::Data { base: 0 }));
        assert_eq!(vm.row(1), Some(RowItem::Fold { region: 0 }));
        assert_eq!(vm.row(2), Some(RowItem::Data { base: 80 }));
    }

    #[test]
    fn unfolded_region_shows_rows() {
        let r = Region::new(16, 64, "blob"); // not folded
        let vm = ViewMap::build(96, &[r], 16);
        assert_eq!(vm.total_rows(), 6); // 96/16
        assert_eq!(vm.row(4), Some(RowItem::Data { base: 64 }));
    }

    #[test]
    fn inaccessible_hidden_by_default() {
        let r = Region::inaccessible(0, 1024, "kernel");
        let vm = ViewMap::build(2048, &[r], 16);
        // row0 fold, then data for [1024,2048)
        assert_eq!(vm.row(0), Some(RowItem::Fold { region: 0 }));
        assert_eq!(vm.row(1), Some(RowItem::Data { base: 1024 }));
        assert_eq!(vm.total_rows(), 1 + 64);
    }

    #[test]
    fn offset_to_row_roundtrip() {
        let mut r = Region::new(16, 64, "blob");
        r.folded = true;
        let vm = ViewMap::build(96, &[r], 16);
        assert_eq!(vm.offset_to_row(0), Some(0));
        assert_eq!(vm.offset_to_row(8), Some(0));
        assert_eq!(vm.offset_to_row(40), Some(1)); // inside folded region -> marker row
        assert_eq!(vm.offset_to_row(80), Some(2));
        assert_eq!(vm.offset_to_row(95), Some(2));
    }

    #[test]
    fn multiple_regions_sorted() {
        let a = {
            let mut x = Region::new(64, 16, "b");
            x.folded = true;
            x
        };
        let b = {
            let mut x = Region::new(16, 16, "a");
            x.folded = true;
            x
        };
        // pass out of order; build should sort
        let vm = ViewMap::build(96, &[a, b], 16);
        // [0,16) data | [16,32) fold(b=idx1) | [32,64) data(2 rows) | [64,80) fold(a=idx0) | [80,96) data
        assert_eq!(vm.row(0), Some(RowItem::Data { base: 0 }));
        assert_eq!(vm.row(1), Some(RowItem::Fold { region: 1 }));
        assert_eq!(vm.row(2), Some(RowItem::Data { base: 32 }));
        assert_eq!(vm.row(3), Some(RowItem::Data { base: 48 }));
        assert_eq!(vm.row(4), Some(RowItem::Fold { region: 0 }));
        assert_eq!(vm.row(5), Some(RowItem::Data { base: 80 }));
    }

    #[test]
    fn overlapping_region_skipped() {
        let r1 = {
            let mut x = Region::new(0, 32, "a");
            x.folded = true;
            x
        };
        let r2 = {
            let mut x = Region::new(16, 32, "overlap");
            x.folded = true;
            x
        };
        // r2 overlaps r1; should be skipped without panicking
        let vm = ViewMap::build(64, &[r1, r2], 16);
        assert_eq!(vm.row(0), Some(RowItem::Fold { region: 0 }));
        // remaining [32,64) is data
        assert_eq!(vm.row(1), Some(RowItem::Data { base: 32 }));
    }
}
