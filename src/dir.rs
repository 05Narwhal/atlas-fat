// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Directory entries: short names, long names, dates and attributes.

use std::sync::Arc;

use super::boot::FatKind;
use super::chain::Chain;
use super::cp437;
use atlas_fs_core::error::Result;
use atlas_fs_core::fs::{EntryFlags, Timestamp};
use atlas_fs_core::io::block::BlockSource;

/// Bytes of a directory entry.
pub const ENTRY_LEN: usize = 32;

/// Attribute: read-only.
pub const ATTR_READ_ONLY: u8 = 0x01;
/// Attribute: hidden.
pub const ATTR_HIDDEN: u8 = 0x02;
/// Attribute: system.
pub const ATTR_SYSTEM: u8 = 0x04;
/// Attribute: volume label.
pub const ATTR_VOLUME: u8 = 0x08;
/// Attribute: directory.
pub const ATTR_DIRECTORY: u8 = 0x10;
/// The attribute byte (masked with `0x3F`) of a long-name entry.
pub const ATTR_LONG_NAME: u8 = 0x0F;

/// Most long-name entries in a run (255 units, 13 per entry, rounded up).
const MAX_LFN_ENTRIES: u8 = 20;
const LFN_UNITS: usize = 260;
/// Longest long name in UTF-16 units.
const MAX_NAME_UNITS: usize = 255;
/// Byte offsets of the 13 UTF-16 units of a long-name entry.
const LFN_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

fn le16(b: &[u8], at: usize) -> u16 {
    b.get(at..at.saturating_add(2))
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map_or(0, u16::from_le_bytes)
}

fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..at.saturating_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(0, u32::from_le_bytes)
}

/// A date and time word pair as a timestamp. Local time, 2-second
/// resolution; `None` when a field is out of range (month 0, day 0, hour 24).
// All values are small (year below 2108), so the arithmetic cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
pub fn dos_time(date: u16, time: u16) -> Option<Timestamp> {
    let year = 1980 + i64::from(date >> 9);
    let month = i64::from((date >> 5) & 0x0F);
    let day = i64::from(date & 0x1F);
    let hour = i64::from(time >> 11);
    let minute = i64::from((time >> 5) & 0x3F);
    let second = i64::from(time & 0x1F) * 2;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days from 1970-01-01 (Howard Hinnant's days_from_civil).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(Timestamp::from_unix(
        days * 86_400 + hour * 3600 + minute * 60 + second,
        0,
    ))
}

/// The checksum a long name's entries carry for their short entry.
pub fn short_checksum(name: &[u8; 11]) -> u8 {
    name.iter()
        .fold(0u8, |sum, &b| sum.rotate_right(1).wrapping_add(b))
}

/// A short (8.3) directory entry, as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortEntry {
    /// The 11 name bytes: 8 of name, 3 of extension, space padded.
    pub raw_name: [u8; 11],
    /// The attribute byte.
    pub attr: u8,
    /// Byte 12: the case bits (`0x08` name in lower case, `0x10` extension).
    pub nt_case: u8,
    /// Creation time word.
    pub created_time: u16,
    /// Creation date word.
    pub created_date: u16,
    /// Last access date word.
    pub accessed_date: u16,
    /// Modification time word.
    pub modified_time: u16,
    /// Modification date word.
    pub modified_date: u16,
    /// First cluster; 0 for an empty file.
    pub first_cluster: u32,
    /// Size in bytes (0 for a directory).
    pub size: u32,
}

impl ShortEntry {
    /// Reads the 32 bytes of `b`. The high half of the first cluster counts
    /// on FAT32 only (FAT12/16 keep other data there).
    pub fn parse(b: &[u8], kind: FatKind) -> Option<Self> {
        if b.len() < ENTRY_LEN {
            return None;
        }
        let high = if kind == FatKind::Fat32 {
            u32::from(le16(b, 20))
        } else {
            0
        };
        Some(Self {
            raw_name: <[u8; 11]>::try_from(b.get(..11)?).ok()?,
            attr: *b.get(11)?,
            nt_case: *b.get(12)?,
            created_time: le16(b, 14),
            created_date: le16(b, 16),
            accessed_date: le16(b, 18),
            modified_time: le16(b, 22),
            modified_date: le16(b, 24),
            first_cluster: (high << 16) | u32::from(le16(b, 26)),
            size: le32(b, 28),
        })
    }

    /// True for a folder.
    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }

    /// Hidden or system entries are hidden.
    pub fn flags(&self) -> EntryFlags {
        if self.attr & (ATTR_HIDDEN | ATTR_SYSTEM) != 0 {
            EntryFlags::HIDDEN
        } else {
            EntryFlags::EMPTY
        }
    }

    /// Creation time.
    pub fn created(&self) -> Option<Timestamp> {
        dos_time(self.created_date, self.created_time)
    }

    /// Modification time.
    pub fn modified(&self) -> Option<Timestamp> {
        dos_time(self.modified_date, self.modified_time)
    }

    /// Last access (a date; midnight).
    pub fn accessed(&self) -> Option<Timestamp> {
        dos_time(self.accessed_date, 0)
    }

    /// Appends the short name: `NAME.EXT` through code page 437, with the
    /// case bits applied and `0x05` read as `0xE5`. Appends nothing for a
    /// blank name.
    pub fn short_name_into(&self, out: &mut String) {
        let (base, ext) = self.raw_name.split_at(8);
        let trim = |s: &[u8]| {
            s.iter()
                .rposition(|&b| b != b' ')
                .map_or(0, |i| i.saturating_add(1))
        };
        let base = base.get(..trim(base)).unwrap_or(&[]);
        let ext = ext.get(..trim(ext)).unwrap_or(&[]);
        let push = |out: &mut String, bytes: &[u8], lower: bool, first_is_name: bool| {
            for (i, &b) in bytes.iter().enumerate() {
                let b = if first_is_name && i == 0 && b == 0x05 {
                    0xE5
                } else {
                    b
                };
                let c = cp437::decode(b);
                if lower {
                    // Code page 437 has accented capitals (0x90 is É); the case
                    // bits lower those too, as Windows does.
                    out.extend(c.to_lowercase());
                } else {
                    out.push(c);
                }
            }
        };
        if base.is_empty() && ext.is_empty() {
            return;
        }
        push(out, base, self.nt_case & 0x08 != 0, true);
        if !ext.is_empty() {
            out.push('.');
            push(out, ext, self.nt_case & 0x10 != 0, false);
        }
    }
}

/// Long-name entries collected on the way to their short entry.
pub struct Lfn {
    units: [u16; LFN_UNITS],
    /// The sequence number the next entry must have; 0 when none is open.
    expect: u8,
    total: u8,
    checksum: u8,
    complete: bool,
}

impl Default for Lfn {
    fn default() -> Self {
        Self::new()
    }
}

impl Lfn {
    /// No entries collected.
    pub fn new() -> Self {
        Self {
            units: [0; LFN_UNITS],
            expect: 0,
            total: 0,
            checksum: 0,
            complete: false,
        }
    }

    /// Forgets what was collected.
    pub fn reset(&mut self) {
        self.expect = 0;
        self.total = 0;
        self.complete = false;
    }

    /// Takes one long-name entry. Anything out of order ends the run.
    pub fn push(&mut self, b: &[u8]) {
        let Some(&seq) = b.first() else {
            return self.reset();
        };
        let n = seq & 0x3F;
        let checksum = b.get(13).copied().unwrap_or(0);
        if seq & 0x40 != 0 {
            if n == 0 || n > MAX_LFN_ENTRIES {
                return self.reset();
            }
            self.expect = n;
            self.total = n;
            self.checksum = checksum;
            self.complete = false;
        }
        if self.expect == 0 || n != self.expect || checksum != self.checksum {
            return self.reset();
        }
        let base = usize::from(n.saturating_sub(1)).saturating_mul(13);
        for (k, &at) in LFN_OFFSETS.iter().enumerate() {
            if let Some(unit) = self.units.get_mut(base.saturating_add(k)) {
                *unit = le16(b, at);
            }
        }
        self.expect = n.saturating_sub(1);
        self.complete = self.expect == 0;
    }

    /// Appends the long name when the collected entries are complete and
    /// belong to the short entry `short`. False (nothing appended) otherwise.
    pub fn name_into(&self, short: &[u8; 11], out: &mut String) -> bool {
        if !self.complete || self.total == 0 || self.checksum != short_checksum(short) {
            return false;
        }
        let count = usize::from(self.total)
            .saturating_mul(13)
            .min(MAX_NAME_UNITS);
        let units = self.units.get(..count).unwrap_or(&[]);
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        let before = out.len();
        out.extend(
            char::decode_utf16(units.get(..end).unwrap_or(&[]).iter().copied())
                .map(|r| r.unwrap_or('\u{FFFD}')),
        );
        out.len() != before
    }
}

/// What one 32-byte slot of a directory is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// End of the directory (a zero first byte).
    End,
    /// Deleted, `.`, `..`, or anything else to pass over.
    Skip,
    /// A long-name entry, taken by the [`Lfn`].
    Long,
    /// The volume label entry.
    Label([u8; 11]),
    /// A short entry for a file or folder.
    Entry,
}

/// Classifies `slot`, feeding long-name entries to `lfn` and clearing it on
/// anything that breaks a run. After [`Slot::Entry`] the caller reads the
/// name from `lfn`, then resets it.
pub fn classify(lfn: &mut Lfn, slot: &[u8]) -> Slot {
    let Some(&first) = slot.first() else {
        return Slot::End;
    };
    if slot.len() < ENTRY_LEN || first == 0 {
        return Slot::End;
    }
    if first == 0xE5 {
        lfn.reset();
        return Slot::Skip;
    }
    let attr = slot.get(11).copied().unwrap_or(0);
    if attr & 0x3F == ATTR_LONG_NAME {
        lfn.push(slot);
        return Slot::Long;
    }
    if attr & ATTR_VOLUME != 0 {
        lfn.reset();
        return match slot.get(..11).and_then(|s| <[u8; 11]>::try_from(s).ok()) {
            Some(label) => Slot::Label(label),
            None => Slot::Skip,
        };
    }
    // `.` and `..`: a dot, an optional second dot, then only spaces.
    let name = slot.get(..11).unwrap_or(&[]);
    let rest = if name.get(1) == Some(&b'.') { 2 } else { 1 };
    if first == b'.'
        && name
            .get(rest..)
            .is_some_and(|r| r.iter().all(|&b| b == b' '))
    {
        lfn.reset();
        return Slot::Skip;
    }
    Slot::Entry
}

/// The volume label in the first entries of a root directory `data`: the
/// label entry's 11 bytes, or `None`.
pub fn find_label(data: &[u8]) -> Option<[u8; 11]> {
    let mut lfn = Lfn::new();
    for slot in data.as_chunks::<ENTRY_LEN>().0 {
        match classify(&mut lfn, slot) {
            Slot::End => return None,
            Slot::Label(label) => return Some(label),
            _ => {}
        }
    }
    None
}

/// One entry found by a [`Walker`].
#[derive(Debug, Clone, Copy)]
pub struct Found {
    /// Offset of the short entry in the volume: the entry's node id.
    pub node: u64,
    /// The short entry.
    pub entry: ShortEntry,
}

/// Bytes of a directory read at once (a multiple of 32).
const BUF_LEN: usize = 4096;

/// Walks the entries of a directory, front to back, assembling long names.
///
/// Bounded by the directory's chain (at most 256 MiB, loops cut). The name
/// of the entry just returned is in [`Self::name`].
pub struct Walker {
    chain: Arc<Chain>,
    kind: FatKind,
    pos: u64,
    buf: Vec<u8>,
    buf_start: u64,
    buf_len: usize,
    lfn: Lfn,
    /// The name of the entry [`Self::next`] last returned: the long name
    /// when the entry has a valid one, else the short name.
    pub name: String,
    done: bool,
}

impl Walker {
    /// A walker over the directory whose bytes are `chain`.
    pub fn new(chain: Arc<Chain>, kind: FatKind) -> Self {
        Self {
            chain,
            kind,
            pos: 0,
            buf: vec![0; BUF_LEN],
            buf_start: 0,
            buf_len: 0,
            lfn: Lfn::new(),
            name: String::new(),
            done: false,
        }
    }

    /// The next entry, `Ok(None)` at the end. After an `Err` the walker is
    /// finished.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Found>> {
        loop {
            if self.done {
                return Ok(None);
            }
            let size = self.chain.len();
            if self.pos >= size {
                self.done = true;
                return match self.chain.broken() {
                    Some(damage) => Err(damage.clone().into()),
                    None => Ok(None),
                };
            }
            let buf_end = self
                .buf_start
                .saturating_add(u64::try_from(self.buf_len).unwrap_or(0));
            if self.buf_len == 0 || self.pos < self.buf_start || self.pos >= buf_end {
                let left = size.saturating_sub(self.pos);
                let want = usize::try_from(left).map_or(BUF_LEN, |l| l.min(BUF_LEN));
                let Some(dst) = self.buf.get_mut(..want) else {
                    self.done = true;
                    return Ok(None);
                };
                if let Err(e) = self.chain.read_at(self.pos, dst) {
                    self.done = true;
                    return Err(e);
                }
                self.buf_start = self.pos;
                self.buf_len = want;
            }
            let at = usize::try_from(self.pos.saturating_sub(self.buf_start)).unwrap_or(usize::MAX);
            let record_pos = self.pos;
            self.pos = self.pos.saturating_add(ENTRY_LEN as u64);
            let slot = self
                .buf
                .get(..self.buf_len)
                .and_then(|b| b.get(at..at.saturating_add(ENTRY_LEN)));
            let Some(slot) = slot else {
                self.done = true;
                return Ok(None);
            };
            match classify(&mut self.lfn, slot) {
                Slot::End => {
                    self.done = true;
                    return Ok(None);
                }
                Slot::Skip | Slot::Long | Slot::Label(_) => {}
                Slot::Entry => {
                    let Some(entry) = ShortEntry::parse(slot, self.kind) else {
                        self.lfn.reset();
                        continue;
                    };
                    self.name.clear();
                    if !self.lfn.name_into(&entry.raw_name, &mut self.name) {
                        entry.short_name_into(&mut self.name);
                    }
                    self.lfn.reset();
                    if self.name.is_empty() {
                        continue;
                    }
                    let Some((node, _)) = self.chain.locate(record_pos) else {
                        self.done = true;
                        return Ok(None);
                    };
                    return Ok(Some(Found { node, entry }));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short(name: &[u8; 11], attr: u8, nt: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..11].copy_from_slice(name);
        b[11] = attr;
        b[12] = nt;
        b
    }

    #[test]
    fn dates_decode_and_reject() {
        // 2024-03-05 13:14:16 (local).
        let date = ((2024 - 1980) << 9) | (3 << 5) | 5;
        let time = (13 << 11) | (14 << 5) | 8;
        let t = dos_time(date, time).unwrap();
        assert_eq!(t.unix_seconds(), 1_709_644_456);
        assert_eq!(dos_time(0, 0), None);
        assert_eq!(dos_time((1 << 9) | (13 << 5) | 1, 0), None);
        assert_eq!(dos_time((1 << 9) | (2 << 5) | 30, 0), None);
        assert_eq!(dos_time((1 << 9) | (2 << 5) | 29, 0), None); // 1981 is not a leap year
        assert!(dos_time(((4) << 9) | (2 << 5) | 29, 0).is_some()); // 1984 is
        assert_eq!(dos_time((1 << 9) | (1 << 5) | 1, 24 << 11), None);
        assert_eq!(dos_time((1 << 9) | (1 << 5) | 1, 60 << 5), None);
        assert_eq!(dos_time((1 << 9) | (1 << 5) | 1, 30), None);
        assert_eq!(dos_time(0xFFFF, 0xFFFF), None);
    }

    #[test]
    fn short_names_use_case_bits_and_the_05_rule() {
        let mut s = String::new();
        let e = ShortEntry::parse(&short(b"README  TXT", 0, 0x18), FatKind::Fat16).unwrap();
        e.short_name_into(&mut s);
        assert_eq!(s, "readme.txt");
        s.clear();
        let e = ShortEntry::parse(&short(b"README  TXT", 0, 0x10), FatKind::Fat16).unwrap();
        e.short_name_into(&mut s);
        assert_eq!(s, "README.txt");
        s.clear();
        let e =
            ShortEntry::parse(&short(b"\x05A      \x80\x20\x20", 0, 0), FatKind::Fat16).unwrap();
        e.short_name_into(&mut s);
        assert_eq!(s, "\u{3C3}A.\u{C7}");
        s.clear();
        let e = ShortEntry::parse(&short(b"           ", 0, 0), FatKind::Fat16).unwrap();
        e.short_name_into(&mut s);
        assert_eq!(s, "");
        // 0x90 is É in code page 437; the lower-case bit makes it é.
        s.clear();
        let e = ShortEntry::parse(&short(b"CAF\x90    TXT", 0, 0x18), FatKind::Fat16).unwrap();
        e.short_name_into(&mut s);
        assert_eq!(s, "caf\u{E9}.txt");
    }

    fn lfn_entry(seq: u8, checksum: u8, text: &[u16]) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = seq;
        b[11] = ATTR_LONG_NAME;
        b[13] = checksum;
        for (k, &at) in LFN_OFFSETS.iter().enumerate() {
            let u = text.get(k).copied().unwrap_or(0xFFFF);
            b[at..at + 2].copy_from_slice(&u.to_le_bytes());
        }
        b
    }

    #[test]
    fn long_names_need_order_and_checksum() {
        let raw = *b"LONGNA~1TXT";
        let sum = short_checksum(&raw);
        let text: Vec<u16> = "a long file name.txt".encode_utf16().collect();
        let mut first = text[13..].to_vec();
        first.push(0);
        let e2 = lfn_entry(0x42, sum, &first);
        let e1 = lfn_entry(1, sum, &text[..13]);

        let mut lfn = Lfn::new();
        assert_eq!(classify(&mut lfn, &e2), Slot::Long);
        assert_eq!(classify(&mut lfn, &e1), Slot::Long);
        let mut out = String::new();
        assert!(lfn.name_into(&raw, &mut out));
        assert_eq!(out, "a long file name.txt");

        // A different short entry: checksum mismatch, so no long name.
        out.clear();
        assert!(!lfn.name_into(b"OTHER   TXT", &mut out));
        assert!(out.is_empty());

        // Out of order: the second entry first, then the second again.
        let mut lfn = Lfn::new();
        lfn.push(&e2);
        lfn.push(&e2);
        assert!(!lfn.name_into(&raw, &mut out));

        // The last piece (sequence 1) alone is not a complete run.
        let mut lfn = Lfn::new();
        lfn.push(&e1);
        assert!(!lfn.name_into(&raw, &mut out));

        // A bad checksum in the second entry breaks the run.
        let mut lfn = Lfn::new();
        lfn.push(&e2);
        lfn.push(&lfn_entry(1, sum.wrapping_add(1), &text[..13]));
        assert!(!lfn.name_into(&raw, &mut out));

        // More than 20 entries cannot start a run.
        let mut lfn = Lfn::new();
        lfn.push(&lfn_entry(0x40 | 21, sum, &text[..13]));
        assert!(!lfn.name_into(&raw, &mut out));
    }

    #[test]
    fn slots_are_classified() {
        let mut lfn = Lfn::new();
        assert_eq!(classify(&mut lfn, &[0u8; 32]), Slot::End);
        assert_eq!(classify(&mut lfn, &[0u8; 5]), Slot::End);
        assert_eq!(
            classify(&mut lfn, &short(b"\xE5BC     TXT", 0, 0)),
            Slot::Skip
        );
        assert_eq!(
            classify(&mut lfn, &short(b".          ", ATTR_DIRECTORY, 0)),
            Slot::Skip
        );
        assert_eq!(
            classify(&mut lfn, &short(b"..         ", ATTR_DIRECTORY, 0)),
            Slot::Skip
        );
        assert_eq!(
            classify(&mut lfn, &short(b".PROFILE   ", 0, 0)),
            Slot::Entry
        );
        assert_eq!(
            classify(&mut lfn, &short(b"MY DISK    ", ATTR_VOLUME, 0)),
            Slot::Label(*b"MY DISK    ")
        );
        assert_eq!(
            classify(&mut lfn, &short(b"A       TXT", 0x20, 0)),
            Slot::Entry
        );
        assert_eq!(
            find_label(&short(b"MY DISK    ", ATTR_VOLUME, 0)),
            Some(*b"MY DISK    ")
        );
    }
}
