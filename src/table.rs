// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The file allocation table: one entry per cluster, linking a file's
//! clusters into a chain.

use std::sync::Arc;

use super::boot::{FatKind, Geometry};
use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::BlockSource;

/// A FAT of at most this many bytes is read into memory at mount. A larger
/// one (FAT32 volumes past about 16 million clusters) is read through the
/// source's cache, entry by entry.
pub const MEM_LIMIT: u64 = 64 * 1024 * 1024;

const STRUCTURE: &str = "file allocation table";

/// What a FAT entry says about the cluster after the one it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// The cluster is free (entry 0).
    Free,
    /// The cluster is marked bad.
    Bad,
    /// The chain ends here.
    End,
    /// The chain continues at this cluster, which is a valid cluster number.
    Data(u32),
    /// A value that is neither: below 2, past the last cluster, or reserved.
    Invalid(u32),
}

/// The first FAT of a volume.
pub struct FatTable {
    kind: FatKind,
    /// The whole table, when it is small enough to keep.
    mem: Option<Vec<u8>>,
    source: Arc<dyn BlockSource>,
    /// Byte offset of the table in `source`.
    offset: u64,
    /// Entries, counting the two reserved ones.
    entries: u32,
    last_cluster: u32,
}

impl FatTable {
    /// Opens the table `geo` describes. Fails with `Corrupt` when the source
    /// ends inside it.
    pub fn load(source: Arc<dyn BlockSource>, geo: &Geometry) -> Result<Self> {
        let end = geo.fat_offset.checked_add(geo.fat_bytes);
        match end {
            Some(end) if end <= source.len() => {}
            _ => {
                return Err(Corruption::new(
                    STRUCTURE,
                    Location::Byte(geo.fat_offset),
                    CorruptKind::Truncated {
                        needed: geo.fat_bytes,
                        available: source.len().saturating_sub(geo.fat_offset),
                    },
                )
                .into());
            }
        }
        let mem = if geo.fat_bytes <= MEM_LIMIT {
            let len = usize::try_from(geo.fat_bytes).map_err(|_| {
                Error::from(Corruption::new(
                    STRUCTURE,
                    Location::Unspecified,
                    CorruptKind::Overflow { field: "FAT size" },
                ))
            })?;
            let mut bytes = vec![0u8; len];
            source.read_bulk(geo.fat_offset, &mut bytes)?;
            Some(bytes)
        } else {
            None
        };
        Ok(Self {
            kind: geo.kind,
            mem,
            source,
            offset: geo.fat_offset,
            entries: geo.cluster_count.saturating_add(2),
            last_cluster: geo.last_cluster(),
        })
    }

    /// True when the whole table is in memory.
    pub fn in_memory(&self) -> bool {
        self.mem.is_some()
    }

    /// Reads `out.len()` bytes at `pos` of the table.
    fn read(&self, pos: u64, out: &mut [u8]) -> Result<()> {
        if let Some(mem) = &self.mem {
            let src = usize::try_from(pos)
                .ok()
                .and_then(|p| Some(p..p.checked_add(out.len())?))
                .and_then(|r| mem.get(r));
            return match src {
                Some(src) => {
                    out.copy_from_slice(src);
                    Ok(())
                }
                None => Err(Corruption::new(
                    STRUCTURE,
                    Location::Byte(pos),
                    CorruptKind::Truncated {
                        needed: u64::try_from(out.len()).unwrap_or(u64::MAX),
                        available: 0,
                    },
                )
                .into()),
            };
        }
        let at = self.offset.checked_add(pos).ok_or_else(|| {
            Error::from(Corruption::new(
                STRUCTURE,
                Location::Byte(pos),
                CorruptKind::Overflow {
                    field: "FAT offset",
                },
            ))
        })?;
        self.source.read_at(at, out)
    }

    /// The raw value of entry `n` (top four bits cleared on FAT32).
    pub fn entry(&self, n: u32) -> Result<u32> {
        if n >= self.entries {
            return Err(Corruption::new(
                STRUCTURE,
                Location::Object(u64::from(n)),
                CorruptKind::OutOfRange {
                    field: "cluster",
                    value: u64::from(n),
                    limit_name: "FAT entries",
                    limit: u64::from(self.entries),
                },
            )
            .into());
        }
        let n64 = u64::from(n);
        match self.kind {
            FatKind::Fat12 => {
                let mut word = [0u8; 2];
                self.read(n64.saturating_add(n64 / 2), &mut word)?;
                let v = u16::from_le_bytes(word);
                Ok(u32::from(if n % 2 == 1 { v >> 4 } else { v & 0x0FFF }))
            }
            FatKind::Fat16 => {
                let mut word = [0u8; 2];
                self.read(n64.saturating_mul(2), &mut word)?;
                Ok(u32::from(u16::from_le_bytes(word)))
            }
            FatKind::Fat32 => {
                let mut word = [0u8; 4];
                self.read(n64.saturating_mul(4), &mut word)?;
                Ok(u32::from_le_bytes(word) & 0x0FFF_FFFF)
            }
        }
    }

    /// What entry `n` says comes after cluster `n`.
    pub fn next(&self, n: u32) -> Result<Next> {
        let v = self.entry(n)?;
        let (bad, end) = match self.kind {
            FatKind::Fat12 => (0x0FF7, 0x0FF8),
            FatKind::Fat16 => (0xFFF7, 0xFFF8),
            FatKind::Fat32 => (0x0FFF_FFF7, 0x0FFF_FFF8),
        };
        Ok(if v == 0 {
            Next::Free
        } else if v == bad {
            Next::Bad
        } else if v >= end {
            Next::End
        } else if v < 2 || v > self.last_cluster {
            Next::Invalid(v)
        } else {
            Next::Data(v)
        })
    }

    /// Appends the raw values of the `count` entries from `first` to `out`.
    /// The caller keeps `count` small (65536 at most is the convention).
    pub fn values(&self, first: u32, count: u32, out: &mut Vec<u32>) -> Result<()> {
        let end = first.saturating_add(count).min(self.entries);
        if self.kind == FatKind::Fat32 && self.mem.is_none() && first < end {
            let n = usize::try_from(end.saturating_sub(first)).unwrap_or(0);
            let mut bytes = vec![0u8; n.saturating_mul(4)];
            self.read(u64::from(first).saturating_mul(4), &mut bytes)?;
            out.extend(
                bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_le_bytes(*c) & 0x0FFF_FFFF),
            );
            return Ok(());
        }
        for n in first..end {
            out.push(self.entry(n)?);
        }
        Ok(())
    }

    /// Clusters whose entry is 0, or `None` when the table is not in memory.
    pub fn count_free(&self) -> Option<u64> {
        let mem = self.mem.as_ref()?;
        let skip = |width: usize| mem.get(width.saturating_mul(2)..).unwrap_or(&[]);
        let live = |width: usize| {
            usize::try_from(self.entries)
                .unwrap_or(0)
                .saturating_sub(2)
                .saturating_mul(width)
        };
        match self.kind {
            FatKind::Fat32 => {
                let bytes = skip(4);
                let bytes = bytes.get(..live(4)).unwrap_or(bytes);
                let free = bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .filter(|c| {
                        c.iter().take(3).all(|&b| b == 0)
                            && c.get(3).is_some_and(|&b| b & 0x0F == 0)
                    })
                    .count();
                Some(u64::try_from(free).unwrap_or(u64::MAX))
            }
            FatKind::Fat16 => {
                let bytes = skip(2);
                let bytes = bytes.get(..live(2)).unwrap_or(bytes);
                let free = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .filter(|c| c.iter().all(|&b| b == 0))
                    .count();
                Some(u64::try_from(free).unwrap_or(u64::MAX))
            }
            FatKind::Fat12 => {
                let mut free = 0u64;
                for n in 2..self.entries {
                    if self.entry(n).ok()? == 0 {
                        free = free.saturating_add(1);
                    }
                }
                Some(free)
            }
        }
    }
}
