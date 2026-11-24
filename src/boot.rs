// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! The boot sector (BIOS parameter block) and the geometry it implies.
//!
//! Offsets follow Microsoft's FAT specification: the common fields are the
//! same on all three types, the extended fields of FAT32 (sectors per FAT,
//! root cluster, label) sit at different offsets from those of FAT12/16.

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};

/// Bytes of the boot sector this module reads.
pub const BOOT_LEN: usize = 512;

/// Most clusters a FAT32 volume can number (entries are 28 bits, and the
/// values from `0x0FFF_FFF7` up are reserved).
pub const MAX_CLUSTERS: u32 = 0x0FFF_FFF5;

const STRUCTURE: &str = "FAT boot sector";

/// Which FAT a volume uses. Decided by the cluster count alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatKind {
    /// 12-bit entries, fewer than 4085 clusters.
    Fat12,
    /// 16-bit entries, fewer than 65525 clusters.
    Fat16,
    /// 32-bit entries (28 bits used).
    Fat32,
}

impl FatKind {
    /// The kind a data area of `clusters` clusters is.
    pub fn of_cluster_count(clusters: u32) -> Self {
        if clusters < 4085 {
            Self::Fat12
        } else if clusters < 65525 {
            Self::Fat16
        } else {
            Self::Fat32
        }
    }

    /// The name shown to users.
    pub fn name(self) -> &'static str {
        match self {
            Self::Fat12 => "FAT12",
            Self::Fat16 => "FAT16",
            Self::Fat32 => "FAT32",
        }
    }

    /// Bytes of FAT that hold `entries` entries.
    pub fn table_bytes(self, entries: u64) -> Option<u64> {
        match self {
            Self::Fat12 => entries.checked_mul(3).map(|b| b.div_ceil(2)),
            Self::Fat16 => entries.checked_mul(2),
            Self::Fat32 => entries.checked_mul(4),
        }
    }
}

/// The validated layout of a volume. Every field has been checked against
/// the others, and every byte offset fits in `u64`.
#[derive(Debug, Clone)]
pub struct Geometry {
    /// FAT12, FAT16 or FAT32.
    pub kind: FatKind,
    /// Bytes per sector: 512, 1024, 2048 or 4096.
    pub bytes_per_sector: u32,
    /// Bytes per cluster.
    pub cluster_size: u32,
    /// Sectors in the volume, as declared.
    pub total_sectors: u64,
    /// Number of clusters in the data area (numbered from 2).
    pub cluster_count: u32,
    /// Byte offset of the first FAT.
    pub fat_offset: u64,
    /// Bytes of the first FAT that the cluster count needs.
    pub fat_bytes: u64,
    /// Byte offset of the fixed root directory (FAT12/16), else 0.
    pub root_offset: u64,
    /// Bytes of the fixed root directory (FAT12/16), else 0.
    pub root_bytes: u64,
    /// First cluster of the root directory (FAT32), else 0.
    pub root_cluster: u32,
    /// Byte offset of cluster 2.
    pub data_offset: u64,
    /// The volume label of the boot sector, as stored.
    pub label: [u8; 11],
}

impl Geometry {
    /// The highest valid cluster number.
    pub fn last_cluster(&self) -> u32 {
        self.cluster_count.saturating_add(1)
    }

    /// Byte offset of cluster `n`; `None` outside `2..=last_cluster`.
    pub fn cluster_offset(&self, n: u32) -> Option<u64> {
        if n < 2 || n > self.last_cluster() {
            return None;
        }
        u64::from(n.saturating_sub(2))
            .checked_mul(u64::from(self.cluster_size))?
            .checked_add(self.data_offset)
    }

    /// Bytes the data area covers.
    pub fn data_bytes(&self) -> u64 {
        u64::from(self.cluster_count).saturating_mul(u64::from(self.cluster_size))
    }
}

fn err(kind: CorruptKind) -> Error {
    Corruption::new(STRUCTURE, Location::Unspecified, kind).into()
}

fn invalid(field: &'static str, value: u64) -> Error {
    err(CorruptKind::InvalidValue { field, value })
}

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

fn label_at(b: &[u8], at: usize) -> [u8; 11] {
    let mut out = [b' '; 11];
    if let Some(src) = b.get(at..at.saturating_add(11)) {
        out.copy_from_slice(src);
    }
    out
}

/// Validates sector 0 and works out the layout.
///
/// Fails with `Error::Corrupt` for a missing signature, a zero or odd field,
/// or fields that contradict each other (a FAT too small for the cluster
/// count, a data area of no clusters, a root cluster outside the volume).
pub fn parse(sector: &[u8]) -> Result<Geometry> {
    if sector.len() < BOOT_LEN {
        return Err(err(CorruptKind::Truncated {
            needed: u64::try_from(BOOT_LEN).unwrap_or(u64::MAX),
            available: u64::try_from(sector.len()).unwrap_or(u64::MAX),
        }));
    }
    let signature = le16(sector, 510);
    if signature != 0xAA55 {
        return Err(err(CorruptKind::BadSignature {
            expected: 0xAA55,
            found: u64::from(signature),
        }));
    }

    let bps = u32::from(le16(sector, 11));
    if !matches!(bps, 512 | 1024 | 2048 | 4096) {
        return Err(invalid("bytes per sector", u64::from(bps)));
    }
    let spc = u32::from(sector.get(13).copied().unwrap_or(0));
    if spc == 0 || spc > 128 || !spc.is_power_of_two() {
        return Err(invalid("sectors per cluster", u64::from(spc)));
    }
    let reserved = u32::from(le16(sector, 14));
    if reserved == 0 {
        return Err(invalid("reserved sectors", 0));
    }
    let fats = u32::from(sector.get(16).copied().unwrap_or(0));
    if fats == 0 {
        return Err(invalid("number of FATs", 0));
    }
    let root_entries = u32::from(le16(sector, 17));
    let total16 = le16(sector, 19);
    let total_sectors = if total16 != 0 {
        u64::from(total16)
    } else {
        u64::from(le32(sector, 32))
    };
    if total_sectors == 0 {
        return Err(invalid("total sectors", 0));
    }
    let fat16 = le16(sector, 22);
    let fat_sectors = if fat16 != 0 {
        u64::from(fat16)
    } else {
        u64::from(le32(sector, 36))
    };
    if fat_sectors == 0 {
        return Err(invalid("sectors per FAT", 0));
    }

    let root_bytes = u64::from(root_entries).saturating_mul(32);
    let root_sectors = root_bytes.div_ceil(u64::from(bps));
    let overflow = || {
        err(CorruptKind::Overflow {
            field: "data start",
        })
    };
    let first_data = u64::from(fats)
        .checked_mul(fat_sectors)
        .and_then(|f| f.checked_add(u64::from(reserved)))
        .and_then(|f| f.checked_add(root_sectors))
        .ok_or_else(overflow)?;
    let data_sectors = match total_sectors.checked_sub(first_data) {
        Some(n) if n > 0 => n,
        _ => {
            return Err(err(CorruptKind::OutOfRange {
                field: "total sectors",
                value: total_sectors,
                limit_name: "first data sector",
                limit: first_data,
            }));
        }
    };
    let clusters = data_sectors.checked_div(u64::from(spc)).unwrap_or(0);
    let cluster_count = match u32::try_from(clusters) {
        Ok(n) if n > 0 && n <= MAX_CLUSTERS => n,
        _ => {
            return Err(err(CorruptKind::OutOfRange {
                field: "cluster count",
                value: clusters,
                limit_name: "most clusters",
                limit: u64::from(MAX_CLUSTERS),
            }));
        }
    };
    let kind = FatKind::of_cluster_count(cluster_count);

    // The FAT must be big enough for every cluster the volume has.
    let entries = u64::from(cluster_count).saturating_add(2);
    let needed = kind.table_bytes(entries).ok_or_else(overflow)?;
    let fat_len = fat_sectors.saturating_mul(u64::from(bps));
    if fat_len < needed {
        return Err(err(CorruptKind::OutOfRange {
            field: "sectors per FAT",
            value: fat_sectors,
            limit_name: "sectors the cluster count needs",
            limit: needed.div_ceil(u64::from(bps)),
        }));
    }

    let (root_cluster, root_bytes, label_at_byte) = if kind == FatKind::Fat32 {
        if root_entries != 0 {
            return Err(invalid("root entries on FAT32", u64::from(root_entries)));
        }
        let root = le32(sector, 44);
        if root < 2 || root > cluster_count.saturating_add(1) {
            return Err(err(CorruptKind::OutOfRange {
                field: "root cluster",
                value: u64::from(root),
                limit_name: "last cluster",
                limit: u64::from(cluster_count.saturating_add(1)),
            }));
        }
        (root, 0, 71)
    } else {
        if root_entries == 0 {
            return Err(invalid("root entries", 0));
        }
        (0, root_bytes, 43)
    };

    let bps64 = u64::from(bps);
    let fat_offset = u64::from(reserved)
        .checked_mul(bps64)
        .ok_or_else(overflow)?;
    let root_offset = if kind == FatKind::Fat32 {
        0
    } else {
        fat_len
            .checked_mul(u64::from(fats))
            .and_then(|f| f.checked_add(fat_offset))
            .ok_or_else(overflow)?
    };
    let data_offset = first_data.checked_mul(bps64).ok_or_else(overflow)?;
    Ok(Geometry {
        kind,
        bytes_per_sector: bps,
        cluster_size: bps.checked_mul(spc).ok_or_else(overflow)?,
        total_sectors,
        cluster_count,
        fat_offset,
        fat_bytes: needed,
        root_offset,
        root_bytes,
        root_cluster,
        data_offset,
        label: label_at(sector, label_at_byte),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boot sector for a small FAT16 volume: 512-byte sectors, 4 per
    /// cluster, 1 reserved, 2 FATs of 32 sectors, 512 root entries, 20000
    /// sectors.
    fn fat16_sector() -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[11..13].copy_from_slice(&512u16.to_le_bytes());
        s[13] = 4;
        s[14..16].copy_from_slice(&1u16.to_le_bytes());
        s[16] = 2;
        s[17..19].copy_from_slice(&512u16.to_le_bytes());
        s[19..21].copy_from_slice(&20000u16.to_le_bytes());
        s[22..24].copy_from_slice(&32u16.to_le_bytes());
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn a_valid_fat16_sector_parses() {
        let g = parse(&fat16_sector()).unwrap();
        assert_eq!(g.kind, FatKind::Fat16);
        // 1 + 2 * 32 + 32 root sectors = 97; (20000 - 97) / 4 clusters.
        assert_eq!(g.cluster_count, 4975);
        assert_eq!(g.data_offset, 97 * 512);
        assert_eq!(g.root_offset, (1 + 64) * 512);
        assert_eq!(g.root_bytes, 512 * 32);
        assert_eq!(g.cluster_size, 2048);
        assert_eq!(g.cluster_offset(2), Some(g.data_offset));
        assert_eq!(g.cluster_offset(1), None);
        assert_eq!(g.cluster_offset(4977), None);
    }

    #[test]
    fn the_type_follows_the_cluster_count() {
        assert_eq!(FatKind::of_cluster_count(4084), FatKind::Fat12);
        assert_eq!(FatKind::of_cluster_count(4085), FatKind::Fat16);
        assert_eq!(FatKind::of_cluster_count(65524), FatKind::Fat16);
        assert_eq!(FatKind::of_cluster_count(65525), FatKind::Fat32);
    }

    #[test]
    fn malformed_sectors_are_corrupt() {
        let good = fat16_sector();
        let patch = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut s = good.clone();
            f(&mut s);
            parse(&s)
        };
        assert!(matches!(
            patch(&|s| s[11..13].fill(0)),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(patch(&|s| s[11] = 0x10), Err(Error::Corrupt(_))));
        assert!(matches!(patch(&|s| s[13] = 3), Err(Error::Corrupt(_))));
        assert!(matches!(patch(&|s| s[13] = 0), Err(Error::Corrupt(_))));
        assert!(matches!(patch(&|s| s[13] = 255), Err(Error::Corrupt(_))));
        assert!(matches!(
            patch(&|s| s[14..16].fill(0)),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(patch(&|s| s[16] = 0), Err(Error::Corrupt(_))));
        assert!(matches!(patch(&|s| s[510] = 0), Err(Error::Corrupt(_))));
        assert!(matches!(
            patch(&|s| s[22..24].fill(0)),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(
            patch(&|s| s[19..21].fill(0)),
            Err(Error::Corrupt(_))
        ));
        // The FAT cannot hold the clusters the size implies.
        assert!(matches!(
            patch(&|s| s[22..24].copy_from_slice(&2u16.to_le_bytes())),
            Err(Error::Corrupt(_))
        ));
        // Fewer sectors than the metadata needs.
        assert!(matches!(
            patch(&|s| s[19..21].copy_from_slice(&50u16.to_le_bytes())),
            Err(Error::Corrupt(_))
        ));
        assert!(matches!(parse(&good[..100]), Err(Error::Corrupt(_))));
        assert!(matches!(parse(&[]), Err(Error::Corrupt(_))));
    }
}
