// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

use hickory_proto::rr::{RData, Record};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum Verdict {
    Consensus(BTreeSet<IpAddr>),
    Probe(Vec<(usize, BTreeSet<IpAddr>)>),
}

pub fn normalize_ips(records: &[Record]) -> BTreeSet<IpAddr> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

/// A tied maximum has no single winner. `max_by_key` over a randomly seeded
/// `HashMap` would pick nondeterministically between evaluations, so a tie
/// falls through to `Probe` and lets latency decide. A tie is unreachable with
/// the current three-provider cap (two distinct sets cannot both reach 2). The
/// rule keeps the outcome deterministic once a fourth provider is added.
pub fn evaluate(ip_sets: &[BTreeSet<IpAddr>]) -> Verdict {
    let mut counts: HashMap<&BTreeSet<IpAddr>, usize> = HashMap::new();
    for s in ip_sets.iter().filter(|s| !s.is_empty()) {
        *counts.entry(s).or_insert(0) += 1;
    }
    if let Some(max_count) = counts.values().copied().max() {
        let winners = counts.values().filter(|&&c| c == max_count).count();
        if max_count >= 2 && winners == 1 {
            let winner = counts
                .iter()
                .find(|(_, &c)| c == max_count)
                .map(|(set, _)| (*set).clone())
                .expect("a counted maximum always has an entry");
            return Verdict::Consensus(winner);
        }
    }
    Verdict::Probe(
        ip_sets
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_empty())
            .map(|(i, s)| (i, s.clone()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    fn set(ips: &[&str]) -> BTreeSet<IpAddr> {
        ips.iter().map(|s| s.parse::<IpAddr>().unwrap()).collect()
    }

    #[test]
    fn unanimous() {
        let r = [set(&["1.2.3.4"]), set(&["1.2.3.4"]), set(&["1.2.3.4"])];
        assert!(matches!(evaluate(&r), Verdict::Consensus(_)));
    }
    #[test]
    fn majority() {
        let r = [set(&["1.2.3.4"]), set(&["5.6.7.8"]), set(&["1.2.3.4"])];
        if let Verdict::Consensus(s) = evaluate(&r) {
            assert_eq!(s, set(&["1.2.3.4"]));
        } else {
            panic!("expected consensus");
        }
    }
    #[test]
    fn all_different() {
        let r = [set(&["1.1.1.1"]), set(&["2.2.2.2"]), set(&["3.3.3.3"])];
        assert!(matches!(evaluate(&r), Verdict::Probe(_)));
    }

    #[test]
    fn two_vs_two_tie_requires_probe() {
        let r = [
            set(&["1.1.1.1"]),
            set(&["2.2.2.2"]),
            set(&["1.1.1.1"]),
            set(&["2.2.2.2"]),
        ];
        assert!(matches!(evaluate(&r), Verdict::Probe(_)));
    }

    #[test]
    fn empty_ip_sets_do_not_form_consensus() {
        let r = [BTreeSet::new(), BTreeSet::new()];
        let Verdict::Probe(candidates) = evaluate(&r) else {
            panic!("CNAME-only results must not form empty consensus");
        };
        assert!(candidates.is_empty());
    }

    #[test]
    fn probe_positions_preserve_original_indexes_after_empty_filter() {
        let r = [BTreeSet::new(), set(&["1.1.1.1"]), set(&["2.2.2.2"])];
        let Verdict::Probe(candidates) = evaluate(&r) else {
            panic!("distinct non-empty answers should require probe");
        };
        assert_eq!(candidates[0].0, 1);
        assert_eq!(candidates[1].0, 2);
    }
}
