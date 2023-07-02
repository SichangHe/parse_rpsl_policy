use std::{iter::*, net::*};

use ip_network_table_deps_treebitmap::*;
use ipnet::*;

use crate::parse::address_prefix::{address_prefix_contains, RangeOperator};

// TODO: Efficient implementations for `Hash` and `Clone`.
#[derive(Default)]
pub struct IpTrie {
    pub v4: IpLookupTable<Ipv4Addr, ()>,
    pub v6: IpLookupTable<Ipv6Addr, ()>,
}

const EXPECT_IP_NET: &str =
    "Arguments to `IpNet` should be valid because they are from another `IpNet` in `IpTrie`.";

impl IpTrie {
    pub fn new() -> Self {
        Self {
            v4: IpLookupTable::new(),
            v6: IpLookupTable::new(),
        }
    }

    pub fn matches(&self, ip: &IpNet) -> Vec<IpNet> {
        match ip {
            IpNet::V4(ip) => self
                .v4
                .matches(ip.addr())
                .map(|(ip, masklen, _)| {
                    IpNet::V4(Ipv4Net::new(ip, masklen as u8).expect(EXPECT_IP_NET))
                })
                .collect(),
            IpNet::V6(ip) => self
                .v6
                .matches(ip.addr())
                .map(|(ip, masklen, _)| {
                    IpNet::V6(Ipv6Net::new(ip, masklen as u8).expect(EXPECT_IP_NET))
                })
                .collect(),
        }
    }

    pub fn match_ip_range(&self, ip: &IpNet, range_operator: RangeOperator) -> bool {
        for ours in self.matches(ip).iter().rev() {
            if address_prefix_contains(ours, range_operator, ip) {
                return true;
            }
        }
        false
    }
}

impl std::iter::Extend<IpNet> for IpTrie {
    fn extend<T: IntoIterator<Item = IpNet>>(&mut self, iter: T) {
        for ip in iter {
            _ = match ip {
                IpNet::V4(ip) => self.v4.insert(ip.addr(), ip.prefix_len() as u32, ()),
                IpNet::V6(ip) => self.v6.insert(ip.addr(), ip.prefix_len() as u32, ()),
            }
        }
    }
}

impl<'a> std::iter::Extend<&'a IpNet> for IpTrie {
    fn extend<T: IntoIterator<Item = &'a IpNet>>(&mut self, iter: T) {
        for ip in iter {
            _ = match ip {
                IpNet::V4(ip) => self.v4.insert(ip.addr(), ip.prefix_len() as u32, ()),
                IpNet::V6(ip) => self.v6.insert(ip.addr(), ip.prefix_len() as u32, ()),
            }
        }
    }
}

impl Eq for IpTrie {}

impl PartialEq for IpTrie {
    fn eq(&self, other: &Self) -> bool {
        matches!(self.cmp(other), std::cmp::Ordering::Equal)
    }
}

impl PartialOrd for IpTrie {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IpTrie {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for (ours, theirs) in self.v4.iter().zip(other.v4.iter()) {
            match ours.cmp(&theirs) {
                std::cmp::Ordering::Equal => (),
                non_equal => return non_equal,
            }
        }
        for (ours, theirs) in self.v6.iter().zip(other.v6.iter()) {
            match ours.cmp(&theirs) {
                std::cmp::Ordering::Equal => (),
                non_equal => return non_equal,
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl std::hash::Hash for IpTrie {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.v4.iter().collect::<Vec<_>>().hash(state);
        self.v6.iter().collect::<Vec<_>>().hash(state);
    }
}

impl std::fmt::Debug for IpTrie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpTrie")
            .field("v4", &self.v4.iter().collect::<Vec<_>>())
            .field("v4", &self.v4.iter().collect::<Vec<_>>())
            .finish()
    }
}

impl Clone for IpTrie {
    fn clone(&self) -> Self {
        let mut v4 = IpLookupTable::with_capacity(self.v4.len());
        self.v4
            .iter()
            .for_each(|(ip, masklen, _)| _ = v4.insert(ip, masklen, ()));
        let mut v6 = IpLookupTable::with_capacity(self.v6.len());
        self.v6
            .iter()
            .for_each(|(ip, masklen, _)| _ = v6.insert(ip, masklen, ()));
        Self { v4, v6 }
    }
}

pub struct IpTrieIter<'a> {
    v4: Iter<'a, Ipv4Addr, ()>,
    v6: Iter<'a, Ipv6Addr, ()>,
}

impl<'a> Iterator for IpTrieIter<'a> {
    type Item = IpNet;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some((ip, masklen, _)) = self.v4.next() {
            return Some(IpNet::V4(
                Ipv4Net::new(ip, masklen as u8).expect(EXPECT_IP_NET),
            ));
        }
        if let Some((ip, masklen, _)) = self.v6.next() {
            return Some(IpNet::V6(
                Ipv6Net::new(ip, masklen as u8).expect(EXPECT_IP_NET),
            ));
        }
        None
    }
}

impl<'a> IntoIterator for &'a IpTrie {
    type Item = IpNet;

    type IntoIter = IpTrieIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            v4: self.v4.iter(),
            v6: self.v6.iter(),
        }
    }
}
