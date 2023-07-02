use std::{collections::BTreeMap, mem};

use ipnet::IpNet;
use rayon::prelude::*;

use crate::parse::{aut_num::AutNum, dump::Dump, set::*};

use super::trie::IpTrie;

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AsSetRoute {
    /// This field should always be sorted.
    pub routes: IpTrie,
    pub unrecorded_nums: Vec<usize>,
    pub set_members: Vec<String>,
}

impl AsSetRoute {
    pub fn clean_up(&mut self) {
        self.unrecorded_nums.sort_unstable();
        self.unrecorded_nums.dedup();
        self.unrecorded_nums.shrink_to_fit();
    }

    pub fn from_as_set(as_set: &AsSet, as_routes: &BTreeMap<usize, Vec<IpNet>>) -> Self {
        let mut routes = IpTrie::new();
        let mut unrecorded_nums = Vec::new();
        for member in &as_set.members {
            match as_routes.get(member) {
                Some(as_route) => routes.extend(as_route),
                None => unrecorded_nums.push(*member),
            }
        }
        let mut result = Self {
            routes,
            unrecorded_nums,
            set_members: as_set.set_members.clone(),
        };
        result.clean_up();
        result
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct QueryDump {
    pub aut_nums: BTreeMap<usize, AutNum>,
    pub as_sets: BTreeMap<String, AsSet>,
    pub route_sets: BTreeMap<String, RouteSet>,
    pub peering_sets: BTreeMap<String, PeeringSet>,
    pub filter_sets: BTreeMap<String, FilterSet>,
    /// Each value should always be sorted.
    // TODO: Switch to `IpTrie`.
    pub as_routes: BTreeMap<usize, Vec<IpNet>>,
    /// Each value should always be sorted.
    pub as_set_routes: BTreeMap<String, AsSetRoute>,
}

impl QueryDump {
    pub fn from_dump(dump: Dump) -> Self {
        let Dump {
            aut_nums,
            as_sets,
            route_sets,
            peering_sets,
            filter_sets,
            as_routes,
        } = dump;
        let as_set_routes = as_sets
            .par_iter()
            .map(|(name, set)| (name.clone(), AsSetRoute::from_as_set(set, &as_routes)))
            .collect();
        let as_set_routes = flatten_as_set_routes(&as_set_routes);
        Self {
            aut_nums,
            as_sets,
            route_sets,
            peering_sets,
            filter_sets,
            as_routes,
            as_set_routes,
        }
    }
}

fn flatten_as_set_routes(
    as_set_routes: &BTreeMap<String, AsSetRoute>,
) -> BTreeMap<String, AsSetRoute> {
    let mut result = as_set_routes.clone();
    result.par_iter_mut().for_each(|(_, v)| {
        let members = mem::take(&mut v.set_members);
        for member in members {
            match as_set_routes.get(&member) {
                Some(as_set_route) => {
                    v.routes.extend(&as_set_route.routes);
                    v.unrecorded_nums.extend(&as_set_route.unrecorded_nums);
                    v.set_members.extend(as_set_route.set_members.clone());
                }
                None => v.set_members.push(member),
            }
        }
        v.clean_up();
    });
    result
}
