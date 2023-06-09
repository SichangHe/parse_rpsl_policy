use hashbrown::HashMap;

use crate::parse::*;

use super::*;

/// Routes for one AS set, including the unrecorded and sets.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AsSetRoute {
    /// Should always be sorted.
    pub routes: Vec<IpNet>,
    pub unrecorded_nums: Vec<usize>,
    pub set_members: Vec<String>,
}

impl AsSetRoute {
    /// Clean up `routes` and `unrecorded_nums` so they are compact ordered
    /// sets.
    pub fn clean_up(&mut self) {
        self.routes.sort_unstable();
        self.routes.dedup();
        self.routes.shrink_to_fit();
        self.unrecorded_nums.sort_unstable();
        self.unrecorded_nums.dedup();
        self.unrecorded_nums.shrink_to_fit();
    }

    /// Fill in routes for the AS with `as_set` with routes in `as_routes`.
    /// The process is done only once, and the result [`AsSetRoute`] is cleaned.
    pub fn from_as_set(as_set: &AsSet, as_routes: &BTreeMap<usize, Vec<IpNet>>) -> Self {
        let mut routes = Vec::with_capacity(as_set.members.len() << 2);
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

/// Cleaned RPSL dump ready for query.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QueryDump {
    pub aut_nums: HashMap<usize, AutNum>,
    pub as_sets: HashMap<String, AsSet>,
    pub route_sets: HashMap<String, RouteSet>,
    pub peering_sets: HashMap<String, PeeringSet>,
    pub filter_sets: HashMap<String, FilterSet>,
    /// Each value should always be sorted.
    pub as_routes: HashMap<usize, Vec<IpNet>>,
    /// Each value should always be sorted.
    pub as_set_routes: HashMap<String, AsSetRoute>,
}

impl QueryDump {
    /// Clean `dump` and use it to create a [`QueryDump`].
    pub fn from_dump(dump: Dump) -> Self {
        let Dump {
            aut_nums,
            as_sets,
            route_sets,
            peering_sets,
            filter_sets,
            mut as_routes,
        } = dump;
        as_routes.par_iter_mut().for_each(|(_, routes)| {
            routes.sort();
            routes.dedup();
            routes.shrink_to_fit();
        });
        let as_set_routes = as_sets
            .par_iter()
            .map(|(name, set)| (name.clone(), AsSetRoute::from_as_set(set, &as_routes)))
            .collect();
        let as_set_routes = flatten_as_set_routes(&as_set_routes);
        let as_set_routes = HashMap::from_iter(as_set_routes);
        let aut_nums = HashMap::from_iter(aut_nums);
        let as_sets = HashMap::from_iter(as_sets);
        let route_sets = HashMap::from_iter(route_sets);
        let peering_sets = HashMap::from_iter(peering_sets);
        let filter_sets = HashMap::from_iter(filter_sets);
        let as_routes = HashMap::from_iter(as_routes);
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
