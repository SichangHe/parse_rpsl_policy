use crate::{
    lex::community::Call,
    parse::{
        address_prefix::{match_ips, AddrPfxRange, RangeOperator},
        filter::Filter::{self, *},
        set::RouteSetMember,
    },
};

use super::{
    cmp::Compare,
    query::QueryDump as Dump,
    report::*,
    verbosity::{Verbosity, VerbosityReport},
};

pub struct CheckFilter<'a> {
    pub dump: &'a Dump,
    pub compare: &'a Compare,
    pub verbosity: Verbosity,
}

impl<'a> CheckFilter<'a> {
    pub fn check(&self, filter: &'a Filter, depth: isize) -> AnyReport {
        if depth <= 0 {
            return recursion_any_report(RecurSrc::CheckFilter);
        }
        match filter {
            FilterSet(name) => self.filter_set(name, depth),
            Any => None,
            AddrPrefixSet(prefixes) => self.filter_prefixes(prefixes),
            RouteSet(name, op) => self.filter_route_set(name, *op, depth),
            AsNum(num, op) => self.filter_as_num(*num, *op),
            AsSet(name, op) => self.filter_as_set(name, *op, depth, &mut Vec::new()),
            AsPathRE(expr) => self.filter_as_regex(expr),
            And { left, right } => self.filter_and(left, right, depth).to_any(),
            Or { left, right } => self.filter_or(left, right, depth),
            Not(filter) => self.filter_not(filter, depth),
            Group(filter) => self.check(filter, depth),
            Community(community) => self.filter_community(community),
            Invalid(reason) => self.invalid_filter(reason),
        }
    }

    fn filter_set(&self, name: &str, depth: isize) -> AnyReport {
        let filter_set = match self.dump.filter_sets.get(name) {
            Some(f) => f,
            None => return self.skip_any_report(|| SkipReason::FilterSetUnrecorded(name.into())),
        };
        let mut aggregator = AnyReportAggregator::new();
        for filter in &filter_set.filters {
            aggregator.join(self.check(filter, depth - 1)?);
        }
        aggregator.to_any()
    }

    fn filter_as_num(&self, num: usize, op: RangeOperator) -> AnyReport {
        let routes = match self.dump.as_routes.get(&num) {
            Some(r) => r,
            None => {
                return match self.compare.goes_through_num(num) {
                    true => self.skip_any_report(|| SkipReason::AsRoutesUnrecorded(num)),
                    false => empty_skip_any_report(),
                }
            }
        };
        if match_ips(&self.compare.prefix, routes, op) {
            None
        } else {
            self.no_match_any_report(|| MatchProblem::FilterAsNum(num, op))
        }
    }

    fn filter_prefixes<I>(&self, prefixes: I) -> AnyReport
    where
        I: IntoIterator<Item = &'a AddrPfxRange>,
    {
        if prefixes
            .into_iter()
            .all(|prefix| !prefix.contains(&self.compare.prefix))
        {
            self.no_match_any_report(|| MatchProblem::FilterPrefixes)
        } else {
            None
        }
    }

    fn filter_route_set(&self, name: &str, op: RangeOperator, depth: isize) -> AnyReport {
        if depth <= 0 {
            return recursion_any_report(RecurSrc::FilterRouteSet(name.into()));
        }
        let route_set = match self.dump.route_sets.get(name) {
            Some(r) => r,
            None => return self.skip_any_report(|| SkipReason::RouteSetUnrecorded(name.into())),
        };
        let mut aggregator = AnyReportAggregator::new();
        for member in &route_set.members {
            aggregator.join(self.filter_route_set_member(member, op, depth - 1)?);
        }
        if aggregator.all_fail {
            self.no_match_any_report(|| MatchProblem::FilterRouteSet(name.into()))
        } else {
            aggregator.to_any()
        }
    }

    fn filter_route_set_member(
        &self,
        member: &RouteSetMember,
        op: RangeOperator,
        depth: isize,
    ) -> AnyReport {
        if depth <= 0 {
            return recursion_any_report(RecurSrc::FilterRouteSetMember(member.clone()));
        }
        match member {
            RouteSetMember::Range(prefix) => match (prefix.range_operator, op) {
                (RangeOperator::NoOp, RangeOperator::NoOp) => self.filter_prefixes([prefix]),
                (RangeOperator::NoOp, op) => self.filter_prefixes([&AddrPfxRange {
                    range_operator: op,
                    ..prefix.clone()
                }]),
                _ => self.filter_prefixes([prefix]),
            },
            RouteSetMember::NameOp(name, op) => self.filter_route_set(name, *op, depth - 1),
        }
    }

    fn filter_as_set(
        &self,
        name: &'a str,
        op: RangeOperator,
        depth: isize,
        visited: &mut Vec<&'a str>,
    ) -> AnyReport {
        if visited.contains(&name) {
            return failed_any_report();
        }
        visited.push(name);

        if depth <= 0 {
            return recursion_any_report(RecurSrc::FilterAsSet(name.into()));
        }
        let as_set_route = match self.dump.as_set_routes.get(name) {
            Some(r) => r,
            None => return self.skip_any_report(|| SkipReason::AsSetRouteUnrecorded(name.into())),
        };

        if as_set_route.routes.match_ip_range(&self.compare.prefix, op) {
            return None;
        }
        let mut aggregator = AnyReportAggregator::new();
        for set in &as_set_route.set_members {
            aggregator.join(self.filter_as_set(set, op, depth - 1, visited)?);
        }
        for num in &as_set_route.unrecorded_nums {
            aggregator.join(self.skip_any_report(|| SkipReason::AsRoutesUnrecorded(*num))?);
        }
        if aggregator.all_fail {
            self.no_match_any_report(|| MatchProblem::FilterAsSet(name.into(), op))
        } else {
            aggregator.to_any()
        }
    }

    fn filter_as_regex(&self, expr: &str) -> AnyReport {
        // TODO: Implement.
        self.skip_any_report(|| SkipReason::AsRegexUnimplemented(expr.into()))
    }

    fn filter_and(&self, left: &'a Filter, right: &'a Filter, depth: isize) -> AllReport {
        if depth <= 0 {
            return recursion_all_report(RecurSrc::FilterAnd);
        }
        self.check(left, depth - 1)
            .to_all()?
            .join(self.check(right, depth).to_all()?)
            .to_all()
    }

    fn filter_or(&self, left: &'a Filter, right: &'a Filter, depth: isize) -> AnyReport {
        if depth <= 0 {
            return recursion_any_report(RecurSrc::FilterOr);
        }
        let mut report: AnyReportAggregator = self.check(left, depth - 1)?.into();
        report.join(self.check(right, depth)?);
        report.to_any()
    }

    fn filter_not(&self, filter: &'a Filter, depth: isize) -> AnyReport {
        if depth <= 0 {
            return recursion_any_report(RecurSrc::FilterNot);
        }
        match self.check(filter, depth) {
            Some((_errors, true)) => None,
            Some(report @ (_, false)) => {
                let mut aggregator: AnyReportAggregator = report.into();
                aggregator.join(self.no_match_any_report(|| MatchProblem::Filter)?);
                aggregator.to_any()
            }
            None => self.no_match_any_report(|| MatchProblem::Filter),
        }
    }

    /// We skip community checks, but this could be an enhancement.
    /// <https://github.com/SichangHe/parse_rpsl_policy/issues/16>.
    fn filter_community(&self, community: &Call) -> AnyReport {
        self.skip_any_report(|| SkipReason::CommunityCheckUnimplemented(community.clone()))
    }

    fn invalid_filter(&self, reason: &str) -> AnyReport {
        self.bad_rpsl_any_report(|| RpslError::InvalidFilter(reason.into()))
    }
}

impl<'a> VerbosityReport for CheckFilter<'a> {
    fn get_verbosity(&self) -> Verbosity {
        self.verbosity
    }
}
