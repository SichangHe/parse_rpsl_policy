use lazy_regex::{regex_captures, regex_is_match};

use super::*;

/// <https://www.rfc-editor.org/rfc/rfc2622#section-5.1>
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AsSet {
    pub body: String,
    /// AS numbers; should be kept sorted.
    pub members: Vec<usize>,
    pub set_members: Vec<String>,
}

impl AsSet {
    pub fn new(mut body: String, mut members: Vec<usize>, mut set_members: Vec<String>) -> Self {
        body.shrink_to_fit();
        members.shrink_to_fit();
        members.sort_unstable();
        set_members.shrink_to_fit();
        Self {
            body,
            members,
            set_members,
        }
    }
}

pub fn is_route_set_name(attr: &str) -> bool {
    regex_is_match!(r"^(AS\d+:)?rs-\S+$"i, attr)
}

/// <https://www.rfc-editor.org/rfc/rfc2622#section-5.2>
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RouteSet {
    pub body: String,
    /// List of `<address-prefix-range>` or `<route-set-name>` or
    /// `<route-set-name><range-operator>`.
    pub members: Vec<RouteSetMember>,
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RouteSetMember {
    /// `<address-prefix-range>`
    Range(AddrPfxRange),
    /// `<route-set-name><range-operator>`
    NameOp(String, RangeOperator),
}

impl std::fmt::Debug for RouteSetMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RouteSetMember::*;
        match self {
            Range(arg0) => f.debug_tuple("Range").field(arg0).finish(),
            NameOp(arg0, arg1) => {
                let mut r = f.debug_tuple("NameOp");
                r.field(arg0);
                if *arg1 != RangeOperator::NoOp {
                    r.field(arg1);
                }
                r.finish()
            }
        }
    }
}

impl From<String> for RouteSetMember {
    fn from(value: String) -> Self {
        if let Ok(range) = value.parse() {
            Self::Range(range)
        } else if let Ok((name, op)) = try_parse_name_operator(&value) {
            Self::NameOp(name.into(), op)
        } else {
            Self::NameOp(value, RangeOperator::NoOp)
        }
    }
}

pub fn try_parse_name_operator(s: &str) -> Result<(&str, RangeOperator)> {
    let (_, name, operator) =
        get_name_operator(s).context(format!("{s} is not in valid NameOp form"))?;
    let op = operator.parse().context(format!("parsing {s} as NameOp"))?;
    Ok((name, op))
}

pub fn get_name_operator(s: &str) -> Option<(&str, &str, &str)> {
    regex_captures!(r"(\S+)(\^[-+\d]+)", s)
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PeeringSet {
    pub body: String,
    pub peerings: Vec<Peering>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FilterSet {
    pub body: String,
    pub filters: Vec<Filter>,
}
