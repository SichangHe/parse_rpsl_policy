use serde::{Deserialize, Serialize};

use crate::lex::peering;

pub fn parse_router_expr(router_expr: peering::AsExpr) -> RouterExpr {
    todo!()
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum RouterExpr {
    // TODO: Fill in
}