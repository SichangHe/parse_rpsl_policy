"""
Parse mp-import statement following
https://www.rfc-editor.org/rfc/rfc4012#section-2.5
"""
from pyparsing import (
    CaselessKeyword,
    Forward,
    Group,
    OneOrMore,
    Opt,
    Word,
    ZeroOrMore,
    delimited_list,
    printables,
)

exclude_chars = "#;"
field = Word(printables, exclude_chars=exclude_chars)
field_wo_comma = Word(printables, exclude_chars=(exclude_chars + ","))
field_w_space = Word(printables + " ", exclude_chars=exclude_chars)
semicolon = Word(";").suppress()
from_kw = CaselessKeyword("from")
action_kw = CaselessKeyword("action")
accept_kw = CaselessKeyword("accept")
protocol = CaselessKeyword("protocol") + field("protocol-1")
into_protocol = "into" + field("protocol-2")
afi = CaselessKeyword("afi") + delimited_list(
    field_wo_comma, delim=","
).set_results_name("afi-list")
action = field_w_space + semicolon
actions = action_kw + Group(
    ZeroOrMore(action + ~(from_kw | accept_kw)) + action
).set_results_name("actions")
mp_peering = Group(ZeroOrMore(field + ~(action_kw | from_kw | accept_kw)) + field)
peering = Group(from_kw + mp_peering.set_results_name("mp-peering") + Opt(actions))
import_factor = (
    Group(OneOrMore(peering)).set_results_name("from")
    + accept_kw
    + field_w_space("mp-filter")
)
import_term = (
    # Semicolon separated list.
    "{"
    + delimited_list(
        Group(import_factor), delim=";", allow_trailing_delim=True
    ).set_results_name("import-factors")
    + "}"
    # Semicolon optional if single.
) | import_factor + Opt(semicolon)

# `import_expression` and `afi_import_expression` are recursively defined.
import_expression = Forward()
afi_import_expression = Opt(afi) + import_expression
import_expression <<= (
    Group(import_term + CaselessKeyword("except") + afi_import_expression)
    | Group(import_term + CaselessKeyword("refine") + afi_import_expression)
    | import_term
)

lex = Opt(protocol) + Opt(into_protocol) + afi_import_expression

# TODO: parse <mp-filter>.
# TODO: parse <mp-peering>.


def main():
    from pprint import pprint

    EXAMPLES = [
        "afi ipv6.unicast from AS9002 accept ANY",
        "afi ipv6.unicast from AS9002 from AS2356 accept ANY",
        "afi ipv6.unicast from AS6939 action pref=100; accept ANY",
        "afi ipv6.unicast from AS21127 action pref=100; accept AS-ZSTTK6-SET;",
        "afi ipv6.unicast from AS21127 action pref=100; med=0; accept AS-ZSTTK6-SET;",
        "afi ipv6 from AS1213 accept { ::/0 }",
        "afi ipv6.unicast from AS1299 action pref = 200; accept ANY AND NOT {0.0.0.0/0};",
        "afi ipv4.unicast from AS6682 at 109.68.121.1 action pref=65435; med=0; community.append(8226:1102); accept ANY AND {0.0.0.0/0^0-24}",
        "afi ipv4.unicast { from AS174 192.38.7.14 at 192.38.7.75 accept AS174; from AS1835 192.38.7.1 at 192.38.7.75 accept AS-UNIC; from AS2603 192.38.7.50 at 192.38.7.75 accept AS-NORDUNET; from AS2686 192.38.7.8 at 192.38.7.75 accept AS-IGNEMEA; from AS2874 192.38.7.10 at 192.38.7.75 accept AS-GLOBALIPNET; from AS6834 192.38.7.4 at 192.38.7.75 accept AS-KMD; from AS8434 192.38.7.92 at 192.38.7.75 accept AS-TELENOR; from AS9120 192.38.7.46 at 192.38.7.75 accept AS-COHAESIO; from AS9167 192.38.7.49 at 192.38.7.75 accept AS-WEBPARTNER; from AS12552 192.38.7.68 at 192.38.7.75 accept AS-IPO; from AS13030 192.38.7.52 at 192.38.7.75 accept AS-INIT7; from AS15516 192.38.7.64 at 192.38.7.75 accept AS-DK-ARROWHEAD; from AS15598 192.38.7.84 at 192.38.7.75 accept AS-IPX; from AS16095 192.38.7.66 at 192.38.7.75 accept AS-JAYNET; from AS16095 192.38.7.67 at 192.38.7.75 accept AS-JAYNET; from AS16150 192.38.7.43 at 192.38.7.75 accept AS16150:AS-CUSTOMERS; from AS16245 192.38.7.93 at 192.38.7.75 accept AS-NGDC; from AS20618 192.38.7.99 at 192.38.7.75 accept AS-INFOCONNECT; from AS20618 192.38.7.100 at 192.38.7.75 accept AS-INFOCONNECT; from AS25384 192.38.7.97 at 192.38.7.75 accept AS-DMDATADK; from AS25384 192.38.7.98 at 192.38.7.75 accept AS-DMDATADK; from AS28717 192.38.7.82 at 192.38.7.75 accept AS-ZENSYSTEMS; from AS29100 192.38.7.77 at 192.38.7.75 accept AS29100; from AS29266 192.38.7.41 at 192.38.7.75 accept AS-DANMARKSRADIO; from AS31027 192.38.7.58 at 192.38.7.75 accept AS-NIANET; from AS31661 192.38.7.12 at 192.38.7.75 accept AS-COMX; from AS33916 192.38.7.87 at 192.38.7.75 accept AS33916; from AS33926 192.38.7.72 at 192.38.7.75 accept AS-EUROTRANSIT; from AS34823 192.38.7.95 at 192.38.7.75 accept AS34823; from AS41025 192.38.7.28 at 192.38.7.75 accept AS-BUTLERNET; from AS42525 192.38.7.26 at 192.38.7.75 accept AS-GCNET; from AS43457 192.38.7.73 at 192.38.7.75 accept AS-VGDC; }",
        "afi ipv4.unicast, ipv6.unicast from AS2895 action pref=10; accept ANY",
        "afi ipv6.unicast from AS8365 ACCEPT AS-MANDA",
        "afi ipv6.unicast from AS8928 action pref= 10; accept ANY",
        "afi ipv4.unicast from AS3344:PRNG-LONAP action pref=64535; community.append(3344:60000, 3344:60020, 3344:8330); accept ANY AND NOT AS3344:fltr-filterlist",
    ]

    for example in EXAMPLES:
        success, results = lex.run_tests(example, full_dump=False)
        if success:
            pprint(results[0][1].as_dict())  # type: ignore


if __name__ == "__main__":
    main()
