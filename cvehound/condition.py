"""Kbuild CONFIG conditions: parse them, simplify them for display, evaluate them.

The Kbuild map (cvehound/kbuildparse) says when a source file is built with a
condition over CONFIG symbols, and it emits exactly one small grammar --
symbols joined by ' & ' and ' | ', '~' for negation, parentheses for grouping:

    or    := and ('|' and)*
    and   := unary ('&' unary)*
    unary := '~' unary | '(' or ')' | SYMBOL

Nothing else reaches here: the '||' alternative in get_config_string() needs a
Kconfig model, and cvehound never passes one.

Simplification is for the reader only -- the verdict is taken on the raw
condition -- so it stops at the rewrites the parser's output needs: flattening,
duplicates, constants, complements, absorption, and hoisting an operand common
to every term, which is the shape a file reached from several parents takes
((X & A) | (X & B) -> X & (A | B)). The printed form keeps the format and the
operand order of the sympy minimizer this replaced; on a v7.2 tree 35 of ~17k
conditions print differently, nearly all shorter, where sympy gave up past
eight symbols.
"""

import re
from collections.abc import Callable, Iterable, Mapping, Set
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

Kind: TypeAlias = Literal['&', '|']


@dataclass(frozen=True)
class Var:
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Not:
    arg: 'Expr'

    def __str__(self) -> str:
        return '~' + _operand(self.arg)


@dataclass(frozen=True)
class Op:
    kind: Kind
    args: frozenset['Expr']

    def __str__(self) -> str:
        return f' {self.kind} '.join(_operand(arg) for arg in sorted(self.args, key=_order))


# Constants are plain bools, which also print as sympy did: 'True', 'False'.
Expr: TypeAlias = bool | Var | Not | Op

_SYMBOL = re.compile(r'[A-Za-z0-9_-]+')
# Anything else is one character long, so a stray one reaches the parser as a
# token of its own and is rejected there.
_TOKEN = re.compile(_SYMBOL.pattern + r'|\S')


def _operand(expr: Expr) -> str:
    return f'({expr})' if isinstance(expr, Op) else str(expr)


def _order(expr: Expr) -> tuple[Any, ...]:
    """Variables alphabetically, then compounds: '&' before '~' before '|',
    fewer operands first, then operand by operand."""
    if isinstance(expr, Op):
        rank, args = (1 if expr.kind == '&' else 3), expr.args
    elif isinstance(expr, Not):
        rank, args = 2, (expr.arg,)
    else:
        return (0, str(expr))
    return (rank, len(args), tuple(sorted(map(_order, args))))


def parse(text: str) -> Expr:
    """Parse one condition of the Kbuild map; ValueError if it is not one."""
    # Reversed, so that the next token is always tokens[-1].
    tokens = _TOKEN.findall(text)[::-1]

    def take() -> str:
        if not tokens:
            raise ValueError(f'truncated condition {text!r}')
        return tokens.pop()

    def junction(kind: Kind, operand: Callable[[], Expr]) -> Expr:
        args = {operand()}
        while tokens and tokens[-1] == kind:
            tokens.pop()
            args.add(operand())
        # A repeated operand (A & A) must not leave a one-operand Op behind.
        return args.pop() if len(args) == 1 else Op(kind, frozenset(args))

    def disjunction() -> Expr:
        return junction('|', conjunction)

    def conjunction() -> Expr:
        return junction('&', unary)

    def unary() -> Expr:
        token = take()
        if token == '~':
            return Not(unary())
        if token == '(':
            inner = disjunction()
            if take() != ')':
                raise ValueError(f'unbalanced parentheses in condition {text!r}')
            return inner
        if not _SYMBOL.fullmatch(token):
            raise ValueError(f'unexpected {token!r} in condition {text!r}')
        return Var(token)

    expr = disjunction()
    if tokens:
        raise ValueError(f'unexpected {tokens[-1]!r} in condition {text!r}')
    return expr


def evaluate(expr: Expr, config: Mapping[str, bool]) -> bool:
    """Kconfig is closed-world: a symbol absent from @config is disabled."""
    if isinstance(expr, bool):
        return expr
    if isinstance(expr, Var):
        return config.get(expr.name, False)
    if isinstance(expr, Not):
        return not evaluate(expr.arg, config)
    test = all if expr.kind == '&' else any
    return test(evaluate(arg, config) for arg in expr.args)


def simplify(expr: Expr) -> Expr:
    """An equivalent condition that reads better (see the module docstring)."""
    if isinstance(expr, Not):
        return _negate(simplify(expr.arg))
    if isinstance(expr, Op):
        return _factor(_join(expr.kind, [simplify(arg) for arg in expr.args]))
    return expr


def _negate(expr: Expr) -> Expr:
    if isinstance(expr, bool):
        return not expr
    if isinstance(expr, Not):
        return expr.arg
    return Not(expr)


def _dual(kind: Kind) -> Kind:
    return '|' if kind == '&' else '&'


def _operands(expr: Expr, kind: Kind) -> frozenset[Expr]:
    """@expr as the operands of a @kind junction: a lone operand is one of one."""
    return expr.args if isinstance(expr, Op) and expr.kind == kind else frozenset({expr})


def _implied(arg: Expr, rest: Set[Expr], kind: Kind) -> bool:
    """Whether @arg adds nothing to a @kind junction of @rest.

    Only a junction of the dual kind can be absorbed: in A | (A & B) the
    conjunction is redundant because it implies one of the other operands
    outright, and in A | B | (C & (A | B)) because one of its own operands
    implies their disjunction. The '&' case is the mirror image: there the
    other operands imply the disjunction, as in A & (A | B).
    """
    if not (isinstance(arg, Op) and arg.kind == _dual(kind)):
        return False
    return any(_operands(other, arg.kind) <= arg.args for other in rest) or any(
        _operands(operand, kind) <= rest for operand in arg.args
    )


def _join(kind: Kind, args: Iterable[Expr]) -> Expr:
    """The @kind junction of @args, flattened and reduced."""
    identity = kind == '&'
    flat: set[Expr] = set()
    for arg in args:
        if isinstance(arg, bool):
            if arg != identity:
                return arg
        else:
            flat |= _operands(arg, kind)
    if any(_negate(arg) in flat for arg in flat):
        return not identity
    # One at a time, in a fixed order, so that what survives never depends on
    # set iteration order.
    for arg in sorted(flat, key=_order):
        if _implied(arg, flat - {arg}, kind):
            flat.discard(arg)
    if not flat:
        return identity
    if len(flat) == 1:
        return flat.pop()
    return Op(kind, frozenset(flat))


def _factor(expr: Expr) -> Expr:
    """Hoist what every term shares: (X & A) | (X & B) -> X & (A | B), and the dual."""
    if not isinstance(expr, Op):
        return expr
    dual = _dual(expr.kind)
    terms = [_operands(arg, dual) for arg in expr.args]
    common = frozenset.intersection(*terms)
    if not common:
        return expr
    rest = _join(expr.kind, [_join(dual, term - common) for term in terms])
    return _join(dual, [*common, rest])
