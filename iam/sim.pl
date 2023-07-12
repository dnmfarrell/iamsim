:- module(iamsim, [action/1, can/2, all/2, why/3, fix/3, policy/5, policy_match/7]).
:- dynamic(action/1).
:- dynamic(policy/5).

% DCG to match strings to patterns containing the wildcard *
patt([])       --> [].
patt([C|Cs])   --> char(C), patt(Cs).
patt(['*'|Cs]) --> word, chrs(Cs).
chrs([])       --> [].
chrs([C|Cs])   --> char(C), patt(Cs).
char(C)        --> [C], { char_type(C, graph) }.
word           --> char(_), (word | empt).
empt           --> [].

policy_match(Ty, Id, Ef, Ac, Re, Ax, Rx) :-
  policy(Ty, Id, Ef, Ax, Rx),
  atom_chars(Ax, As),
  atom_chars(Rx, Rs),
  atom_chars(Ac, Al),
  atom_chars(Re, Rl),
  phrase(patt(As), Al),
  phrase(patt(Rs), Rl).

match([], []).
match(['*'|RestPattern], String) :-
  match_star(RestPattern, String).
match([Char|RestPattern], [Char|RestString]) :-
  match(RestPattern, RestString).

match_star(Pattern, RestString) :-
  match(Pattern, RestString).
match_star(Pattern, [_|RestString]) :-
  match_star(Pattern, RestString).

list_empty([], true).
list_empty([_|_], false).

list_not_empty([], false).
list_not_empty([_|_], true).

error(Msg) :-
  write(user_error, Msg), nl(user_error), fail.

can(Action, Resource) :-
  action(Action),
  context_build(Action, Resource, Ctx),
  eval(Ctx, IsOk, _),
  IsOk.

all(Actions, Resource) :-
  ( var(Resource), !, error('Resource must be ground'));
  (setof(Action, can(Action, Resource), Actions),!);
  Actions = [].

why(Action, Resource, Reasons) :-
  ( var(Resource), !, error('Resource must be ground'));
  action(Action),
  context_build(Action, Resource, Ctx),
  eval(Ctx, _, Reasons).

eval(Ctx, IsOk, Reasons) :-
  context(_, _, Perms) = Ctx,
  eval(Perms, true, [], [], IsOk, OkReasons, NotOkReasons),
  ((IsOk, Reasons = OkReasons);
   (not(IsOk), Reasons = NotOkReasons)).

eval([], IsOk, OkReasons, NotOkReasons, IsOk, OkReasons, NotOkReasons).
eval([P|Ps], AccBool, AccOkReasons, AccNotOkReasons, IsOk, OkReasons, NotOkReasons) :-
  eval_perm(P, OkP, ReasonP),
  and(AccBool, OkP, NewAccBool),
  ((OkP, eval(Ps, NewAccBool, [ReasonP|AccOkReasons], AccNotOkReasons, IsOk, OkReasons, NotOkReasons));
  (not(OkP), eval(Ps, NewAccBool, AccOkReasons, [ReasonP|AccNotOkReasons], IsOk, OkReasons, NotOkReasons))).

and(B1, B2, B3) :-
  (B1, B2, B3 = true);
  ((not(B1);not(B2)),B3 = fail).

eval_perm(whitelist([], T), IsOk, Reason) :-
  IsOk = fail,
  join(['Not explicitly allowed by', T], ' ', Reason).

eval_perm(whitelist([P|Ps], T), IsOk, Reason) :-
  IsOk = true,
  policy_sids([P|Ps], [], Sids),
  join(Sids, ',', SidStr),
  join(['Allowed by', T, ':', SidStr], ' ', Reason).

eval_perm(blacklist([], T), IsOk, Reason) :-
  IsOk = true,
  join(['Not explicitly denied by', T], ' ', Reason).

eval_perm(blacklist([P|Ps], T), IsOk, Reason) :-
  IsOk = fail,
  policy_sids([P|Ps], [], Sids),
  join(Sids, ',', SidStr),
  join(['Denied by', T, ':', SidStr], ' ', Reason).

policy_sids([], Sids, Sids).
policy_sids([policy(_,Sid,_,_,_)|Ps], Acc, Sids) :-
  policy_sids(Ps, [Sid|Acc], Sids).

join([], _, '').
join([X|Xs], Sep, Res) :-
  atom_chars(Sep, SepChars),
  join([X|Xs], SepChars, [], ResChars),
  atom_chars(Res, ResChars).

join([], _, Res, Res).
join([X|Xs], SepChars, [], Res) :-
  atom_chars(X, XChars),
  join(Xs, SepChars, XChars, Res).
join([X|Xs], SepChars, [Y|Ys], Res) :-
  atom_chars(X, XChars),
  append([Y|Ys], SepChars, Acc1),
  append(Acc1, XChars, Acc2),
  join(Xs, SepChars, Acc2, Res).

concat(Str1, Str2, Res) :-
  atom_chars(Str1, S1s),
  atom_chars(Str2, S2s),
  append(S1s, S2s, Codes),
  atom_chars(Res, Codes).

context_build(Ac, Re, Ctx) :-
  findall(policy(identity, Id, deny, Ax, Rx), policy_match(identity, Id,  deny, Ac, Re, Ax, Rx), Denies),
  findall(policy(identity, Id, allow, Ax, Rx), policy_match(identity, Id, allow, Ac, Re, Ax, Rx), Allows),
  findall(policy(boundary, Id, deny, Ax, Rx), policy_match(boundary, Id,  deny, Ac, Re, Ax, Rx), Bdenies),
  findall(policy(boundary, Id, allow, Ax, Rx), policy_match(boundary, Id, allow, Ac, Re, Ax, Rx), Ballows),
  findall(Id, policy(boundary, Id, _, _, _), Boundaries),
  A = whitelist(Allows, identity),
  B = blacklist(Denies, identity),
  C = blacklist(Bdenies,boundary),
  D = whitelist(Ballows,boundary),
  list_not_empty(Boundaries, HasBoundaries),
  ((HasBoundaries, Ctx = context(Ac, Re, [A, B, C, D]));
   (not(HasBoundaries), Ctx = context(Ac, Re, [A, B]))).

fix(Action, Resource, Changes) :-
  ( var(Resource), !, error('Resource must be ground'));
  ( var(Action), !, error('Action must be ground'));
  action(Action),
  context_build(Action, Resource, Ctx),
  Ctx = context(_, _, Ps),
  fix(Action, Resource, Ps, [], Changes).

fix(_, _, [], Changes, Changes).
fix(A, R, [whitelist([], T)| Ps], Acc, Changes) :-
  join([A,R,allow], '-', N),
  P = policy(T, N, allow, A, R),
  assertz(P),
  U = changelog(add, P),
  fix(A, R, Ps, [U|Acc], Changes).
fix(A, R, [whitelist([_|_], _)| Ps], Acc, Changes) :-
  fix(A, R, Ps, Acc, Changes).
fix(A, R, [blacklist([], _)| Ps], Acc, Changes) :-
  fix(A, R, Ps, Acc, Changes).
fix(A, R, [blacklist([B|Bs], T)| Ps], Acc, Changes) :-
  retract(B),
  U = changelog(del, B),
  fix(A, R, [blacklist(Bs, T)|Ps], [U|Acc], Changes).
