:- dynamic(policy/5).
:- set_prolog_flag(double_quotes, chars).
:- use_module(library(format), [format_//2]).
:- use_module(library(lists), [append/3, maplist/3]).
:- use_module('../wildcard', [patt//1]).
:- use_module('arn', [arn//1, arn_service//1]).
:- use_module('s3').

policy_add(Type,Id,Effect,Action,ArnStr,Errs) :-
  As = [],
  (   policy_type_invalid(Type) ->
      Bs = ["Policy type must be one of: identity, boundary"| As]
  ;   Bs = As
  ),
  (   list_empty(Id) ->
      Cs = ["Requires a policy id string"|Bs]
  ;   Cs = Bs
  ),
  (   policy_effect_invalid(Effect) ->
      Ds = ["Policy effect must be one of: allow, deny"|Cs]
  ;   Ds = Cs
  ),
  (   list_empty(Action) ->
      Es = ["Requires a policy action string"|Ds]
  ;   Es = Ds
  ),
  (   phrase(policy_action,Action) ->
      Fs = Es
  ;   Fs = ["Invalid action string"|Es]
  ),
  (   arn_or_star(ArnStr, ArnOrStar, ArnErrs) ->
      append(ArnErrs, Fs, Gs),
      service_match(Action, ArnOrStar, Err),
      append(Err, Gs, Hs)
  ;   Hs = ["ARN is an invalid format"|Fs]
  ),
  (   Hs = [] ->
      (   assertz(policy(Type,Id,Effect,Action,ArnOrStar)) ->
          Errs = []
      ;   Errs = ["Unknown error adding policy"]
      )
  ;   Errs = Hs
  ).

% A policy action string can be either "*" or "$service:$pattern".
policy_action --> action_star | action_with_service(_).
action_with_service(S) --> arn_service(S), ":", [_], any(_).
action_star --> [*].
any("") --> "".
any([C|Cs]) --> [C], any(Cs).

% Verifies the service in a policy action ("s3:..") matches the service
% in the policy ARN. Either can be wildcards, which always match.
service_match(Action, ArnOrStar, Err) :-
  (   Action = "*" ->
      Err = []
  ;   ArnOrStar = star ->
      Err = []
  ;   (   ArnOrStar = arn(_,Service,_,_,_),
          phrase(action_with_service(ActionService), Action),
          Service = ActionService ->
          Err = []
      ;   Err = "Service in action does not match the service in ARN"
      )
  ).

policy_action_invalid(Action) :-
  policy_action(Action) -> false ; true.

policy_effect_invalid(Effect) :-
  policy_effect(Effect) -> false ; true.

policy_type_invalid(Type) :-
  policy_type(Type) -> false ; true.

policy_remove(A,B,C,D,E,Errs) :-
  (   retractall(policy(A,B,C,D,E)) ->
      Errs = []
  ;   Errs = ["Unexpected error removing policy"]
  ).

policy_match(Ty, Id, Ef, Action, Arn, PAction, ArnOrStar) :-
  policy(Ty, Id, Ef, PAction, ArnOrStar),
  phrase(patt(PAction), Action),
  arn_match(ArnOrStar, Arn).

% A star matches any ARN.
arn_match(star, _).

% match an ARN to a policy ARN. The policy ARN's resource part can contain
% wildcards and placeholders for a pattern match.
arn_match(PolicyArn, ResourceArn) :-
  arn(PPartition, PService, PRegion, PAcc, PResource) = PolicyArn,
  arn(RPartition, RService, RRegion, RAcc, RResource) = ResourceArn,
  PPartition = RPartition,
  PService = RService,
  PRegion = RRegion,
  PAcc = RAcc,
  once(phrase(patt(PResource), RResource)).

list_empty([]).
list_empty([_]) :- false.
list_not_empty([]) :- false.
list_not_empty([_]).

all(Actions, ArnStr, Errs) :-
  arn_parse(ArnStr,Arn,Errs),
  (   Errs = [],
      setof(Action, Reasons^(action(Action), can_arn(Action,Arn,true,Reasons)), Actions)
  ;   Actions = []
  ).

can(Action, ArnStr, Allowed, Reasons, Errs) :-
  (   var(Action) ->
      As = ["Action must be ground"]
  ;   As = []
  ),
  (   action(Action) ->
      Bs = As
  ;   Bs = ["Action not found"|As]
  ),
  arn_parse(ArnStr,Arn,Cs),
  append(Cs, Bs, Ds),
  (   Ds = [] ->
      once(can_arn(Action, Arn, Allowed, Reasons))
  ;   Errs = Ds
  ).

can_arn(Action, Arn, Allowed, Reasons) :-
  context_build(Action, Arn, Perms),
  eval(Perms, Allowed, Reasons).

eval(Perms, IsOk, Reasons) :-
  eval(Perms, true, [], [], IsOk, OkReasons, NotOkReasons),
  (   IsOk ->
      Reasons = OkReasons
  ;   Reasons = NotOkReasons
  ).

eval([], IsOk, OkReasons, NotOkReasons, IsOk, OkReasons, NotOkReasons).
eval([P|Ps], AccBool, AccOkReasons, AccNotOkReasons, IsOk, OkReasons, NotOkReasons) :-
  eval_perm(P, OkP, ReasonP),
  and(AccBool, OkP, NewAccBool),
  (   OkP ->
      eval(Ps, NewAccBool, [ReasonP|AccOkReasons], AccNotOkReasons, IsOk, OkReasons, NotOkReasons)
  ;   eval(Ps, NewAccBool, AccOkReasons, [ReasonP|AccNotOkReasons], IsOk, OkReasons, NotOkReasons)
  ).

and(B1, B2, B3) :-
  (   B1, B2 ->
      B3 = true
  ;   B3 = false
  ).

eval_perm(whitelist([], Type), IsOk, Reason) :-
  IsOk = false,
  phrase(format_("~q ~q", ['Not explicitly allowed by', Type]), Reason).

eval_perm(whitelist([P|Ps], Type), IsOk, Reason) :-
  IsOk = true,
  policy_sids([P|Ps], [], Sids),
  list_join(Sids, SidStr),
  phrase(format_("~q ~q: ~q", ['Allowed by', Type, SidStr]), Reason).

eval_perm(blacklist([], Type), IsOk, Reason) :-
  IsOk = true,
  phrase(format_("~q ~q", ['Not explicitly denied by', Type]), Reason).

eval_perm(blacklist([P|Ps], Type), IsOk, Reason) :-
  IsOk = false,
  policy_sids([P|Ps], [], Sids),
  list_join(Sids, SidStr),
  phrase(format_("~q ~q: ~q", ['Denied by', Type, SidStr]), Reason).

policy_sids([], Sids, Sids).
policy_sids([policy(_,Sid,_,_,_)|Ps], Acc, Sids) :-
  policy_sids(Ps, [Sid|Acc], Sids).

arn_or_star(ArnStr, Arn, Errs) :-
  (   ArnStr = "*" ->
      Arn = star,
      Errs = []
  ;   arn_parse(ArnStr, Arn, Errs)
  ).

arn_parse(ArnStr, Arn, Errs) :-
  (   nonvar(ArnStr) ->
      (   once(phrase(arn(Arn), ArnStr)) ->
          setof(Es, arn_verify(Arn, Es), ErrList),
          list_flatten(ErrList, Errs)
      ;   Errs = ["Failed to parse ARN"]
      )
  ;   Errs = ["ArnStr must be ground"]
  ).

% Service modules can define additional rules to apply specific ARN rules.
:- multifile(arn_verify/2).
arn_verify(_, []).

list_flatten(As, Bs) :-
  list_flatten(As, [], Bs).

list_flatten([], Acc, Acc).
list_flatten([A|As], Acc, Bs) :-
  append(Acc, A, Acc2),
  list_flatten(As, Acc2, Bs).

list_join(As, Bs) :-
  list_join(As, ',', [], Bs).

list_join([],_,Acc,Acc).
list_join([A|As],Sep,[],Res) :-
  list_join(As, Sep, A, Res).
list_join([A|As],Sep,[B|Bs],Res) :-
  append([B|Bs], [Sep|A], Acc),
  list_join(As, Sep, Acc, Res).

context_build(Ac, RArn, Perms) :-
  findall(policy(identity, Id, deny, Ax, Rx), policy_match(identity, Id,  deny, Ac, RArn, Ax, Rx), Denies),
  findall(policy(identity, Id, allow, Ax, Rx), policy_match(identity, Id, allow, Ac, RArn, Ax, Rx), Allows),
  findall(policy(boundary, Id, deny, Ax, Rx), policy_match(boundary, Id,  deny, Ac, RArn, Ax, Rx), Bdenies),
  findall(policy(boundary, Id, allow, Ax, Rx), policy_match(boundary, Id, allow, Ac, RArn, Ax, Rx), Ballows),
  findall(Id, policy(boundary, Id, _, _, _), Boundaries),
  A = whitelist(Allows, identity),
  B = blacklist(Denies, identity),
  C = blacklist(Bdenies,boundary),
  D = whitelist(Ballows,boundary),
  (   list_not_empty(Boundaries) ->
      Perms = [A, B, C, D]
  ;   Perms = [A, B]
  ).

fix(Action, ArnStr, Changes, Errs) :-
  (   var(Action) ->
      As = ["Action must be ground"]
  ;   As = []
  ),
  arn_parse(ArnStr,Arn,Bs),
  append(Bs,As,Cs),
  (   Cs = [] ->
      (   action(Action) ->
          context_build(Action, Arn, Perms),
          fix(Action, ArnStr, Perms, [], Changes, Errs)
      ;   Errs = ["Action not found"],
          Changes = []
      )
  ;   Errs = Cs,
      Changes = []
  ).

fix(_, _, [], Changes, Changes, _).

fix(A, ArnStr, [P|Ps], Acc, Changes, Errs) :-
  (   whitelist([], Type) = P ->
      perms_grant(A, ArnStr, Type, Ps, Acc, Changes, Errs)
  ;   blacklist([_|_], _) = P ->
      perms_loosen(A, ArnStr, [P|Ps], Acc, Changes, Errs)
  ;   fix(A, ArnStr, Ps, Acc, Changes, Errs)
  ).

perms_grant(A, ArnStr, Type, Ps, Acc, Changes, Errs) :-
  phrase(format_("~q ~q ~q", [A,ArnStr,allow]), Id),
  policy_add(Type, Id, allow, A, ArnStr, PolicyErrs),
  (   PolicyErrs = [] ->
      U = changelog(add, policy(Type, Id, allow, A, ArnStr)),
      fix(A, ArnStr, Ps, [U|Acc], Changes, Errs)
  ;   Errs = PolicyErrs,
      Changes = []
  ).

perms_loosen(A, ArnStr, [blacklist([B|Bs], Type)| Ps], Acc, Changes, Errs) :-
  policy(Type,Id,Effect,Action,Arn) = B,
  policy_remove(Type,Id,Effect,Action,Arn,PolicyErrs),
  (   PolicyErrs = [] ->
      U = changelog(del, B),
      fix(A, ArnStr, [blacklist(Bs, Type)|Ps], [U|Acc], Changes, Errs)
  ;   Errs = PolicyErrs,
      Changes = []
  ).

policy_type(identity).
policy_type(boundary).

policy_effect(allow).
policy_effect(deny).
