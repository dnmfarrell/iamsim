:- module(iam_sim, [
                    action/1,
                    arn_match/2,
                    arn_parse/2,
                    can/2,
                    all/2,
                    why/3,
                    fix/3,
                    policy/5,
                    policy_add/5,
                    policy_remove/5,
                    policy_match/7,
                    service_match/2
                   ]).

:- use_module(library(format), [format_//2]).
:- use_module(library(lists), [append/3]).
:- use_module('../wildcard', [patt//1]).
:- use_module('arn', [arn//1]).

:- dynamic(policy/5).
:- dynamic(action/1).

policy_add(Type,Id,Effect,Action,ArnStr) :-
  (   policy_type_invalid(Type) ->
      error("Policy type must be one of: identity, boundary")
  ;   list_empty(Id) ->
      error("Requires a policy id string")
  ;   policy_effect_invalid(Effect) ->
      error("Policy effect must be one of: allow, deny")
  ;   list_empty(Action) ->
      error("Requires a policy action string")
  ;   (   arn_or_star(ArnStr, ArnOrStar),
          service_match(Action, ArnOrStar),
          assertz(policy(Type,Id,Effect,Action,ArnOrStar))
      )
  ).

% Verifies the service in a policy action ("s3:..") matches the service
% in the policy ARN. Either can be wildcards, which always match.
service_match(Action, ArnOrStar) :-
  (   Action = "*" ->
      true
  ;   ArnOrStar = star ->
      true
  ;   (   ArnOrStar = arn(_,Service,_,_,_),
          append(Service, _, Action) ->
          true
      ;   error("Service in action does not match the service in ARN")
      )
  ).

policy_action_invalid(Action) :-
  policy_action(Action) -> false ; true.

policy_effect_invalid(Effect) :-
  policy_effect(Effect) -> false ; true.

policy_type_invalid(Type) :-
  policy_type(Type) -> false ; true.

policy_remove(A,B,C,D,E) :-
   retractall(policy(A,B,C,D,E)).

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

error(Msg) :-
  !, write(user_error, Msg), nl(user_error), false.

can(Action, ArnStr) :-
  action(Action),
  context_build(Action, ArnStr, Ctx),
  eval(Ctx, IsOk, _),
  IsOk.

all(Actions, ArnStr) :-
  (   var(ArnStr) ->
      error('ArnStr must be ground')
  ;   setof(Action, can(Action, ArnStr), Actions)
  ;   Actions = []
  ).

why(Action, ArnStr, Reasons) :-
  (   var(ArnStr) ->
      error('ArnStr must be ground')
  ;   (   action(Action),
          context_build(Action, ArnStr, Ctx),
          eval(Ctx, _, Reasons)
      )
  ).

eval(Ctx, IsOk, Reasons) :-
  context(_, _, Perms) = Ctx,
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

arn_or_star(ArnStr, Arn) :-
  (   ArnStr = "*" ->
      Arn = star
  ;   arn_parse(ArnStr, Arn)
  ).

arn_parse(ArnStr, Arn) :-
  (   nonvar(ArnStr), once(phrase(arn(Arn), ArnStr)) ->
      true
  ;   error('Failed to parse ARN')
  ).

list_join(As, Bs) :-
  list_join(As, ',', [], Bs).

list_join([],_,Acc,Acc).
list_join([A|As],Sep,[],Res) :-
  list_join(As, Sep, A, Res).
list_join([A|As],Sep,[B|Bs],Res) :-
  append([B|Bs], [Sep|A], Acc),
  list_join(As, Sep, Acc, Res).

context_build(Ac, ArnStr, Ctx) :-
  arn_parse(ArnStr, RArn),
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
      Ctx = context(Ac, RArn, [A, B, C, D])
  ;   Ctx = context(Ac, RArn, [A, B])
  ).

fix(Action, ArnStr, Changes) :-
  (   var(Action) ->
      error('Action must be ground')
  ;   var(ArnStr) ->
      error('ArnStr must be ground')
  ;   (   action(Action),
          context_build(Action, ArnStr, Ctx),
          Ctx = context(_, _, Ps),
          fix(Action, ArnStr, Ps, [], Changes)
      )
  ).

fix(_, _, [], Changes, Changes).

fix(A, ArnStr, [whitelist([], Type)| Ps], Acc, Changes) :-
  phrase(format_("~q ~q ~q", [A,ArnStr,allow]), Id),
  policy_add(Type, Id, allow, A, ArnStr),
  U = changelog(add, policy(Type, Id, allow, A, ArnStr)),
  fix(A, ArnStr, Ps, [U|Acc], Changes).

fix(A, ArnStr, [whitelist([_|_], _)| Ps], Acc, Changes) :-
  fix(A, ArnStr, Ps, Acc, Changes).
fix(A, ArnStr, [blacklist([], _)| Ps], Acc, Changes) :-
  fix(A, ArnStr, Ps, Acc, Changes).
fix(A, ArnStr, [blacklist([B|Bs], Type)| Ps], Acc, Changes) :-
  retract(B),
  U = changelog(del, B),
  fix(A, ArnStr, [blacklist(Bs, Type)|Ps], [U|Acc], Changes).

policy_type(identity).
policy_type(boundary).

policy_effect(allow).
policy_effect(deny).
