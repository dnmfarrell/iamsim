:- set_prolog_flag(double_quotes, chars).
:- use_module(library(dcgs)).
:- use_module(library(format)).
:- use_module('../src/iam/sim').
:- use_module('../src/iam/s3').

:- dynamic(policy/5).

test("all-no-policies", (
  Arn = "arn:aws:s3:::foo",
  all_denied(Arn)),
  true).

test("arn_match", (
  PolicyArn = arn("aws","s3","","","*"),
  ResourceArn = arn("aws","s3","","","foo"),
  arn_match(PolicyArn, ResourceArn),
  % star matches everything
  arn_match(star, ResourceArn)),
  true).

test("service_match", (
  PolicyArn = arn("aws","s3","","","*"),
  service_match("s3:PutObject", PolicyArn),
  service_match("*", PolicyArn),
  service_match("*", star),
  service_match("s3:PutObject", star),
  (   service_match("dynamodb:GetItem", PolicyArn) ->
      false
  ;   true
  )),
  true).

test("all-except-denied", (
  Action = "s3:PutObject",
  Arn = "arn:aws:s3:::foo",
  policy_add(identity,"foo-s3",allow,"*","*"),
  policy_add(identity,"foo-s3",deny,Action,Arn),
  setof(A, action_except(Action, A), Expected),
  all(Allowed,Arn),
  Allowed = Expected),
  retract_policies).

test("all-deny-beats-allow", (
  Action = "s3:PutObject",
  Arn = "arn:aws:s3:::foo",
  policy_add(identity,"foo-s3-putobject",allow,Action,Arn),
  policy_add(identity,"foo-s3-putobject",deny,Action,Arn),
  all_denied(Arn)),
  retract_policies).
 
test("all-boundary-implicit-deny", (
  Arn = "arn:aws:s3:::foo",
  policy_add(identity,"foo-s3",allow,"s3:PutObject",Arn),
  policy_add(boundary,"foo-s3",allow,"s3:GetObject",Arn),
  all_denied(Arn)),
  retract_policies).

test("all-boundary-explicit-deny", (
  Action = "s3:GetObject",
  Arn = "arn:aws:s3:::foo",
  policy_add(identity,"foo-s3",allow,Action,Arn),
  policy_add(boundary,"foo-s3",deny,Action,Arn),
  all_denied(Arn)),
  retract_policies).

test("fix-no-policies", (
  Action = "s3:PutObject",
  Arn = "arn:aws:s3:::foo",
  setof(Changes, fix(Action, Arn, Changes), _),
  all(Allowed, Arn),
  Allowed = [Action]),
  retract_policies).

test("fix-boundary-implicit-deny", (
  Action = "s3:PutObject",
  Arn = "arn:aws:s3:::foo",
  policy_add(identity,"foo-s3",allow,Action,Arn),
  policy_add(boundary,"foo-s3",allow,"s3:GetObject",Arn),
  setof(Changes, fix(Action, Arn, Changes), _),
  all(Allowed, Arn),
  Allowed = [Action]),
  retract_policies).

test("fix-explicit-deny", (
  Action = "s3:PutObject",
  Arn = "arn:aws:s3:::foo",
  policy_add(identity,"foo-s3",deny,Action,Arn),
  policy_add(boundary,"foo-s3",deny,Action,Arn),
  setof(Changes, fix(Action, Arn, Changes), _),
  all(Allowed, Arn),
  Allowed = [Action]),
  retract_policies).

retract_policies :-
   policy_remove(_,_,_,_,_).

all_denied(Arn) :-
  all(Allowed,Arn),
  [] = Allowed.

action_except(A, B) :-
  action(B), B \== A.

main :-
  findall(test(Name, Goal, Cleanup), test(Name, Goal, Cleanup), Tests),
  run_tests(Tests, Failed),
  show_failed(Failed),
  halt.

run_tests([], []).
run_tests([test(Name, Goal, Cleanup)|Tests], Failed) :-
  format("Running test \"~s\"~n", [Name]),
  (   call(Goal) ->
      Failed = Failed1
  ;   format("Failed test \"~s\"~n", [Name]),
      Failed = [Name|Failed1]
  ),
  call(Cleanup),
  run_tests(Tests, Failed1).

show_failed(Failed) :-
  phrase(portray_failed(Failed), F),
  format("~s", [F]).

portray_failed_([]) --> [].
portray_failed_([F|Fs]) -->
  "\"", F, "\"",  "\n", portray_failed_(Fs).

portray_failed([]) --> [].
portray_failed([F|Fs]) -->
  "\n", "Failed tests:", "\n", portray_failed_([F|Fs]).

:- initialization(main).

