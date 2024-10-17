:- use_module(library(dcgs)).
:- use_module(library(format)).
:- use_module('../src/iam/sim').
:- use_module('../src/iam/s3').

:- dynamic(policy/5).

test("all-no-policies", all_denied, true).

test("all-except-denied", (
  D = 's3:PutObject',
  setof(A, action_except(D, A), Expected),
  policy_add(identity,'foo-s3',allow,'*',foo),
  policy_add(identity,'foo-s3',deny,D,foo),
  all(Allowed,foo),
  Allowed = Expected),
  retract_policies).

test("all-deny-beats-allow", (
  D = 's3:PutObject',
  policy_add(identity,'foo-s3-putobject',allow,D,foo),
  policy_add(identity,'foo-s3-putobject',deny,D,foo),
  all_denied),
  retract_policies).
 
test("all-boundary-implicit-deny", (
  policy_add(identity,'foo-s3',allow,'s3:PutObject',foo),
  policy_add(boundary,'foo-s3',allow,'s3:GetObject',foo),
  all_denied),
  retract_policies).

test("all-boundary-explicit-deny", (
  D = 's3:GetObject',
  policy_add(identity,'foo-s3',allow,D,foo),
  policy_add(boundary,'foo-s3',deny,D,foo),
  all_denied),
  retract_policies).

test("fix-no-policies", (
  D = 's3:PutObject',
  setof(Changes, fix(D, foo, Changes), _),
  all(Allowed, foo),
  Allowed = [D]),
  retract_policies).

test("fix-boundary-implicit-deny", (
  D = 's3:PutObject',
  policy_add(identity,'foo-s3',allow,D,foo),
  policy_add(boundary,'foo-s3',allow,'s3:GetObject',foo),
  setof(Changes, fix(D, foo, Changes), _),
  all(Allowed, foo),
  Allowed = [D]),
  retract_policies).

test("fix-explicit-deny", (
  D = 's3:PutObject',
  policy_add(identity,'foo-s3',deny,D,foo),
  policy_add(boundary,'foo-s3',deny,D,foo),
  setof(Changes, fix(D, foo, Changes), _),
  all(Allowed, foo),
  Allowed = [D]),
  retract_policies).

retract_policies :-
   policy_remove(_,_,_,_,_).

all_denied :-
  all(Allowed,foo),
  Allowed = [].

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

