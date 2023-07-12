:- begin_tests(iamsim).
:- use_module(iam/sim).
:- consult(iam/s3).

test('all-no-policies') :-
  all_denied.

test('all-deny-beats-allow', [cleanup(retract_policies)]) :-
  D = 's3:PutObject',
  assertz(policy(identity,'foo-s3-putobject',allow,D,foo)),
  assertz(policy(identity,'foo-s3-putobject',deny,D,foo)),
  all_denied.

test('all-except-denied', [cleanup(retract_policies)]) :-
  D = 's3:PutObject',
  setof(A, action_except(D, A), Expected),
  assertz(policy(identity,'foo-s3',allow,'*',foo)),
  assertz(policy(identity,'foo-s3',deny,D,foo)),
  all(Allowed,foo),
  Allowed = Expected.

test('all-boundary-implicit-deny', [cleanup(retract_policies)]) :-
  assertz(policy(identity,'foo-s3',allow,'s3:PutObject',foo)),
  assertz(policy(boundary,'foo-s3',allow,'s3:GetObject',foo)),
  all_denied.

test('all-boundary-explicit-deny', [cleanup(retract_policies)]) :-
  D = 's3:GetObject',
  assertz(policy(identity,'foo-s3',allow,D,foo)),
  assertz(policy(boundary,'foo-s3',deny,D,foo)),
  all_denied.

test('fix-no-policies', [cleanup(retract_policies)]) :-
  D = 's3:PutObject',
  setof(Changes, fix(D, foo, Changes), _),
  all(Allowed, foo),
  Allowed = [D].

test('fix-boundary-implicit-deny', [cleanup(retract_policies)]) :-
  D = 's3:PutObject',
  assertz(policy(identity,'foo-s3',allow,D,foo)),
  assertz(policy(boundary,'foo-s3',allow,'s3:GetObject',foo)),
  setof(Changes, fix(D, foo, Changes), _),
  all(Allowed, foo),
  Allowed = [D].

test('fix-explicit-deny', [cleanup(retract_policies)]) :-
  D = 's3:PutObject',
  assertz(policy(identity,'foo-s3',deny,D,foo)),
  assertz(policy(boundary,'foo-s3',deny,D,foo)),
  setof(Changes, fix(D, foo, Changes), _),
  all(Allowed, foo),
  Allowed = [D].

retract_policies() :-
  retractall(policy(_,_,_,_,_)).

all_denied() :-
  all(Allowed,foo),
  Allowed = [].

action_except(A, B) :-
  action(B), B \== A.

:- end_tests(iamsim).
