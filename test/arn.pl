:- use_module(library(dcgs)).
:- use_module(library(format)).
:- use_module('../src/iam/arn').

:- set_prolog_flag(double_quotes, chars).
:- dynamic(policy/5).

test("arn:aws:ec2:us-east-1:123456789012:foo/bar", (
  Arn="arn:aws:ec2:us-east-1:123456789012:foo/bar",
  phrase(arn(arn(A,B,C,D,E)), Arn),
  A="aws",
  B="ec2",
  C="us-east-1",
  D="123456789012",
  E="foo/bar"
  ), true).

test("arn:aws:s3:::foo/bar", (
  Arn="arn:aws:s3:::foo/bar",
  phrase(arn(arn(A,B,C,D,E)), Arn),
  A="aws",
  B="s3",
  C="",
  D="",
  E="foo/bar"
  ), true).

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

