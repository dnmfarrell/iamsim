% arn:partition:service:region:account-id:resource-type/resource-id
:- use_module(library(clpz)).
:- use_module(library(charsio)).
:- use_module(library(debug)).
:- use_module(library(lists)).

arn          --> "arn", ":", partition, ":", service.
partition    --> ("aws" | "aws-cn" | "aws-us-gov").
service      --> s3.
s3           --> "s3:::", (bucket_w_obj|bucket).
bucket       --> call(prefix_ok), call(suffix_ok), bucket_name.
bucket_w_obj --> call(prefix_ok), call(suffix_w_obj), bucket_name, object_utf8.
bucket_name  --> bucket_init, bucket_name, call(popit).
object_utf8  --> object_init, utf8_chars, call(popit).

object_init, [1]  --> "/".
object_term, [L]  --> [L], call(eos).
utf8_chars        --> utf8_char, (utf8_chars|object_term).
utf8_char, [M]    --> [L], [A], { char_type(A, prolog), L #=< 1023, M #= L + 1 }.

prefix_ok(A, A) :-
  take(13, A, B), dif(B, "amzn-s3-demo-"),
  take( 6, A, C), dif(C, "sthree"),
  take( 4, A, D), dif(D, "xn--").

suffix_ok(A,A) :-
  B=[1,2,3,4,5,6,7,8|A], % minimum to match our not_ rules
  phrase((...,not_ols3,call(eos)), B),
  phrase((...,not_xs3,call(eos)), B),
  phrase((...,not_s3alias,call(eos)), B),
  phrase((...,not_mrap,call(eos)), B).

suffix_w_obj(A,A) :-
  B=[1,2,3,4,5,6,7,8|A], % minimum to match our not_ rules
  phrase((...,not_ols3,"/",...), B),
  phrase((...,not_xs3,"/",...), B),
  phrase((...,not_s3alias,"/",...), B),
  phrase((...,not_mrap,"/",...), B).

not_mrap    --> [A,B,C,D,E], { dif([A,B,C,D,E], ".mrap") }.
not_xs3     --> [A,B,C,D,E,F], { dif([A,B,C,D,E,F], "--x-s3") }.
not_ols3    --> [A,B,C,D,E,F,G], { dif([A,B,C,D,E,F,G], "--ol-s3") }.
not_s3alias --> [A,B,C,D,E,F,G,H], { dif([A,B,C,D,E,F,G,H], "-s3alias") }.

bucket_init, [0]  --> [].
bucket_name       --> char_alnum, bucket_midl, char_alnum.
bucket_midl       --> (char_hypen, (bucket_midl|[]))|(char_perio, midl_perio).
midl_perio        --> char_hypen, (bucket_midl|[]).
midl_perio        --> [].
char_alnum, [L1]  --> [L], alnum,  { L #< 63, L1 #= L + 1 }.
char_hypen, [L1]  --> [L], hpnum,  { L #< 63, L1 #= L + 1 }.
char_perio, [L1]  --> [L], ".",    { L #< 63, L1 #= L + 1 }.
char_anyof, [L1]  --> [L], hypdot, { L #< 63, L1 #= L + 1 }.
alnum             --> [C], { member(C, "abcdefghijklmnopqrstuvwxyz0123456789") }.
hpnum             --> [C], { member(C, "abcdefghijklmnopqrstuvwxyz0123456789-") }.
hypdot            --> [C], { member(C, "abcdefghijklmnopqrstuvwxyz0123456789-.") }.

eos([],[]).
popit([_|As],As).
take(N,Src,L) :- findall(E, (nth1(I,Src,E), I =< N), L).

run_tests :-
  !, test_bucket.

test_bucket :-
  test_failing_cases(bucket),
  test_passing_cases(bucket),
  test_failing_cases(bucket_w_obj),
  test_passing_cases(bucket_w_obj).

test_failing_cases(Rule) :-
  findall((Rule, Input, Desc, Output), test_case(Rule, Input, fail, Desc, Output), Ts),
  maplist(test_fail, Ts).

test_fail(RuleInputDescOutput) :-
  (R, I, D, _) = RuleInputDescOutput,
  format('~s\t"~s"\t~s~n', [R, I, D]),
  not(phrase(R, I)).

test_passing_cases(Rule) :-
  findall((Rule, Input, Desc, Output), test_case(Rule, Input, true, Desc, Output), Ts),
  maplist(test_pass, Ts).

test_pass(RuleInputDescOutput) :-
  (R, I, D, O) = RuleInputDescOutput,
  format('~s\t"~s"\t~s~n', [R, I, D]),
  phrase(R, I, O).

test_case(bucket, "1-3", true, "min len", []).
test_case(bucket, "1.-a56789012345678901234567890123456789012345678901234567890123", true, "max len", []).
test_case(bucket, "A12", fail, "uc chars not allowed", []).
test_case(bucket, "13", fail, "bucket too short", []).
test_case(bucket, "1..3", fail, "illegal sequence", []).
test_case(bucket, "1.-a567890123456789012345678901234567890123456789012345678901234", fail, "bucket too long", []).
test_case(bucket, "sthreeb", fail, "illegal prefix", []).
test_case(bucket, "1.mrap", fail, "illegal suffix", []).

test_case(bucket_w_obj, "1-3/foo", true, "min len", []).
test_case(bucket_w_obj, "1.-a56789012345678901234567890123456789012345678901234567890123/foo", true, "max len", []).
test_case(bucket_w_obj, "A13/foo", fail, "uc chars not allowed", []).
test_case(bucket_w_obj, "13/foo", fail, "bucket too short", []).
test_case(bucket_w_obj, "1..3/foo", fail, "illegal sequence", []).
test_case(bucket_w_obj, "1.-a567890123456789012345678901234567890123456789012345678901234/foo", fail, "bucket too long", []).
test_case(bucket_w_obj, "sthreeb/foo", fail, "illegal prefix", []).
test_case(bucket_w_obj, "1.mrap/foo", fail, "illegal suffix", []).
