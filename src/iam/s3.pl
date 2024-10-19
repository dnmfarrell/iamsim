:- dynamic(action/1).
:- set_prolog_flag(double_quotes, chars).
:- use_module(library(between)).
:- use_module(library(clpz)).
:- use_module(library(dcgs)).
:- use_module(library(dif)).
:- use_module(library(lists)).

% S3 specific Arn rules.
:- multifile(arn_verify/2).
arn_verify(Arn, Err) :-
  arn(_,Service,Region, AccId, Resource) = Arn,
  (   Service = "s3" ->
      (   Region = "" ->
          As = []
      ;   As = ["Region not empty"]
      ),
      (   AccId = "" ->
          Bs = As
      ;   Bs = ["AccountID not empty"|As]
      ),
      (   nonvar(Resource), phrase(resource, Resource) ->
          Cs = Bs
      ;   Cs = ["Resource is invalid"| Bs]
      ),
      Err = Cs
  ;   Err = []
  ).

eos([],[]).
pop([_|As],As).
take(N,Src,L) :- findall(E, (nth1(I,Src,E), I =< N), L).

resource     --> bucket_w_obj|bucket.
bucket       --> call(prefix_ok), call(suffix_ok), bucket_name.
bucket_w_obj --> call(prefix_ok), call(suffix_w_obj), bucket_name, object.

object -->
  (   parsing ->
      object_utf8
  ;   object_safe
  ).

parsing, [C] --> [C], { nonvar(C) }.
bucket_name  --> bucket_init, bucket_chrs, call(pop).
object_safe  --> object_init, safe_chars, call(pop).
object_utf8  --> object_init, utf8_points, call(pop).

object_init, [1]  --> "/".
object_term, [L]  --> [L], call(eos).
safe_chars        --> safe_char, (safe_chars|object_term).
safe_char, [M]    --> [L], { L #< 1024, M #= L + 1 }, (alnum|safe_symbol).
utf8_points    --> utf8_point, (utf8_points|object_term).
utf8_point, [M]--> [L], [A], {
  L #< 1024,
  char_code(A, D),
  ccode(D),
  M #= L + 1 }.

ccode(Code) :- between(0, 0xD7FF, Code).
ccode(Code) :- between(0xE000, 0x10FFFF, Code).

prefix_ok(A, A) :-
  take(13, A, B), dif(B, "amzn-s3-demo-"),
  take( 6, A, C), dif(C, "sthree"),
  take( 4, A, D), dif(D, "xn--"),
  !.

suffix_ok(A,A) :-
  B=[1,2,3,4,5,6,7,8|A], % minimum to match our not_ rules
  phrase((...,not_ols3,call(eos)), B),
  phrase((...,not_xs3,call(eos)), B),
  phrase((...,not_s3alias,call(eos)), B),
  phrase((...,not_mrap,call(eos)), B),
  !.

suffix_w_obj(A,A) :-
  B=[1,2,3,4,5,6,7,8|A], % minimum to match our not_ rules
  phrase((...,not_ols3,"/",...), B),
  phrase((...,not_xs3,"/",...), B),
  phrase((...,not_s3alias,"/",...), B),
  phrase((...,not_mrap,"/",...), B),
  !.

not_mrap    --> [A,B,C,D,E], { dif([A,B,C,D,E], ".mrap") }.
not_xs3     --> [A,B,C,D,E,F], { dif([A,B,C,D,E,F], "--x-s3") }.
not_ols3    --> [A,B,C,D,E,F,G], { dif([A,B,C,D,E,F,G], "--ol-s3") }.
not_s3alias --> [A,B,C,D,E,F,G,H], { dif([A,B,C,D,E,F,G,H], "-s3alias") }.

bucket_init, [0]  --> [].
bucket_chrs       --> char_alnum, bucket_midl, char_alnum.
bucket_midl       --> (char_alnumhyp, (bucket_midl|[]))|(char_dot, midl_dot).
midl_dot          --> char_alnumhyp, (bucket_midl|[]).
midl_dot          --> [].
char_alnum, [L1]  --> [L], alnum,  { L #< 63, L1 #= L + 1 }.
char_alnumhyp, [L1]  --> [L], alnumhyp,  { L #< 63, L1 #= L + 1 }.
char_dot, [L1]  --> [L], ".",    { L #< 63, L1 #= L + 1 }.
char_anyof, [L1]  --> [L], alnumhypdot, { L #< 63, L1 #= L + 1 }.
alnum             --> upper | lower | digit.
alnumhyp          --> alnum | hyphen.
alnumhypdot       --> alnumhyp | dot.
upper             --> [C], { memberchk(C, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") }.
lower             --> [C], { memberchk(C, "abcdefghijklmnopqrstuvwxyz") }.
digit             --> [C], { memberchk(C, "0123456789") }.
hyphen            --> [-].
dot               --> [.].
safe_symbol       --> [C], { memberchk(C, "!-_.*\\()") }.

action("s3:AbortMultipartUpload").
action("s3:BypassGovernanceRetention").
action("s3:CreateAccessPoint").
action("s3:CreateAccessPointForObjectLambda").
action("s3:CreateBucket").
action("s3:CreateJob").
action("s3:CreateMultiRegionAccessPoint").
action("s3:DeleteAccessPoint").
action("s3:DeleteAccessPointForObjectLambda").
action("s3:DeleteAccessPointPolicy").
action("s3:DeleteAccessPointPolicyForObjectLambda").
action("s3:DeleteBucket").
action("s3:DeleteBucketPolicy").
action("s3:DeleteBucketWebsite").
action("s3:DeleteIntelligentTieringConfiguration").
action("s3:DeleteJobTagging").
action("s3:DeleteMultiRegionAccessPoint").
action("s3:DeleteObject").
action("s3:DeleteObjectTagging").
action("s3:DeleteObjectVersion").
action("s3:DeleteObjectVersionTagging").
action("s3:DeleteStorageLensConfiguration").
action("s3:DeleteStorageLensConfigurationTagging").
action("s3:DescribeJob").
action("s3:DescribeMultiRegionAccessPointOperation").
action("s3:GetAccelerateConfiguration").
action("s3:GetAccessPoint").
action("s3:GetAccessPointConfigurationForObjectLambda").
action("s3:GetAccessPointForObjectLambda").
action("s3:GetAccessPointPolicy").
action("s3:GetAccessPointPolicyForObjectLambda").
action("s3:GetAccessPointPolicyStatus").
action("s3:GetAccessPointPolicyStatusForObjectLambda").
action("s3:GetAccountPublicAccessBlock").
action("s3:GetAnalyticsConfiguration").
action("s3:GetBucketAcl").
action("s3:GetBucketCORS").
action("s3:GetBucketLocation").
action("s3:GetBucketLogging").
action("s3:GetBucketNotification").
action("s3:GetBucketObjectLockConfiguration").
action("s3:GetBucketOwnershipControls").
action("s3:GetBucketPolicy").
action("s3:GetBucketPolicyStatus").
action("s3:GetBucketPublicAccessBlock").
action("s3:GetBucketRequestPayment").
action("s3:GetBucketTagging").
action("s3:GetBucketVersioning").
action("s3:GetBucketWebsite").
action("s3:GetEncryptionConfiguration").
action("s3:GetIntelligentTieringConfiguration").
action("s3:GetInventoryConfiguration").
action("s3:GetJobTagging").
action("s3:GetLifecycleConfiguration").
action("s3:GetMetricsConfiguration").
action("s3:GetMultiRegionAccessPoint").
action("s3:GetMultiRegionAccessPointPolicy").
action("s3:GetMultiRegionAccessPointPolicyStatus").
action("s3:GetMultiRegionAccessPointRoutes").
action("s3:GetObject").
action("s3:GetObjectAcl").
action("s3:GetObjectAttributes").
action("s3:GetObjectLegalHold").
action("s3:GetObjectRetention").
action("s3:GetObjectTagging").
action("s3:GetObjectTorrent").
action("s3:GetObjectVersion").
action("s3:GetObjectVersionAcl").
action("s3:GetObjectVersionAttributes").
action("s3:GetObjectVersionForReplication").
action("s3:GetObjectVersionTagging").
action("s3:GetObjectVersionTorrent").
action("s3:GetReplicationConfiguration").
action("s3:GetStorageLensConfiguration").
action("s3:GetStorageLensConfigurationTagging").
action("s3:GetStorageLensDashboard").
action("s3:InitiateReplication").
action("s3:ListAccessPoints").
action("s3:ListAccessPointsForObjectLambda").
action("s3:ListAllMyBuckets").
action("s3:ListBucket").
action("s3:ListBucketMultipartUploads").
action("s3:ListBucketVersions").
action("s3:ListJobs").
action("s3:ListMultipartUploadParts").
action("s3:ListMultiRegionAccessPoints").
action("s3:ListStorageLensConfigurations").
action("s3-object-lambda:AbortMultipartUpload").
action("s3-object-lambda:DeleteObject").
action("s3-object-lambda:DeleteObjectTagging").
action("s3-object-lambda:DeleteObjectVersion").
action("s3-object-lambda:DeleteObjectVersionTagging").
action("s3-object-lambda:GetObject").
action("s3-object-lambda:GetObjectAcl").
action("s3-object-lambda:GetObjectLegalHold").
action("s3-object-lambda:GetObjectRetention").
action("s3-object-lambda:GetObjectTagging").
action("s3-object-lambda:GetObjectVersion").
action("s3-object-lambda:GetObjectVersionAcl").
action("s3-object-lambda:GetObjectVersionTagging").
action("s3-object-lambda:ListBucket").
action("s3-object-lambda:ListBucketMultipartUploads").
action("s3-object-lambda:ListBucketVersions").
action("s3-object-lambda:ListMultipartUploadParts").
action("s3-object-lambda:PutObject").
action("s3-object-lambda:PutObjectAcl").
action("s3-object-lambda:PutObjectLegalHold").
action("s3-object-lambda:PutObjectRetention").
action("s3-object-lambda:PutObjectTagging").
action("s3-object-lambda:PutObjectVersionAcl").
action("s3-object-lambda:PutObjectVersionTagging").
action("s3-object-lambda:RestoreObject").
action("s3-object-lambda:WriteGetObjectResponse").
action("s3:ObjectOwnerOverrideToBucketOwner").
action("s3:PutAccelerateConfiguration").
action("s3:PutAccessPointConfigurationForObjectLambda").
action("s3:PutAccessPointPolicy").
action("s3:PutAccessPointPolicyForObjectLambda").
action("s3:PutAccessPointPublicAccessBlock").
action("s3:PutAccountPublicAccessBlock").
action("s3:PutAnalyticsConfiguration").
action("s3:PutBucketAcl").
action("s3:PutBucketCORS").
action("s3:PutBucketLogging").
action("s3:PutBucketNotification").
action("s3:PutBucketObjectLockConfiguration").
action("s3:PutBucketOwnershipControls").
action("s3:PutBucketPolicy").
action("s3:PutBucketPublicAccessBlock").
action("s3:PutBucketRequestPayment").
action("s3:PutBucketTagging").
action("s3:PutBucketVersioning").
action("s3:PutBucketWebsite").
action("s3:PutEncryptionConfiguration").
action("s3:PutIntelligentTieringConfiguration").
action("s3:PutInventoryConfiguration").
action("s3:PutJobTagging").
action("s3:PutLifecycleConfiguration").
action("s3:PutMetricsConfiguration").
action("s3:PutMultiRegionAccessPointPolicy").
action("s3:PutObject").
action("s3:PutObjectAcl").
action("s3:PutObjectLegalHold").
action("s3:PutObjectRetention").
action("s3:PutObjectTagging").
action("s3:PutObjectVersionAcl").
action("s3:PutObjectVersionTagging").
action("s3:PutReplicationConfiguration").
action("s3:PutStorageLensConfiguration").
action("s3:PutStorageLensConfigurationTagging").
action("s3:ReplicateDelete").
action("s3:ReplicateObject").
action("s3:ReplicateTags").
action("s3:RestoreObject").
action("s3:SubmitMultiRegionAccessPointRoutes").
action("s3:UpdateJobPriority").
action("s3:UpdateJobStatus").
