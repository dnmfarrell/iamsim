AWS IAM Simulator
=================
A Prolog module that stores IAM policies and actions to simulate permissions.

For more info about the project background and rationale, see this [blog post](https://blog.dnmfarrell.com/post/simulating-aws-iam-with-prolog/).

Requires [Scryer-Prolog](https://scryer.pl/) or similar interpreter.

Limitations
-----------
Only supports identity-based policies and permissions boundaries for now. However, session policies (and some resource-based policies) can be modeled as identity policies and service control policies can be modeled as permissions boundaries.

Assumes one principal per-database session.

Does not support [policy conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).

Only includes S3 actions (PRs welcome see *iam/s3.pl*).

Facts
-----
* `changelog/2` represents adding/deleting a policy.
* `policy/5` represents an IAM policy (identity/boundary, nameString, allow/deny, actionString, resourceString).
* `action/1` is an IAM action string, e.g. 's3:PutObject'.

Policy action and resource strings may contain wildcards (`*`) and placeholders (`?`) which can be escaped with `\`.

Predicates
----------
* `can/2` succeeds if an action may be performed on the resource.
* `why/3` returns a list of strings explaining which policies allow/deny an action on a resource.
* `all/2` returns a list of actions that can be performed on a resource.
* `fix/3` adds/retracts policies to enable the requested action on the resource. Returns the changes as a list of changelog facts.

Example
-------
    $ scryer-prolog -f iam/sim.pl iam/s3.pl
    ?- % add a new policy granting s3:Get* on /public/*
    policy_add(identity, 's3-get-all', allow, 's3:Get*', '/public/*').
       true.
    ?- % test permissions
    can('s3:GetObject','/public/logo.png').
       true
    ;  ... .
    ?- % explain permissions
    why('s3:GetObject','/public/logo.png', Rs).
       Rs = ['Not explicitly denied by identity','Allowed by identity : s3-get-all']
    ;  ... .
    ?- % show all permissions
    all(As,'/public/logo.png').
       As = ['s3:GetAccelerateConfiguration','s3:GetAccessPoint','s3:GetAccessPointConfigurationForObjectLambda','s3:GetAccessPointForObjectLambda','s3:GetAccessPointPolicy','s3:GetAccessPointPolicyForObjectLambda','s3:GetAccessPointPolicyStatus','s3:GetAccessPointPolicyStatusForObjectLambda','s3:GetAccountPublicAccessBlock','s3:GetAnalyticsConfiguration','s3:GetBucketAcl','s3:GetBucketCORS','s3:GetBucketLocation','s3:GetBucketLogging','s3:GetBucketNotification','s3:GetBucketObjectLockConfiguration','s3:GetBucketOwnershipControls','s3:GetBucketPolicy','s3:GetBucketPolicyStatus','s3:GetBucketPublicAccessBlock'|...].
    ?- % test PutObject permission
    can('s3:PutObject','/public/*').
       false.
    ?- % fix the policy to allow PutObject
    fix('s3:PutObject', '/public/*', Ps).
       Ps = [changelog(add,policy(identity,'s3:PutObject-/public/*-allow',allow,'s3:PutObject','/public/*'))]
    ;  false.
    ?- % re-test PutObject permission
    can('s3:PutObject','/public/*').
       true
    ;  ... .

Testing
-------
    $ bin/run-tests
    Running test "all-no-policies"
    Running test "all-except-denied"
    Running test "all-deny-beats-allow"
    Running test "all-boundary-implicit-deny"
    Running test "all-boundary-explicit-deny"
    Running test "fix-no-policies"
    Running test "fix-boundary-implicit-deny"
    Running test "fix-explicit-deny"
