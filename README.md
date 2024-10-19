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

Only includes S3 actions (PRs welcome see [iam/s3.pl](src/iam/s3.pl).


Predicates
----------
### `policy_add(+Type,+Id,+Effect,+Action,+ArnStr, -Errs)`

Adds a policy to the database, where:

* `Type` is one of: `boundary` or `identity`.
* `Id` is a list string which names the policy, e.g. `"s3-foo-allow-all"`.
* `Effect` is one of: `allow` or `deny`.
* `Action` is a list string pattern, e.g. `"s3:PutObject"`, `"s3:*"`, or `"*"`.
* `ArnStr` is a list string of an AWS Arn, e.g. `"arn:aws:s3:::foo/bar"`. The resource portion (the last part) may be a string pattern, e.g. `"fo?/*"`.
* `Errs` is a list of error messages that is empty when the policy was successfully added.

### `can(+Action, +ArnStr, -Allowed, -Reasons, -Errs)`

Evaluates whether the principal is permitted to perform the action on the resource, where:

* `Action` is a list string, e.g. `"s3:PutObject"`.
* `ArnStr` is a list string of an AWS Arn, e.g. `"arn:aws:s3:::foo/bar"`.
* `Allowed` is a boolean.
* `Reasons` is a list of messsages explaining the evaluation reasoning.
* `Errs` is a list of error messages that is empty when the evaluation succeeded.

### `all(-Actions, +ArnStr, -Err)`

Returns all actions the principal may perform on the resource, where:

* `Actions` is a list of permitted actions.
* `ArnStr` is a list string of an AWS Arn, e.g. `"arn:aws:s3:::foo/bar"`.
* `Errs` is a list of error messages that is empty when the evaluation succeeded.

### `fix(+Action, +ArnStr, -Changes, -Errs)`

Fixes a permission issue by creating/deleting policies, where:

* `Action` is a list string of the action to grant, e.g. `"s3:PutObject"`.
* `ArnStr` is a list string of an AWS Arn, e.g. `"arn:aws:s3:::foo/bar"`.
* `Changes` is a list of strings describing the operations performed.
* `Errs` is a list of error messages that is empty when the fix succeeded.


Example
-------
    $ scryer-prolog -f src/iam/sim.pl
    ?- % check if we can get foo/bar.csv
    can("s3:GetObject", "arn:aws:s3:::foo/bar.csv", Allowed, Reasons, Errs).
       Allowed = false, Reasons = ["\'Not explicitly all ..."].
    ?- % grant the permission
    fix("s3:GetObject", "arn:aws:s3:::foo/bar.csv", Changelog, Errs).
       Changelog = [changelog(add,policy(identity,"[s,\'3\',:,\'G\',e,t, ...",allow,"s3:GetObject","arn:aws:s3:::foo/ ..."))], Errs = []
    ;  false.
    ?- % re-test
    can("s3:GetObject", "arn:aws:s3:::foo/bar.csv", Allowed, Reasons, Errs).
       Allowed = true, Reasons = ["\'Not explicitly den ...","\'Allowed by\' ident ..."].
    ?- % create a policy to grant all
    policy_add(identity, "s3-foo-*", allow, "*", "arn:aws:s3:::foo/*", Errs).
       Errs = [].
    ?- % What actions can we perform?
    all(Actions, "arn:aws:s3:::foo/bar.csv", Errs).
    ;  Actions = ["s3-object-lambda:Ab ...","s3-object-lambda:D ...","s3-object-lambda: ...","s3-object-lambda ...","s3-object-lambd ...","s3-object-lamb ...","s3-object-lam ...","s3-object-la ...","s3-object-l ...","s3-object- ...","s3-object ...","s3-objec ...","s3-obje ...","s3-obj ...","s3-ob ...","s3-o ...","s3- ...","s3 ...","s ...","s3-object-lambda:PutObjectLegalHold"|...], Errs = []


Testing
-------
    $ bin/run-tests
    + scryer-prolog -f test/arn.pl
    Running test "arn:aws:ec2:us-east-1:123456789012:foo/bar"
    Running test "arn:aws:s3:::foo/bar"
    + scryer-prolog -f test/sim.pl
    Running test "all-no-policies"
    Running test "arn_match"
    Running test "arn_parse"
    Running test "service_match"
    Running test "all-except-denied"
    Running test "all-deny-beats-allow"
    Running test "all-boundary-implicit-deny"
    Running test "all-boundary-explicit-deny"
    Running test "fix-no-policies"
    Running test "fix-boundary-implicit-deny"
    Running test "fix-explicit-deny"
