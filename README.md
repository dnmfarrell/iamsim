AWS IAM Simulator
=================
A Prolog module that stores IAM policies and actions to simulate permissions.

Tested with [SWI-Prolog](https://www.swi-prolog.org/).

Limitations
-----------
Only supports identity-based policies and permissions boundaries for now. However, session policies (and some resource-based policies) can be modeled as identity policies and service control policies can be modeled as permissions boundaries.

Assumes one identity per-database session.

Does not support [policy conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html).

Facts
-----
* `changelog/2` represents adding/deleting a policy.
* `policy/5` represents an IAM policy (identity/boundary, nameString, allow/deny, actionString, resourceString).
* `action/1` is an IAM action string, e.g. 's3:PutObject'.

Policy action and resource strings may contain asterisk wildcards.

Predicates
----------
* `can/2` succeeds if an action may be performed on the resource.
* `why/3` returns a list of strings explaining which policies allow/deny an action on a resource.
* `all/2` returns a list of actions that can be performed on a resource.
* `fix/3` returns a changelog of polices required to enable the requested action on the resource.

Example
-------
    % load simulator
    ?- consult(iam/sim).
    true.
    
    % load s3 actions
    ?- consult(iam/s3).
    true.

    % add a new policy granting s3:Get* on /public/*
    ?- assertz(policy(identity, 's3-get-all', allow, 's3:Get*', '/public/*')).
    true.
    
    % test permissions
    ?- can('s3:GetObject','/public/logo.png').
    true .
    
    % explain  permissions
    ?- why('s3:GetObject','/public/logo.png', Rs).
    Rs = ['Not explicitly denied by identity', 'Allowed by identity : s3-get-all'] .
    
    % show all permissions
    ?- all(As,'/public/logo.png').
    As = ['s3:GetAccelerateConfiguration', 's3:GetAccessPoint', 's3:GetAccessPointConfigurationForObjectLambda', 's3:GetAccessPointForObjectLambda', 's3:GetAccessPointPolicy', 's3:GetAccessPointPolicyForObjectLambda', 's3:GetAccessPointPolicyStatus', 's3:GetAccessPointPolicyStatusForObjectLambda', 's3:GetAccountPublicAccessBlock'|...].

    % test permissions
    ?- can('s3:PutObject','/public/*').
    false.
    
    % emit policy changes to fix permissions
    ?- fix('s3:PutObject', '/public/*', Ps).
    Ps = [changelog(add, policy(identity, 's3:PutObject-/public/*-allow', allow, 's3:PutObject', '/public/*'))] .

Testing
-------
    $ bin/run-tests
    % PL-Unit: iamsim ........ done
    % All 8 tests passed

