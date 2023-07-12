:- use_module(sim, []).

:- assertz(action('s3:AbortMultipartUpload')).
:- assertz(action('s3:BypassGovernanceRetention')).
:- assertz(action('s3:CreateAccessPoint')).
:- assertz(action('s3:CreateAccessPointForObjectLambda')).
:- assertz(action('s3:CreateBucket')).
:- assertz(action('s3:CreateJob')).
:- assertz(action('s3:CreateMultiRegionAccessPoint')).
:- assertz(action('s3:DeleteAccessPoint')).
:- assertz(action('s3:DeleteAccessPointForObjectLambda')).
:- assertz(action('s3:DeleteAccessPointPolicy')).
:- assertz(action('s3:DeleteAccessPointPolicyForObjectLambda')).
:- assertz(action('s3:DeleteBucket')).
:- assertz(action('s3:DeleteBucketPolicy')).
:- assertz(action('s3:DeleteBucketWebsite')).
:- assertz(action('s3:DeleteIntelligentTieringConfiguration')).
:- assertz(action('s3:DeleteJobTagging')).
:- assertz(action('s3:DeleteMultiRegionAccessPoint')).
:- assertz(action('s3:DeleteObject')).
:- assertz(action('s3:DeleteObjectTagging')).
:- assertz(action('s3:DeleteObjectVersion')).
:- assertz(action('s3:DeleteObjectVersionTagging')).
:- assertz(action('s3:DeleteStorageLensConfiguration')).
:- assertz(action('s3:DeleteStorageLensConfigurationTagging')).
:- assertz(action('s3:DescribeJob')).
:- assertz(action('s3:DescribeMultiRegionAccessPointOperation')).
:- assertz(action('s3:GetAccelerateConfiguration')).
:- assertz(action('s3:GetAccessPoint')).
:- assertz(action('s3:GetAccessPointConfigurationForObjectLambda')).
:- assertz(action('s3:GetAccessPointForObjectLambda')).
:- assertz(action('s3:GetAccessPointPolicy')).
:- assertz(action('s3:GetAccessPointPolicyForObjectLambda')).
:- assertz(action('s3:GetAccessPointPolicyStatus')).
:- assertz(action('s3:GetAccessPointPolicyStatusForObjectLambda')).
:- assertz(action('s3:GetAccountPublicAccessBlock')).
:- assertz(action('s3:GetAnalyticsConfiguration')).
:- assertz(action('s3:GetBucketAcl')).
:- assertz(action('s3:GetBucketCORS')).
:- assertz(action('s3:GetBucketLocation')).
:- assertz(action('s3:GetBucketLogging')).
:- assertz(action('s3:GetBucketNotification')).
:- assertz(action('s3:GetBucketObjectLockConfiguration')).
:- assertz(action('s3:GetBucketOwnershipControls')).
:- assertz(action('s3:GetBucketPolicy')).
:- assertz(action('s3:GetBucketPolicyStatus')).
:- assertz(action('s3:GetBucketPublicAccessBlock')).
:- assertz(action('s3:GetBucketRequestPayment')).
:- assertz(action('s3:GetBucketTagging')).
:- assertz(action('s3:GetBucketVersioning')).
:- assertz(action('s3:GetBucketWebsite')).
:- assertz(action('s3:GetEncryptionConfiguration')).
:- assertz(action('s3:GetIntelligentTieringConfiguration')).
:- assertz(action('s3:GetInventoryConfiguration')).
:- assertz(action('s3:GetJobTagging')).
:- assertz(action('s3:GetLifecycleConfiguration')).
:- assertz(action('s3:GetMetricsConfiguration')).
:- assertz(action('s3:GetMultiRegionAccessPoint')).
:- assertz(action('s3:GetMultiRegionAccessPointPolicy')).
:- assertz(action('s3:GetMultiRegionAccessPointPolicyStatus')).
:- assertz(action('s3:GetMultiRegionAccessPointRoutes')).
:- assertz(action('s3:GetObject')).
:- assertz(action('s3:GetObjectAcl')).
:- assertz(action('s3:GetObjectAttributes')).
:- assertz(action('s3:GetObjectLegalHold')).
:- assertz(action('s3:GetObjectRetention')).
:- assertz(action('s3:GetObjectTagging')).
:- assertz(action('s3:GetObjectTorrent')).
:- assertz(action('s3:GetObjectVersion')).
:- assertz(action('s3:GetObjectVersionAcl')).
:- assertz(action('s3:GetObjectVersionAttributes')).
:- assertz(action('s3:GetObjectVersionForReplication')).
:- assertz(action('s3:GetObjectVersionTagging')).
:- assertz(action('s3:GetObjectVersionTorrent')).
:- assertz(action('s3:GetReplicationConfiguration')).
:- assertz(action('s3:GetStorageLensConfiguration')).
:- assertz(action('s3:GetStorageLensConfigurationTagging')).
:- assertz(action('s3:GetStorageLensDashboard')).
:- assertz(action('s3:InitiateReplication')).
:- assertz(action('s3:ListAccessPoints')).
:- assertz(action('s3:ListAccessPointsForObjectLambda')).
:- assertz(action('s3:ListAllMyBuckets')).
:- assertz(action('s3:ListBucket')).
:- assertz(action('s3:ListBucketMultipartUploads')).
:- assertz(action('s3:ListBucketVersions')).
:- assertz(action('s3:ListJobs')).
:- assertz(action('s3:ListMultipartUploadParts')).
:- assertz(action('s3:ListMultiRegionAccessPoints')).
:- assertz(action('s3:ListStorageLensConfigurations')).
:- assertz(action('s3-object-lambda:AbortMultipartUpload')).
:- assertz(action('s3-object-lambda:DeleteObject')).
:- assertz(action('s3-object-lambda:DeleteObjectTagging')).
:- assertz(action('s3-object-lambda:DeleteObjectVersion')).
:- assertz(action('s3-object-lambda:DeleteObjectVersionTagging')).
:- assertz(action('s3-object-lambda:GetObject')).
:- assertz(action('s3-object-lambda:GetObjectAcl')).
:- assertz(action('s3-object-lambda:GetObjectLegalHold')).
:- assertz(action('s3-object-lambda:GetObjectRetention')).
:- assertz(action('s3-object-lambda:GetObjectTagging')).
:- assertz(action('s3-object-lambda:GetObjectVersion')).
:- assertz(action('s3-object-lambda:GetObjectVersionAcl')).
:- assertz(action('s3-object-lambda:GetObjectVersionTagging')).
:- assertz(action('s3-object-lambda:ListBucket')).
:- assertz(action('s3-object-lambda:ListBucketMultipartUploads')).
:- assertz(action('s3-object-lambda:ListBucketVersions')).
:- assertz(action('s3-object-lambda:ListMultipartUploadParts')).
:- assertz(action('s3-object-lambda:PutObject')).
:- assertz(action('s3-object-lambda:PutObjectAcl')).
:- assertz(action('s3-object-lambda:PutObjectLegalHold')).
:- assertz(action('s3-object-lambda:PutObjectRetention')).
:- assertz(action('s3-object-lambda:PutObjectTagging')).
:- assertz(action('s3-object-lambda:PutObjectVersionAcl')).
:- assertz(action('s3-object-lambda:PutObjectVersionTagging')).
:- assertz(action('s3-object-lambda:RestoreObject')).
:- assertz(action('s3-object-lambda:WriteGetObjectResponse')).
:- assertz(action('s3:ObjectOwnerOverrideToBucketOwner')).
:- assertz(action('s3:PutAccelerateConfiguration')).
:- assertz(action('s3:PutAccessPointConfigurationForObjectLambda')).
:- assertz(action('s3:PutAccessPointPolicy')).
:- assertz(action('s3:PutAccessPointPolicyForObjectLambda')).
:- assertz(action('s3:PutAccessPointPublicAccessBlock')).
:- assertz(action('s3:PutAccountPublicAccessBlock')).
:- assertz(action('s3:PutAnalyticsConfiguration')).
:- assertz(action('s3:PutBucketAcl')).
:- assertz(action('s3:PutBucketCORS')).
:- assertz(action('s3:PutBucketLogging')).
:- assertz(action('s3:PutBucketNotification')).
:- assertz(action('s3:PutBucketObjectLockConfiguration')).
:- assertz(action('s3:PutBucketOwnershipControls')).
:- assertz(action('s3:PutBucketPolicy')).
:- assertz(action('s3:PutBucketPublicAccessBlock')).
:- assertz(action('s3:PutBucketRequestPayment')).
:- assertz(action('s3:PutBucketTagging')).
:- assertz(action('s3:PutBucketVersioning')).
:- assertz(action('s3:PutBucketWebsite')).
:- assertz(action('s3:PutEncryptionConfiguration')).
:- assertz(action('s3:PutIntelligentTieringConfiguration')).
:- assertz(action('s3:PutInventoryConfiguration')).
:- assertz(action('s3:PutJobTagging')).
:- assertz(action('s3:PutLifecycleConfiguration')).
:- assertz(action('s3:PutMetricsConfiguration')).
:- assertz(action('s3:PutMultiRegionAccessPointPolicy')).
:- assertz(action('s3:PutObject')).
:- assertz(action('s3:PutObjectAcl')).
:- assertz(action('s3:PutObjectLegalHold')).
:- assertz(action('s3:PutObjectRetention')).
:- assertz(action('s3:PutObjectTagging')).
:- assertz(action('s3:PutObjectVersionAcl')).
:- assertz(action('s3:PutObjectVersionTagging')).
:- assertz(action('s3:PutReplicationConfiguration')).
:- assertz(action('s3:PutStorageLensConfiguration')).
:- assertz(action('s3:PutStorageLensConfigurationTagging')).
:- assertz(action('s3:ReplicateDelete')).
:- assertz(action('s3:ReplicateObject')).
:- assertz(action('s3:ReplicateTags')).
:- assertz(action('s3:RestoreObject')).
:- assertz(action('s3:SubmitMultiRegionAccessPointRoutes')).
:- assertz(action('s3:UpdateJobPriority')).
:- assertz(action('s3:UpdateJobStatus')).
