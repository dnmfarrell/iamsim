/*
    DCG which describes the general AWS ARN format.

    N.B. region and account-id can be empty, as is with s3 ARNs.

    partition/1, service/1 and region/1 are complete sets of facts about
    AWS as of 2024/09.

    Copyright 2024 David Farrell

    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use, copy,
    modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*/

:- module(arn, [
                arn//3,
                arn_scheme//3,
                arn_partition//3,
                arn_partition/1,
                arn_service//3,
                arn_service/1,
                arn_region//3,
                arn_region/1,
                arn_acc_id//3,
                arn_resource//3
               ]).

:- set_prolog_flag(double_quotes, chars).
:- use_module(library(clpz)).
:- use_module(library(dcgs)).
:- use_module(library(between)).

arn([A,B,C,D,E,F]) -->
  arn_scheme(A),
  ":",
  arn_partition(B),
  ":",
  arn_service(C),
  ":",
  arn_region(D),
  ":",
  arn_acc_id(E),
  ":",
  arn_resource(F).

arn_scheme(S) --> "arn", { S = "arn" }.

arn_any("") --> "".
arn_any([C|Cs]) --> [C], arn_any(Cs).

arn_partition(P) --> arn_any(P), { arn_partition(P) }.

arn_service(S) --> arn_any(S), { arn_service(S) }.

arn_parsing, [A] --> [A], { nonvar(A) }.

arn_region(R) -->
  (  arn_parsing ->
     arn_region_lazy(R)
  ;  arn_region_greedy(R) % prefer non-empty solutions
  ).

arn_region_lazy("") --> "".
arn_region_lazy(R)  --> arn_any(R), { arn_region(R) }.

arn_region_greedy(R)  --> arn_any(R), { arn_region(R) }.
arn_region_greedy("") --> "".

arn_acc_id(A) -->
  (  arn_parsing ->
     arn_acc_id_lazy(A)
  ;  arn_acc_id_greedy(A)
  ).

arn_acc_id_lazy("") --> "".
arn_acc_id_lazy(A) --> arn_acc_id_nums(A).

arn_acc_id_greedy(A) --> arn_acc_id_nums(A).
arn_acc_id_greedy("") --> "".

arn_acc_id_nums(A) -->
  arn_digit(B),
  arn_digit(C),
  arn_digit(D),
  arn_digit(E),
  arn_digit(F),
  arn_digit(G),
  arn_digit(H),
  arn_digit(I),
  arn_digit(J),
  arn_digit(K),
  arn_digit(L),
  arn_digit(M),
  { A=[B,C,D,E,F,G,H,I,J,K,L,M] }.

arn_digit('0') --> "0".
arn_digit('1') --> "1".
arn_digit('2') --> "2".
arn_digit('3') --> "3".
arn_digit('4') --> "4".
arn_digit('5') --> "5".
arn_digit('6') --> "6".
arn_digit('7') --> "7".
arn_digit('8') --> "8".
arn_digit('9') --> "9".

arn_resource([C|Cs]) -->
  arn_init_counter,
  arn_resource_([C|Cs]),
  arn_drop_counter.

arn_init_counter, [0] --> "".
arn_drop_counter      --> [_], "".

arn_resource_(""), [N] --> [N], "".
arn_resource_([C|Cs]) --> arn_resource_char_([C|Cs]), arn_resource_(Cs).

arn_resource_char_([C|_]), [M] -->
  [N],
  {
      N #=< 2036, % arn max len is 2048, min prefix is 12
      M #= N + 1
  },
  [C],
  { arn_utf8_char(C) }.

arn_utf8(Code) :- between(0, 0xD7FF, Code).
arn_utf8(Code) :- between(0xE000, 0x10FFFF, Code).

arn_utf8_char(Char) :- arn_utf8(Code), char_code(Char, Code).

arn_partition("aws").
arn_partition("aws-cn").
arn_partition("aws-us-gov").

arn_region("ap-southeast-3").
arn_region("ap-southeast-4").
arn_region("ap-southeast-5").
arn_region("ca-central-1").
arn_region("ca-west-1").
arn_region("cn-north-1").
arn_region("cn-northwest-1").
arn_region("eu-central-1").
arn_region("eu-central-2").
arn_region("eu-north-1").
arn_region("eu-south-1").
arn_region("eu-south-2").
arn_region("eu-west-1").
arn_region("eu-west-2").
arn_region("eu-west-3").
arn_region("il-central-1").
arn_region("me-central-1").
arn_region("me-south-1").
arn_region("sa-east-1").
arn_region("us-east-1").
arn_region("us-east-2").
arn_region("us-gov-east-1").
arn_region("us-gov-west-1").
arn_region("us-west-1").
arn_region("us-west-2").

arn_service("a2c").
arn_service("a4b").
arn_service("access-analyzer").
arn_service("account").
arn_service("acm").
arn_service("acm-pca").
arn_service("activate").
arn_service("airflow").
arn_service("amplify").
arn_service("amplifybackend").
arn_service("amplifyuibuilder").
arn_service("aoss").
arn_service("apigateway").
arn_service("apigateway").
arn_service("appconfig").
arn_service("appfabric").
arn_service("appflow").
arn_service("app-integrations").
arn_service("application-autoscaling").
arn_service("application-cost-profiler").
arn_service("applicationinsights").
arn_service("application-signals").
arn_service("application-transformation").
arn_service("appmesh").
arn_service("appmesh-preview").
arn_service("apprunner").
arn_service("appstream").
arn_service("appstudio").
arn_service("appsync").
arn_service("apptest").
arn_service("aps").
arn_service("arc-zonal-shift").
arn_service("arsenal").
arn_service("artifact").
arn_service("athena").
arn_service("auditmanager").
arn_service("autoscaling").
arn_service("autoscaling-plans").
arn_service("awsconnector").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace").
arn_service("aws-marketplace-management").
arn_service("aws-portal").
arn_service("b2bi").
arn_service("backup").
arn_service("backup-gateway").
arn_service("backup-storage").
arn_service("batch").
arn_service("bcm-data-exports").
arn_service("bedrock").
arn_service("billing").
arn_service("billingconductor").
arn_service("braket").
arn_service("budgets").
arn_service("bugbust").
arn_service("cases").
arn_service("cassandra").
arn_service("ce").
arn_service("chatbot").
arn_service("chime").
arn_service("cleanrooms").
arn_service("cleanrooms-ml").
arn_service("cloud9").
arn_service("clouddirectory").
arn_service("cloudformation").
arn_service("cloudformation").
arn_service("cloudfront").
arn_service("cloudfront-keyvaluestore").
arn_service("cloudhsm").
arn_service("cloudsearch").
arn_service("cloudshell").
arn_service("cloudtrail").
arn_service("cloudtrail-data").
arn_service("cloudwatch").
arn_service("codeartifact").
arn_service("codebuild").
arn_service("codecatalyst").
arn_service("codecommit").
arn_service("codeconnections").
arn_service("codedeploy").
arn_service("codedeploy-commands-secure").
arn_service("codeguru").
arn_service("codeguru-profiler").
arn_service("codeguru-reviewer").
arn_service("codeguru-security").
arn_service("codepipeline").
arn_service("codestar").
arn_service("codestar-connections").
arn_service("codestar-notifications").
arn_service("codewhisperer").
arn_service("cognito-identity").
arn_service("cognito-idp").
arn_service("cognito-sync").
arn_service("comprehend").
arn_service("comprehendmedical").
arn_service("compute-optimizer").
arn_service("config").
arn_service("connect").
arn_service("connect-campaigns").
arn_service("consoleapp").
arn_service("consolidatedbilling").
arn_service("controlcatalog").
arn_service("controltower").
arn_service("cost-optimization-hub").
arn_service("cur").
arn_service("customer-verification").
arn_service("databrew").
arn_service("dataexchange").
arn_service("datapipeline").
arn_service("datasync").
arn_service("datazone").
arn_service("dax").
arn_service("dbqms").
arn_service("deadline").
arn_service("deepcomposer").
arn_service("deeplens").
arn_service("deepracer").
arn_service("detective").
arn_service("devicefarm").
arn_service("devops-guru").
arn_service("directconnect").
arn_service("discovery").
arn_service("dlm").
arn_service("dms").
arn_service("docdb-elastic").
arn_service("drs").
arn_service("ds").
arn_service("ds-data").
arn_service("dynamodb").
arn_service("ebs").
arn_service("ec2").
arn_service("ec2-instance-connect").
arn_service("ec2messages").
arn_service("ecr").
arn_service("ecr-public").
arn_service("ecs").
arn_service("eks").
arn_service("eks-auth").
arn_service("elasticache").
arn_service("elasticbeanstalk").
arn_service("elasticfilesystem").
arn_service("elastic-inference").
arn_service("elasticloadbalancing").
arn_service("elasticloadbalancing").
arn_service("elasticmapreduce").
arn_service("elastictranscoder").
arn_service("elemental-activations").
arn_service("elemental-appliances-software").
arn_service("elemental-support-cases").
arn_service("elemental-support-content").
arn_service("emr-containers").
arn_service("emr-serverless").
arn_service("entityresolution").
arn_service("es").
arn_service("events").
arn_service("evidently").
arn_service("execute-api").
arn_service("finspace").
arn_service("finspace-api").
arn_service("firehose").
arn_service("fis").
arn_service("fms").
arn_service("forecast").
arn_service("frauddetector").
arn_service("freertos").
arn_service("freetier").
arn_service("fsx").
arn_service("gamelift").
arn_service("geo").
arn_service("glacier").
arn_service("globalaccelerator").
arn_service("glue").
arn_service("grafana").
arn_service("greengrass").
arn_service("greengrass").
arn_service("groundstation").
arn_service("groundtruthlabeling").
arn_service("guardduty").
arn_service("health").
arn_service("healthlake").
arn_service("honeycode").
arn_service("iam").
arn_service("identitystore").
arn_service("identitystore-auth").
arn_service("identity-sync").
arn_service("imagebuilder").
arn_service("importexport").
arn_service("inspector").
arn_service("inspector2").
arn_service("inspector-scan").
arn_service("internetmonitor").
arn_service("invoicing").
arn_service("iot").
arn_service("iot1click").
arn_service("iotanalytics").
arn_service("iotdeviceadvisor").
arn_service("iot-device-tester").
arn_service("iotevents").
arn_service("iotfleethub").
arn_service("iotfleetwise").
arn_service("iotjobsdata").
arn_service("iotsitewise").
arn_service("iottwinmaker").
arn_service("iotwireless").
arn_service("iq").
arn_service("iq-permission").
arn_service("ivs").
arn_service("ivschat").
arn_service("kafka").
arn_service("kafka-cluster").
arn_service("kafkaconnect").
arn_service("kendra").
arn_service("kendra-ranking").
arn_service("kinesis").
arn_service("kinesisanalytics").
arn_service("kinesisanalytics").
arn_service("kinesisvideo").
arn_service("kms").
arn_service("lakeformation").
arn_service("lambda").
arn_service("launchwizard").
arn_service("lex").
arn_service("lex").
arn_service("license-manager").
arn_service("license-manager-linux-subscriptions").
arn_service("license-manager-user-subscriptions").
arn_service("lightsail").
arn_service("logs").
arn_service("lookoutequipment").
arn_service("lookoutmetrics").
arn_service("lookoutvision").
arn_service("m2").
arn_service("machinelearning").
arn_service("macie2").
arn_service("managedblockchain").
arn_service("managedblockchain-query").
arn_service("mapcredits").
arn_service("marketplacecommerceanalytics").
arn_service("mechanicalturk").
arn_service("mediaconnect").
arn_service("mediaconvert").
arn_service("mediaimport").
arn_service("medialive").
arn_service("mediapackage").
arn_service("mediapackagev2").
arn_service("mediapackage-vod").
arn_service("mediastore").
arn_service("mediatailor").
arn_service("medical-imaging").
arn_service("memorydb").
arn_service("mgh").
arn_service("mgn").
arn_service("migrationhub-orchestrator").
arn_service("migrationhub-strategy").
arn_service("mobileanalytics").
arn_service("mobiletargeting").
arn_service("monitron").
arn_service("mq").
arn_service("neptune-db").
arn_service("neptune-graph").
arn_service("network-firewall").
arn_service("networkmanager").
arn_service("networkmanager-chat").
arn_service("networkmonitor").
arn_service("nimble").
arn_service("notifications").
arn_service("notifications-contacts").
arn_service("oam").
arn_service("omics").
arn_service("one").
arn_service("opsworks").
arn_service("opsworks-cm").
arn_service("organizations").
arn_service("osis").
arn_service("outposts").
arn_service("panorama").
arn_service("partnercentral-account-management").
arn_service("payment-cryptography").
arn_service("payments").
arn_service("pca-connector-ad").
arn_service("pca-connector-scep").
arn_service("pcs").
arn_service("personalize").
arn_service("pi").
arn_service("pipes").
arn_service("polly").
arn_service("pricing").
arn_service("private-networks").
arn_service("profile").
arn_service("proton").
arn_service("purchase-orders").
arn_service("q").
arn_service("qapps").
arn_service("qbusiness").
arn_service("qldb").
arn_service("quicksight").
arn_service("ram").
arn_service("rbin").
arn_service("rds").
arn_service("rds-data").
arn_service("rds-db").
arn_service("redshift").
arn_service("redshift-data").
arn_service("redshift-serverless").
arn_service("refactor-spaces").
arn_service("rekognition").
arn_service("repostspace").
arn_service("resiliencehub").
arn_service("resource-explorer").
arn_service("resource-explorer-2").
arn_service("resource-groups").
arn_service("rhelkb").
arn_service("robomaker").
arn_service("rolesanywhere").
arn_service("route53").
arn_service("route53domains").
arn_service("route53profiles").
arn_service("route53-recovery-cluster").
arn_service("route53-recovery-control-config").
arn_service("route53-recovery-readiness").
arn_service("route53resolver").
arn_service("rum").
arn_service("s3").
arn_service("s3express").
arn_service("s3-object-lambda").
arn_service("s3-outposts").
arn_service("sagemaker").
arn_service("sagemaker-geospatial").
arn_service("sagemaker-groundtruth-synthetic").
arn_service("sagemaker-mlflow").
arn_service("savingsplans").
arn_service("scheduler").
arn_service("schemas").
arn_service("scn").
arn_service("sdb").
arn_service("secretsmanager").
arn_service("securityhub").
arn_service("securitylake").
arn_service("serverlessrepo").
arn_service("servicecatalog").
arn_service("servicediscovery").
arn_service("serviceextract").
arn_service("servicequotas").
arn_service("ses").
arn_service("ses").
arn_service("ses").
arn_service("ses").
arn_service("shield").
arn_service("signer").
arn_service("signin").
arn_service("simspaceweaver").
arn_service("sms").
arn_service("sms-voice").
arn_service("sms-voice").
arn_service("snowball").
arn_service("snow-device-management").
arn_service("sns").
arn_service("sqlworkbench").
arn_service("sqs").
arn_service("ssm").
arn_service("ssm-contacts").
arn_service("ssm-guiconnect").
arn_service("ssm-incidents").
arn_service("ssmmessages").
arn_service("ssm-quicksetup").
arn_service("ssm-sap").
arn_service("sso").
arn_service("sso-directory").
arn_service("sso-oauth").
arn_service("states").
arn_service("storagegateway").
arn_service("sts").
arn_service("support").
arn_service("supportapp").
arn_service("supportplans").
arn_service("supportrecommendations").
arn_service("sustainability").
arn_service("swf").
arn_service("synthetics").
arn_service("tag").
arn_service("tax").
arn_service("textract").
arn_service("thinclient").
arn_service("timestream").
arn_service("timestream-influxdb").
arn_service("tiros").
arn_service("tnb").
arn_service("transcribe").
arn_service("transfer").
arn_service("translate").
arn_service("trustedadvisor").
arn_service("ts").
arn_service("user-subscriptions").
arn_service("vendor-insights").
arn_service("verified-access").
arn_service("verifiedpermissions").
arn_service("voiceid").
arn_service("vpc-lattice").
arn_service("vpc-lattice-svcs").
arn_service("waf").
arn_service("waf-regional").
arn_service("wafv2").
arn_service("wam").
arn_service("wellarchitected").
arn_service("wickr").
arn_service("wisdom").
arn_service("workdocs").
arn_service("worklink").
arn_service("workmail").
arn_service("workmailmessageflow").
arn_service("workspaces").
arn_service("workspaces-web").
arn_service("xray").
