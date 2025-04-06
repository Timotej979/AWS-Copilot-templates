resource "aws_iam_role" "cloudformation_execution_role" {
  name = "${local.stack_name}-CFNExecutionRole"
  assume_role_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "cloudformation.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  }
  path = "/"
  force_detach_policies = [
    {
      PolicyName = "executeCfn"
      PolicyDocument = {
        Version = "2012-10-17"
        Statement = [
          {
            Effect = "Allow"
            NotAction = [
              "organizations:*",
              "account:*"
            ]
            Resource = "*"
          },
          {
            Effect = "Allow"
            Action = [
              "organizations:DescribeOrganization",
              "account:ListRegions"
            ]
            Resource = "*"
          }
        ]
      }
    }
  ]
}

resource "aws_iam_role" "environment_manager_role" {
  name = "${local.stack_name}-EnvManagerRole"
  assume_role_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "${var.tools_account_principal_arn}"
        }
        Action = "sts:AssumeRole"
      }
    ]
  }
  path = "/"
  force_detach_policies = [
    {
      PolicyName = "root"
      PolicyDocument = {
        Version = "2012-10-17"
        Statement = [
          {
            Sid = "CloudwatchLogs"
            Effect = "Allow"
            Action = [
              "logs:GetLogRecord",
              "logs:GetQueryResults",
              "logs:StartQuery",
              "logs:GetLogEvents",
              "logs:DescribeLogStreams",
              "logs:StopQuery",
              "logs:TestMetricFilter",
              "logs:FilterLogEvents",
              "logs:GetLogGroupFields",
              "logs:GetLogDelivery"
            ]
            Resource = "*"
          },
          {
            Sid = "Cloudwatch"
            Effect = "Allow"
            Action = [
              "cloudwatch:DescribeAlarms"
            ]
            Resource = "*"
          },
          {
            Sid = "ECS"
            Effect = "Allow"
            Action = [
              "ecs:ListAttributes",
              "ecs:ListTasks",
              "ecs:DescribeServices",
              "ecs:DescribeTaskSets",
              "ecs:ListContainerInstances",
              "ecs:DescribeContainerInstances",
              "ecs:DescribeTasks",
              "ecs:DescribeClusters",
              "ecs:UpdateService",
              "ecs:PutAttributes",
              "ecs:StartTelemetrySession",
              "ecs:StartTask",
              "ecs:StopTask",
              "ecs:ListServices",
              "ecs:ListTaskDefinitionFamilies",
              "ecs:DescribeTaskDefinition",
              "ecs:ListTaskDefinitions",
              "ecs:ListClusters",
              "ecs:RunTask",
              "ecs:ListServicesByNamespace"
            ]
            Resource = "*"
          },
          {
            Sid = "ExecuteCommand"
            Effect = "Allow"
            Action = [
              "ecs:ExecuteCommand",
              "ssm:StartSession"
            ]
            Resource = "*"
            Condition = {
              StringEquals = {
                aws:ResourceTag/copilot-application = "${var.app_name}"
                aws:ResourceTag/copilot-environment = "${var.environment_name}"
              }
            }
          },
          {
            Sid = "StartStateMachine"
            Effect = "Allow"
            Action = [
              "states:StartExecution",
              "states:DescribeStateMachine"
            ]
            Resource = [
              "arn:${data.aws_partition.current.partition}:states:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stateMachine:${var.app_name}-${var.environment_name}-*"
            ]
          },
          {
            Sid = "CloudFormation"
            Effect = "Allow"
            Action = [
              "cloudformation:CancelUpdateStack",
              "cloudformation:CreateChangeSet",
              "cloudformation:CreateStack",
              "cloudformation:DeleteChangeSet",
              "cloudformation:DeleteStack",
              "cloudformation:Describe*",
              "cloudformation:DetectStackDrift",
              "cloudformation:DetectStackResourceDrift",
              "cloudformation:ExecuteChangeSet",
              "cloudformation:GetTemplate",
              "cloudformation:GetTemplateSummary",
              "cloudformation:UpdateStack",
              "cloudformation:UpdateTerminationProtection"
            ]
            Resource = "*"
          },
          {
            Sid = "GetAndPassCopilotRoles"
            Effect = "Allow"
            Action = [
              "iam:GetRole",
              "iam:PassRole"
            ]
            Resource = "*"
            Condition = {
              StringEquals = {
                iam:ResourceTag/copilot-application = "${var.app_name}"
                iam:ResourceTag/copilot-environment = "${var.environment_name}"
              }
            }
          },
          {
            Sid = "ECR"
            Effect = "Allow"
            Action = [
              "ecr:BatchGetImage",
              "ecr:BatchCheckLayerAvailability",
              "ecr:CompleteLayerUpload",
              "ecr:DescribeImages",
              "ecr:DescribeRepositories",
              "ecr:GetDownloadUrlForLayer",
              "ecr:InitiateLayerUpload",
              "ecr:ListImages",
              "ecr:ListTagsForResource",
              "ecr:PutImage",
              "ecr:UploadLayerPart",
              "ecr:GetAuthorizationToken"
            ]
            Resource = "*"
          },
          {
            Sid = "ResourceGroups"
            Effect = "Allow"
            Action = [
              "resource-groups:GetGroup",
              "resource-groups:GetGroupQuery",
              "resource-groups:GetTags",
              "resource-groups:ListGroupResources",
              "resource-groups:ListGroups",
              "resource-groups:SearchResources"
            ]
            Resource = "*"
          },
          {
            Sid = "SSM"
            Effect = "Allow"
            Action = [
              "ssm:DeleteParameter",
              "ssm:DeleteParameters",
              "ssm:GetParameter",
              "ssm:GetParameters",
              "ssm:GetParametersByPath"
            ]
            Resource = "*"
          },
          {
            Sid = "SSMSecret"
            Effect = "Allow"
            Action = [
              "ssm:PutParameter",
              "ssm:AddTagsToResource"
            ]
            Resource = [
              "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/copilot/${var.app_name}/${var.environment_name}/secrets/*"
            ]
          },
          {
            Sid = "SSMSession"
            Effect = "Allow"
            Action = [
              "ssm:StartSession"
            ]
            Resource = [
              "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.name}::document/AWS-StartPortForwardingSessionToRemoteHost"
            ]
          },
          {
            Sid = "ELBv2"
            Effect = "Allow"
            Action = [
              "elasticloadbalancing:DescribeLoadBalancerAttributes",
              "elasticloadbalancing:DescribeSSLPolicies",
              "elasticloadbalancing:DescribeLoadBalancers",
              "elasticloadbalancing:DescribeTargetGroupAttributes",
              "elasticloadbalancing:DescribeListeners",
              "elasticloadbalancing:DescribeTags",
              "elasticloadbalancing:DescribeTargetHealth",
              "elasticloadbalancing:DescribeTargetGroups",
              "elasticloadbalancing:DescribeRules"
            ]
            Resource = "*"
          },
          {
            Sid = "BuiltArtifactAccess"
            Effect = "Allow"
            Action = [
              "s3:ListBucketByTags",
              "s3:GetLifecycleConfiguration",
              "s3:GetBucketTagging",
              "s3:GetInventoryConfiguration",
              "s3:GetObjectVersionTagging",
              "s3:ListBucketVersions",
              "s3:GetBucketLogging",
              "s3:ListBucket",
              "s3:GetAccelerateConfiguration",
              "s3:GetBucketPolicy",
              "s3:GetObjectVersionTorrent",
              "s3:GetObjectAcl",
              "s3:GetEncryptionConfiguration",
              "s3:GetBucketRequestPayment",
              "s3:GetObjectVersionAcl",
              "s3:GetObjectTagging",
              "s3:GetMetricsConfiguration",
              "s3:HeadBucket",
              "s3:GetBucketPublicAccessBlock",
              "s3:GetBucketPolicyStatus",
              "s3:ListBucketMultipartUploads",
              "s3:GetBucketWebsite",
              "s3:ListJobs",
              "s3:GetBucketVersioning",
              "s3:GetBucketAcl",
              "s3:GetBucketNotification",
              "s3:GetReplicationConfiguration",
              "s3:ListMultipartUploadParts",
              "s3:GetObject",
              "s3:GetObjectTorrent",
              "s3:GetAccountPublicAccessBlock",
              "s3:ListAllMyBuckets",
              "s3:DescribeJob",
              "s3:GetBucketCORS",
              "s3:GetAnalyticsConfiguration",
              "s3:GetObjectVersionForReplication",
              "s3:GetBucketLocation",
              "s3:GetObjectVersion",
              "kms:Decrypt"
            ]
            Resource = "*"
          },
          {
            Sid = "PutObjectsToArtifactBucket"
            Effect = "Allow"
            Action = [
              "s3:PutObject",
              "s3:PutObjectAcl"
            ]
            Resource = [
              "arn:aws:s3:::stackset-template-infrast-pipelinebuiltartifactbuc-o7flafrof1md",
              "arn:aws:s3:::stackset-template-infrast-pipelinebuiltartifactbuc-o7flafrof1md/*"
            ]
          },
          {
            Sid = "EncryptObjectsInArtifactBucket"
            Effect = "Allow"
            Action = [
              "kms:GenerateDataKey"
            ]
            Resource = "arn:aws:kms:eu-central-1:418295677964:key/093df57b-f0bb-4536-98b3-d287d0760bff"
          },
          {
            Sid = "EC2"
            Effect = "Allow"
            Action = [
              "ec2:DescribeSubnets",
              "ec2:DescribeSecurityGroups",
              "ec2:DescribeNetworkInterfaces",
              "ec2:DescribeRouteTables"
            ]
            Resource = "*"
          },
          {
            Sid = "AppRunner"
            Effect = "Allow"
            Action = [
              "apprunner:DescribeService",
              "apprunner:ListOperations",
              "apprunner:ListServices",
              "apprunner:PauseService",
              "apprunner:ResumeService",
              "apprunner:StartDeployment",
              "apprunner:DescribeObservabilityConfiguration",
              "apprunner:DescribeVpcIngressConnection"
            ]
            Resource = "*"
          },
          {
            Sid = "Tags"
            Effect = "Allow"
            Action = [
              "tag:GetResources"
            ]
            Resource = "*"
          },
          {
            Sid = "ApplicationAutoscaling"
            Effect = "Allow"
            Action = [
              "application-autoscaling:DescribeScalingPolicies"
            ]
            Resource = "*"
          },
          {
            Sid = "DeleteRoles"
            Effect = "Allow"
            Action = [
              "iam:DeleteRole",
              "iam:ListRolePolicies",
              "iam:DeleteRolePolicy"
            ]
            Resource = [
              aws_iam_role.cloudformation_execution_role.arn,
              "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${local.stack_name}-EnvManagerRole"
            ]
          },
          {
            Sid = "DeleteEnvStack"
            Effect = "Allow"
            Action = [
              "cloudformation:DescribeStacks",
              "cloudformation:DeleteStack"
            ]
            Resource = [
              "arn:${data.aws_partition.current.partition}:cloudformation:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:stack/${local.stack_name}/*"
            ]
          },
          {
            Sid = "ListStacks"
            Effect = "Allow"
            Action = [
              "cloudformation:ListStacks"
            ]
            Resource = "*"
          },
          {
            Sid = "RDS"
            Effect = "Allow"
            Action = [
              "rds:DescribeDBInstances",
              "rds:DescribeDBClusters"
            ]
            Resource = "*"
          }
        ]
      }
    }
  ]
}

