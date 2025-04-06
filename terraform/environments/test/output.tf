output "environment_manager_role_arn" {
  description = "The role to be assumed by the ecs-cli to manage environments."
  value = aws_iam_role.environment_manager_role.arn
}

output "cfn_execution_role_arn" {
  description = "The role to be assumed by the Cloudformation service when it deploys application infrastructure."
  value = aws_iam_role.cloudformation_execution_role.arn
}

