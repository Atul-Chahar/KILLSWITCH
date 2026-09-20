"""Cognito and the API the operator console talks to.

Every route sits behind a Cognito authorizer. An unauthenticated caller cannot read an
incident, and more importantly cannot approve one: the approval endpoint is the last gate
in the whole system and it is not open to the internet.

The console itself is static and is deployed to Amplify Hosting from console/dist. That
step is a CLI command in docs/RUNBOOK.md rather than a construct here, so the project does
not take on the alpha Amplify CDK module for one static site.
"""

from __future__ import annotations

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_cognito as cognito
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_stepfunctions as sfn
from constructs import Construct


class ConsoleApiStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        lambda_code_path: str,
        incidents_table: dynamodb.ITable,
        state_machine: sfn.IStateMachine,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        user_pool = cognito.UserPool(
            self,
            "Operators",
            self_sign_up_enabled=False,
            sign_in_aliases=cognito.SignInAliases(email=True),
            password_policy=cognito.PasswordPolicy(min_length=12, require_symbols=True),
            removal_policy=RemovalPolicy.DESTROY,
        )
        client = user_pool.add_client(
            "ConsoleClient",
            # SRP is the right flow for a browser login. admin_user_password is enabled
            # alongside it so an operator can obtain an id token from the CLI
            # (scripts/run_console.sh) without the console shipping a login screen.
            # Both go through the same user pool, so the authorizer is unchanged.
            auth_flows=cognito.AuthFlow(user_srp=True, admin_user_password=True),
            prevent_user_existence_errors=True,
        )

        api_function = lambda_.Function(
            self,
            "ApprovalApiFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="workflow.approval_api.lambda_handler",
            code=lambda_.Code.from_asset(lambda_code_path),
            timeout=Duration.seconds(30),
            environment={"INCIDENT_TABLE_NAME": incidents_table.table_name},
        )
        incidents_table.grant_read_write_data(api_function)
        # Releasing the task token is the only Step Functions right it needs. It cannot
        # start an execution, and it cannot fail one.
        api_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="AnswerTheWaitingApproval",
                actions=["states:SendTaskSuccess"],
                resources=[state_machine.state_machine_arn],
            )
        )

        api = apigateway.RestApi(
            self,
            "ConsoleApi",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=apigateway.Cors.ALL_ORIGINS,
                allow_methods=["GET", "POST", "OPTIONS"],
            ),
            deploy_options=apigateway.StageOptions(stage_name="prod"),
        )
        authorizer = apigateway.CognitoUserPoolsAuthorizer(
            self, "ConsoleAuthorizer", cognito_user_pools=[user_pool]
        )
        integration = apigateway.LambdaIntegration(api_function)

        incident = api.root.add_resource("incidents").add_resource("{incident_id}")
        incident.add_method(
            "GET",
            integration,
            authorizer=authorizer,
            authorization_type=apigateway.AuthorizationType.COGNITO,
        )
        incident.add_resource("decisions").add_method(
            "POST",
            integration,
            authorizer=authorizer,
            authorization_type=apigateway.AuthorizationType.COGNITO,
        )

        CfnOutput(self, "ConsoleApiUrl", value=api.url)
        CfnOutput(self, "UserPoolId", value=user_pool.user_pool_id)
        CfnOutput(self, "UserPoolClientId", value=client.user_pool_client_id)
