"""Detection: the incident table, the webhook, and the quarantine rule.

One caveat worth knowing before demo day. IAM is a global service and its CloudTrail
events are only delivered to EventBridge in us-east-1, so a real AWS quarantine will
only reach this rule if the stack is deployed there. The demo repository is private,
which means AWS's own leak scanning would never fire against it anyway, so the second
trigger is exercised with a synthetic event (scripts/simulate_quarantine.py). This is
called out in the README's limitations rather than papered over.
"""

from __future__ import annotations

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_events as events
from aws_cdk import aws_events_targets as targets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from constructs import Construct

INCIDENT_PARTITION_KEY = "incident_id"
LAMBDA_TIMEOUT = Duration.seconds(30)
QUARANTINE_EVENT_NAMES = ["AttachUserPolicy", "PutUserPolicy"]


class DetectionStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        lambda_code_path: str,
        github_app_token: str = "",
        github_webhook_secret: str = "",
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.incidents = dynamodb.Table(
            self,
            "Incidents",
            partition_key=dynamodb.Attribute(
                name=INCIDENT_PARTITION_KEY, type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=True
            ),
            # The demo account is disposable; a retained table would outlive it.
            removal_policy=RemovalPolicy.DESTROY,
        )

        code = lambda_.Code.from_asset(lambda_code_path)
        # An unset webhook secret makes verify_signature reject every delivery, so a
        # half-configured deployment refuses webhooks rather than trusting them.
        shared_environment = {
            "INCIDENT_TABLE_NAME": self.incidents.table_name,
            "GITHUB_WEBHOOK_SECRET": github_webhook_secret,
            "GITHUB_APP_TOKEN": github_app_token,
        }

        self.detect_function = lambda_.Function(
            self,
            "DetectFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="detect.handler.lambda_handler",
            code=code,
            timeout=LAMBDA_TIMEOUT,
            environment=shared_environment,
        )
        self.incidents.grant_write_data(self.detect_function)

        self.quarantine_function = lambda_.Function(
            self,
            "QuarantineFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="detect.quarantine.lambda_handler",
            code=code,
            timeout=LAMBDA_TIMEOUT,
            environment=shared_environment,
        )
        self.incidents.grant_write_data(self.quarantine_function)
        self.quarantine_function.add_to_role_policy(
            iam.PolicyStatement(
                sid="ResolveTheOwnerOfALeakedKey",
                actions=["iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"],
                resources=["*"],
            )
        )

        api = apigateway.LambdaRestApi(
            self,
            "WebhookApi",
            handler=self.detect_function,
            proxy=False,
            deploy_options=apigateway.StageOptions(stage_name="prod"),
        )
        api.root.add_resource("webhook").add_method("POST")

        events.Rule(
            self,
            "QuarantineRule",
            description="AWS attaching its compromised-key quarantine policy to a user",
            event_pattern=events.EventPattern(
                source=["aws.iam"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={"eventSource": ["iam.amazonaws.com"], "eventName": QUARANTINE_EVENT_NAMES},
            ),
            targets=[targets.LambdaFunction(self.quarantine_function)],
        )

        CfnOutput(self, "IncidentTableName", value=self.incidents.table_name)
        CfnOutput(self, "WebhookUrl", value=f"{api.url}webhook")
