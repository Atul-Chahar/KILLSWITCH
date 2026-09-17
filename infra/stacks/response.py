"""The response workflow, and the policy store that decides what needs a person.

The approval state uses waitForTaskToken, so the execution genuinely stops until a human
answers. There is no timeout-and-proceed path: if nobody approves, nothing is destroyed.
"""

from __future__ import annotations

from pathlib import Path

from aws_cdk import CfnOutput, Duration, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from aws_cdk import aws_verifiedpermissions as avp
from constructs import Construct

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CEDAR_POLICY_PATH = REPO_ROOT / "authorize/policies/containment.cedar"
LAMBDA_TIMEOUT = Duration.seconds(60)
# A human has an hour to answer. On expiry the execution fails; it never proceeds alone.
APPROVAL_TIMEOUT = Duration.hours(1)

CEDAR_ACTIONS = (
    "read_evidence",
    "tag_resource",
    "deactivate_key",
    "terminate_instance",
    "open_pr",
)

CEDAR_SCHEMA = {
    "Killswitch": {
        "entityTypes": {
            "Automation": {"shape": {"type": "Record", "attributes": {}}},
            "Incident": {"shape": {"type": "Record", "attributes": {}}},
        },
        "actions": {
            action: {
                "appliesTo": {
                    "principalTypes": ["Automation"],
                    "resourceTypes": ["Incident"],
                    "context": {
                        "type": "Record",
                        "attributes": {"human_approved": {"type": "Boolean"}},
                    },
                }
            }
            for action in CEDAR_ACTIONS
        },
    }
}


class ResponseStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        lambda_code_path: str,
        incidents_table: dynamodb.ITable,
        demo_regions: list[str],
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        policy_store = avp.CfnPolicyStore(
            self,
            "PolicyStore",
            validation_settings=avp.CfnPolicyStore.ValidationSettingsProperty(mode="STRICT"),
            schema=avp.CfnPolicyStore.SchemaDefinitionProperty(
                cedar_json=self.to_json_string(CEDAR_SCHEMA)
            ),
        )
        avp.CfnPolicy(
            self,
            "ContainmentPolicy",
            policy_store_id=policy_store.attr_policy_store_id,
            definition=avp.CfnPolicy.PolicyDefinitionProperty(
                static=avp.CfnPolicy.StaticPolicyDefinitionProperty(
                    description="Destructive actions are forbidden without a human approval",
                    statement=CEDAR_POLICY_PATH.read_text(),
                )
            ),
        )

        code = lambda_.Code.from_asset(lambda_code_path)
        environment = {
            "INCIDENT_TABLE_NAME": incidents_table.table_name,
            "AWS_SECONDARY_REGION": demo_regions[-1],
            "VERIFIED_PERMISSIONS_POLICY_STORE_ID": policy_store.attr_policy_store_id,
        }

        def task_function(name: str, handler: str) -> lambda_.Function:
            function = lambda_.Function(
                self,
                name,
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler=handler,
                code=code,
                timeout=LAMBDA_TIMEOUT,
                environment=environment,
            )
            incidents_table.grant_read_write_data(function)
            return function

        investigate = task_function("InvestigateFunction", "workflow.tasks.investigate_task")
        verify = task_function("VerifyFunction", "workflow.tasks.verify_task")
        authorize = task_function("AuthorizeFunction", "workflow.tasks.authorize_task")
        request_approval = task_function(
            "RequestApprovalFunction", "workflow.tasks.request_approval_task"
        )
        contain = task_function("ContainFunction", "workflow.tasks.contain_task")
        confirm = task_function("ConfirmFunction", "workflow.tasks.confirm_task")

        # Reading evidence is not destructive, so investigation gets it unconditionally.
        investigate.add_to_role_policy(
            iam.PolicyStatement(
                sid="ReadTheEvidence",
                actions=[
                    "cloudtrail:LookupEvents",
                    "iam:GetAccessKeyLastUsed",
                    "iam:ListAccessKeys",
                ],
                resources=["*"],
            )
        )
        authorize.add_to_role_policy(
            iam.PolicyStatement(
                sid="AskThePolicyStore",
                actions=["verifiedpermissions:IsAuthorized"],
                resources=[policy_store.attr_arn],
            )
        )
        # The only principal in the system that may destroy anything. Its code refuses to
        # act without an approval token, and this is the matching grant.
        contain.add_to_role_policy(
            iam.PolicyStatement(
                sid="ContainWhatTheHumanApproved",
                actions=["ec2:TerminateInstances", "iam:UpdateAccessKey"],
                resources=["*"],
            )
        )
        confirm.add_to_role_policy(
            iam.PolicyStatement(
                sid="ConfirmTheEndState",
                actions=["ec2:DescribeInstances", "iam:ListAccessKeys"],
                resources=["*"],
            )
        )

        outcome = (
            sfn.Choice(self, "WasItConfirmed")
            .when(sfn.Condition.boolean_equals("$.confirmed", True), sfn.Succeed(self, "Contained"))
            # An unconfirmed end state is a failure. It is never rounded up to success.
            .otherwise(
                sfn.Fail(
                    self,
                    "ContainmentUnconfirmed",
                    error="ContainmentUnconfirmed",
                    cause="AWS did not confirm the expected end state for every action",
                )
            )
        )

        definition = (
            tasks.LambdaInvoke(
                self, "Investigate", lambda_function=investigate, payload_response_only=True
            )
            .next(
                tasks.LambdaInvoke(
                    self, "Verify", lambda_function=verify, payload_response_only=True
                )
            )
            .next(
                tasks.LambdaInvoke(
                    self, "Authorize", lambda_function=authorize, payload_response_only=True
                )
            )
            .next(
                tasks.LambdaInvoke(
                    self,
                    "WaitForHumanApproval",
                    lambda_function=request_approval,
                    integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
                    task_timeout=sfn.Timeout.duration(APPROVAL_TIMEOUT),
                    payload=sfn.TaskInput.from_object(
                        {
                            "incident_id": sfn.JsonPath.string_at("$.incident_id"),
                            "blast_radius": sfn.JsonPath.object_at("$.blast_radius"),
                            "verification": sfn.JsonPath.object_at("$.verification"),
                            "tiers": sfn.JsonPath.object_at("$.tiers"),
                            "task_token": sfn.JsonPath.task_token,
                        }
                    ),
                    result_path="$.approval",
                )
            )
            .next(
                tasks.LambdaInvoke(
                    self, "Contain", lambda_function=contain, payload_response_only=True
                )
            )
            .next(
                tasks.LambdaInvoke(
                    self, "ConfirmEndState", lambda_function=confirm, payload_response_only=True
                )
            )
            .next(outcome)
        )

        self.state_machine = sfn.StateMachine(
            self,
            "ResponseWorkflow",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            state_machine_type=sfn.StateMachineType.STANDARD,
            timeout=Duration.hours(2),
        )

        CfnOutput(self, "StateMachineArn", value=self.state_machine.state_machine_arn)
        CfnOutput(self, "PolicyStoreId", value=policy_store.attr_policy_store_id)
