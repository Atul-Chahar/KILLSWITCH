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
from aws_cdk import aws_lambda_event_sources as lambda_events
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from aws_cdk import aws_verifiedpermissions as avp
from constructs import Construct

from narrate.narrator import NarratorMode
from shared.models import IncidentStatus

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CEDAR_POLICY_PATH = REPO_ROOT / "authorize/policies/containment.cedar"
LAMBDA_TIMEOUT = Duration.seconds(60)
# The narrator waits on someone else's inference endpoint. Measured at ~22s against
# NVIDIA NIM on a quiet endpoint, and a queued one is slower — 60s would truncate the
# one step whose failure means no plan reaches the human at all.
NARRATE_TIMEOUT = Duration.seconds(180)
# Lambda's default 128 MB is not enough to import strands plus litellm — the first
# deployed run maxed it out and timed out at 180s after taking 22s on a laptop.
# Memory also buys CPU: 128 MB is a fraction of a vCPU, which is the real cause.
DEFAULT_MEMORY_MB = 512
NARRATE_MEMORY_MB = 2048
# A human has an hour to answer. On expiry the execution fails; it never proceeds alone.
APPROVAL_TIMEOUT = Duration.hours(1)
# How long to wait before asking CloudTrail again. workflow.tasks caps the attempts.
EVIDENCE_POLL_INTERVAL = Duration.seconds(60)

# Nothing here configures retries. CDK gives every LambdaInvoke a default retry policy
# covering Lambda.ServiceException and its siblings -- failures to *run* our code -- and
# never States.TaskFailed. That is exactly the policy we want: a NarrationError or a
# refused approval is an answer, not a blip, and asking three times would not change it.
# tests/test_response_stack.py asserts that property rather than trusting the default.

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
        bedrock_model_id: str = "",
        narrator_mode: str = "",
        nvidia_api_key: str = "",
        nim_model_id: str = "",
        use_verified_permissions: bool = True,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Refuse at synth rather than deploying a workflow that is certain to fail at the
        # Narrate step. Rehearsal and NIM narrators do not need a Bedrock model id.
        model_free_modes = {NarratorMode.REHEARSAL.value, NarratorMode.NIM.value}
        if narrator_mode not in model_free_modes and not bedrock_model_id:
            raise ValueError(
                "BEDROCK_MODEL_ID must be set to deploy the response workflow, or set "
                f"NARRATOR_MODE to one of: {', '.join(sorted(model_free_modes))}"
            )

        # Cut-list item 1 in docs/PLAN.md. Verified Permissions is not enabled on every
        # account or region — a fresh account gets a 403 "needs a subscription" on create.
        # Without it the workflow still runs: authorize/decide.py falls back to a table
        # where anything destructive needs a human, which is the strict direction. The
        # tiering stays visible in the console either way.
        policy_store = None
        policy_store_id = ""
        if use_verified_permissions:
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
            "VERIFIED_PERMISSIONS_POLICY_STORE_ID": policy_store_id,
            # Empty is a deploy-time mistake, not a default. narrate/agent.py raises on it
            # rather than quietly asking whichever model the SDK happens to prefer.
            "BEDROCK_MODEL_ID": bedrock_model_id,
            "NARRATOR_MODE": narrator_mode,
            "NIM_MODEL_ID": nim_model_id,
        }

        def task_function(name: str, handler: str) -> lambda_.Function:
            function = lambda_.Function(
                self,
                name,
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler=handler,
                code=code,
                timeout=LAMBDA_TIMEOUT,
                memory_size=DEFAULT_MEMORY_MB,
                environment=environment,
            )
            incidents_table.grant_read_write_data(function)
            return function

        investigate = task_function("InvestigateFunction", "workflow.tasks.investigate_task")
        narrate = task_function("NarrateFunction", "workflow.tasks.narrate_task")
        narrate.node.default_child.add_property_override(  # type: ignore[union-attr]
            "Timeout", NARRATE_TIMEOUT.to_seconds()
        )
        narrate.node.default_child.add_property_override(  # type: ignore[union-attr]
            "MemorySize", NARRATE_MEMORY_MB
        )
        # The NVIDIA key goes on the narrator alone, not into the shared environment.
        # Anyone with lambda:GetFunctionConfiguration can read a function's variables,
        # and the containment function has no business carrying a credential that can
        # spend money on someone else's API.
        if nvidia_api_key:
            narrate.add_environment("NVIDIA_API_KEY", nvidia_api_key)
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
        # The narrator's entire power: ask one model one question. Not InvokeModelWith-
        # ResponseStream, because narrate/agent.py turns streaming off precisely so this
        # grant can stay a single action.
        narrate.add_to_role_policy(
            iam.PolicyStatement(
                sid="AskTheModelToPropose",
                actions=["bedrock:InvokeModel"],
                resources=["*"],
            )
        )
        if policy_store is not None:
            authorize.add_to_role_policy(
                iam.PolicyStatement(
                    sid="AskThePolicyStore",
                    actions=["verifiedpermissions:IsAuthorized"],
                    resources=[policy_store.attr_arn],
                )
            )
        # The only principal in the system that may destroy anything. Its code refuses to
        # act without an approval token, and this is the matching grant.
        #
        # Two statements rather than one, because the two actions can be narrowed in
        # different ways and a single wildcard statement narrowed neither. EC2 is regional
        # so it is pinned to the regions the demo runs in; IAM is global but access-key
        # calls are authorised against the owning user, so root is out of reach. Neither
        # is as tight as a tag condition would be -- attacker-created instances carry no
        # tag of ours, so there is nothing of ours to match on.
        contain.add_to_role_policy(
            iam.PolicyStatement(
                sid="TerminateOnlyInTheRegionsWeSearch",
                actions=["ec2:TerminateInstances"],
                resources=["*"],
                conditions={"StringEquals": {"aws:RequestedRegion": demo_regions}},
            )
        )
        # Reading which user owns a key is not destructive, and containment needs it: an
        # access key the attacker minted belongs to whichever user they created it under,
        # not to the user this incident is about.
        contain.add_to_role_policy(
            iam.PolicyStatement(
                sid="ResolveTheOwnerBeforeActing",
                actions=["iam:GetAccessKeyLastUsed"],
                resources=["*"],
            )
        )
        contain.add_to_role_policy(
            iam.PolicyStatement(
                sid="ContainTheLeakedIdentity",
                actions=["iam:UpdateAccessKey", "iam:PutUserPolicy", "iam:ListAccessKeys"],
                resources=[f"arn:aws:iam::{self.account}:user/*"],
            )
        )
        confirm.add_to_role_policy(
            iam.PolicyStatement(
                sid="ConfirmTheEndState",
                # GetUserPolicy is how Confirm checks the session-revocation policy is
                # really attached. Without it "the key is Inactive" would be the whole of
                # our containment claim, and that claim leaves live sessions untouched.
                actions=["ec2:DescribeInstances", "iam:ListAccessKeys", "iam:GetUserPolicy"],
                resources=["*"],
            )
        )

        def invoke(state_id: str, function: lambda_.Function) -> tasks.LambdaInvoke:
            return tasks.LambdaInvoke(
                self, state_id, lambda_function=function, payload_response_only=True
            )

        outcome = (
            sfn.Choice(self, "HowDidItEnd")
            .when(
                sfn.Condition.string_equals("$.status", IncidentStatus.CONTAINED.value),
                sfn.Succeed(self, "Contained"),
            )
            # The operator denied every action. Nothing was destroyed and nothing broke,
            # so this ends successfully and says which of the two happened.
            .when(
                sfn.Condition.string_equals("$.status", IncidentStatus.DECLINED.value),
                sfn.Succeed(self, "DeclinedByOperator"),
            )
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

        # Deliberately not retried: this task mints the approval token, so re-invoking it
        # would issue a second one and orphan whatever the operator was already looking at.
        wait_for_human = tasks.LambdaInvoke(
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
                    # The console reads DynamoDB, not the execution state, so the
                    # narrator's prose and its author travel with the token.
                    "summary": sfn.JsonPath.string_at("$.summary"),
                    "narrator": sfn.JsonPath.string_at("$.narrator"),
                    "task_token": sfn.JsonPath.task_token,
                }
            ),
            result_path="$.approval",
        )

        respond = (
            invoke("Narrate", narrate)
            .next(invoke("Verify", verify))
            .next(invoke("Authorize", authorize))
            .next(wait_for_human)
            .next(invoke("Contain", contain))
            .next(invoke("ConfirmEndState", confirm))
            .next(outcome)
        )

        # Investigate is a poll, not a single read. CloudTrail delivers minutes after the
        # API call and KILLSWITCH is looking seconds after the push, so a first lookup
        # that finds nothing is the expected case rather than a clean incident.
        look_for_evidence = invoke("Investigate", investigate)
        wait_for_evidence = sfn.Wait(
            self,
            "WaitForEvidence",
            time=sfn.WaitTime.duration(EVIDENCE_POLL_INTERVAL),
        )
        wait_for_evidence.next(look_for_evidence)

        definition = look_for_evidence.next(
            sfn.Choice(self, "HasTheEvidenceLanded")
            .when(sfn.Condition.boolean_equals("$.evidence_settled", True), respond)
            .otherwise(wait_for_evidence)
        )

        self.state_machine = sfn.StateMachine(
            self,
            "ResponseWorkflow",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            state_machine_type=sfn.StateMachineType.STANDARD,
            timeout=Duration.hours(2),
        )

        # Nothing started this workflow before. The detection Lambdas write an incident
        # and stop; this is the wire between that write and the response.
        start_workflow = lambda_.Function(
            self,
            "StartWorkflowFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="workflow.start.lambda_handler",
            code=code,
            timeout=LAMBDA_TIMEOUT,
            memory_size=DEFAULT_MEMORY_MB,
            environment={"STATE_MACHINE_ARN": self.state_machine.state_machine_arn},
        )
        self.state_machine.grant_start_execution(start_workflow)
        start_workflow.add_event_source(
            lambda_events.DynamoEventSource(
                incidents_table,
                starting_position=lambda_.StartingPosition.LATEST,
                retry_attempts=3,
                bisect_batch_on_error=True,
            )
        )

        CfnOutput(self, "StateMachineArn", value=self.state_machine.state_machine_arn)
        if policy_store is not None:
            CfnOutput(self, "PolicyStoreId", value=policy_store.attr_policy_store_id)
