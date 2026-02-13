"""
Tests for watchdog.parser — command parsing and classification.

Covers:
  - AWS command parsing (service, action, action_type, resource_id, flags)
  - GCP command parsing (gcloud multi-token services, actions, resource IDs)
  - Non-cloud commands → None
  - Compound commands (&&, ;, |)
  - Shell variable detection and warning
  - Opaque wrappers (bash, eval, source)
  - Prefix stripping (sudo, env vars)
  - Edge cases (empty input, malformed quotes, etc.)
"""

import sys
import os
import json
import pytest

# Ensure project root is importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from watchdog.parser import parse_command, parse_compound_command, ParsedCommand


# =========================================================================
# Fixtures — load sample_commands.json for parametrized tests
# =========================================================================

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_sample_commands():
    path = os.path.join(FIXTURES_DIR, "sample_commands.json")
    with open(path) as f:
        return json.load(f)


# =========================================================================
# AWS — basic service/action parsing
# =========================================================================

class TestAWSParsing:

    def test_s3_ls_is_read(self):
        result = parse_command("aws s3 ls")
        assert result is not None
        assert result.provider == "aws"
        assert result.service == "s3"
        assert result.action == "ls"
        assert result.action_type == "READ"

    def test_rds_delete_db_instance(self):
        cmd = "aws rds delete-db-instance --db-instance-identifier prod-main"
        result = parse_command(cmd)
        assert result is not None
        assert result.provider == "aws"
        assert result.service == "rds"
        assert result.action == "delete-db-instance"
        assert result.action_type == "DELETE"
        assert result.resource_id == "prod-main"

    def test_ec2_describe_instances_is_read(self):
        result = parse_command("aws ec2 describe-instances")
        assert result is not None
        assert result.action_type == "READ"
        assert result.service == "ec2"

    def test_iam_attach_role_policy_is_admin(self):
        cmd = (
            "aws iam attach-role-policy --role-name api-prod "
            "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        )
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "ADMIN"
        assert result.service == "iam"
        assert result.resource_id is not None  # role-name or policy-arn

    def test_ec2_authorize_sg_ingress_is_admin(self):
        cmd = (
            "aws ec2 authorize-security-group-ingress "
            "--group-id sg-abc --protocol tcp --port 22 --cidr 0.0.0.0/0"
        )
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "ADMIN"
        assert result.resource_id == "sg-abc"

    def test_lambda_update_function_code_is_write(self):
        cmd = "aws lambda update-function-code --function-name my-func --zip-file fileb://func.zip"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "WRITE"
        assert result.service == "lambda"
        assert result.resource_id == "my-func"

    def test_s3_rm_recursive_is_delete(self):
        cmd = "aws s3 rm s3://my-bucket --recursive"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "DELETE"
        assert result.service == "s3"
        # resource_id should be the s3:// URI
        assert result.resource_id == "s3://my-bucket"

    def test_s3_cp_is_write(self):
        cmd = "aws s3 cp file.txt s3://my-bucket/"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "WRITE"

    def test_s3_sync_is_write(self):
        cmd = "aws s3 sync ./build s3://deploy-bucket"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "WRITE"

    def test_s3_mb_is_write(self):
        cmd = "aws s3 mb s3://new-bucket"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "WRITE"

    def test_s3_rb_is_delete(self):
        cmd = "aws s3 rb s3://old-bucket"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "DELETE"

    def test_ec2_terminate_instances_is_delete(self):
        cmd = "aws ec2 terminate-instances --instance-ids i-1234567890abcdef0"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "DELETE"
        assert result.resource_id == "i-1234567890abcdef0"

    def test_dynamodb_delete_table_is_delete(self):
        cmd = "aws dynamodb delete-table --table-name my-table"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "DELETE"
        assert result.resource_id == "my-table"

    def test_cloudformation_create_stack_is_write(self):
        cmd = "aws cloudformation create-stack --stack-name my-stack --template-body file://template.yaml"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "WRITE"
        assert result.resource_id == "my-stack"

    def test_sts_assume_role_is_admin(self):
        cmd = "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/admin --role-session-name test"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "ADMIN"

    def test_kms_is_admin(self):
        cmd = "aws kms describe-key --key-id alias/my-key"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "ADMIN"


# =========================================================================
# AWS — profile and region extraction
# =========================================================================

class TestAWSProfileRegion:

    def test_profile_flag_extracted(self):
        cmd = "aws --profile prod rds describe-db-instances"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "READ"
        assert result.profile == "prod"

    def test_region_flag_extracted(self):
        cmd = "aws --region eu-west-1 ec2 describe-instances"
        result = parse_command(cmd)
        assert result is not None
        assert result.action_type == "READ"
        assert result.region == "eu-west-1"

    def test_both_profile_and_region(self):
        cmd = "aws --profile staging --region ap-southeast-1 s3 ls"
        result = parse_command(cmd)
        assert result is not None
        assert result.profile == "staging"
        assert result.region == "ap-southeast-1"


# =========================================================================
# GCP — gcloud command parsing
# =========================================================================

class TestGCPParsing:

    def test_compute_instances_list_is_read(self):
        cmd = "gcloud compute instances list"
        result = parse_command(cmd)
        assert result is not None
        assert result.provider == "gcp"
        assert result.action_type == "READ"
        assert "compute" in result.service.lower()

    def test_compute_instances_delete_is_delete(self):
        cmd = "gcloud compute instances delete my-instance --zone us-central1-a"
        result = parse_command(cmd)
        assert result is not None
        assert result.provider == "gcp"
        assert result.action_type == "DELETE"
        assert result.resource_id == "my-instance"

    def test_iam_service_accounts_create_is_admin(self):
        cmd = "gcloud iam service-accounts create test-sa"
        result = parse_command(cmd)
        assert result is not None
        assert result.provider == "gcp"
        assert result.action_type == "ADMIN"

    def test_sql_instances_describe_is_read(self):
        cmd = "gcloud sql instances describe prod-db"
        result = parse_command(cmd)
        assert result is not None
        assert result.provider == "gcp"
        assert result.action_type == "READ"
        assert result.resource_id == "prod-db"

    def test_container_clusters_delete_is_delete(self):
        cmd = "gcloud container clusters delete my-cluster"
        result = parse_command(cmd)
        assert result is not None
        assert result.provider == "gcp"
        assert result.action_type == "DELETE"
        assert result.resource_id == "my-cluster"

    def test_gcp_zone_extracted_as_region(self):
        cmd = "gcloud compute instances delete my-vm --zone=us-central1-a"
        result = parse_command(cmd)
        assert result is not None
        assert result.region == "us-central1-a"

    def test_gcp_project_flag(self):
        cmd = "gcloud compute instances list --project my-project"
        result = parse_command(cmd)
        assert result is not None
        assert result.profile == "my-project"


# =========================================================================
# Non-cloud commands → None
# =========================================================================

class TestNonCloudCommands:

    def test_ls_returns_none(self):
        assert parse_command("ls -la") is None

    def test_git_push_returns_none(self):
        assert parse_command("git push") is None

    def test_python_script_returns_none(self):
        assert parse_command("python3 script.py") is None

    def test_empty_string_returns_none(self):
        assert parse_command("") is None

    def test_whitespace_returns_none(self):
        assert parse_command("   ") is None

    def test_none_input_returns_none(self):
        assert parse_command(None) is None

    def test_docker_command_returns_none(self):
        assert parse_command("docker run -it ubuntu bash") is None

    def test_curl_returns_none(self):
        assert parse_command("curl https://example.com") is None


# =========================================================================
# Compound commands
# =========================================================================

class TestCompoundCommands:

    def test_two_aws_commands_with_and(self):
        cmd = "aws s3 ls && aws rds delete-db-instance --db-instance-identifier prod"
        results = parse_compound_command(cmd)
        assert len(results) == 2
        assert results[0].action_type == "READ"
        assert results[1].action_type == "DELETE"
        assert results[1].resource_id == "prod"

    def test_cloud_and_non_cloud_with_and(self):
        cmd = "echo hello && aws s3 ls"
        results = parse_compound_command(cmd)
        # Non-cloud segments are silently dropped
        assert len(results) == 1
        assert results[0].service == "s3"

    def test_pipe_separator(self):
        cmd = "aws s3 ls | grep my-bucket"
        results = parse_compound_command(cmd)
        assert len(results) == 1
        assert results[0].action == "ls"

    def test_semicolon_separator(self):
        cmd = "aws ec2 describe-instances; aws rds describe-db-instances"
        results = parse_compound_command(cmd)
        assert len(results) == 2
        assert all(r.action_type == "READ" for r in results)

    def test_empty_compound_returns_empty(self):
        assert parse_compound_command("") == []

    def test_no_cloud_in_compound_returns_empty(self):
        results = parse_compound_command("ls -la && echo done")
        assert results == []


# =========================================================================
# Shell variables
# =========================================================================

class TestVariableHandling:

    def test_variable_in_resource_id_sets_none(self):
        cmd = "aws rds delete-db-instance --db-instance-identifier $DB_NAME"
        result = parse_command(cmd)
        assert result is not None
        assert result.resource_id is None
        assert result.warning is not None
        assert "variable" in result.warning.lower()

    def test_braced_variable_detected(self):
        cmd = "aws rds delete-db-instance --db-instance-identifier ${DB_NAME}"
        result = parse_command(cmd)
        assert result is not None
        assert result.resource_id is None

    def test_subshell_variable_detected(self):
        cmd = "aws s3 rm s3://$(echo bucket-name)"
        result = parse_command(cmd)
        assert result is not None
        assert result.warning is not None

    def test_backtick_variable_detected(self):
        cmd = "aws s3 rm s3://`echo bucket-name`"
        result = parse_command(cmd)
        assert result is not None
        assert result.warning is not None


# =========================================================================
# Opaque wrappers
# =========================================================================

class TestOpaqueCommands:

    def test_bash_script_returns_none(self):
        result = parse_command("bash deploy.sh")
        assert result is None

    def test_eval_returns_none(self):
        result = parse_command("eval 'aws s3 ls'")
        assert result is None

    def test_source_returns_none(self):
        result = parse_command("source setup.sh")
        assert result is None


# =========================================================================
# Prefix stripping (sudo, env vars)
# =========================================================================

class TestPrefixStripping:

    def test_sudo_prefix_stripped(self):
        result = parse_command("sudo aws s3 ls")
        assert result is not None
        assert result.action_type == "READ"
        assert result.service == "s3"

    def test_env_var_prefix_stripped(self):
        result = parse_command("AWS_PROFILE=prod aws s3 ls")
        assert result is not None
        assert result.action_type == "READ"
        assert result.service == "s3"

    def test_time_prefix_stripped(self):
        result = parse_command("time aws s3 ls")
        assert result is not None
        assert result.action_type == "READ"

    def test_multiple_env_vars_stripped(self):
        result = parse_command("AWS_PROFILE=prod AWS_REGION=us-east-1 aws s3 ls")
        assert result is not None
        assert result.service == "s3"


# =========================================================================
# ParsedCommand dataclass fields
# =========================================================================

class TestParsedCommandFields:

    def test_raw_command_preserved(self):
        cmd = "aws s3 ls"
        result = parse_command(cmd)
        assert result is not None
        assert result.raw_command == cmd

    def test_flags_dict_populated(self):
        cmd = "aws ec2 describe-instances --instance-ids i-abc123 --output json"
        result = parse_command(cmd)
        assert result is not None
        assert isinstance(result.flags, dict)
        # The instance ID should be somewhere in flags
        assert result.resource_id == "i-abc123"

    def test_provider_is_aws(self):
        result = parse_command("aws sts get-caller-identity")
        assert result is not None
        assert result.provider == "aws"

    def test_provider_is_gcp(self):
        result = parse_command("gcloud compute instances list")
        assert result is not None
        assert result.provider == "gcp"


# =========================================================================
# Parametrized tests from fixture file
# =========================================================================

@pytest.fixture(scope="module")
def sample_commands():
    return _load_sample_commands()


def test_fixture_commands_parse_correctly(sample_commands):
    """Validate each entry in sample_commands.json against the parser."""
    for entry in sample_commands:
        cmd = entry["command"]
        expected_type = entry.get("expected_action_type")
        expected_provider = entry.get("expected_provider")
        expect_none = entry.get("expect_none", False)

        result = parse_command(cmd)

        if expect_none:
            assert result is None, f"Expected None for: {cmd}"
        else:
            assert result is not None, f"Expected ParsedCommand for: {cmd}"
            if expected_type:
                assert result.action_type == expected_type, (
                    f"For '{cmd}': expected {expected_type}, got {result.action_type}"
                )
            if expected_provider:
                assert result.provider == expected_provider, (
                    f"For '{cmd}': expected provider {expected_provider}, got {result.provider}"
                )
