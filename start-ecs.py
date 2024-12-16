#!/usr/bin/env python3
"""
This script is used by Jenkins to run an ECS task with environment variable overrides.

Default execution is in us-west-2 production-a
 but can be overridden by setting the following environment variables in Jenkins:
- ANSIBLE_AWS_PROFILE
- ANSIBLE_ENVIRONMENT
- ANSIBLE_REGION
"""

import boto3
import botocore.exceptions
import copy
import os
import sys
import time
import yaml


def get_task_exit_info(client, arn):
    """
    Retrieves the exit code and stop reason for a specific container in an ECS task.
    :param client: Boto3 ECS client
    :param arn: Full ARN of the ECS task
    :return: Tuple of (exit_code, stop_reason)
    """
    # Extract the cluster name from the task ARN
    # This is also used as the container name
    cluster = arn.split(':')[5].split('/')[1]

    try:
        # Describe the task to get its details
        response_tasks = client.describe_tasks(cluster=cluster_name, tasks=[task_arn])

        if not response_tasks['tasks']:
            print(f'Task {task_arn} not found!')
            return 1, 'Task not found'

        task = response_tasks['tasks'][0]
        stop_reason = task.get('stoppedReason', 'No stop reason provided')

        for task_container in task['containers']:
            if task_container['name'] == cluster.replace('-cluster', ''):
                exit_code = task_container.get('exitCode')
                if exit_code is not None:
                    return exit_code, stop_reason
                else:
                    return 0, 'Exit code not available'

        print(f'Container {cluster} not found in task response')
        return 1, f'Container {cluster} not found'

    except Exception as e:
        print(f'Error retrieving task information: {str(e)}')
        return 1, f'Error: {str(e)}'


def mask_credentials(value, keep=5, mask='*****'):
    """
    Mask the credentials in the environment variables
    :param value:
    :param keep:
    :param mask:
    :return:
    """
    return value[:keep] + mask if len(value) > keep else value + mask


def is_task_running(arn):
    """
    Check if the task is still running
    :param arn: Task ARN
    :return: Boolean; True if the task is still running
    """
    task_description = ecs_client.describe_tasks(cluster=ansible_cluster_name, tasks=[arn])['tasks'][0]
    return bool(task_description['lastStatus'] != 'STOPPED')


def get_log_group_name(client, prefix):
    """
    Get the log group name using the prefix
    :param client: boto3 logs_client
    :param prefix: Prefix string to search for
    :return: Log Group name and ARN
    """
    try:
        client_response = client.describe_log_groups(logGroupNamePrefix=prefix)
        group_name = client_response['logGroups'][0]['logGroupName']
        group_arn = client_response['logGroups'][0]['logGroupArn']
        return group_name, group_arn
    except botocore.exceptions.ClientError as uhhh:
        raise Exception('Error occurred while searching for the log group') from uhhh


def get_log_stream_name(client, prefix, taskid):
    """
    Get the log stream name using the log group name
    :param client: boto3 logs_client
    :param prefix: Prefix string to search for
    :param taskid: Task ID (derived from taskArn)
    :return: Log Stream name and ARN
    """
    try:
        client_response = client.describe_log_streams(
            logGroupName=log_group_name, logStreamNamePrefix=f'{prefix}/{prefix}/{taskid}'
        )
        stream_name = client_response['logStreams'][0]['logStreamName']
        stream_arn = client_response['logStreams'][0]['arn']
        return stream_name, stream_arn
    except botocore.exceptions.ClientError as uhhh:
        raise Exception('Error occurred while searching for the log stream') from uhhh


def print_new_logs(arn, name, token=None):
    """
    Print the log events
    :param arn: Log Group ARN
    :param name: Log Stream name
    :param token: Next Token for pagination
    :return: NextForwardToken for pagination
    """
    try:
        if next_token:
            events = logs_client.get_log_events(
                logGroupIdentifier=arn, logStreamName=name, nextToken=token, startFromHead=False
            )
        else:
            events = logs_client.get_log_events(logGroupIdentifier=arn, logStreamName=name, startFromHead=True)

        for event in events['events']:
            print(event['message'])

        return events['nextForwardToken']
    except logs_client.exceptions.ResourceNotFoundException:
        print('Waiting for logs to be available...')
        return None


# Capture Ansible credentials from Jenkins (via AWS SSM)
# Credentials are sourced from /all/ansible/{account_alias}/sa-admin (us-west-2)
ansible_aws_access_key = os.getenv('AWS_ACCESS_KEY_ID', '')
ansible_aws_secret_key = os.getenv('AWS_SECRET_ACCESS_KEY', '')
if not ansible_aws_access_key or not ansible_aws_secret_key:
    raise Exception('[ERROR] AWS credentials have not been found in the environment.')

# Check for Jenkins profile overrides in the environment
aws_profile_override = os.getenv('ANSIBLE_AWS_PROFILE', '')
aws_env_override = os.getenv('ANSIBLE_ENVIRONMENT', '')
aws_region_override = os.getenv('ANSIBLE_REGION', '')
# Set the AWS profile name and region
# This determines the AWS account the ECS tasks are executed from
aws_profile_name = 'admin' if not aws_profile_override else aws_profile_override
jenkins_business_region = os.getenv('BUSINESS_REGION', '').lower()
if jenkins_business_region in ['apac', 'emea']:
    aws_region = 'eu-west-2' if not aws_region_override else aws_region_override
else:
    aws_region = 'us-west-2' if not aws_region_override else aws_region_override

# Configure the deployed stack name, used for locating the task definition and cluster
ansible_environment = 'production-a' if not aws_env_override else aws_env_override
ansible_worker_stack_name = 'ansible-worker-ecs'
vpc_subnet_type = 'public' if ansible_environment.endswith(('-a', '-b')) else 'private'

# Container name as defined by the task definition
ansible_container_name = f'{ansible_environment}-{ansible_worker_stack_name}'

# Fargate overrides for per-playbook performance adjustments
# This may require adjustment if "ERROR! A worker was found in a dead state" is present in logs
# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
fargate_cpu_override = os.getenv('FARGATE_CPU', '512')
fargate_memory_override = os.getenv('FARGATE_MEMORY', '1024')

# Create boto3 session and clients
try:
    session = boto3.Session(profile_name=aws_profile_name, region_name=aws_region)
    ecs_client = session.client('ecs')
    ec2_client = session.client('ec2')
    iam_client = session.client('iam')
    logs_client = session.client('logs')
except botocore.exceptions.ProfileNotFound as err:
    raise Exception(f'Profile not found: {aws_profile_name}') from err
except botocore.exceptions.NoRegionError as err:
    raise Exception(f'Region not found: {aws_region}') from err

# Retrieve the cluster name by searching for the stack name
try:
    clusters = ecs_client.list_clusters()
    next_token = clusters.get('nextToken', None)
    while next_token is not None:
        more_results = ecs_client.list_clusters(nextToken=next_token)
        clusters['clusterArns'] += more_results['clusterArns']
        next_token = more_results.get('nextToken', None)

    ansible_cluster_name = ''
    for cluster_arn in clusters['clusterArns']:
        cluster_description = ecs_client.describe_clusters(clusters=[cluster_arn])['clusters'][0]
        cluster_name = cluster_description['clusterName']
        if ansible_container_name in cluster_name:
            print(f'\nECS Cluster: {cluster_name}')
            ansible_cluster_name = cluster_name
            break

    if not ansible_cluster_name:
        raise Exception(f'No cluster found with the name containing {ansible_container_name}')
except Exception as err:
    raise Exception('Error occurred while searching for the cluster') from err

# Retrieve the task definition ARN by searching for the stack name
try:
    task_definition_arns = ecs_client.list_task_definitions(status='ACTIVE')
    next_token = task_definition_arns.get('nextToken', None)
    while next_token is not None:
        more_task_definition_arns = ecs_client.list_task_definitions(status='ACTIVE', nextToken=next_token)
        task_definition_arns['taskDefinitionArns'] += more_task_definition_arns['taskDefinitionArns']
        next_token = more_task_definition_arns.get('nextToken', None)

except Exception as err:
    raise Exception('Error occurred while searching for the task definition') from err

ansible_task_arn = ''
if task_definition_arns['taskDefinitionArns']:
    for task_definition_arn in task_definition_arns['taskDefinitionArns']:
        if ansible_worker_stack_name in task_definition_arn:
            ansible_task_arn = task_definition_arn
            print(f'ECS Task Definition: {ansible_worker_stack_name}')
            break

else:
    raise Exception(f'No task definition found with the prefix {ansible_worker_stack_name}')

# Retrieve the Security Group ID by searching for the stack name
security_group_id = ''
try:
    response = ec2_client.describe_security_groups(
        Filters=[{'Name': 'tag:Name', 'Values': [f'{ansible_container_name}-ecs-private-sg']}]
    )
    security_group_id = response['SecurityGroups'][0]['GroupId']
    if not security_group_id:
        raise Exception(f'No security group found for {ansible_container_name}-ecs-private-sg')

except Exception as err:
    raise Exception('Error occurred while searching for the security group') from err

# Retrieve the subnets that match the format production-a-subnet-1 or production-a-public-subnet-1
ansible_subnets = []
try:
    response = ec2_client.describe_subnets(
        Filters=[
            {
                'Name': 'tag:Name',
                'Values': [f'{ansible_environment}-subnet-?', f'{ansible_environment}-{vpc_subnet_type}-subnet-?'],
            }
        ]
    )
    for subnet in response['Subnets']:
        ansible_subnets.append(subnet['SubnetId'])

    if not ansible_subnets:
        raise Exception(f'No subnets found for {ansible_environment}-subnet-*')

except Exception as err:
    raise Exception('Error occurred while searching for the subnets') from err

# Retrieve the IAM role ARN by searching for the stack name
try:
    response = iam_client.list_roles()
    response_marker = response.get('Marker', None)
    while response_marker is not None:
        more_roles = iam_client.list_roles(Marker=response_marker)
        response['Roles'] += more_roles['Roles']
        response_marker = more_roles.get('Marker', None)

    ansible_role_arn = ''
    for role in response['Roles']:
        if ansible_container_name in role['Arn']:
            role_name = role['RoleName']
            role_tags = iam_client.list_role_tags(RoleName=role_name)
            for tag in role_tags['Tags']:
                if tag['Key'] == 'Region':
                    if tag['Value'] == aws_region:
                        ansible_role_arn = role['Arn']
                        break

    if not ansible_role_arn:
        raise Exception(f'No IAM Role found containing: {ansible_container_name}')

except Exception as err:
    raise Exception('Error occurred while searching for the IAM role') from err

# Manipulate the environment variables received from Jenkins
jenkins_check_mode = bool(os.getenv('ANSIBLE_CHECK_MODE', 'NO').upper() == 'YES')
if jenkins_check_mode:
    ansible_check_mode = '--check'
else:
    ansible_check_mode = ''

jenkins_build_debug = bool(os.getenv('BUILD_DEBUG', 'NO').upper() == 'YES')
if jenkins_build_debug:
    ansible_debug = '--skip-tags nodebug'
else:
    ansible_debug = '--skip-tags debug'

jenkins_build_verbose = bool(os.getenv('BUILD_VERBOSE', 'NO').upper() == 'YES')
if jenkins_build_verbose:
    ansible_verbose = '-vvvv'
else:
    ansible_verbose = ''

jenkins_node_labels = os.getenv('NODE_LABELS', 'amd64')
is_arm = bool('aarch64' in jenkins_node_labels)
if is_arm:
    config_arch = 'aarch64'
else:
    config_arch = 'amd64'

jenkins_redis_cache = bool(os.getenv('REDIS_CACHE', 'NO').upper() == 'YES')
if jenkins_redis_cache:
    if not jenkins_business_region:
        ansible_cache_config = ''
    else:
        if jenkins_business_region not in ['amer', 'emea']:
            raise Exception(f'Invalid business region: {jenkins_business_region}')

        ansible_cache_config = f'-e ANSIBLE_CONFIG=/etc/ansible/ansible-{config_arch}-{jenkins_business_region}.cfg'
else:
    ansible_cache_config = '-e ANSIBLE_CONFIG=/etc/ansible/ansible-nocache.cfg'

jenkins_targeted_host = os.getenv('TARGETED_HOST', '')
if not jenkins_targeted_host:
    ansible_limit_host = ''
else:
    ansible_limit_host = f'--limit localhost,{jenkins_targeted_host}'

ansible_custom_params = os.getenv('ANSIBLE_CUSTOM_PARAMS', '')

jenkins_job_name = os.getenv('JOB_NAME', '').replace('/', '-')
jenkins_branch = os.getenv('BRANCH', 'unknown')
jenkins_build_cause = os.getenv('BUILD_CAUSE', 'unknown')
jenkins_build_user_id = os.getenv('BUILD_USER_ID', 'unknown')
jenkins_build_number = os.getenv('BUILD_NUMBER', '1')
jenkins_branch_tag = os.getenv('BRANCH', '')
jenkins_docker_tag = os.getenv('DOCKER_TAG', jenkins_branch_tag.replace('/', '-'))
jenkins_job_base_name = os.getenv('JOB_BASE_NAME', 'undefined')
jenkins_targeted_env = os.getenv('TARGETED_ENV', 'ALL')
jenkins_targeted_function = os.getenv('TARGETED_FUNCTION', 'NONE')
jenkins_targeted_stack = os.getenv('TARGETED_STACK', 'ALL')
if jenkins_branch_tag != 'master':
    print('[WARN] Using a non-master branch will only impact the job execution script.')
    print('       Please use "DOCKER_TAG" and bash script "./scripts/jenkins" for branch and tag testing.')

if jenkins_docker_tag != 'master':
    print('[ERROR] Container image tags cannot be overridden when running playbooks in ECS.')
    print('        Please use the Jenkins bash script "./scripts/jenkins" for branch and tag testing.')
    sys.exit(20)

# Define the environment variable overrides as a dictionary
env_vars = {
    'AWS_ACCESS_KEY_ID': ansible_aws_access_key,
    'AWS_SECRET_ACCESS_KEY': ansible_aws_secret_key,
    'ANSIBLECHECKMODE': ansible_check_mode,
    'ANSIBLE_CONFIG': ansible_cache_config,
    'ANSIBLEDEBUG': ansible_debug,
    'BUSINESS_REGION': jenkins_business_region.upper(),
    'DOCKER_TAG': jenkins_docker_tag,
    'INVENTORY': os.getenv('INVENTORY', 'undefined'),
    'LIMIT_HOST': ansible_limit_host,
    'PLAYBOOK': os.getenv('PLAYBOOK', 'undefined'),
    'TARGETED_ENV': jenkins_targeted_env,
    'TARGETED_FUNCTION': jenkins_targeted_function,
    'TARGETED_STACK': jenkins_targeted_stack,
    'VERBOSE': ansible_verbose,
    'BUILD_CAUSE': jenkins_build_cause,
    'BUILD_NUMBER': jenkins_build_number,
    'BUILD_USER_ID': jenkins_build_user_id,
    'JOB_BASE_NAME': jenkins_job_base_name,
    'JOB_NAME': jenkins_job_name,
}

# If a list of custom parameters is provided, add them to the environment variables
if ansible_custom_params:
    for param in ansible_custom_params.split(','):
        if param not in env_vars.keys():
            env_vars[param] = os.getenv(param, '')

# Prepare the container overrides
container_overrides = [
    {
        'name': ansible_container_name,
        'environment': [{'name': name, 'value': value} for name, value in env_vars.items()],
    }
]

# Run the task with environment variable overrides
# Mask credentials
credential_keys = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
container_overrides_clean = copy.deepcopy(container_overrides)
for container in container_overrides_clean:
    for override in container['environment']:
        if override['name'] in credential_keys:
            override['value'] = mask_credentials(override['value'])

container_overrides_txt = yaml.dump(container_overrides_clean, default_flow_style=False)
subnet_txt = yaml.dump(ansible_subnets, default_flow_style=False)
print(f'Running task: {ansible_task_arn} on cluster:{ansible_cluster_name}\n')
if jenkins_build_debug:
    print(f'IAM Role: {ansible_role_arn}')
    print(f'EC2 Security Group: {security_group_id}')
    print(f'VPC Subnets:\n{subnet_txt}')
    print(f'ECS Container overrides:\n{container_overrides_txt}')

try:
    response = ecs_client.run_task(
        taskDefinition=ansible_task_arn,
        cluster=ansible_cluster_name,
        launchType='FARGATE',
        networkConfiguration={
            'awsvpcConfiguration': {
                'subnets': ansible_subnets,
                'securityGroups': [security_group_id],
                'assignPublicIp': 'ENABLED' if vpc_subnet_type == 'public' else 'DISABLED',
            }
        },
        overrides={
            'containerOverrides': container_overrides,
            'executionRoleArn': ansible_role_arn,
            'taskRoleArn': ansible_role_arn,
            'cpu': fargate_cpu_override,
            'memory': fargate_memory_override,
        },
        propagateTags='TASK_DEFINITION',
    )
except botocore.exceptions.ClientError as err:
    raise Exception('Error occurred while running the task') from err
except botocore.exceptions.ParamValidationError as err:
    raise Exception('Invalid parameters provided to run_task') from err
except Exception as err:
    raise Exception('Unhandled exception occurred') from err

task_arn = response['tasks'][0]['taskArn']
task_id = task_arn.split('/')[-1]
response_task = response['tasks'][0]
response_containers = response_task['containers']
print(f'Launching task: {task_arn}\n')
for container in response_containers:
    if 'ansible' in container['image']:
        container_name = container['name']
        image_name = container['image'].split('/')[-1]
        container_status = container['lastStatus']
        print(f'Launching container {container_name} ({image_name}): {container_status}\n')

# Grab the taskArn, so we can monitor status
# Monitor the taskArn every 10 seconds until it reaches a terminal state
try:
    waiter = ecs_client.get_waiter('tasks_running')
    waiter.wait(
        cluster=ansible_cluster_name,
        tasks=[task_arn],
        WaiterConfig={
            'Delay': 10,
        },
    )
    print('Task is running.\n')
except botocore.exceptions.WaiterError as err:
    raise Exception('Error occurred while waiting for the task to stop') from err


# Monitor Cloudwatch logs
# NOTE: Log stream is not available until the task is running
# Get LogGroup, LogStream name and ARN
log_group_name, log_group_arn = get_log_group_name(logs_client, ansible_container_name)
task_id = task_arn.split('/')[-1]
log_stream_name, log_stream_arn = get_log_stream_name(logs_client, ansible_container_name, task_id)
print(f'LogGroup: {log_group_name}\nLogStream: {log_stream_name}\n')

task_running = True
next_token = None
while task_running:
    next_token = print_new_logs(log_group_arn, log_stream_name, next_token)
    task_running = is_task_running(task_arn)
    time.sleep(5)

print('\nTask has stopped.')

# Get the exit code and stop reason
ecs_exit_code, ecs_stop_reason = get_task_exit_info(ecs_client, task_arn)
if ecs_exit_code != 0:
    print(f'\nTask exited with code {ecs_exit_code}: {ecs_stop_reason}')
    sys.exit(ecs_exit_code)
