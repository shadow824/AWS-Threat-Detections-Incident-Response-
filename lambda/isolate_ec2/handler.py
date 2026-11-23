import os
import boto3

ec2 = boto3.client("ec2")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
SG_NAME = "ir-isolation-sg"


def get_isolation_sg(vpc_id):
    r = ec2.describe_security_groups(Filters=[
        {"Name": "group-name", "Values": [SG_NAME]},
        {"Name": "vpc-id", "Values": [vpc_id]},
    ])
    if r["SecurityGroups"]:
        return r["SecurityGroups"][0]["GroupId"]
    sg = ec2.create_security_group(
        GroupName=SG_NAME, Description="IR isolation - no traffic", VpcId=vpc_id)
    sg_id = sg["GroupId"]
    # شيل قاعدة الـ egress الافتراضية عشان الـ SG يبقى معزول فعلاً
    ec2.revoke_security_group_egress(GroupId=sg_id, IpPermissions=[
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    return sg_id


def lambda_handler(event, context):
    instance_id = event["detail"]["resource"]["instanceDetails"]["instanceId"]
    finding_type = event["detail"].get("type", "unknown")

    if DRY_RUN:
        print(f"[DRY_RUN] would isolate {instance_id} for {finding_type}")
        return {"instance": instance_id, "dry_run": True}

    inst = ec2.describe_instances(InstanceIds=[instance_id])[
        "Reservations"][0]["Instances"][0]
    sg_id = get_isolation_sg(inst["VpcId"])

    for eni in inst["NetworkInterfaces"]:
        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni["NetworkInterfaceId"], Groups=[sg_id])

    snapshots = []
    for m in inst.get("BlockDeviceMappings", []):
        snap = ec2.create_snapshot(
            VolumeId=m["Ebs"]["VolumeId"],
            Description=f"IR evidence for {instance_id}")
        snapshots.append(snap["SnapshotId"])

    ec2.create_tags(Resources=[instance_id], Tags=[
        {"Key": "Quarantined", "Value": "true"}])

    return {"instance": instance_id, "isolation_sg": sg_id, "snapshots": snapshots}