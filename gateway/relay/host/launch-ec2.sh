#!/bin/bash
# Launch the relay host on EC2 in the older Fount account (us-east-1), with
# install.sh as user data, and attach the relay Elastic IP. No key pair, so
# there's no way in; read the pin with check-pin.sh afterwards.
#   AWS_PROFILE=<older account> gateway/relay/host/launch-ec2.sh
set -euo pipefail
cd "$(dirname "$0")"
REGION=us-east-1
ALLOC=${ALLOC:-eipalloc-08d450ea8ebaf9575}
TYPE=${TYPE:-t4g.small}
grep -qE '^RELAY_CLIENT_PINS=\$\{RELAY_CLIENT_PINS:-[0-9a-f]{64}' install.sh ||
  { echo "set RELAY_CLIENT_PINS in install.sh first" >&2; exit 1; }
git diff --quiet HEAD -- install.sh ||
  { echo "install.sh differs from the committed file" >&2; exit 1; }

ami=$(aws ssm get-parameter --region $REGION --name /aws/service/debian/release/13/latest/arm64 \
  --query Parameter.Value --output text)
vpc=$(aws ec2 describe-vpcs --region $REGION --filters Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' --output text)
sg=$(aws ec2 describe-security-groups --region $REGION \
  --filters Name=group-name,Values=fount-mail-relay Name=vpc-id,Values=$vpc \
  --query 'SecurityGroups[0].GroupId' --output text)
if [ "$sg" = None ]; then
  sg=$(aws ec2 create-security-group --region $REGION --vpc-id $vpc --group-name fount-mail-relay \
    --description "Fount mail relay: 443 in (pinned mTLS), all out" --query GroupId --output text)
  aws ec2 authorize-security-group-ingress --region $REGION --group-id $sg \
    --protocol tcp --port 443 --cidr 0.0.0.0/0 >/dev/null
fi

id=$(aws ec2 run-instances --region $REGION --image-id $ami --instance-type $TYPE \
  --security-group-ids $sg --user-data file://install.sh \
  --metadata-options HttpTokens=required,HttpPutResponseHopLimit=1 \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=8,VolumeType=gp3,Encrypted=true}' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=fount-mail-relay}]' \
  --query 'Instances[0].InstanceId' --output text)
echo "instance $id ($ami, $TYPE)"
aws ec2 wait instance-running --region $REGION --instance-ids $id
aws ec2 associate-address --region $REGION --allocation-id $ALLOC --instance-id $id >/dev/null
ip=$(aws ec2 describe-addresses --region $REGION --allocation-ids $ALLOC --query 'Addresses[0].PublicIp' --output text)
echo "attached $ip. install.sh builds the relay (a few minutes), then:"
echo "  gateway/relay/host/check-pin.sh $ip:443"
