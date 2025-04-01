import json
import boto3
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate

# Helper function to generate JWT tokens
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Register New User
@api_view(['POST'])
def register_user(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    if User.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'}, status=400)

    user = User.objects.create_user(username=username, email=email, password=password)
    return Response({'message': 'User created successfully'})

# Login User
@api_view(['POST'])
def login_user(request):
    username = request.data.get('username')
    password = request.data.get('password')
    account_id = request.data.get('account_id')
    role_name = request.data.get('role_name')

    user = authenticate(username=username, password=password)
    if user:
        # After authentication, get tokens and assume the AWS role
        tokens = get_tokens_for_user(user)
        return Response({'message': 'Login successful', 'tokens': tokens, 'account_id': account_id, 'role_name': role_name})
    
    return Response({'error': 'Invalid credentials'}, status=400)

# Logout User (Blacklist Refresh Token)
@api_view(['POST'])
def logout_user(request):
    try:
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": "Refresh token is required"}, status=400)
        
        token = RefreshToken(refresh_token)
        token.blacklist()  # This will now work after migration
        
        return Response({"message": "Successfully logged out"}, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=400)

# AWS Resource Management Functions
def get_aws_resources(request):
    try:
        ebs_volumes = list_ebs_volumes()
        ebs_snapshots = list_ebs_snapshots()
        elastic_ips = list_elastic_ips()

        response = {
            "ebs_volumes": ebs_volumes,
            "ebs_snapshots": ebs_snapshots,
            "elastic_ips": elastic_ips
        }

        return JsonResponse(response, safe=False)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

# Function to list all EBS volumes
def list_ebs_volumes():
    ec2_client = boto3.client('ec2', region_name=get_region())
    volumes = []
    next_token = None
    while True:
        if next_token:
            response = ec2_client.describe_volumes(NextToken=next_token)
        else:
            response = ec2_client.describe_volumes()

        volumes.extend(response['Volumes'])
        next_token = response.get('NextToken', None)
        if not next_token:
            break

    return volumes

# Function to list all EBS snapshots
def list_ebs_snapshots():
    ec2_client = boto3.client('ec2', region_name=get_region())
    snapshots = ec2_client.describe_snapshots(OwnerIds=['self'])

    snapshot_details = []
    for snap in snapshots['Snapshots']:
        snapshot_details.append({
            "snapshot_id": snap['SnapshotId'],
            "size_gb": snap['VolumeSize'],
            "associated_volume": snap.get('VolumeId', 'N/A'),
            "start_time": str(snap['StartTime'])
        })

    return snapshot_details

# Function to list all Elastic IPs
def list_elastic_ips():
    ec2_client = boto3.client('ec2', region_name=get_region())
    addresses = ec2_client.describe_addresses()

    elastic_ips = {"used": [], "idle": []}
    for addr in addresses['Addresses']:
        eip_info = {
            "public_ip": addr['PublicIp'],
            "allocation_id": addr.get('AllocationId', 'N/A'),
            "instance_id": addr.get('InstanceId', 'Not Associated')
        }

        if 'InstanceId' in addr:
            elastic_ips["used"].append(eip_info)
        else:
            elastic_ips["idle"].append(eip_info)

    return elastic_ips

# Get the AWS region from the session
def get_region():
    session = boto3.session.Session()
    return session.region_name

# AWS Pricing Function (example for EC2)
def get_instance_price(instance_type, region):
    """Fetches the on-demand hourly price of an EC2 instance from AWS Pricing API."""
    session = boto3.Session()  # Uses configured AWS credentials
    client = session.client('pricing', region_name='us-east-1')  # AWS Pricing API is only available in us-east-1

    try:
        response = client.get_products(
            ServiceCode='AmazonEC2',
            Filters=[
                {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': get_aws_region_name(region)},
                {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Linux'},
                {'Type': 'TERM_MATCH', 'Field': 'preInstalledSw', 'Value': 'NA'},
                {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'},
                {'Type': 'TERM_MATCH', 'Field': 'capacitystatus', 'Value': 'Used'}
            ]
        )

        price_item = response['PriceList'][0]
        price_data = json.loads(price_item)
        price_per_hour = next(iter(price_data['terms']['OnDemand'].values()))['priceDimensions']
        hourly_rate = next(iter(price_per_hour.values()))['pricePerUnit']['USD']
        
        return float(hourly_rate)

    except Exception as e:
        return f"Error: {str(e)}"

# Convert AWS region code to region name for pricing
def get_aws_region_name(region_code):
    region_map = {
        "ap-south-1": "Asia Pacific (Mumbai)",
        "us-east-1": "US East (N. Virginia)",
        "us-west-2": "US West (Oregon)"
    }
    return region_map.get(region_code, region_code)

def get_all_compute_optimizer_recommendations(request):
    """Fetches Compute Optimizer recommendations for EC2 instances."""
    try:
        session = boto3.Session()
        region = session.region_name  # Detect region from AWS CLI
        client = session.client('compute-optimizer', region_name=region)
        ec2_recommendations = client.get_ec2_instance_recommendations()

        formatted_instances = []
        for instance in ec2_recommendations.get("instanceRecommendations", []):
            instance_id = instance.get("instanceArn", "").split("/")[-1]
            current_instance = instance.get("currentInstanceType", "Unknown")
            recommendations = instance.get("recommendationOptions", [])
            recommended_instances = [option.get("instanceType", "Unknown") for option in recommendations]

            # Fetch prices for current and recommended instances
            current_price = get_instance_price(current_instance, region)
            recommended_prices = [get_instance_price(inst, region) for inst in recommended_instances]

            estimated_savings = {
                recommended_instances[i]: {
                    metric["name"]: metric["value"]
                    for metric in option.get("projectedUtilizationMetrics", [])
                }
                for i, option in enumerate(recommendations)
            }

            formatted_instances.append({
                "instance_id": instance_id,
                "instance_name": instance.get("instanceName", "Unknown"),
                "finding": instance.get("finding", "Unknown"),
                "finding_reasons": instance.get("findingReasonCodes", []),
                "current_instance_type": current_instance,
                "recommended_instance_type": recommended_instances,
                "current_price": current_price,
                "recommended_price": recommended_prices,
                "estimated_savings": estimated_savings,
                "account_id": instance.get("accountId", "Unknown"),
                "region": region
            })

        return JsonResponse({"ec2_instances": formatted_instances}, safe=False)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

# S3 Pricing and Recommendations
S3_PRICING = {
    "STANDARD": 0.023,  # $ per GB
    "GLACIER": 0.004,   # $ per GB
    "GLACIER_IR": 0.005,  # $ per GB for Instant Retrieval
    "DEEP_ARCHIVE": 0.00099  # $ per GB
}

def format_storage_size(size_in_bytes):
    if size_in_bytes < 1024:
        return f"{size_in_bytes} Bytes"
    elif size_in_bytes < 1024**2:
        return f"{round(size_in_bytes / 1024, 2)} KB"
    elif size_in_bytes < 1024**3:
        return f"{round(size_in_bytes / 1024**2, 2)} MB"
    else:
        return f"{round(size_in_bytes / 1024**3, 2)} GB"

def estimate_monthly_cost(storage_classes):
    cost = 0
    for storage_class, size_gb in storage_classes.items():
        cost += size_gb * S3_PRICING.get(storage_class, 0)
    return round(cost, 2)

def recommend_lifecycle_rules(storage_classes):
    recommendations = []
    
    for storage_class, size_gb in storage_classes.items():
        if size_gb > 100:
            recommendations.append(f"Consider moving {storage_class} data to Glacier for cost savings.")
        elif 10 < size_gb <= 100:
            recommendations.append(f"Enable Intelligent Tiering for {storage_class} to optimize costs.")
        elif size_gb <= 10:
            recommendations.append(f"Storage size is small; lifecycle rules may not be necessary.")
    
    return recommendations if recommendations else "No recommendations"

# Fetch S3 bucket details
def get_s3_bucket_details(request):
    try:
        s3_client = boto3.client('s3')
        response = s3_client.list_buckets()

        bucket_list = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            region = s3_client.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
            region = region if region else "us-east-1"  # Default for us-east-1

            storage_classes = {}
            total_size = 0
            bucket_objects = s3_client.list_objects_v2(Bucket=bucket_name)

            if 'Contents' in bucket_objects:
                for obj in bucket_objects['Contents']:
                    size_bytes = obj['Size']
                    total_size += size_bytes
                    storage_classes["STANDARD"] = storage_classes.get("STANDARD", 0) + (size_bytes / (1024**3))

            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                lifecycle_rules = lifecycle['Rules']
            except:
                lifecycle_rules = "No lifecycle rules configured"

            formatted_size = format_storage_size(total_size)
            cost = estimate_monthly_cost(storage_classes)
            recommendations = recommend_lifecycle_rules(storage_classes)

            bucket_list.append({
                "bucket_name": bucket_name,
                "region": region,
                "total_storage": formatted_size,
                "storage_classes": storage_classes,
                "monthly_estimated_cost": f"${cost}",
                "lifecycle_rules": lifecycle_rules,
                "lifecycle_recommendations": recommendations
            })

        return JsonResponse({"s3_buckets": bucket_list}, safe=False)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
