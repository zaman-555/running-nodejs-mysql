
# Running MySQL & Node.js using systemd Services



## Prerequisites

Two servers have been deployed in our infrastructure, correct? a database server and an application server for Node.js. We've positioned the database server in a private subnet to improve security by blocking direct public access. If you look at our Infrastructure as Code (IaC) Pulumi settings, you'll see that the database server isn't accessible from the internet since we haven't given it a public IP address.

We must use a jump box technique in order to reach the database server.  Using the same key pair, we first SSH into the Node.js server using its public IP and then go on to the database server using its private IP.  The database security group setting, which only allows SSH and database connection ports from the public network (where our Node.js server is located), is an example of how the infrastructure code reflects this architecture.

## Task Overview

We'll carry out each following task.

- Use Pulumi to create the necessary resources on AWS.
- On the DB-server, create an MYSQL server.
- On the app server, create a Node.js application service.
- Make sure the MySQL service is a prerequisite for the Node.js application service.
- To wait for MySQL to be ready, implement a health check in the Node.js application service.


## AWS infrastructure

We will set up a VPC and two subnets in separate regions for this lab.  The database server will be on one subnet, while the Node.is server will be on the other.  The private subnet will consist of the database server, whereas the public subnet will contain the Nodeis server.  Their security group will be separate.


![Diagram](./images/image_1.png)


## Configure AWS Credentials

```bash
aws configure
```

```bash

AWS Access Key ID [None]: AKIAXXXXXXXXXXXXXXXX                  # Get from IAM
AWS Secret Access Key [None]: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  # Get from IAM
Default region name [None]: us-east-1                           # Preferred region
Default output format [None]: json                              # Recommended

```

## Create a Directory for Infrastructure

Let's create a root folder that i called running-nodejs-mysql inside i created two different one for script and service-infra. 


```bash
mkdir running-nodejs-mysql
cd running-nodejs-mysql
mkdir service-infra
mkdir script
```

In order to work with Pulumi following, set up a Python virtual environment.

Before you run `pulumi new aws-python` make sure to create a new SSH key pair for use with an AWS RDS DB Cluster, you can use the AWS CLI command aws ec2 create-key-pair. Here's the command to create a new key pair and save it to a file named db-cluster.pem:

```bash
cd ~/.ssh/
aws ec2 create-key-pair --key-name db-cluster --query 'KeyMaterial' --output text > db-cluster.pem

```
After creating the key pair, set restrictive permissions on the .pem file to keep it secure:

```bash
chmod 400 db-cluster.pem

```

```bash
brew install pulumi
pulumi new aws-python
pulumi new aws-python --force

```
Project:  `mysqlapp`
Stack name: `dev`
Description: `A simple nodejs db cluster`
Region: `us-east-1`

Go with the default values and enter to create the project.



## Update the  `__main__.py` file:

Define the AWS infrastructure needed for the database and application server by opening the __main__.py file.  The foundational architecture needed to set up a database and Virtual Private Cloud (VPC) application, including subnets, security groups, NAT gateways, Internet gateways, route tables, and EC2 instances, is provided by this Pulumi code.



```bash
import pulumi
import pulumi_aws as aws
import os

# Get available availability zones in the region
available_zones = aws.get_availability_zones(state="available")

# Create a VPC
vpc = aws.ec2.Vpc(
    'nodejs-db-vpc',
    cidr_block='10.0.0.0/16',
    enable_dns_support=True,
    enable_dns_hostnames=True,
    tags={'Name': 'nodejs-db-vpc'}
)

# Create public and private subnets in different AZs for high availability
public_subnet = aws.ec2.Subnet(
    'nodejs-public-subnet',
    vpc_id=vpc.id,
    cidr_block='10.0.1.0/24',
    map_public_ip_on_launch=True,
    availability_zone=available_zones.names[0],  # First available AZ
    tags={'Name': 'nodejs-public-subnet'}
)

private_subnet = aws.ec2.Subnet(
    'db-private-subnet',
    vpc_id=vpc.id,
    cidr_block='10.0.2.0/24',
    map_public_ip_on_launch=False,
    availability_zone=available_zones.names[1],  # Second available AZ
    tags={'Name': 'db-private-subnet'}
)
# Create an Internet Gateway
internet_gateway = aws.ec2.InternetGateway(
    'nodejs-db-internet-gateway',
    vpc_id=vpc.id,
    tags={'Name': 'nodejs-db-internet-gateway'}
)

# Create NAT Gateway for private subnet
elastic_ip = aws.ec2.Eip('nat-eip')

nat_gateway = aws.ec2.NatGateway(
    'nat-gateway',
    allocation_id=elastic_ip.id,
    subnet_id=public_subnet.id,
    tags={'Name': 'nodejs-db-nat-gateway'}
)

# Create public Route Table
public_route_table = aws.ec2.RouteTable(
    'public-route-table',
    vpc_id=vpc.id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block='0.0.0.0/0',
            gateway_id=internet_gateway.id,
        )
    ],
    tags={'Name': 'nodejs-public-route-table'}
)

# Create private Route Table
private_route_table = aws.ec2.RouteTable(
    'private-route-table',
    vpc_id=vpc.id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block='0.0.0.0/0',
            nat_gateway_id=nat_gateway.id,
        )
    ],
    tags={'Name': 'db-private-route-table'}
)

# Associate route tables with subnets
public_route_table_association = aws.ec2.RouteTableAssociation(
    'public-route-table-association',
    subnet_id=public_subnet.id,
    route_table_id=public_route_table.id
)

private_route_table_association = aws.ec2.RouteTableAssociation(
    'private-route-table-association',
    subnet_id=private_subnet.id,
    route_table_id=private_route_table.id
)

# Create security group for Node.js application
nodejs_security_group = aws.ec2.SecurityGroup(
    'nodejs-security-group',
    vpc_id=vpc.id,
    description="Security group for Node.js application",
    ingress=[
        # SSH access
        aws.ec2.SecurityGroupIngressArgs(
            protocol='tcp',
            from_port=22,
            to_port=22,
            cidr_blocks=['0.0.0.0/0'],  # Consider restricting to your IP
        ),
        # Node.js application port
        aws.ec2.SecurityGroupIngressArgs(
            protocol='tcp',
            from_port=3000,
            to_port=3000,
            cidr_blocks=['0.0.0.0/0'],
        ),
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol='-1',
            from_port=0,
            to_port=0,
            cidr_blocks=['0.0.0.0/0'],
        )
    ],
    tags={'Name': 'nodejs-security-group'}
)

# Create security group for MySQL database
db_security_group = aws.ec2.SecurityGroup(
    'db-security-group',
    vpc_id=vpc.id,
    description="Security group for MySQL database",
    ingress=[
        # SSH access from Node.js subnet
        aws.ec2.SecurityGroupIngressArgs(
            protocol='tcp',
            from_port=22,
            to_port=22,
            cidr_blocks=[public_subnet.cidr_block],
        ),
        # MySQL access from Node.js subnet
        aws.ec2.SecurityGroupIngressArgs(
            protocol='tcp',
            from_port=3306,
            to_port=3306,
            cidr_blocks=[public_subnet.cidr_block],
        ),
    ],
    egress=[
        aws.ec2.SecurityGroupEgressArgs(
            protocol='-1',
            from_port=0,
            to_port=0,
            cidr_blocks=['0.0.0.0/0'],
        )
    ],
    tags={'Name': 'db-security-group'}
)

# Create EC2 Instance for DB
db = aws.ec2.Instance(
    'db-server',
    instance_type='t2.micro',
    ami='ami-0655cec52acf2717b',  # Update with correct Ubuntu AMI ID
    subnet_id=private_subnet.id,
    key_name="db-cluster",
    vpc_security_group_ids=[db_security_group.id],
    tags={'Name': 'db-server'}
)

# Update the path of the script to the path of the script in the root directory
with open('/Users/mohammaduzzaman/Documents/running-nodejs-mysql/script/check-mysql.sh', 'r') as file:
    print("Reading From script...\n")
    mysql_check_script = file.read()

def generate_nodejs_user_data(db_private_ip):
    return f'''#!/bin/bash
exec > >(tee /var/log/user-data.log) 2>&1

# Update system and install dependencies
apt-get update
apt-get upgrade -y
apt-get install -y netcat-openbsd

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Create script directory
mkdir -p /usr/local/bin

# Set environment variable for DB IP
echo "DB_PRIVATE_IP={db_private_ip}" >> /etc/environment

# Create MySQL check script
cat > /usr/local/bin/check-mysql.sh << 'EOL'
{mysql_check_script}
EOL

chmod +x /usr/local/bin/check-mysql.sh
'''

# Update your Pulumi EC2 instance configurations
nodejs = aws.ec2.Instance(
    'nodejs-server',
    instance_type='t2.micro',
    ami='ami-0655cec52acf2717b',  # Update with correct Ubuntu AMI ID
    subnet_id=public_subnet.id,
    key_name="db-cluster",
    vpc_security_group_ids=[nodejs_security_group.id],
    associate_public_ip_address=True,
    user_data=pulumi.Output.all(db.private_ip).apply(
        lambda args: generate_nodejs_user_data(args[0])
    ),
    user_data_replace_on_change=True,
    tags={'Name': 'nodejs-server'}
)


# Export Public and Private IPs
pulumi.export('nodejs_public_ip', nodejs.public_ip)
pulumi.export('nodejs_private_ip', nodejs.private_ip)
pulumi.export('db_private_ip', db.private_ip)

# Export the VPC ID and Subnet IDs for reference
pulumi.export('vpc_id', vpc.id)
pulumi.export('public_subnet_id', public_subnet.id)
pulumi.export('private_subnet_id', private_subnet.id)

# Create config file
def create_config_file(all_ips):
    config_content = f"""Host nodejs-server
    HostName {all_ips[0]}
    User ubuntu
    IdentityFile ~/.ssh/db-cluster.id_rsa

Host db-server
    ProxyJump nodejs-server
    HostName {all_ips[1]}
    User ubuntu
    IdentityFile ~/.ssh/db-cluster.id_rsa
"""
    
    config_path = os.path.expanduser("~/.ssh/config")
    with open(config_path, "w") as config_file:
        config_file.write(config_content)

# Collect the IPs for all nodes
all_ips = [nodejs.public_ip, db.private_ip]

# Create the config file with the IPs once the instances are ready
pulumi.Output.all(*all_ips).apply(create_config_file)


```
This will create the infrastructure and output the public and private IPs of the Node.js and db-servers.

```bash
pulumi up --yes 

```
We must use a jump box technique in order to reach the database server.  Using the same key pair, we first SSH into the Nodejs-server using its public IP and then go on to the database server or db-server using its private IP.  The database security group setting, which only allows SSH and database connection ports from the public network (where our Node.js server is located), is an example of how the infrastructure code reflects this architecture.

![Diagram](./images/image_3.png)


A network protocol called SSH (Secure Shell or Secure Socket Shell) provides users—especially system administrators—with a safe means of connecting to a machine across an unprotected network.   It also describes the group of programs that carry out the SSH protocol.  Secure Shell offers secured data communications between two computers connected via the internet, as well as robust password and public key authentication.  Network administrators frequently use SSH to remotely administer systems and apps, allowing them to move files between computers, run commands, and log in to another computer via a network.


![Diagram](./images/image_4.png)

# Rename Both Instances

```bash
sudo hostnamectl set-hostname nodejs-server
sudo hostnamectl set-hostname db-server

```


# Create a script to check if MySql is up and running

We created a directory name script from the beginning called `script`and add the following content to the file named `checked-mysql.sh` This Bash script verifies TCP connectivity to a MySQL server with configurable retry logic, making it ideal for deployment health checks or service dependency verification.

- Port Connectivity Testing: Uses netcat (nc -z) to check if MySQL's port (default: 3306) is reachable.
- Retry Mechanism: Retries up to MAX_RETRIES (default: 30) with a delay of RETRY_INTERVAL (default: 10 seconds) between attempts.
- Clear Logging: Outputs connection attempts and success/failure status.
- Lightweight: No external dependencies beyond netcat.
- Configurable: Customize via environment variables (DB_PRIVATE_IP, DB_PORT, etc.).

## Typical Use Cases:

- Validate MySQL availability before application deployment.
- Health checks for containers or auto-scaling groups.
- Integration in CI/CD pipelines to ensure database readiness.

```bash
#!/bin/bash
DB_HOST="$DB_PRIVATE_IP"
DB_PORT=3306
MAX_RETRIES=30
RETRY_INTERVAL=10

check_mysql() {
    nc -z "$DB_HOST" "$DB_PORT"
    return $?
}

retry_count=0
while [ $retry_count -lt $MAX_RETRIES ]; do
    if check_mysql; then
        echo "Successfully connected to MySQL at $DB_HOST:$DB_PORT"
        exit 0
    fi
    echo "Attempt $((retry_count + 1))/$MAX_RETRIES: Cannot connect to MySQL at $DB_HOST:$DB_PORT. Retrying in $RETRY_INTERVAL seconds..."
    sleep $RETRY_INTERVAL
    retry_count=$((retry_count + 1))
done

echo "Failed to connect to MySQL after $MAX_RETRIES attempts"
exit 1


```
>  **Note** 
> If you create the script in the root directory, you need to change or modify the path of the script in the `__main__.py` file. In my case i did `'/Users/mohammaduzzaman/Documents/running-nodejs-mysql/script/check-mysql.sh'`

![Diagram](./images/image_5.png)


# Install MySQL

```bash
sudo apt-get update
sudo apt-get install mysql-server

```
# Configure MySQL to allow remote connections

We need to modify or update `blind-address = 172.0.0.1` to  `blind-address = 0.0.0.0`

```bash
sudo sudo vi /etc/mysql/mysql.conf.d/mysqld.cnf
sudo mysql

```


```bash
CREATE DATABASE app_db;
CREATE USER 'app_user'@'%' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON app_db.* TO 'app_user'@'%';
FLUSH PRIVILEGES;
exit;

```
run this command you can see the newly created database app_db.

```bash
mysql> show databases;

```
![Diagram](./images/image_6.png)

# Restart MySql to apply change

```bash
sudo systemctl restart mysql
sudo systemctl status mysql

```

![Diagram](./images/image_7.png)

# Create mySql-check.service in the nodejs-server

Follow the sequence based on **Image_8**  First, check if we have the envirment variable ssh for the **DB private IP**.

```bash
echo $DB_PRIVATE_IP

```

![Diagram](./images/image_8.png)

# Create a systemd service for the MySQL check script

This will create a systemd servic for the MySql check script `check-mysql.sh` in the nodejs-server. It will start the MySQL check script once the network is up.

```bash
sudo vi /etc/systemd/system/mysql-check.service

```
Add the following content to the file:

```bash
[Unit]
Description=MySQL Availability Check
After=network.target

[Service]
Type=oneshot
EnvironmentFile=/etc/environment
ExecStart=/usr/local/bin/check-mysql.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target

```
