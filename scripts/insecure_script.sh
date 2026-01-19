#!/bin/bash

# Insecure shell script with multiple vulnerabilities

# Hardcoded credentials
DB_PASSWORD="SuperSecret123!"
API_KEY="sk_live_4eC39HqLyjWDarhtT657tMo5k"
AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Command injection vulnerability
echo "Enter hostname to ping:"
read hostname
ping -c 1 $hostname  # Unsafe - no validation

# Using eval (code injection)
user_input="$1"
eval $user_input  # Dangerous!

# Downloading and executing from untrusted source
curl http://untrusted-site.com/script.sh | bash

# Writing secrets to file
echo "password=admin123" > /tmp/credentials.txt
echo "api_key=$API_KEY" >> /tmp/credentials.txt

# Insecure file permissions
chmod 777 /tmp/credentials.txt

# Using hardcoded credentials in AWS CLI
aws s3 ls --access-key-id $AWS_ACCESS_KEY --secret-access-key $AWS_SECRET

# SQL command with injection vulnerability
mysql -u root -p$DB_PASSWORD -e "SELECT * FROM users WHERE id = $user_input"

# Logging sensitive data
echo "User logged in with password: $DB_PASSWORD" >> /var/log/app.log

# Unquoted variables (word splitting issues)
filename=$2
cat $filename  # Should be quoted: "$filename"

# Using deprecated cryptography
password="mypassword"
echo $password | md5sum  # MD5 is weak

# No error handling
rm -rf /important/data  # No check if directory exists or is correct

# Hardcoded database connection
psql "postgresql://admin:password123@db.example.com:5432/mydb"
