# Log Analyser

A Python-based log analysis tool for detecting security-related events in authentication logs. The script parses log files, identifies failed and successful login attempts, privilege escalations, and sends alerts to an AWS Lambda function when suspicious activity (such as repeated failed logins) is detected.

---

## Features

- **Pattern Matching:** Uses regular expressions to detect:
  - Failed login attempts
  - Successful logins
  - Privilege escalation events (e.g., sudo session opened)
- **Threshold Alerting:** Triggers an AWS Lambda function if a user exceeds a configurable threshold of failed login attempts.
- **AWS Lambda Integration:** Sends alert payloads to a specified Lambda function for further processing (e.g., notifications, logging).
- **Unmatched Line Reporting:** Collects and displays log lines that do not match any known pattern for further investigation.

---

## Requirements

- Python 3.7+
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- AWS credentials configured (via environment variables, AWS CLI, or IAM role)
- An AWS Lambda function set up to receive and process alert payloads

---

## Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/log-analyser.git
   cd log-analyser
   ```
2. **Install Dependencies**
   ```bash
   pip install boto3
   ```
3. **Configure AWS Credentials**
   Ensure your AWS credentials are configured. You can do this by:
   - Setting environment variables: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   - Using the AWS CLI: `aws configure`
   - Assigning an IAM role to your instance if running on EC2
4. **Set Up AWS Lambda Function**
   Create an AWS Lambda function that will process the alert payloads. Note the function's ARN, as you will need it for configuration.

5. Set the env on your local machine
- Windows:
```bash 
   set FunctionName=YourLambdaFunctionName
```
- macOS/Linux:
```bash
export FunctionName=YourLambdaFunctionName
```

---

The script will parse the log file, detect patterns, and send alerts to the configured AWS Lambda function if suspicious activity is found.