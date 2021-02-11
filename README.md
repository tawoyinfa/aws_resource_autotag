## Companion source code for "Automatically tag new AWS resources based on Azure AD user attributes" blog post

Use the Python file & AWS IAM policy files located in the "source" directory as input to build an AWS Lambda function that tags matching AWS resources as they are created.  The "Automatically tag new AWS resources based on Azure AD user attribute" blog post explains this resource tagging solution.


The solution details an event driven architecture for automating the tagging of AWS resources using metadata from user attributes of the resource creator obtained from Azure AD. A CloudWatch event is used to trigger a Lambda function that parses Cloudtrail Logs to obtain session tags associated to the username of the resource creator. Asides from EC2 instances, the serverless function in this use case can be extended for tagging other service creation API in AWS.

![Alt text](auto_tag.png?raw=true "Title")


