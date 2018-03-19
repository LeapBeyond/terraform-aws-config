# AWS Config with Terraform

This example shows enabling [Config](https://aws.amazon.com/documentation/config/). It includes setting up
a role for Config to use, an S3 bucket for logging, and uses a pre-existing SNS topic to send alerts.
In reality, it would be expected that the resources used by [terraform-aws-cloudtrail](https://github.com/LeapBeyond/terraform-aws-cloudtrail)
and [terraform-aws-guardduty](https://github.com/LeapBeyond/terraform-aws-guardduty) would be shared in a coordinated
fashion rather than creating independent S3 and IAM resources.

This example uses a reasonably complete set of [managed Config rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html),
but does not include an example of writing your own rules to be managed by Lambda. [Config](https://aws.amazon.com/documentation/config/) is a particularly
sophisticated service, and ideally you go into using it with some understanding of what the rules are that you want on your account. Be cautious as well,
the [pricing](https://aws.amazon.com/config/pricing/) on this service gets pretty exciting if you are just experimenting!

## Usage
It is assumed that:
 - appropriate AWS credentials are available
 - terraform is available

Make a `terraform.tfvars` file using the `terraform.tfvars.template`, and then

```
terraform init
terraform apply
```

Eventually you should see output similar to

```
bucket_arn = arn:aws:s3:::config20180319151029294700000001
recorder_id = config-example
```


## License
Copyright 2018 Leap Beyond Analytics

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
