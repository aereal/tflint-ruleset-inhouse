package rules

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AwsIamEnforcePolicyDocumentData(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		expected helper.Issues
	}{
		{
			name: "use data.aws_iam_policy_document",
			content: `
data "aws_iam_policy_document" "example" {
  statement {
    actions = [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
    ]
    resources = [
      "arn:aws:s3:::*",
    ]
  }
}

resource "aws_iam_policy" "example" {
	policy = data.aws_iam_policy_document.example.json
}
`,
			expected: helper.Issues{},
		},
		{
			name: "use jsonencode()",
			content: `
resource "aws_iam_policy" "example" {
	policy = jsonencode({})
}
`,
			expected: helper.Issues{
				{
					Rule:    NewAwsIamEnforcePolicyDocumentData(),
					Message: "aws_iam_policy.policy must be a reference to aws_iam_policy_document data",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 2},
						End:      hcl.Pos{Line: 3, Column: 25},
					},
				},
			},
		},
		{
			name: "string literal",
			content: `
resource "aws_iam_policy" "example" {
	policy = "{}"
}
`,
			expected: helper.Issues{
				{
					Rule:    NewAwsIamEnforcePolicyDocumentData(),
					Message: "aws_iam_policy.policy must be a reference to aws_iam_policy_document data",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 2},
						End:      hcl.Pos{Line: 3, Column: 15},
					},
				},
			},
		},
	}
	rule := NewAwsIamEnforcePolicyDocumentData()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": tc.content})
			if err := rule.Check(runner); err != nil {
				t.Fatal(err)
			}
			helper.AssertIssues(t, tc.expected, runner.Issues)
		})
	}
}
