package rules

import (
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

type AwsIamEnforcePolicyDocumentData struct {
	tflint.DefaultRule
}

func NewAwsIamEnforcePolicyDocumentData() *AwsIamEnforcePolicyDocumentData {
	return &AwsIamEnforcePolicyDocumentData{}
}

func (r *AwsIamEnforcePolicyDocumentData) Name() string {
	return "aws_iam_enforce_policy_document_data"
}

func (r *AwsIamEnforcePolicyDocumentData) Enabled() bool {
	return true
}

func (r *AwsIamEnforcePolicyDocumentData) Severity() tflint.Severity {
	return tflint.WARNING
}

func (r *AwsIamEnforcePolicyDocumentData) Link() string {
	return ""
}

func (r *AwsIamEnforcePolicyDocumentData) Check(runner tflint.Runner) error {
	schema := &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "policy"},
		},
	}
	resources, err := runner.GetResourceContent("aws_iam_policy", schema, nil)
	if err != nil {
		return err
	}
	for _, resource := range resources.Blocks {
		attr, found := resource.Body.Attributes["policy"]
		if !found {
			continue
		}
		var policy string
		if err := runner.EvaluateExpr(attr.Expr, &policy, nil); err == nil {
			_ = runner.EmitIssue(r, "aws_iam_policy.policy must be a reference to aws_iam_policy_document data", attr.Range)
			continue
		}
		if _, ok := attr.Expr.(*hclsyntax.FunctionCallExpr); ok {
			_ = runner.EmitIssue(r, "aws_iam_policy.policy must be a reference to aws_iam_policy_document data", attr.Range)
			continue
		}
	}
	return nil
}
