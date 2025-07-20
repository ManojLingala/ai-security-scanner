using FluentValidation;
using AISecurityScanner.Application.Models;

namespace AISecurityScanner.Application.Validators
{
    public class StartScanRequestValidator : AbstractValidator<StartScanRequest>
    {
        public StartScanRequestValidator()
        {
            RuleFor(x => x.RepositoryId)
                .NotEmpty()
                .WithMessage("Repository ID is required");

            RuleFor(x => x.ScanType)
                .IsInEnum()
                .WithMessage("Invalid scan type");

            RuleFor(x => x.Branch)
                .MaximumLength(100)
                .WithMessage("Branch name cannot exceed 100 characters");

            RuleFor(x => x.CommitHash)
                .MaximumLength(100)
                .WithMessage("Commit hash cannot exceed 100 characters");

            RuleFor(x => x.TriggerSource)
                .MaximumLength(100)
                .WithMessage("Trigger source cannot exceed 100 characters");
        }
    }
}