using FluentValidation;
using AISecurityScanner.Application.Interfaces;

namespace AISecurityScanner.Application.Validators
{
    public class CreateRepositoryRequestValidator : AbstractValidator<CreateRepositoryRequest>
    {
        public CreateRepositoryRequestValidator()
        {
            RuleFor(x => x.Name)
                .NotEmpty()
                .WithMessage("Repository name is required")
                .MaximumLength(200)
                .WithMessage("Repository name cannot exceed 200 characters");

            RuleFor(x => x.GitUrl)
                .NotEmpty()
                .WithMessage("Git URL is required")
                .MaximumLength(500)
                .WithMessage("Git URL cannot exceed 500 characters")
                .Must(BeValidGitUrl)
                .WithMessage("Invalid Git URL format");

            RuleFor(x => x.OrganizationId)
                .NotEmpty()
                .WithMessage("Organization ID is required");

            RuleFor(x => x.Language)
                .NotEmpty()
                .WithMessage("Programming language is required")
                .MaximumLength(50)
                .WithMessage("Language cannot exceed 50 characters");

            RuleFor(x => x.DefaultBranch)
                .MaximumLength(100)
                .WithMessage("Default branch cannot exceed 100 characters");
        }

        private static bool BeValidGitUrl(string gitUrl)
        {
            if (string.IsNullOrEmpty(gitUrl))
                return false;

            return gitUrl.StartsWith("https://") || gitUrl.StartsWith("git@");
        }
    }
}