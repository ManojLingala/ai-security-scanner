using FluentValidation;
using AISecurityScanner.Application.Interfaces;

namespace AISecurityScanner.Application.Validators
{
    public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
    {
        public CreateUserRequestValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .WithMessage("Email is required")
                .EmailAddress()
                .WithMessage("Invalid email format")
                .MaximumLength(256)
                .WithMessage("Email cannot exceed 256 characters");

            RuleFor(x => x.FirstName)
                .NotEmpty()
                .WithMessage("First name is required")
                .MaximumLength(100)
                .WithMessage("First name cannot exceed 100 characters");

            RuleFor(x => x.LastName)
                .NotEmpty()
                .WithMessage("Last name is required")
                .MaximumLength(100)
                .WithMessage("Last name cannot exceed 100 characters");

            RuleFor(x => x.Role)
                .IsInEnum()
                .WithMessage("Invalid user role");

            RuleFor(x => x.OrganizationId)
                .NotEmpty()
                .WithMessage("Organization ID is required");

            RuleFor(x => x.PhoneNumber)
                .MaximumLength(20)
                .WithMessage("Phone number cannot exceed 20 characters");
        }
    }
}