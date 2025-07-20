using Raven.Client.Documents.Indexes;
using AISecurityScanner.Domain.Entities;
using System.Linq;

namespace AISecurityScanner.Infrastructure.Data.Indexes
{
    public class Users_ByOrganization : AbstractIndexCreationTask<User>
    {
        public class Result
        {
            public string OrganizationId { get; set; } = string.Empty;
            public string Email { get; set; } = string.Empty;
            public string FullName { get; set; } = string.Empty;
            public bool IsActive { get; set; }
        }

        public Users_ByOrganization()
        {
            Map = users => from user in users
                          select new Result
                          {
                              OrganizationId = user.OrganizationId.ToString(),
                              Email = user.Email,
                              FullName = user.FirstName + " " + user.LastName,
                              IsActive = user.IsActive
                          };

            Index(x => x.OrganizationId, FieldIndexing.Exact);
            Index(x => x.Email, FieldIndexing.Search);
            Index(x => x.FullName, FieldIndexing.Search);
        }
    }
}