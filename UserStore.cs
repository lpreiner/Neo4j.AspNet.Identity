using Microsoft.AspNet.Identity;
using Neo4jClient;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Neo4j.AspNet.Identity
{
    public class UserStore<TUser> : IUserLoginStore<TUser>, IUserClaimStore<TUser>, IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>, IUserStore<TUser>, IUserEmailStore<TUser>
        where TUser : IdentityUser
    {
		const string LOGIN_NODE_LABEL = "Login";
		const string USER_NODE_LABEL = "User";		
		const string USER_LOGIN_LABEL = "HAS_LOGIN";
		
        readonly GraphClient db;
        bool _disposed;

        static GraphClient GetGraphDatabaseFromUri(string serverUriOrName)
        {
            return new GraphClient(new Uri(serverUriOrName));
        }

        public UserStore(string connectionNameOrUri)
			: this(GetGraphDatabaseFromUri(connectionNameOrUri))
        { }

        public UserStore(GraphClient neoDb)
        {
			neoDb.Connect();

            db = neoDb;			
        }

        #region IUserLoginStore

        public Task AddLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null || user.Id == null)
                throw new ArgumentNullException("user");

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
				db.Cypher
					.Match(GetUserNode("u"), GetLoginNode("l"))
					.Where((TUser u) => u.Id == user.Id)
					.AndWhere((UserLoginInfo l) => l.LoginProvider == login.LoginProvider)
					.Create("(u)-[ul:HAS_LOGIN {login}]->(l)")
					.WithParam("login", new 
						{ 
							ProviderKey = login.ProviderKey,
							ConnectedOn = DateTime.Now,
						})
					.ExecuteWithoutResults();

                user.Logins.Add(login);
            }

            return Task.FromResult(true);
        }

        public Task<TUser> FindAsync(UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (login == null)
                throw new ArgumentNullException("login");

            var query = db.Cypher
                .Match(GetLoginNode("l") + "<-[ul:HAS_LOGIN]-" + GetUserNode("u"))
                .Where((UserLoginInfo l) => l.LoginProvider == login.LoginProvider)
				.AndWhere((UserLoginInfo ul) => ul.ProviderKey == login.ProviderKey)
                .Return(u => u.As<TUser>());

			var user = query.Results.FirstOrDefault();

            return Task.FromResult(user);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.Logins as IList<UserLoginInfo>);
        }

        public Task RemoveLoginAsync(TUser user, UserLoginInfo login)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Logins.RemoveAll(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);

            return Task.FromResult(0);
        }

        public Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Id = Guid.NewGuid().ToString();

            db.Cypher.Create("(u:User { user })")
                                      .WithParams(new { user })
                                      .ExecuteWithoutResults();

            return Task.FromResult(user);
        }

        public Task DeleteAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null || user.Id == null)
                throw new ArgumentNullException("user");

            db.Cypher
				.Match(GetUserNode("u"))
                .Where((TUser u) => u.Id == user.Id)
                .Delete("u")
                .ExecuteWithoutResults();

            return Task.FromResult(0);
        }

        public Task<TUser> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();

            TUser user = db.Cypher
					  .Match(GetUserNode("u"))
                      .Where((TUser u) => u.Id == userId)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault();

            return Task.FromResult(user);
        }

        public Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();

            TUser user = db.Cypher
						.Match(GetUserNode("u"))
                        .Where((TUser u) => u.UserName == userName)
                        .Return(u => u.As<TUser>())
                        .Results
                        .FirstOrDefault();

            return Task.FromResult(user);
        }

        public Task UpdateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null || user.Id == null)
                throw new ArgumentNullException("user");

            db.Cypher
				.Match(GetUserNode("u"))
                .Where((TUser u) => u.Id == user.Id)
                .Set("u = {user}")
                .WithParam("user", user)
                .ExecuteWithoutResults();

            return Task.FromResult(user);
        }

        public void Dispose()
        {
            _disposed = true;
        } 
        
		#endregion

        #region IUserClaimStore

        public Task AddClaimAsync(TUser user, System.Security.Claims.Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Claims.Any(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value))
            {
                user.Claims.Add(new IdentityUserClaim
                {
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value
                });
            }

            return Task.FromResult(0);
        }

        public Task<IList<Claim>> GetClaimsAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

			var roles = GetRolesAsync(user).Result.Take(0).Select(r => new Claim(ClaimTypes.Role, r));
            var claims = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue));

			IList<Claim> result = claims.Concat(roles).ToList();
            return Task.FromResult(result);
        }

        public Task RemoveClaimAsync(TUser user, System.Security.Claims.Claim claim)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Claims.RemoveAll(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            return Task.FromResult(0);
        } 
        #endregion

        #region IUserRoleStore
        public Task AddToRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            if (!user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase))
                user.Roles.Add(roleName);

            return Task.FromResult(true);
        }

        public Task<IList<string>> GetRolesAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult<IList<string>>(user.Roles);
        }

        public Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase));
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.Roles.RemoveAll(r => String.Equals(r, roleName, StringComparison.InvariantCultureIgnoreCase));

            return Task.FromResult(0);
        } 
        #endregion

        #region IUserPasswordStore
        public Task<string> GetPasswordHashAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        } 
        #endregion

        #region IUserSecurityStampStore
        public Task<string> GetSecurityStampAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            return Task.FromResult(user.SecurityStamp);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp)
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException("user");

            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        } 
        #endregion

        #region IUserEmailStore
        public Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();

            TUser user = db.Cypher
					  .Match(GetUserNode("u"))
                      .Where((TUser u) => u.Email == email)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault();
            
            return Task.FromResult(user);
        }

        public Task<string> GetEmailAsync(TUser user)
        {
            ThrowIfDisposed();

            string email = db.Cypher
					  .Match(GetUserNode("u"))
                      .Where((TUser u) => u.Id == user.Id)
                      .Return(u => u.As<TUser>())
                      .Results
                      .SingleOrDefault()
                      .Email;

            return Task.FromResult<string>(email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailAsync(TUser user, string email)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
        {
            throw new NotImplementedException();
        } 
        #endregion

		#region Utility

		void ThrowIfDisposed()
		{
			if (_disposed)
				throw new ObjectDisposedException(GetType().Name);
		}

		string GetNode(string alias, string label)
		{
			return String.Format("({0}:{1})", alias, label);
		}

		string GetUserNode(string alias)
		{
			return GetNode(alias, USER_NODE_LABEL);
		}

		string GetLoginNode(string alias)
		{
			return GetNode(alias, LOGIN_NODE_LABEL);
		}

		#endregion

	}
}