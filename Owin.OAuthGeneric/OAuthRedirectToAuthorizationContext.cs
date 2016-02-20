// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.OAuthGeneric
{
	/// <summary>
	/// Context passed when a Challenge causes a redirect to authorize endpoint in the middleware.
	/// </summary>
	public class OAuthRedirectToAuthorizationContext : BaseContext
	{
		/// <summary>
		/// Creates a new context object.
		/// </summary>
		/// <param name="context">The HTTP request context.</param>
		/// <param name="properties">The authentication properties of the challenge.</param>
		/// <param name="redirectUri">The initial redirect URI.</param>
		public OAuthRedirectToAuthorizationContext(IOwinContext context, OAuthOptions options, AuthenticationProperties properties, string redirectUri)
			: base(context)
		{
			RedirectUri = redirectUri;
			Properties = properties;
			Options = options;
		}

		public OAuthOptions Options { get; private set; }

		/// <summary>
		/// Gets the URI used for the redirect operation.
		/// </summary>
		public string RedirectUri { get; private set; }

		/// <summary>
		/// Gets the authentication properties of the challenge.
		/// </summary>
		public AuthenticationProperties Properties { get; private set; }
	}
}