// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace Owin.OAuthGeneric
{
	/// <summary>
	/// Extension methods to add OAuth 2.0 authentication capabilities to an HTTP application pipeline.
	/// </summary>
	public static class OAuthAppBuilderExtensions
	{
		/// <summary>
		/// Adds the <see cref="OAuthMiddleware{TOptions}"/> middleware to the specified <see cref="IApplicationBuilder"/>, which enables OAuth 2.0 authentication capabilities.
		/// </summary>
		/// <param name="app">The <see cref="IApplicationBuilder"/> to add the middleware to.</param>
		/// <param name="options">A <see cref="OAuthOptions"/> that specifies options for the middleware.</param>
		/// <returns>A reference to this instance after the operation has completed.</returns>
		public static IAppBuilder UseOAuthAuthentication(this IAppBuilder app, Action<OAuthOptions> configurer)
		{
			if (app == null)
			{
				throw new ArgumentNullException("app");
			}

			var options = new OAuthOptions();
			if (configurer != null) configurer(options);
			return app.Use<OAuthMiddleware<OAuthOptions>>(app, options);
		}
	}
}