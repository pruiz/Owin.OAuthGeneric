// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.Http;
using System.Text;

using Owin;

using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.OAuthGeneric
{
	/// <summary>
	/// An ASP.NET middleware for authenticating users using OAuth services.
	/// </summary>
	[SuppressMessage("Microsoft.Design", "CA1001:TypesThatOwnDisposableFieldsShouldBeDisposable", Justification = "Middleware are not disposable.")]
	public class OAuthMiddleware<TOptions> : AuthenticationMiddleware<TOptions> 
		where TOptions : OAuthOptions, new()
	{
		protected IAppBuilder App { get; private set; }
		protected HttpClient Backchannel { get; private set; }

		/// <summary>
		/// Initializes a new <see cref="OAuthAuthenticationMiddleware"/>.
		/// </summary>
		/// <param name="next">The next middleware in the HTTP pipeline to invoke.</param>
		/// <param name="dataProtectionProvider"></param>
		/// <param name="loggerFactory"></param>
		/// <param name="options">Configuration options for the middleware.</param>
		public OAuthMiddleware(
			OwinMiddleware next,
			IAppBuilder app,
			TOptions options)
			: base(next, options)
		{
			if (next == null)
			{
				throw new ArgumentNullException("next");
			}

			if (app == null)
			{
				throw new ArgumentNullException("app");
			}

			if (options == null)
			{
				throw new ArgumentNullException("options");
			}

			App = app;

			var message = /*message*/ "Missing required option: {0}";

			// todo: review error handling
			if (string.IsNullOrEmpty(Options.AuthenticationType))
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "Options.AuthenticationType"));
			}

			if (string.IsNullOrEmpty(Options.ClientId))
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "Options.ClientId"));
			}

			if (string.IsNullOrEmpty(Options.ClientSecret))
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "Options.ClientSecret"));
			}

			if (string.IsNullOrEmpty(Options.AuthorizationEndpoint))
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "Options.AuthorizationEndpoint"));
			}

			if (string.IsNullOrEmpty(Options.TokenEndpoint))
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "Options.TokenEndpoint"));
			}

			if (!Options.CallbackPath.HasValue)
			{
				throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "Options.CallbackPath"));
			}

			if (Options.Events == null)
			{
				Options.Events = new OAuthEvents();
			}

			if (Options.StateDataFormat == null)
			{
				var dataProtector = app.CreateDataProtector(GetType().FullName, Options.AuthenticationType, "v1");
				Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
			}

			Backchannel = new HttpClient(Options.BackchannelHttpHandler ?? new HttpClientHandler());
			Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Generic Owin OAuth middleware");
			Backchannel.DefaultRequestHeaders.ExpectContinue = false;
			Backchannel.Timeout = Options.BackchannelTimeout;
			Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB

			if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
			{
				Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
			}
		}


		/// <summary>
		/// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
		/// </summary>
		/// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="OAuthOptions"/> supplied to the constructor.</returns>
		protected override AuthenticationHandler<TOptions> CreateHandler()
		{
			return new OAuthHandler<TOptions>(Backchannel, App.CreateLogger("OAuthHandler:" + Options.AuthenticationType));
		}
	}
}