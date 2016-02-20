// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net.Http;

using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.OAuthGeneric
{
	/// <summary>
	/// Configuration options for <see cref="OAuthMiddleware"/>.
	/// </summary>
	public class OAuthOptions : AuthenticationOptions
	{
		public const string DEFAULT_AUTH_TYPE = "OAuth";
		private IOAuthEvents _events = new OAuthEvents();

		#region Client & Endpoints options
		
		/// <summary>
		/// Gets or sets the provider-assigned client id.
		/// </summary>
		public string ClientId { get; set; }

		/// <summary>
		/// Gets or sets the provider-assigned client secret.
		/// </summary>
		public string ClientSecret { get; set; }

		/// <summary>
		/// A list of permissions to request.
		/// </summary>
		public IList<string> Scopes { get; private set; }

		/// <summary>
		/// Gets or sets the URI where the client will be redirected to authenticate.
		/// </summary>
		public string AuthorizationEndpoint { get; set; }

		/// <summary>
		/// Gets or sets the URI the middleware will access to exchange the OAuth token.
		/// </summary>
		public string TokenEndpoint { get; set; }

		/// <summary>
		/// Gets or sets the URI the middleware will access to obtain the user information.
		/// This value is not used in the default implementation, it is for use in custom implementations of
		/// IOAuthAuthenticationEvents.Authenticated or OAuthAuthenticationHandler.CreateTicketAsync.
		/// </summary>
		public string UserInformationEndpoint { get; set; }

		/// <summary>
		///     The request path within the application's base path where the user-agent will be returned.
		///     The middleware will process this request when it arrives.
		///     Default value is "/signin".
		/// </summary>
		public PathString CallbackPath { get; set; }

		#endregion

		#region Backchannel

		/// <summary>
		/// Gets or sets timeout value in milliseconds for back channel communications with the remote provider.
		/// </summary>
		/// <value>
		/// The back channel timeout.
		/// </value>
		public TimeSpan BackchannelTimeout { get; set; }

		/// <summary>
		/// The HttpMessageHandler used to communicate with Twitter.
		/// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
		/// can be downcast to a WebRequestHandler.
		/// </summary>
		public HttpMessageHandler BackchannelHttpHandler { get; set; }

		#endregion

		#region Authentication Options

		/// <summary>
		/// Defines whether access and refresh tokens should be stored in the
		/// <see cref="ClaimsPrincipal"/> after a successful authorization with the remote provider.
		/// This property is set to <c>false</c> by default to reduce
		/// the size of the final authentication cookie.
		/// </summary>
		public bool SaveTokensAsClaims { get; set; }

		/// <summary>
		///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
		///     <see cref="System.Security.Claims.ClaimsIdentity" />.
		/// </summary>
		public string SignInAsAuthenticationType { get; set; }

		#endregion

		/// <summary>
		/// Gets or sets the <see cref="IOAuthEvents"/> used to handle authentication events.
		/// </summary>
		public IOAuthEvents Events
		{
			get { return _events; }
			set { _events = value; }
		}

		/// <summary>
		/// Gets or sets the type used to secure data handled by the middleware.
		/// </summary>
		public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

		public OAuthOptions()
			: base(DEFAULT_AUTH_TYPE)
		{
			CallbackPath = new PathString("/oauth/return");
			AuthenticationMode = AuthenticationMode.Passive;
			BackchannelTimeout = TimeSpan.FromSeconds(60);
			Scopes = new List<string>
			{
				"user"
			};
			Description.Caption = "OAuth";

			_events = new OAuthEvents();
		}
	}
}