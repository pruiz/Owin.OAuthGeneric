// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;

using Microsoft.Owin.Security;

namespace Owin.OAuthGeneric
{
	/// <summary>
	/// Default <see cref="IOAuthEvents"/> implementation.
	/// </summary>
	public class OAuthEvents : IOAuthEvents
	{
		public OAuthEvents()
		{
			OnCreatingTicket = context => Task.FromResult(0);
			OnRedirectToAuthorizationEndpoint = context =>
			{
				context.Response.Redirect(context.RedirectUri);
				return Task.FromResult(0);
			};
			OnRemoteFailure = context => Task.FromResult(0);
			OnTicketReceived = context => Task.FromResult(0);
		}

		/// <summary>
		/// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
		/// </summary>
		public Func<OAuthCreatingTicketContext, Task> OnCreatingTicket { get; set; }

		/// <summary>
		/// Gets or sets the delegate that is invoked when the RedirectToAuthorizationEndpoint method is invoked.
		/// </summary>
		public Func<OAuthRedirectToAuthorizationContext, Task> OnRedirectToAuthorizationEndpoint { get; set; }

		public Func<OAuthFailureContext, Task> OnRemoteFailure { get; set; }

		public Func<OAuthTicketReceivedContext, Task> OnTicketReceived { get; set; }

		/// <summary>
		/// Invoked after the provider successfully authenticates a user.
		/// </summary>
		/// <param name="context">Contains information about the login session as well as the user <see cref="ClaimsIdentity"/>.</param>
		/// <returns>A <see cref="Task"/> representing the completed operation.</returns>
		public virtual Task CreatingTicket(OAuthCreatingTicketContext context)
		{
			return OnCreatingTicket(context);
		}

		/// <summary>
		/// Called when a Challenge causes a redirect to authorize endpoint in the OAuth middleware.
		/// </summary>
		/// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge.</param>
		public virtual Task RedirectToAuthorizationEndpoint(OAuthRedirectToAuthorizationContext context)
		{
			return OnRedirectToAuthorizationEndpoint(context);
		}

		/// <summary>
		/// Invoked when there is a remote failure
		/// </summary>
		public virtual Task RemoteFailure(OAuthFailureContext context)
		{
			return OnRemoteFailure(context);
		}

		/// <summary>
		/// Invoked after the remote ticket has been received.
		/// </summary>
		public virtual Task TicketReceived(OAuthTicketReceivedContext context)
		{
			return OnTicketReceived(context);
		}
	}
}