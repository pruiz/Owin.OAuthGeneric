// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.OAuthGeneric
{
	/// <summary>
	/// Provides failure context information to middleware providers.
	/// </summary>
	public class OAuthFailureContext : BaseContext
	{
		public OAuthFailureContext(IOwinContext context, Exception failure)
			: base(context)
		{
			Failure = failure;
		}

		/// <summary>
		/// User friendly error message for the error.
		/// </summary>
		public Exception Failure { get; set; }

		#region IBaseControlContext

		public OAuthEventState State { get; set; }

		public bool HandledResponse
		{
			get { return State == OAuthEventState.HandledResponse; }
		}

		public bool Skipped
		{
			get { return State == OAuthEventState.Skipped; }
		}

		/// <summary>
		/// Discontinue all processing for this request and return to the client.
		/// The caller is responsible for generating the full response.
		/// Set the <see cref="Ticket"/> to trigger SignIn.
		/// </summary>
		public void HandleResponse()
		{
			State = OAuthEventState.HandledResponse;
		}

		/// <summary>
		/// Discontinue processing the request in the current middleware and pass control to the next one.
		/// SignIn will not be called.
		/// </summary>
		public void SkipToNextMiddleware()
		{
			State = OAuthEventState.Skipped;
		}

		#endregion
	}
}