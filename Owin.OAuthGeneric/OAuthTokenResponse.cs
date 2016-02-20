// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace Owin.OAuthGeneric
{
	public class OAuthTokenResponse
	{
		private OAuthTokenResponse(dynamic response)
		{
			Response = response;
			AccessToken = response.access_token as string;
			TokenType = response.token_type as string;
			RefreshToken = response.refresh_token as string;
			ExpiresIn = response.expires_in as string;
		}

		private OAuthTokenResponse(Exception error)
		{
			Error = error;
		}

		public static OAuthTokenResponse Success(dynamic response)
		{
			return new OAuthTokenResponse(response);
		}

		public static OAuthTokenResponse Failed(Exception error)
		{
			return new OAuthTokenResponse(error);
		}

		public dynamic Response { get; set; }
		public string AccessToken { get; set; }
		public string TokenType { get; set; }
		public string RefreshToken { get; set; }
		public string ExpiresIn { get; set; }
		public Exception Error { get; set; }
	}
}