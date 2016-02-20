// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

using MoreLinq;

using WebUtils = Microsoft.Owin.Infrastructure.WebUtilities;

namespace Owin.OAuthGeneric
{
	public class OAuthHandler<TOptions> : AuthenticationHandler<TOptions> 
		where TOptions : OAuthOptions
	{
		private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();
		private readonly ILogger Logger;

		protected HttpClient Backchannel { get; private set; }

		public OAuthHandler(HttpClient backchannel, ILogger logger)
		{
			Backchannel = backchannel;
			this.Logger = logger;
		}

		#region Private Methods

		private string BuildCurrentUri()
		{
			string requestPrefix = Request.Scheme + "://" + Request.Host;
			return requestPrefix + Request.PathBase + Request.Path + Request.QueryString;
		}

		private string BuildRedirectUri(PathString path)
		{
			string requestPrefix = Request.Scheme + "://" + Request.Host;
			return requestPrefix + Request.PathBase + path;
		}

		private static async Task<string> Display(HttpResponseMessage response)
		{
			var output = new StringBuilder();
			output.Append("Status: " + response.StatusCode + ";");
			output.Append("Headers: " + response.Headers.ToString() + ";");
			output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
			return output.ToString();
		}

		#endregion

		protected AuthenticationTicket AuthError(string message, AuthenticationProperties properties = null)
		{
			properties = properties ?? new AuthenticationProperties();
			Logger.WriteError(message);
			properties.Dictionary.Add("message", message);
			return new AuthenticationTicket(null, properties);
		}

		protected AuthenticationTicket AuthError(Exception exception, AuthenticationProperties properties = null)
		{
			properties = properties ?? new AuthenticationProperties();
			Logger.WriteError("Authentication failed", exception);
			properties.Dictionary.Add("message", exception.Message);
			return new AuthenticationTicket(null, properties);
		}

		#region Authenticate
		
		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			AuthenticationProperties properties = null;
			var query = Request.Query;

			var error = query.GetValues("error");
			if (error != null && error.Any())
			{
				var message = new StringBuilder();
				error.ForEach(x => message.Append(x));

				var errorDescription = query["error_description"];
				if (!string.IsNullOrEmpty(errorDescription))
				{
					message.Append(";Description=").Append(errorDescription);
				}
				var errorUri = query["error_uri"];
				if (!string.IsNullOrEmpty(errorUri))
				{
					message.Append(";Uri=").Append(errorUri);
				}

				return AuthError(message.ToString(), properties);
			}

			var code = query["code"];
			var state = query["state"];

			properties = Options.StateDataFormat.Unprotect(state);
			if (properties == null)
			{
				return AuthError("The oauth state was missing or invalid.");
			}

			// OAuth2 10.12 CSRF
			if (!ValidateCorrelationId(properties, Logger))
			{
				return AuthError("Correlation failed.");
			}

			if (string.IsNullOrEmpty(code))
			{
				return AuthError("Code was not found.");
			}

			var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));

			if (tokens.Error != null)
			{
				return AuthError(tokens.Error);
			}

			if (string.IsNullOrEmpty(tokens.AccessToken))
			{
				return AuthError("Failed to retrieve access token.");
			}

			var identity = new ClaimsIdentity(Options.AuthenticationType);

			if (Options.SaveTokensAsClaims)
			{
				identity.AddClaim(new Claim("access_token", tokens.AccessToken, ClaimValueTypes.String, Options.AuthenticationType));

				if (!string.IsNullOrEmpty(tokens.RefreshToken))
				{
					identity.AddClaim(new Claim("refresh_token", tokens.RefreshToken, ClaimValueTypes.String, Options.AuthenticationType));
				}

				if (!string.IsNullOrEmpty(tokens.TokenType))
				{
					identity.AddClaim(new Claim("token_type", tokens.TokenType, ClaimValueTypes.String, Options.AuthenticationType));
				}

				if (!string.IsNullOrEmpty(tokens.ExpiresIn))
				{
					identity.AddClaim(new Claim("expires_in", tokens.ExpiresIn, ClaimValueTypes.String, Options.AuthenticationType));
				}
			}

			//await Options.Events.Authenticated(context);

			return await CreateTicketAsync(identity, properties, tokens);
		}

		protected virtual async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
		{
			var tokenRequestParameters = new Dictionary<string, string>()
			{
				{ "client_id", Options.ClientId },
				{ "redirect_uri", redirectUri },
				{ "client_secret", Options.ClientSecret },
				{ "code", code },
				{ "grant_type", "authorization_code" },
			};

			var requestContent = new FormUrlEncodedContent(tokenRequestParameters);
			var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
			requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
			requestMessage.Content = requestContent;
			var response = await Backchannel.SendAsync(requestMessage, Context.Request.CallCancelled);
			if (response.IsSuccessStatusCode)
			{
				var payload = SimpleJson.DeserializeObject(await response.Content.ReadAsStringAsync()) as dynamic;
				return OAuthTokenResponse.Success(payload);
			}
			else
			{
				var error = "OAuth token endpoint failure: " + await Display(response);
				Logger.WriteError(error);
				return OAuthTokenResponse.Failed(new Exception(error));
			}
		}

		protected virtual async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
		{
			var ticket = new AuthenticationTicket(identity, properties);
			var context = new OAuthCreatingTicketContext(ticket, Context, Options, Backchannel, tokens);
			await Options.Events.CreatingTicket(context);
			return context.Ticket;
		}

		#endregion

		#region Challenge Response Code

		protected virtual string FormatScope()
		{
			// OAuth2 3.3 space separated
			return string.Join(" ", Options.Scopes);
		}

		protected virtual string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
		{
			var scope = FormatScope();
			var state = Options.StateDataFormat.Protect(properties);

			var queryBuilder = new QueryBuilder()
			{
				{ "client_id", Options.ClientId },
				{ "scope", scope },
				{ "response_type", "code" },
				{ "redirect_uri", redirectUri },
				{ "state", state },
			};
			return Options.AuthorizationEndpoint + queryBuilder.ToString();
		}

		protected override Task ApplyResponseChallengeAsync()
		{
			if (Response.StatusCode != 401)
			{
				return Task.FromResult<object>(null);
			}

			AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

			if (challenge == null)
			{
				return Task.FromResult<object>(null);
			}

			var properties = challenge.Properties;
			if (string.IsNullOrEmpty(properties.RedirectUri))
			{
				properties.RedirectUri = BuildCurrentUri();
			}

			// OAuth2 10.12 CSRF
			GenerateCorrelationId(properties);

			var authorizationEndpoint = BuildChallengeUrl(properties, BuildRedirectUri(Options.CallbackPath));
			var redirectContext = new OAuthRedirectToAuthorizationContext(Context, Options, properties, authorizationEndpoint);

			Options.Events.RedirectToAuthorizationEndpoint(redirectContext);

			return Task.FromResult<object>(null);
		}

		#endregion

		#region Invoke / InvokeReply

		public override async Task<bool> InvokeAsync()
		{
			return await InvokeReplyPathAsync();
		}

		private async Task<bool> InvokeReplyPathAsync()
		{
			if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
			{
				AuthenticationTicket ticket = await AuthenticateAsync();

				if (ticket == null || ticket.Identity == null || !ticket.Identity.IsAuthenticated)
				{
					var ex = new Exception("Invalid return state, unable to redirect.");
					var errorContext = new OAuthFailureContext(Context, ex);
					Logger.WriteWarning(ex.Message);

					await Options.Events.RemoteFailure(errorContext);

					if (errorContext.HandledResponse)
					{
						return true;
					}
					if (errorContext.Skipped)
					{
						return false;
					}

					throw new AggregateException("Unhandled remote failure.", errorContext.Failure);
					//Response.StatusCode = 500;
					//return true;
				}

				// We have a ticket if we get here
				var context = new OAuthTicketReceivedContext(Context, Options, ticket)
				{
					SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
					RedirectUri = ticket.Properties.RedirectUri,
				};

				await Options.Events.TicketReceived(context);

				if (context.HandledResponse)
				{
					Logger.WriteVerbose("The SigningIn event returned Handled.");
					return true;
				}
				else if (context.Skipped)
				{
					Logger.WriteVerbose("The SigningIn event returned Skipped.");
					return false;
				}

				if (context.SignInAsAuthenticationType != null && context.Identity != null)
				{
					ClaimsIdentity identity = context.Identity;
					if (!string.Equals(identity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
					{
						identity = new ClaimsIdentity(identity.Claims, context.SignInAsAuthenticationType, identity.NameClaimType, identity.RoleClaimType);
					}
					Context.Authentication.SignIn(context.Properties, identity);
				}

				if (!context.IsRequestCompleted && context.RedirectUri != null)
				{
					string redirectUri = context.RedirectUri;
					if (context.Identity == null)
					{
						// add a redirect hint that sign-in failed in some way
						redirectUri = WebUtils.AddQueryString(redirectUri, "error", "access_denied");
					}
					Response.Redirect(redirectUri);
					context.RequestCompleted();
				}

				return context.IsRequestCompleted;
			}
			return false;
		}

		#endregion
	}
}