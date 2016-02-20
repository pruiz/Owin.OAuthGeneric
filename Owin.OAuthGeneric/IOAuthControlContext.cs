
using Microsoft.Owin.Security;

namespace Owin.OAuthGeneric
{
	public interface IBaseControlContext
	{
		AuthenticationTicket Ticket { get; }
		OAuthEventState State { get; set; }
		bool HandledResponse { get; }
		bool Skipped { get; }

		void HandleResponse();
		void SkipToNextMiddleware();
	}
}