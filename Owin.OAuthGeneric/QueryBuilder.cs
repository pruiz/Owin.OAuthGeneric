﻿// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using Microsoft.Owin;

namespace Owin.OAuthGeneric
{
	// The IEnumerable interface is required for the collection initialization syntax: new QueryBuilder() { { "key", "value" } };
	internal class QueryBuilder : IEnumerable<KeyValuePair<string, string>>
	{
		private IList<KeyValuePair<string, string>> _params;

		public QueryBuilder()
		{
			_params = new List<KeyValuePair<string, string>>();
		}

		public QueryBuilder(IEnumerable<KeyValuePair<string, string>> parameters)
		{
			_params = new List<KeyValuePair<string, string>>(parameters);
		}

		public void Add(string key, IEnumerable<string> values)
		{
			foreach (var value in values)
			{
				_params.Add(new KeyValuePair<string, string>(key, value));
			}
		}

		public void Add(string key, string value)
		{
			_params.Add(new KeyValuePair<string, string>(key, value));
		}

		public override string ToString()
		{
			var builder = new StringBuilder();
			bool first = true;
			for (int i = 0; i < _params.Count; i++)
			{
				var pair = _params[i];
				builder.Append(first ? "?" : "&");
				first = false;
				builder.Append(Uri.EscapeDataString(pair.Key));
				builder.Append("=");
				builder.Append(Uri.EscapeDataString(pair.Value));
			}

			return builder.ToString();
		}

		public QueryString ToQueryString()
		{
			return new QueryString(ToString());
		}

		public override int GetHashCode()
		{
			return ToQueryString().GetHashCode();
		}

		public override bool Equals(object obj)
		{
			return ToQueryString().Equals(obj);
		}

		public IEnumerator<KeyValuePair<string, string>> GetEnumerator()
		{
			return _params.GetEnumerator();
		}

		IEnumerator IEnumerable.GetEnumerator()
		{
			return _params.GetEnumerator();
		}
	}
}
