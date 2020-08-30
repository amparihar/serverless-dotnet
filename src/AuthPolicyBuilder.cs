using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using CWE.APIGateway.Auth.Model;

namespace CWE.APIGateway.Auth
{
    public class AuthPolicyBuilder
    {
        private const string PolicyVersion = "2012-10-17";

        private readonly Regex _pathRegex = new Regex("^[/.a-zA-Z0-9-\\*]+$");
        
        private readonly string _restApiId;
        private readonly string _region;
        private readonly string _stage;

        public string PrincipalId { get; }

        private struct Method
        {
            internal string ArnResource;
        }
        private readonly List<Method> _allowMethods = new List<Method>();
        private readonly List<Method> _denyMethods = new List<Method>();

        public AuthPolicyBuilder(string principalId, ApiOptions apiOptions)
        {
            PrincipalId = principalId;
            _restApiId = string.IsNullOrWhiteSpace(apiOptions?.RestApiId) ? "*" : apiOptions.RestApiId;
            _region = string.IsNullOrWhiteSpace(apiOptions?.Region) ? "*" : apiOptions.Region;
            _stage = string.IsNullOrWhiteSpace(apiOptions?.Stage) ? "*" : apiOptions.Stage;
        }

        public void DenyAll()
        {
            AddResource(Effect.Deny, "*");
        }

        public void AllowAll()
        {
            AddResource(Effect.Allow, "*");
        }

        public AuthPolicy Build()
        {
            var statements = new List<Statement>();
            foreach (var method in _allowMethods)
            {
                statements.Add(new Statement
                {
                    Effect = Effect.Allow.ToString(),
                    Resource = method.ArnResource,
                    Action = "execute-api:Invoke"
                });
            }
            foreach (var method in _denyMethods)
            {
                statements.Add(new Statement
                {
                    Effect = Effect.Deny.ToString(),
                    Resource = method.ArnResource,
                    Action = "execute-api:Invoke"
                });
            }

            return new AuthPolicy
            {
                PrincipalId = PrincipalId,
                PolicyDocument = new PolicyDocument
                {
                    Version = PolicyVersion,
                    Statement = statements
                }
            };
        }

        private void AddResource(Effect effect, string resource)
        {
            if (resource == null)
                throw new ArgumentNullException(nameof(resource));

            if (!_pathRegex.IsMatch(resource))
                throw new Exception($"Invalid resource path: {resource}. Path should match {_pathRegex}");

            string cleanedResource = resource.First() == '/' ? resource.Substring(1) : resource;

            switch (effect)
            {
                case Effect.Deny:
                    _denyMethods.Add(new Method
                    {
                        ArnResource = resource
                    });
                    return;
                case Effect.Allow:
                    _allowMethods.Add(new Method
                    {
                        ArnResource = resource
                    });
                    return;
            }
        }
        
    }
}