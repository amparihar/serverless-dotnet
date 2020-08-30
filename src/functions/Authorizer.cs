
using System;
using Amazon.Lambda.Core;
using Newtonsoft.Json;

using CWE.APIGateway.Auth.Model;

namespace CWE.APIGateway.Auth
{
    public class TokenAuthorizerContext
    {
        [JsonProperty(PropertyName = "Type")]
        public string Type { get; set; }

        [JsonProperty(PropertyName = "AuthorizationToken")]
        public string AuthorizationToken { get; set; }

        [JsonProperty(PropertyName = "MethodArn")]
        public string MethodArn { get; set; }
    }

    internal class UnauthorizedException : System.Exception
    {
        public UnauthorizedException() : base("Unauthorized")
        {
        }
    }
    public class Authorizer
    {
        //[LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]
        [LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]
        public AuthPolicy Authorize(TokenAuthorizerContext input, ILambdaContext context)
        {
            try
            {
                context.Logger.LogLine($"{nameof(input.AuthorizationToken)}: {input.AuthorizationToken}");
                context.Logger.LogLine($"{nameof(input.MethodArn)}: {input.MethodArn}");

                var principalId = "";
                AuthPolicyBuilder policyBuilder;
                if (bool.Parse(input.AuthorizationToken))
                {
                    principalId = "user|u1";
                    policyBuilder = new AuthPolicyBuilder(principalId, null);
                    policyBuilder.AllowAll();
                }
                else
                {
                    policyBuilder = new AuthPolicyBuilder(principalId, null);
                    policyBuilder.DenyAll();
                }
                var authResponse = policyBuilder.Build();

                // context values are  available by APIGW in : context.Authorizer.<key>
                
                authResponse.Context.Add("userId", principalId);
                return authResponse;
            }
            catch (Exception ex)
            {
                if (ex is UnauthorizedException)
                    throw;
                context.Logger.LogLine(ex.ToString());
                throw new UnauthorizedException();
            }
        }
    }

}