
using System;
using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using System.Collections.Generic;
using Newtonsoft.Json;
using Amazon.DynamoDBv2;
//using Amazon.DynamoDBv2.DocumentModel;

namespace CWE.Lambda.Functions
{
    public class GetNotesFunction
    {
        [LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]
        public APIGatewayProxyResponse Get(APIGatewayProxyRequest request)
        {
            //var _dbClient = CreateDbClient();
            
            return new APIGatewayProxyResponse
            {
                StatusCode = 200,
                Body = JsonConvert.SerializeObject(request),
                Headers = new Dictionary<string, string>{
                  { "Content-Type", "application/json" },
                  { "Access-Control-Allow-Origin","*" }
              }
            };
        }

        public static AmazonDynamoDBClient CreateDbClient()
        {
            AmazonDynamoDBConfig ddbConfig = new AmazonDynamoDBConfig();
            ddbConfig.ServiceURL = Environment.GetEnvironmentVariable("DYNAMODB_SERVICEURL");
            try
            {
                var client = new AmazonDynamoDBClient(ddbConfig);
                return client;
            }
            catch (Exception ex)
            {
                Console.WriteLine("FAILED to create a DynamoDB client; " + ex.Message);
                return null;
            }

        }
    }
}
