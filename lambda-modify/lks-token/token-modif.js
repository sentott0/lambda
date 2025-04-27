const crypto = require("crypto");
const moment = require("/opt/node_modules/moment");
const saltedMd5 = require("/opt/node_modules/salted-md5");
const { PutItemCommand, DynamoDBClient } = require("/opt/node_modules/@aws-sdk/client-dynamodb");
const { buildResponse } = require("/opt/utilities");

const config = { region: "us-east-1" };
const client = new DynamoDBClient(config);
const TableName = "tokens";

module.exports.handler = async (event) => {
   console.log("Raw event received:", JSON.stringify(event, null, 2));

   try {
      // Handle both API Gateway Proxy (with body) and direct invocation (without body)
      const requestData = event.body ? JSON.parse(event.body) : event;

      // Input validation
      if (!requestData.deviceId || requestData.expired === undefined) {
         return buildResponse(400, "Both deviceId and expired fields are required");
      }

      if (typeof requestData.expired !== 'number' || requestData.expired <= 0) {
         return buildResponse(400, "expired must be a positive number");
      }

      // Token generation
      const currentDate = moment();
      const token = saltedMd5(moment().unix(), crypto.randomBytes(16));
      const expiredDate = moment(currentDate)
         .add(requestData.expired, "days")
         .toISOString();

      // DynamoDB operation
      const params = {
         TableName,
         Item: {
            token: { S: token },
            deviceId: { S: requestData.deviceId },
            expiredDate: { S: expiredDate },
            createdAt: { S: currentDate.toISOString() },
         },
         ConditionExpression: "attribute_not_exists(deviceId)",
      };

      await client.send(new PutItemCommand(params));

      return buildResponse(200, "Generate token success", {
         token,
         deviceId: requestData.deviceId,
         expired: expiredDate,
         createdAt: currentDate.toISOString(),
      });

   } catch (e) {
      console.error("Error details:", {
         message: e.message,
         stack: e.stack,
         event: event
      });

      if (e.name === 'ConditionalCheckFailedException') {
         return buildResponse(409, "Device ID already exists");
      }

      return buildResponse(500, "Generate token error", {
         error: e.message,
         type: e.name,
      });
   }
};