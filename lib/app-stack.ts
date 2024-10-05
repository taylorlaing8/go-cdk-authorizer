import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as constructs from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as actions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as codedeploy from 'aws-cdk-lib/aws-codedeploy';
import * as ddb from 'aws-cdk-lib/aws-dynamodb';

export interface AppStackProps extends cdk.StackProps {
	stage: string;
	service: string;
	iso3166Code: string;
}

export class AppStack extends cdk.Stack {
	constructor(scope: constructs.Construct, id: string, props: AppStackProps) {
		super(scope, id, props);

		const snsTopic = new sns.Topic(this, 'SnsTopic', {
			topicName: `${this.stackName}-alarm`,
		});

		// dynamoDb tables
		const authCacheTable = this.createAuthCacheTable();

		const authorizerFunction = this.createAuthorizer(
			props,
			authCacheTable,
			snsTopic
		);
		authCacheTable.grantReadWriteData(authorizerFunction);
	}

	private createAuthorizer(
		props: AppStackProps,
		authCacheTable: cdk.aws_dynamodb.Table,
		snsTopic: cdk.aws_sns.Topic
	) {
		const authorizerFunction = new lambda.Function(
			this,
			'AuthorizerFunction',
			{
				functionName: `${this.stackName}-auth`,
				code: lambda.Code.fromAsset('./dist/authorizer/bootstrap.zip'),
				handler: 'bootstrap',
				runtime: lambda.Runtime.PROVIDED_AL2,
				architecture: lambda.Architecture.ARM_64,
				memorySize: 1024,
				timeout: cdk.Duration.seconds(15),
				tracing: lambda.Tracing.ACTIVE,
				environment: {
					SERVICE: props.service,
					STAGE: props.stage,
					AUTHORIZER_CONFIG_PATH: '/authorizer/config',
					AUTH_CACHE_TABLE_NAME: authCacheTable.tableName,
				},
				currentVersionOptions: {
					removalPolicy: cdk.RemovalPolicy.RETAIN,
				},
			}
		);

		new logs.LogGroup(this, 'AuthorizerFunctionLogGroup', {
			logGroupName: `/aws/lambda/${authorizerFunction.functionName}`,
			retention:
				props.stage === 'prod'
					? logs.RetentionDays.ONE_YEAR
					: logs.RetentionDays.ONE_WEEK,
			removalPolicy: cdk.RemovalPolicy.DESTROY,
		});

		const authorizerFunctionAlias = new lambda.Alias(
			this,
			'AuthorizerFunctionAlias',
			{
				aliasName: 'LIVE',
				version: authorizerFunction.currentVersion,
			}
		);

		const authorizerFunctionErrors = new cloudwatch.Alarm(
			this,
			'AuthorizerFunctionErrors',
			{
				alarmDescription: 'The latest deployment errors >= 5',
				metric: authorizerFunctionAlias.metricErrors({
					statistic: 'Sum',
					period: cdk.Duration.minutes(1),
				}),
				threshold: 5,
				evaluationPeriods: 1,
				actionsEnabled: true,
				comparisonOperator:
					cloudwatch.ComparisonOperator
						.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
			}
		);

		authorizerFunctionErrors.addAlarmAction(
			new actions.SnsAction(snsTopic)
		);

		const lambdaDeploymentConfig = this.isCicdStage(props.stage)
			? codedeploy.LambdaDeploymentConfig.CANARY_10PERCENT_5MINUTES
			: codedeploy.LambdaDeploymentConfig.ALL_AT_ONCE;

		new codedeploy.LambdaDeploymentGroup(
			this,
			'AuthorizerDeploymentGroup',
			{
				alias: authorizerFunctionAlias,
				deploymentConfig: lambdaDeploymentConfig,
				alarms: [authorizerFunctionErrors],
			}
		);

		authorizerFunctionAlias.addToRolePolicy(
			new iam.PolicyStatement({
				effect: iam.Effect.ALLOW,
				actions: ['ssm:GetParameter'],
				resources: [
					`arn:aws:ssm:${this.region}:${this.account}:parameter/authorizer/config`,
				],
			})
		);

		authorizerFunctionAlias.addToRolePolicy(
			new iam.PolicyStatement({
				effect: iam.Effect.ALLOW,
				actions: ['kms:Decrypt'],
				resources: ['*'],
			})
		);

		new cdk.CfnOutput(this, 'AuthFunctionArn', {
			value: authorizerFunctionAlias.functionArn,
		});

		return authorizerFunctionAlias;
	}

	private createAuthCacheTable(): ddb.Table {
		const table = new ddb.Table(this, 'AuthCacheTable', {
			tableName: `${this.stackName}-auth-cache`,
			billingMode: ddb.BillingMode.PAY_PER_REQUEST,
			partitionKey: {
				name: 'PK',
				type: ddb.AttributeType.STRING,
			},
			sortKey: {
				name: 'SK',
				type: ddb.AttributeType.STRING,
			},
			removalPolicy: cdk.RemovalPolicy.DESTROY,
			encryption: ddb.TableEncryption.AWS_MANAGED,
		});

		return table;
	}

	private isCicdStage(stage: string): boolean {
		return ['rd', 'dev', 'staging', 'prod'].includes(stage);
	}

	private isProdStage(stage: string): boolean {
		return 'prod' === stage;
	}
}
