# cf-authorizer

## Prereqs

- Install VS Code for working in CDK in Typescript
- Install Node.js 16 LTS https://nodejs.org/en/
- Install cdk cli tool globally https://docs.aws.amazon.com/cdk/v2/guide/getting_started.html
- Install AWS cli tool https://aws.amazon.com/cli/ and setup default credentials using `aws configure`.

## Notes

The repo was patterned after `https://github.com/adamelmore/cdk-top-level-await`.

## Install

Install CDK cli

```
npm install -g aws-cdk
```

Install cdk packages

```
npm i
```

Create a `.env` file and add the following variables:

```
CDK_DEFAULT_ACCOUNT=<AWS ACCOUNT ID>
CDK_DEFAULT_REGION=<AWS REGION>
SERVICE=cf-authorizer
STAGE=dev
ISO_3166_CODE=us
```

Create an instance profile called `cf-dev`

## Build

```
npm run go:build
```

## Deploy

Step 1: Refresh your AWS credentials

```
aws sso login --profile cf-dev
```

Step 2: Deploy the app stack

```
cdk deploy cf-authorizer-dev-app --profile cf-dev
```
