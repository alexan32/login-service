# tome
Discord bot and user interface for roll playing games with AWS backend



## SERVERLESS

### Deployment

You must add a folder called 'config' in the root, and add a yaml file for each environment before you can deploy.

a 'env.yml' file would look something like this:

```
env: d0
account: 123456789012
region: us-east-1
encryptionKey: ******************************
```

In order to deploy a serverless stack, you need to run the following command:

```
$ serverless deploy --stage < dev | test | prod >
```

### Local development

You can invoke your function locally by using the following command:

```
serverless invoke local --function hello
```