# @serverless-queue/nodejs

A Node.js client for working with [ServerlessQueue](https://www.serverlessqueue.com).  Use this only if there isn't a premade adapter for the framework you are using.

## Getting Started

1. `npm install --save @serverless-queue/nodejs`
2. Create a client using your secret token from [ServerlessQueue](https://www.serverlessqueue.com)
```
import Client from "@serverless-queue/nodejs"
const client = new Client("secret token here")

```
3. Enqueue a job 
```
// this will be useful for viewing analytics about your jobs
const queueName = "anything/you/want"

// the data your job needs to operate, can be any javascript object
const jobPayload = { key: value }

// the callback url to use to handle the job
const callbackUrl = "https://www.yoursite.com/api/queues/queue-name"

await client.enqueue({ queueName, jobPayload, callbackUrl })
```

4. Handle the callback request and perform the job

```
// depending on the framework you are using this will be different
// but you'll need some way to receive incoming requests to a specific endpoint
app.post('/api/queues/queue-name', (req, res) => {
    const webhookSignature = req.headers['sq-webhook-signature']
    const entryId = req.headers['sq-entry-id']
    const rawPayload = req.body

    // verify the request is coming from serverlessqueue.com
    const jobPayload = client.verifyAndDecrypt(rawPayload, webhookSignature)
    if(!jobPayload) {
        res.status(401).json("{error: 'invalid signature'}")
        return
    }

    // setup a heartbeat so we know you are still working on the job
    // 30 seconds is a good amount of time as we assume failure after 1 minute
    // each heartbeat extends the life of the job for another minute
    const heartbeat = setInterval(async () => {
        await client.heartbeat(entryId)
    }, 30000)

    // actually do the job using data in jobPayload
    
    // acknowledge that the job was succesfully completed so we do not retry
    client.ack(entryId)
    
    // stop the heartbeat
    clearInterval(heartbeat)
      
    res.status(200).end()
})

```

## End-to-End Encryption

Serverless Queue supports encrypting the job payload data so that our servers never have access to potentially sensitive information.  To enable this feature simply set a 32 character encryption key using the environment variable `SERVERLESS_QUEUE_ENCRYPTION_KEY` and the client library will automatically encrypt and decrypt the payload using this key.
