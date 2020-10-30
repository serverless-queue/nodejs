import fetch from 'node-fetch'
import superjson from 'superjson'
import Encryptor from './utils/encryption'
import { sign, verify } from './utils/verification'

const serverlessQueueHost = process.env.SERVERLESS_QUEUE_HOST || "https://queue.serverlessqueue.com"
const serverlessQueueEncryptionSecret = process.env.SERVERLESS_QUEUE_ENCRYPTION_SECRET
const serverlessQueuePreviousSecret  = process.env.SERVERLESS_QUEUE_PREVIOUS_SECRET

interface EnqueueArgs {
    queueName: string,
    jobPayload: Record<any, any>,
    callbackUrl: string
}

class Client {
    private readonly token;
    private readonly encryptor;

    constructor(token: string) {
        this.token = token;
        if(serverlessQueueEncryptionSecret) {
            this.encryptor = new Encryptor(serverlessQueueEncryptionSecret, serverlessQueuePreviousSecret)        
        }
    }

    async enqueue({ queueName, jobPayload, callbackUrl }: EnqueueArgs) {
        let payloadString = superjson.stringify(jobPayload)
        if(this.encryptor) {
            payloadString = this.encryptor.encrypt(payloadString)
        }
        return await this.request(`/enqueue`, payloadString, { 'sq-queue': queueName, 'sq-callback': callbackUrl })
    }

    async ack(entryId: string) {
        return await this.request(`/ack`, '', { 'sq-entry-id': entryId })
    }

    async heartbeat(entryId: string) {
        return await this.request(`/heartbeat`, '', { 'sq-entry-id': entryId })
    }

    async request(path: string, body = '', headers = {}) {
        const url = `${serverlessQueueHost}${path}`
        const response = await fetch(url, {
            method: "POST",
            body,
            headers: {
                'Content-Type': 'text/plain',
                'sq-token': this.token,
                ...headers
            }
        })
        const json = await response.json()
        return json
    }

    sign(payload: string, secret: string = this.token) {
        return sign(payload, secret)
    }

    decrypt(payload: string): Record<any,any> {
        if(!this.encryptor) {
            return superjson.parse(payload) 
        }
        return superjson.parse(this.encryptor.decrypt(payload))
    }

    verify(input: string, signature: string) {
        return verify(input, this.token, signature)
    }

    verifyAndDecrypt(input: string, signature: string): Record<any,any> | null {
        if(!this.verify(input, signature)) {
            return null
        }
        return this.decrypt(input)
    }
}

export default Client