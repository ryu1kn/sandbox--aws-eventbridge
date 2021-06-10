import {App, Duration, RemovalPolicy, Stack, StackProps} from '@aws-cdk/core'
import {Trail} from '@aws-cdk/aws-cloudtrail'
import {Key} from '@aws-cdk/aws-kms'
import {PolicyDocument, PolicyStatement} from '@aws-cdk/aws-iam'
import {EventBus, Rule} from '@aws-cdk/aws-events'
import {SqsQueue} from '@aws-cdk/aws-events-targets'
import {Queue} from '@aws-cdk/aws-sqs'

const spikeName = 'spike-eventbridge'
const buildId = (name?: string) => name ? `${spikeName}-${name}` : spikeName

export class MyStack extends Stack {
    constructor(scope: App, id: string, props: StackProps) {
        super(scope, id, props)

        const key = new Key(this, buildId(), {
            pendingWindow: Duration.days(7),
            enableKeyRotation: true,
            removalPolicy: RemovalPolicy.DESTROY,
            policy: new PolicyDocument({
                statements: [
                    PolicyStatement.fromJson({
                        Sid: 'Allow CloudTrail to encrypt logs',
                        Effect: 'Allow',
                        Principal: {Service: 'cloudtrail.amazonaws.com'},
                        Action: [
                            'kms:GenerateDataKey*',
                            'kms:DescribeKey'
                        ],
                        Resource: '*',
                        Condition: {
                            StringLike: {
                                'kms:EncryptionContext:aws:cloudtrail:arn': [
                                    `arn:aws:cloudtrail:*:${this.account}:trail/*`
                                ]
                            }
                        }
                    })
                ]
            })
        });
        key.addAlias(`alias/${spikeName}`)

        new Trail(this, 'management-events', {
            trailName: 'management-events',
            encryptionKey: key
        })

        const bus = EventBus.fromEventBusArn(
            this,
            buildId('default-bus'),
            `arn:aws:events:${this.region}:${this.account}:event-bus/default`
        )

        const queue = new Queue(this, buildId('queue'), {
            retentionPeriod: Duration.days(1)
        })

        new Rule(this, buildId('cloudtrail-event'), {
            ruleName: `${spikeName}-from-cloudtrail`,
            description: 'Events from CloudTrail',
            eventBus: bus,
            eventPattern: {
                source: ['aws.dynamodb'],
                detailType: ['AWS API Call via CloudTrail'],
                detail: {eventSource: ['dynamodb.amazonaws.com']}
            },
            targets: [new SqsQueue(queue)]
        })
    }
}

const app = new App()
const stackProps = {env: {region: 'ap-southeast-2'}}

new MyStack(app, 'sandbox--eventbridge', stackProps)

app.synth()
