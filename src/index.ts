/*
 * Copyright 2021, Graham Daley.
 *
 * With thanks to vados
 * https://vadosware.io/post/setting-up-ses-with-pulumi/
 *
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * If a copy of the MPL was not distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 */

import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { ComponentResource, ComponentResourceOptions, Input, Output } from "@pulumi/pulumi";

export interface SesArgs {
    description: string;
    baseTags: aws.Tags;

    region: string;
    baseDomain: string;
    dnsZoneId: Input<string>;
    adminEmailAddress: string;
}

export class Ses extends ComponentResource {
    private readonly name: string;
    private readonly description: string;
    private readonly baseTags: { [k: string]: Input<string> };
    private readonly emailUserSmtpPassword: Output<string>;
    private readonly emailUserId: Output<string>;

    constructor(name: string, args: SesArgs, opts?: ComponentResourceOptions) {
        super("codicy:aws-ses", name, {}, opts);

        // Make base info available to other methods.
        this.name = name;
        this.description = args.description;
        this.baseTags = args.baseTags;

        const stack = pulumi.getStack();
        const resourcePrefix = [args.baseDomain, stack].join("-");

        // IAM email identity
        const emailUsername = `${resourcePrefix}-email`; // i.e. "domain.tld-production-email"
        const emailUser = new aws.iam.User(
            `${resourcePrefix}-ses`,
            {
                name: emailUsername,
                path: "/system/",
                tags: { Environment: stack }
            },
        );

        const allowedFromAddress = stack === "production" ? `*@${args.baseDomain}` : `*@${stack}.${args.baseDomain}`;

        // Policy
        const emailUserPolicy = new aws.iam.UserPolicy(
            `${resourcePrefix}-ses-policy`,
            {
                user: emailUser.name,
                policy: JSON.stringify({
                    Version: "2012-10-17",
                    Statement: [
                        {
                            Action: [
                                "ses:SendEmail",
                                "ses:SendTemplatedEmail",
                                "ses:SendRawEmail",
                                "ses:SendBulkTemplatedEmail",
                            ],
                            Effect: "Allow",
                            Resource: "*",
                            Condition: {
                                StringLike: {
                                    "ses:FromAddress": allowedFromAddress,
                                }
                            }
                        }
                    ]
                }, null, '  '),
            },
        );

        // Email Access key
        const emailAccessKey = new aws.iam.AccessKey(
            `${resourcePrefix}-ses-access-key`,
            { user: emailUser.name }
        );

        this.emailUserSmtpPassword = emailAccessKey.sesSmtpPasswordV4;
        this.emailUserId = emailAccessKey.id;

        ///////////////////
        // SES / Route53 //
        ///////////////////

        // Domain Identity
        const domain: string = stack === "production" ? args.baseDomain : `${stack}.${args.baseDomain}`;
        const stackDomainIdentity = new aws.ses.DomainIdentity(
            `${resourcePrefix}`,
            { domain: domain },
        );

        // Verification record
        const sesStackVerificationRecord = new aws.route53.Record(
            `${resourcePrefix}-ses-verification`,
            {
                zoneId: args.dnsZoneId,
                name: `_amazonses.${stack}`,
                ttl: 3600,
                type: "TXT",
                records: [stackDomainIdentity.verificationToken],
            }
        );

        ///////////////
        // MAIL FROM //
        ///////////////

        // MAIL FROM Domain (bounce.<stack>.domain.tld)
        //
        // NOTE: The MAIL FROM domain shouldn't actually be used to send or receive email,
        // mail should be received/sent from <stack>.domain.tld
        // https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mail-from.html

        const stackMailFrom = new aws.ses.MailFrom(
            `${resourcePrefix}-ses-mail-from`,
            {
                domain: stackDomainIdentity.domain,
                mailFromDomain: pulumi.interpolate`bounce.${stackDomainIdentity.domain}`,
            }
        );

        // MAIL FROM MX record
        const stackMailFromMXRecord = new aws.route53.Record(
            `${resourcePrefix}-ses-mail-from-mx-record`,
            {
                zoneId: args.dnsZoneId,
                name: stackMailFrom.mailFromDomain,
                type: "MX",
                ttl: 3600,
                records: [`10 feedback-smtp.${args.region}.amazonses.com`],
            }
        );

        /////////
        // SPF //
        /////////

        // SPF MX record
        const stackSPFMXRecord = new aws.route53.Record(
            `${resourcePrefix}-ses-spf-mx-record`,
            {
                name: stackMailFrom.mailFromDomain,
                type: "TXT",
                ttl: 3600,
                zoneId: args.dnsZoneId,
                // Allow email from amazonses.com and the stack's FQDN (ex. stack
                records: [`v=spf1 include:amazonses.com mail -all`],
            }
        );

        ////////////////
        // DKIM - AWS //
        ////////////////

        const stackDomainDKIM = new aws.ses.DomainDkim(
            `${resourcePrefix}-ses-domain-dkim`,
            { domain: stackDomainIdentity.domain },
        );

        const stackDKIMRecords: aws.route53.Record[] = [];
        const dkimRecordCount = 3;

        for (let i = 0; i < dkimRecordCount; i++) {
            const token = stackDomainDKIM.dkimTokens[i].apply(t => `${t}.dkim.amazonses.com`);
            const name = stackDomainDKIM.dkimTokens[i].apply(t => `${t}._domainkey.${stack}.${args.baseDomain}`);

            const dkimRecord = new aws.route53.Record(
                `${resourcePrefix}-dkim-record-${i + 1}-of-${dkimRecordCount}`,
                {
                    zoneId: args.dnsZoneId,
                    name,
                    type: "CNAME",
                    ttl: 3600,
                    records: [token],
                });

            stackDKIMRecords.push(dkimRecord);
        }

        ///////////
        // DMARC //
        ///////////

        // DMARC MX record
        const dmarcRecord = new aws.route53.Record(
            `${resourcePrefix}-external-dmarc`,
            {
                name: `_dmarc.${domain}`,
                zoneId: args.dnsZoneId,
                ttl: 3600,
                type: "TXT",
                records: [
                    `v=DMARC1; p=none; rua=mailto:${args.adminEmailAddress}; fo=1;`,
                ],
            }
        );

        this.registerOutputs({});
    }

    public getEmailUserSmtpPassword(): Output<string> {
        return this.emailUserSmtpPassword;
    }

    public getEmailUserId(): Output<string> {
        return this.emailUserId;
    }

}
