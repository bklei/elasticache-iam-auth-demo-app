package com.amazon.elasticache;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityResponse;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Utility app to create an IAM Auth token
 */
public class IAMAuthTokenGeneratorApp {

    @Parameter(names = {"-h", "--help"}, help = true)
    private boolean help;

    @Parameter(names = {"--user-id"})
    private String userId;

    @Parameter(names = {"--replication-group-id"})
    private String replicationGroupId;

    @Parameter(names = {"--region"})
    private String region = "us-east-1";

    public static void main(String[] args) throws Exception {
        IAMAuthTokenGeneratorApp app = new IAMAuthTokenGeneratorApp();
        JCommander jc = JCommander.newBuilder().addObject(app).build();
        jc.parse(args);

        if (app.help) {
            jc.usage();
            return;
        }
        app.run();
    }

    private void run() throws Exception {
        Preconditions.checkArgument(!Strings.isNullOrEmpty(userId),
            "userId cannot be be null or emtpy");

        Preconditions.checkArgument(!Strings.isNullOrEmpty(replicationGroupId),
            "replicationGroupId cannot be be null or emtpy");

        // Read the EKS service account token
        String tokenPath = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token";
        String webIdentityToken = new String(Files.readAllBytes(Paths.get(tokenPath)));

        // Assume the IAM role using STS
        String roleArn = "arn:aws:iam::647619633241:role/cicd01-gel-ingress-nginx-websocket-access";
        String roleSessionName = "nginx-ingress";
        StsClient stsClient = StsClient.builder().region(software.amazon.awssdk.regions.Region.of(region)).build();
        AssumeRoleWithWebIdentityRequest stsRequest = AssumeRoleWithWebIdentityRequest.builder()
            .roleArn(roleArn)
            .roleSessionName(roleSessionName)
            .webIdentityToken(webIdentityToken)
            .build();
        AssumeRoleWithWebIdentityResponse stsResponse = stsClient.assumeRoleWithWebIdentity(stsRequest);

        // Debug output to confirm role assumption
        System.out.println("DEBUG: Assumed role ARN: " + stsResponse.assumedRoleUser().arn());
        System.out.println("DEBUG: Session token prefix: " + stsResponse.credentials().sessionToken().substring(0, 20) + "...");
        System.out.println("DEBUG: Expiration: " + stsResponse.credentials().expiration());

        AwsSessionCredentials sessionCredentials = AwsSessionCredentials.create(
            stsResponse.credentials().accessKeyId(),
            stsResponse.credentials().secretAccessKey(),
            stsResponse.credentials().sessionToken()
        );

        System.out.println("DEBUG: Access key: " + sessionCredentials.accessKeyId());
        System.out.println("DEBUG: Secret key: " + sessionCredentials.secretAccessKey());

        // Use the assumed role credentials to generate the IAM auth token
        IAMAuthTokenRequest iamAuthTokenRequest = new IAMAuthTokenRequest(userId, replicationGroupId, region);
        String iamAuthToken = iamAuthTokenRequest.toSignedRequestUri(sessionCredentials);

        // Debug output for canonical request and string to sign
        System.out.println("DEBUG: Canonical Request:\n" + iamAuthTokenRequest.getCanonicalRequest());
        System.out.println("DEBUG: String to Sign:\n" + iamAuthTokenRequest.getStringToSign());

        System.out.println(iamAuthToken);
    }
}
