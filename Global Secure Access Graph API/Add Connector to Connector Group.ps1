# Prepare body for API access token retrieval
$clientID = ""
$ClientSecret = ""
$body = @{
    client_id = $clientID
    client_secret = $ClientSecret
    scope = "https://graph.microsoft.com/.default"
    grant_type = "client_credentials"
}

# Get API access token
$tenantID = ""
$TokenEndpoint = "https://login.microsoft.com/$tenantId/oauth2/v2.0/token"
$tokenResponse = Invoke-RestMethod -Uri $TokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
$AccessToken = $tokenResponse.access_token
$Headers = @{
    Authorization = "Bearer $AccessToken"
    "Content-Type" = "application/json"
}

# Prepare the request body
$ConnectorGroupName = ""
$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/?`$Filter=name eq '$ConnectorGroupName'"
    Headers = $Headers
}
$ConnectorGroup = Invoke-RestMethod @params
$ConnectorGroupId = $ConnectorGroup.value.id

$PrivateNetworkConnectorFQDN = "" #hostname is case sensitive
$params = @{
    Method = 'Get'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectors/?`$Filter=machinename eq '$PrivateNetworkConnectorFQDN'"
    Headers = $Headers
}
$Connector = Invoke-RestMethod @params
$ConnectorId = $Connector.value.id

# Prepare the request body
$Body = @{
    "@odata.id" = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectors/$ConnectorId"    
} | ConvertTo-Json -Depth 99 -Compress

$params = @{
    Method = 'Post'
    Uri = "https://graph.microsoft.com/beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/$ConnectorGroupId/members/`$ref"
    Headers = $Headers
    Body = $Body
}
Invoke-RestMethod @params